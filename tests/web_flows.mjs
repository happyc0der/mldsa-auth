// V4-13c: the browser's login and rotation flows (web/client/flows.mjs)
// against the REAL daemon, with an in-memory store standing in for IndexedDB.
//
//   node web_flows.mjs FIXTURE MODULE.mjs CLIENT_DIR
//
// One scenario per branch of the .ek.next rule (spec 10.2, erratum 33), each
// set up in the store exactly as a crash would leave it:
//   no pending key          login uses the current key
//   stale pending key       login uses the current key and LEAVES the pending
//                           one; rotate discards it (proven stale) and rotates
//   lost ACK                the daemon committed, the store did not: the next
//                           login completes the rotation
//   neither key works       refused, and the store is byte-identical afterwards
// and, since V4-68 (F137), that the server key used is the one pinned at
// enrollment, whatever the page offers; and, since V4-136 (F218), that two
// rotations of one identity run one after the other, a login waits for a
// rotation in progress, and the store promotes only the key its caller staged; and, since V4-138
// (F220), that a new key follows the site's answer to its enrollment:
// removed when refused, confirmed when enrolled, kept and marked when the
// site did not answer, and confirmed by the first login that succeeds.
// And, since V4-147 (F226), that a recovery whose probes never reached the
// daemon's verdict (a wrong passphrase, an unreachable daemon, a pending key
// that will not open) is reported as unresolved, not as two refused keys.
// And, since V4-159 (F235), that a rotation which never got a session leaves
// nothing pending, while one whose ACK was lost keeps its key.
// The IndexedDB store itself (its transactions) is tested in a real browser.
import { spawn, spawnSync } from 'node:child_process';
import { argon2Sync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createConnection } from 'node:net';
import { isDeepStrictEqual } from 'node:util';
import { pathToFileURL } from 'node:url';

const [fixturePath, modulePath, clientDir] = process.argv.slice(2);
if (!fixturePath || !modulePath || !clientDir) {
  console.log('usage: web_flows.mjs FIXTURE MODULE.mjs CLIENT_DIR');
  process.exit(2);
}
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) fail = 1; };
const hex = (b) => Buffer.from(b).toString('hex');
const PASS = 'correct horse battery staple';

const fx = spawn(fixturePath, ['120'], { stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  fx.stdout.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { resolve(JSON.parse(buf.slice(0, nl))); } });
  fx.on('exit', (c) => reject(new Error(`fixture exited ${c}`)));
  setTimeout(() => reject(new Error('fixture never became ready')), 20000);
});
const serverPub = Uint8Array.from(Buffer.from(info.server_pub, 'hex'));
const site = (line) => new Promise((resolve, reject) => {
  const s = createConnection(info.site);
  let buf = '';
  s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { s.end(); resolve(buf.slice(0, nl)); } });
  s.on('error', reject);
  s.write(line + '\n');
});
const pkOf = (img) => img.slice(9 + img[8]);
const enroll = (handle, img) => site(`ENROLL user=${hex(new TextEncoder().encode('u-' + handle.slice(0, 8)))} ` +
  `handle=${hex(new TextEncoder().encode(handle))} pk=${hex(pkOf(img))} via=site`);

try {
  const { default: createMldsaClient } = await import(pathToFileURL(modulePath).href);
  const { AuthdClient, Session } = await import(pathToFileURL(`${clientDir}/authd-client.mjs`).href);
  const { MemoryStore, IdentityStore } = await import(pathToFileURL(`${clientDir}/store.mjs`).href);
  const flows = await import(pathToFileURL(`${clientDir}/flows.mjs`).href);
  const client = await AuthdClient.load(createMldsaClient);
  const url = `ws://127.0.0.1:${info.ws_port}/authd/v1`;

  // A fresh enrolled identity in a fresh store.
  const fresh = async () => {
    const id = client.newIdentity(PASS);
    const r = await enroll(id.handle, id.publicImage);
    const store = new MemoryStore();
    await store.create({ handle: id.handle, serverId: info.server_id, serverPub, envelope: id.envelope });
    return { id, store, enrolled: r.startsWith('OK'),
             params: { url, serverId: info.server_id, serverPub, handle: id.handle, passphrase: PASS, probeTimeoutMs: 3000 } };
  };

  { const { store, params, enrolled } = await fresh();
    const s = await flows.login(client, store, params);
    check(enrolled && s.code.length === 32, 'no pending key: login uses the current key');
    await s.close(); }

  { const { store, params } = await fresh();
    const stale = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, stale.envelope);
    const said = [];
    const s = await flows.login(client, store, params, (e) => said.push(e));
    await s.close();
    const after = await store.get(params.handle);
    check(said.includes('the current key is live; the pending one was never committed') &&
          after.pending !== null && isDeepStrictEqual(after.pending, stale.envelope),
          'stale pending key: login proves the current key live and LEAVES the pending key alone');
    await flows.rotate(client, store, params);
    const rot = await store.get(params.handle);
    check(rot.pending === null && !isDeepStrictEqual(rot.envelope, stale.envelope) && rot.rotatedAt !== null,
          'stale pending key: rotate discards it (proven stale) and rotates to a NEW key');
    const s2 = await flows.login(client, store, params);
    check(s2.code.length === 32, 'stale pending key: the rotated key logs in');
    await s2.close(); }

  { const { store, params } = await fresh();
    // The crash: the daemon commits the rotation, the store never hears of it.
    const next = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, next.envelope);
    const cur = await store.get(params.handle);
    const s = await client.login({ ...params, envelope: cur.envelope, keepForRotate: true });
    await s.rotate(next.envelope, PASS);
    await s.close();                               // ... and promote() is never called
    const said = [];
    const s2 = await flows.login(client, store, params, (e) => said.push(e));
    await s2.close();
    const after = await store.get(params.handle);
    check(said.includes('completed the interrupted rotation') && after.pending === null &&
          isDeepStrictEqual(after.envelope, next.envelope),
          'lost ACK: the next login finds the pending key live and completes the rotation'); }

  { const { store, params } = await fresh();
    // Neither key is one the daemon knows: an unenrolled current key, and an
    // unenrolled pending one.
    const a = client.newIdentity(PASS, params.handle), b = client.newIdentity(PASS, params.handle);
    const orphan = new MemoryStore();
    await orphan.create({ handle: params.handle, serverId: info.server_id, serverPub, envelope: a.envelope });
    await orphan.stagePending(params.handle, b.envelope);
    const before = await orphan.get(params.handle);
    let refused = false;
    try { const s = await flows.login(client, orphan, params); await s.close(); }
    catch (e) { refused = e.name === 'RecoveryRefused'; }
    check(refused && isDeepStrictEqual(await orphan.get(params.handle), before),
          'neither key works: refused, and the store is exactly as it was -- nothing deleted, nothing promoted');
    void store; }

  // V4-147 (F226): a probe that never reached the daemon's verdict is not the
  // daemon refusing the key. Each of these used to end in RecoveryRefused,
  // "neither the current nor the pending key authenticates", for an identity
  // whose current key the daemon accepts.
  const unresolved = async (label, alter, wants) => {
    const { store, params } = await fresh();
    const stale = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, stale.envelope);
    const before = await store.get(params.handle);
    let err = null;
    try { const s = await flows.login(client, store, { ...params, ...alter }); await s.close(); }
    catch (e) { err = e; }
    check(err !== null && err.name !== 'RecoveryRefused',
          `recovery, ${label}: not reported as two keys the daemon refused (F226)`);
    check(err !== null && err.name === 'RecoveryUnresolved' && wants.test(err.message) &&
          /nothing has been changed/.test(err.message) || (console.log(`  got: ${err?.name}: ${err?.message}`), false),
          `recovery, ${label}: the error says the daemon was not asked, and why (F226)`);
    check(isDeepStrictEqual(await store.get(params.handle), before),
          `recovery, ${label}: the store is exactly as it was (F226)`);
    // ... and with the obstacle gone the same store logs in.
    const s = await flows.login(client, store, params);
    check(s.code.length === 32, `recovery, ${label}: the same identity then logs in (F226)`);
    await s.close();
  };
  await unresolved('wrong passphrase', { passphrase: 'not the passphrase at all, sorry' }, /neither key of .* could be opened .*decryption-failed.*the daemon was not asked/);
  await unresolved('daemon unreachable', { url: 'ws://127.0.0.1:9/authd/v1' }, /could not ask the daemon/);

  { // V4-312 (F431): the daemon accepts the current key and cannot record the
    // login. It answers ERROR(0x05); it used to close, which read as the key
    // being refused, and with the stale pending key refused too the page said
    // neither key authenticates. The store is made to refuse a new login code
    // by a second connection that holds its write lock for the login.
    const { store, params } = await fresh();
    const stale = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, stale.envelope);
    const before = await store.get(params.handle);
    const db = join(dirname(info.site), 'wasm.sqlite3');
    // V4-339 (F653): by a second connection HOLDING THE WRITE LOCK while
    // the login runs; it was a planted trigger, and the daemon no longer
    // runs anything the file holds.
    const flag = join(dirname(info.site), 'lock.held');
    rmSync(flag, { force: true });
    const holder = spawn('python3', ['-I', '-c',
      'import sqlite3, sys, time\nc = sqlite3.connect(sys.argv[1], timeout=5, isolation_level=None)\n' +
      'c.execute("BEGIN IMMEDIATE")\nopen(sys.argv[2], "w").close()\ntime.sleep(120)', db, flag], { stdio: 'ignore' });
    for (let i = 0; i < 100 && !existsSync(flag); i++) { await new Promise((r) => setTimeout(r, 50)); }
    const blocked = existsSync(flag);
    let err = null, unblocked = false;
    try {
      try { const s = await flows.login(client, store, params); await s.close(); } catch (e) { err = e; }
      unblocked = holder.exitCode === null;            // it held the lock to the end
    } finally {
      // F666: whatever happens above, the holder does not outlive it.
      holder.kill();
      await new Promise((r) => (holder.exitCode !== null || holder.signalCode !== null ? r() : holder.once('exit', r)));
    }
    check(blocked && unblocked,
          `recovery, login not recorded: the store was made to refuse a login code, and put back (${blocked}, ${unblocked})`);
    check(err !== null && err.name !== 'RecoveryRefused',
          `recovery, login not recorded: not reported as two keys the daemon refused (${err?.name}) (F431)`);
    check(err !== null && err.name === 'RecoveryUnresolved' &&
          /could not ask the daemon which key .* is live \(daemon-could-not-answer at login-code/.test(err.message),
          `recovery, login not recorded: the error says the daemon could not answer (${err?.name}: ${err?.message}) (F431)`);
    check(isDeepStrictEqual(await store.get(params.handle), before),
          'recovery, login not recorded: the store is exactly as it was (F431)');
    const s = await flows.login(client, store, params);
    check(s.code.length === 32, 'recovery, login not recorded: the same identity then logs in (F431)');
    await s.close(); }

  { // The daemon refuses the current key (the rotation committed) and the
    // pending key will not open: that is not "neither authenticates" either.
    const { store, params } = await fresh();
    const next = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, next.envelope);
    const cur = await store.get(params.handle);
    const s = await client.login({ ...params, envelope: cur.envelope, keepForRotate: true });
    await s.rotate(next.envelope, PASS);
    await s.close();
    const broken = next.envelope.slice(); broken[broken.length - 1] ^= 1;
    const damaged = new MemoryStore();
    await damaged.create({ handle: params.handle, serverId: info.server_id, serverPub, envelope: cur.envelope });
    await damaged.stagePending(params.handle, broken);
    let err = null;
    try { const s2 = await flows.login(client, damaged, params); await s2.close(); } catch (e) { err = e; }
    check(err !== null && err.name === 'RecoveryUnresolved' && /pending key could not be opened/.test(err.message),
          'recovery, damaged pending key: the error says which key was refused and which would not open (F226)'); }

  // V4-136 (F218): two rotations of one identity at once -- two tabs of the
  // account page. Tab A is held between staging its key and sending ROTATE,
  // which is where tab B used to find "a pending key and a live current key",
  // discard A's pending key as stale and stage its own; A's ROTATE then
  // committed, and A promoted B's key -- one the daemon never saw -- over the
  // only copy of the key the daemon now accepts. A waits for B to stage, or
  // for 1.5 s: with the rotations serialized B cannot stage until A is done.
  // B, once it has staged, waits for A's rotation to be answered.
  { const { store, params } = await fresh();
    let bStaged; const bHasStaged = new Promise((r) => { bStaged = r; });
    let aStaged; const aHasStaged = new Promise((r) => { aStaged = r; });
    const tab = (after) => new Proxy(store, { get: (t, k) => (k === 'stagePending'
      ? async (...a) => { await t.stagePending(...a); await after(); }
      : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    const tabA = tab(async () => { aStaged(); await Promise.race([bHasStaged, new Promise((r) => setTimeout(r, 1500))]); });
    let a = null;
    const tabB = tab(async () => { bStaged(); await a; });   // B's ROTATE leaves after A's has been answered
    a = flows.rotate(client, tabA, params).then(() => 'ok', (e) => e.message);
    // Review 76: a wait with its own end. If the rotation fails before it
    // stages, this used to sit until the fixture's 120 s ran out, and the run
    // ended with no summary line.
    check(await Promise.race([aHasStaged.then(() => true), new Promise((r) => setTimeout(() => r(false), 20000))]),
          'two tabs: the first rotation reaches its staging step (the test can go on)');
    const b = flows.rotate(client, tabB, params).then(() => 'ok', (e) => e.message);
    const [ra, rb] = await Promise.all([a, b]);
    console.log(`  two rotations: A ${ra}; B ${rb}`);
    let logged = false, why = '';
    try { const s = await flows.login(client, store, params); logged = s.code.length === 32; await s.close(); }
    catch (e) { why = e.message; }
    check(logged, `two rotations at once: the identity still logs in afterwards ${why && `(${why})`}`);
    const after = await store.get(params.handle);
    check(ra === 'ok' && rb === 'ok' && after.pending === null,
          'two rotations at once: they run one after the other, both succeed, nothing is left pending'); }

  // A login in another tab while a rotation is between the daemon's ACK and
  // its promote: it waits for the rotation instead of completing it underneath
  // (which made the rotation that had succeeded report "nothing pending").
  { const { store, params } = await fresh();
    let atPromote; const reached = new Promise((r) => { atPromote = r; });
    let loginDone; const loggedIn = new Promise((r) => { loginDone = r; });
    const tabA = new Proxy(store, { get: (t, k) => (k === 'promote'
      ? async (...a) => { atPromote(); await Promise.race([loggedIn, new Promise((r) => setTimeout(r, 1500))]); return t.promote(...a); }
      : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    const a = flows.rotate(client, tabA, params).then(() => 'ok', (e) => e.message);
    check(await Promise.race([reached.then(() => true), new Promise((r) => setTimeout(() => r(false), 20000))]),
          'login during a rotation: the rotation reaches its promote step (the test can go on)');
    let logged = false;
    try { const s = await flows.login(client, store, params); logged = s.code.length === 32; await s.close(); } catch { logged = false; }
    loginDone();
    const ra = await a;
    check(ra === 'ok' && logged, `a login during a rotation waits for it: the rotation reports success and the login uses its key (rotation: ${ra})`); }

  // V4-159 (F235): a rotation that never got a session leaves nothing pending.
  // The new key is staged before the login that carries ROTATE, and that login
  // is the first time the passphrase meets the current key. A mistyped
  // passphrase (one the policy accepts), or a daemon that could not be
  // reached, failed that login and left the new key staged: every later login
  // then ran the interrupted-rotation probe, for a rotation that never left.
  for (const [label, alter] of [['wrong passphrase', { passphrase: 'not the passphrase at all, sorry' }],
                                ['daemon unreachable', { url: 'ws://127.0.0.1:9/authd/v1' }]]) {
    const { store, params } = await fresh();
    const before = await store.get(params.handle);
    let threw = false;
    try { await flows.rotate(client, store, { ...params, ...alter }); } catch { threw = true; }
    const after = await store.get(params.handle);
    check(threw && after.pending === null,
          `rotate, ${label}: the rotation fails and no key is left pending (F235)`);
    check(isDeepStrictEqual(after, before), `rotate, ${label}: the store is exactly as it was (F235)`);
    const said = [];
    const s = await flows.login(client, store, params, (e) => said.push(e));
    check(s.code.length === 32 && said.length === 0,
          `rotate, ${label}: the next login is an ordinary one, with no interrupted rotation to resolve (F235)`);
    await s.close();
  }

  // ... and the other side of that rule, which nothing drove through
  // flows.rotate until V4-159: once there IS a session, a rotation that is not
  // acknowledged KEEPS its key. Here the daemon commits and the ACK is lost
  // (the session's rotate runs for real and then throws). Discarding the
  // staged key at that point would discard the only copy of the key the
  // daemon now accepts.
  { const { store, params } = await fresh();
    const lossy = new Proxy(client, { get: (t, k) => (k === 'login'
      ? async (...a) => { const s = await t.login(...a); const real = s.rotate.bind(s);
                          s.rotate = async (...b) => { await real(...b); throw new Error('the ACK was lost'); };
                          return s; }
      : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    let msg = '';
    try { await flows.rotate(lossy, store, params); } catch (e) { msg = e.message; }
    const mid = await store.get(params.handle);
    check(msg === 'the ACK was lost' && mid.pending !== null,
          'rotate, ACK lost after the daemon committed: the new key is KEPT pending');
    const said = [];
    let logged = false;
    try { const s = await flows.login(client, store, params, (e) => said.push(e)); logged = s.code.length === 32; await s.close(); }
    catch { logged = false; }
    check(logged && said.includes('completed the interrupted rotation'),
          'rotate, ACK lost after the daemon committed: the next login completes the rotation with the kept key'); }

  // Where the lock cannot span tabs (no Web Locks), rotate refuses and stages nothing.
  { const { store, params } = await fresh();
    const before = await store.get(params.handle);
    const pageOnly = new Proxy(store, { get: (t, k) => (k === 'sharedLock' ? false : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    let msg = '';
    try { await flows.rotate(client, pageOnly, params); } catch (e) { msg = e.message; }
    check(/no Web Locks/.test(msg) && isDeepStrictEqual(await store.get(params.handle), before),
          'no cross-tab lock: rotate refuses, and the store is unchanged'); }

  // The store promotes only the key the caller staged (compare-and-swap).
  { const { store, params } = await fresh();
    const mine = client.newIdentity(PASS, params.handle), theirs = client.newIdentity(PASS, params.handle);
    await store.stagePending(params.handle, theirs.envelope);
    const before = await store.get(params.handle);
    let refused = false;
    try { await store.promote(params.handle, mine.envelope); } catch { refused = true; }
    check(refused && isDeepStrictEqual(await store.get(params.handle), before),
          'promote: a pending key that is not the one the caller staged is not promoted, and the store is unchanged');
    await store.promote(params.handle, theirs.envelope);
    check(isDeepStrictEqual((await store.get(params.handle)).envelope, theirs.envelope),
          'promote: the staged key is promoted'); }

  { const weak = client.checkPassphrase('password1234');
    const good = client.checkPassphrase(PASS);
    let threw = false;
    try { client.newIdentity('zzzzzzzzzzzz'); } catch (e) { threw = e.statusName === 'passphrase-policy'; }
    check(!weak.ok && good.ok && good.codePoints === 28 && threw,
          'policy: the page sees the verdict, and cannot seal under a refused passphrase'); }

  // F137 (V4-68): the server identity a login or a rotation trusts is the one
  // pinned at enrollment, not the one the page offers this time. Each step is
  // caught separately, so a broken pin fails its own check by name.
  { const { store, params } = await fresh();
    const before = await store.get(params.handle);
    const other = Uint8Array.from(serverPub);
    other[other.length - 1] ^= 1;
    const bare = { ...params };
    delete bare.serverId;
    delete bare.serverPub;
    let logged = false;
    try { const s = await flows.login(client, store, bare); logged = s.code.length === 32; await s.close(); }
    catch { logged = false; }
    check(logged, 'pin: a page that offers no server key logs in with the one pinned at enrollment');
    let name = null;
    try { const s = await flows.login(client, store, { ...params, serverPub: other }); await s.close(); }
    catch (e) { name = e.name; }
    check(name === 'PinMismatch' && isDeepStrictEqual(await store.get(params.handle), before),
          'pin: a page offering a different server key is refused by the pin check (PinMismatch), and the store is unchanged');
    let rname = null;
    try { await flows.rotate(client, store, { ...params, serverId: `not-${params.serverId}` }); }
    catch (e) { rname = e.name; }
    check(rname === 'PinMismatch' && isDeepStrictEqual(await store.get(params.handle), before),
          'pin: a rotation offered a different server identity is refused too, and stages nothing'); }

  // F220 (V4-138): the key is stored before the site is asked to enroll it,
  // so what the site then answers decides what becomes of it. Each answer is
  // set up as the page's submit function sees it.
  { const want = { serverId: info.server_id, serverPub, passphrase: PASS };
    const paramsOf = (handle) => ({ url, serverId: info.server_id, serverPub, handle, passphrase: PASS, probeTimeoutMs: 3000 });
    const logsIn = async (store, handle) => {
      try { const s = await flows.login(client, store, paramsOf(handle)); const ok = s.code.length === 32; await s.close(); return ok; }
      catch { return false; }
    };

    // F736 (V4-352): a pin that is not a server key is refused before a key
    // is made, the site is asked nothing, and nothing is stored.
    { const junk = [new TextEncoder().encode('<html>502 Bad Gateway</html>'), new Uint8Array(0),
                    new Uint8Array([0xab]), new TextEncoder().encode('undefined')];
      let allRefused = true, asked = 0, stored = 0;
      for (const serverPub of junk) {
        const store = new MemoryStore();
        let threw = false;
        try { await flows.enroll(client, store, { ...want, serverPub }, async () => { asked++; return 'OK'; }); }
        catch { threw = true; }
        if (!threw) { allRefused = false; }
        stored += (await store.list()).length;
      }
      check(allRefused && asked === 0 && stored === 0,
            `enroll: a server key that is not one is refused before a key is made: the site is not asked and nothing is stored (asked ${asked}, stored ${stored}) (F736)`);
      let ok = true;
      try { client.checkServerPin(want.serverPub, want.serverId); } catch { ok = false; }
      check(ok, 'enroll: the real server key passes the same check (the control) (F736)');
      // F744: and one far too long is refused without being copied in.
      const before = client.M.HEAPU8.length;
      let long = false;
      // (More than the module's whole memory, so that copying it in would have to grow it.)
      try { client.checkServerPin(new Uint8Array(client.M.HEAPU8.length + 32 * 1024 * 1024), want.serverId); } catch { long = true; }
      check(long && client.M.HEAPU8.length === before,
            `enroll: a server key far too long is refused before it is copied into the module (memory ${before} -> ${client.M.HEAPU8.length}) (F744)`);
      // F752: the id has a length too, and login() holds both to the same.
      const huge = 'x'.repeat(client.M.HEAPU8.length + 32 * 1024 * 1024);
      let longId = false;
      try { client.checkServerPin(want.serverPub, huge); } catch (e) { longId = /server id is longer/.test(e.message); }
      check(longId && client.M.HEAPU8.length === before,
            `enroll: a server id far too long is refused before it is copied into the module (memory ${before} -> ${client.M.HEAPU8.length}) (F752)`);
      let loginKey = '', loginId = '';
      try { await client.login({ url: 'ws://127.0.0.1:1/', serverId: want.serverId, handle: 'd1' + '0'.repeat(32),
                                 serverPub: new Uint8Array(client.M.HEAPU8.length + 32 * 1024 * 1024),
                                 envelope: new Uint8Array(8), passphrase: 'x' }); } catch (e) { loginKey = e.message; }
      try { await client.login({ url: 'ws://127.0.0.1:1/', serverId: huge, handle: 'd1' + '0'.repeat(32),
                                 serverPub: want.serverPub, envelope: new Uint8Array(8), passphrase: 'x' }); } catch (e) { loginId = e.message; }
      check(/server key is longer/.test(loginKey) && /server id is longer/.test(loginId) && client.M.HEAPU8.length === before,
            `login: a server key or id far too long is refused before it is copied into the module ('${loginKey}', '${loginId}', memory ${before} -> ${client.M.HEAPU8.length}) (F752)`); }

    // F739 (V4-352): the module's source of randomness cannot be replaced.
    { let replaced = true;
      try { client.M.getRandomValue = () => 7; replaced = client.M.getRandomValue() === 7; } catch { replaced = false; }
      const a = client.newIdentity(PASS), b = client.newIdentity(PASS);
      check(!replaced && a.handle !== b.handle,
            'random: the module\'s random source cannot be reassigned, and two new identities differ (F739)'); }

    // The site answers no: nothing is left behind.
    { const store = new MemoryStore();
      let name = null, seen = null;
      try { await flows.enroll(client, store, want, async (id) => { seen = id; throw new flows.EnrollRefused('user-exists'); }); }
      catch (e) { name = e.name; }
      check(seen !== null && typeof seen.handle === 'string' && seen.publicImage instanceof Uint8Array,
            'enroll: the site is offered the handle and the public key (the canary)');
      const left = await store.list();
      check(name === 'EnrollRefused' && left.length === 0,
            `enroll: a key the site refused is not left in the store (${left.length} left, ${name}) (F220)`); }

    // The site answers yes: the key is confirmed, and it is the one enrolled.
    { const store = new MemoryStore();
      let during = null;
      const r = await flows.enroll(client, store, want, async (id) => {
        during = (await store.get(id.handle))?.unconfirmed;
        return enroll(id.handle, id.publicImage);
      });
      const rec = await store.get(r.handle);
      check(during === true, `enroll: the key is in the store, marked unconfirmed, before the site is asked (${during}) (F220)`);
      check(r.answer.startsWith('OK') && rec !== null && rec.unconfirmed === false,
            `enroll: a key the site enrolled is confirmed (unconfirmed=${rec && rec.unconfirmed}) (F220)`);
      check(await logsIn(store, r.handle), 'enroll: and it logs in (the canary)'); }

    // No answer, and the daemon had not enrolled it: kept, unconfirmed, and a
    // login that fails leaves it so.
    { const store = new MemoryStore();
      let err = null;
      try { await flows.enroll(client, store, want, async () => { throw new Error('HTTP 503'); }); }
      catch (e) { err = e; }
      const left = await store.list();
      check(err !== null && err.name === 'EnrollUnconfirmed' && left.length === 1 && left[0].handle === err.handle &&
            left[0].unconfirmed === true,
            `enroll: a key the site did not answer for is kept, marked unconfirmed (${left.length} kept, ${err && err.name}) (F220)`);
      const logged = left.length === 1 && await logsIn(store, left[0].handle);
      const after = await store.list();
      check(!logged && after.length === 1 && after[0].unconfirmed === true,
            'enroll: a login the daemon refuses leaves it unconfirmed, and in the store (F220)'); }

    // No answer, but the daemon HAD enrolled it (the reply was lost): it is
    // the account's key, and the login that proves so confirms it.
    { const store = new MemoryStore();
      let err = null, committed = '';
      try {
        await flows.enroll(client, store, want, async (id) => {
          committed = await enroll(id.handle, id.publicImage);
          throw new Error('HTTP 503');
        });
      } catch (e) { err = e; }
      const logged = err !== null && err.handle !== undefined && await logsIn(store, err.handle);
      const rec = err !== null && err.handle !== undefined ? await store.get(err.handle) : null;
      check(committed.startsWith('OK') && logged, 'enroll: a key enrolled behind a lost answer still logs in (F220)');
      check(rec !== null && rec.unconfirmed === false, `enroll: and that login confirms it (unconfirmed=${rec && rec.unconfirmed}) (F220)`); }

    // V4-329 (F611): a login does not use what the second look would say, and
    // so does not take it. It awaited a reread that, behind another tab's
    // blocked delete, never answered: the login succeeded and its session
    // was never handed back.
    { const store = new MemoryStore();
      let err = null, rereads = 0;
      try {
        await flows.enroll(client, store, want, async (id) => {
          await enroll(id.handle, id.publicImage);
          throw new Error('HTTP 503');
        });
      } catch (e) { err = e; }
      store.confirm = async () => { throw new Error('The database connection is closing'); };
      store.reread = () => { rereads++; return new Promise(() => {}); };
      const logged = err !== null && err.handle !== undefined && await Promise.race([
        logsIn(store, err.handle), new Promise((r) => setTimeout(() => r('hung'), 6000))]);
      check(logged === true && rereads === 0,
            `login: a login whose confirmation cannot be recorded returns its session without a second look (${logged}, ${rereads} looks) (F611)`); }

    // A refused passphrase stores nothing and asks the site nothing.
    { const store = new MemoryStore();
      let asked = false, status = null;
      try { await flows.enroll(client, store, { ...want, passphrase: 'password1234' }, async () => { asked = true; }); }
      catch (e) { status = e.statusName; }
      check(status === 'passphrase-policy' && !asked && (await store.list()).length === 0,
            'enroll: a passphrase the policy refuses stores nothing and asks the site nothing'); }

    // F303: a key cannot be forgotten while its enrollment is in flight. The
    // forget is started from inside the site's answer -- another tab pressing
    // Forget while the POST is pending -- and settles only after the
    // enrollment has confirmed the key, which it then refuses to remove.
    { const store = new MemoryStore();
      let forgetting = null, early = 'not settled';
      const r = await flows.enroll(client, store, want, async (id) => {
        forgetting = flows.forgetUnconfirmed(store, id.handle).then(() => 'removed', (e) => e.name);
        early = await Promise.race([forgetting, new Promise((res) => setTimeout(() => res('not settled'), 300))]);
        return enroll(id.handle, id.publicImage);
      });
      const how = await forgetting;
      const rec = await store.get(r.handle);
      check(early === 'not settled' && how === 'ForgetRefused' && rec !== null && rec.unconfirmed === false,
            `enroll: a forget started while the site is enrolling the key waits, and then leaves the confirmed key ` +
            `(during: ${early}; after: ${how}; kept: ${rec !== null}) (F303)`);
      check(await logsIn(store, r.handle), 'enroll: and the key the daemon holds still logs in (F303)'); }

    // V4-140: a key the site never confirmed can be forgotten, and only such
    // a key. Without this an enrollment the site never answered left its key
    // on the login page for good.
    { const store = new MemoryStore();
      try { await flows.enroll(client, store, want, async () => { throw new Error('HTTP 503'); }); } catch { /* kept */ }
      await flows.enroll(client, store, want, async (id) => { await enroll(id.handle, id.publicImage); });
      const all = await store.list();
      const unsure = all.find((r) => r.unconfirmed === true), sure = all.find((r) => r.unconfirmed === false);
      const refusal = async (h) => { try { await flows.forgetUnconfirmed(store, h); return null; } catch (e) { return e; } };
      let e = await refusal(sure.handle);
      check(e !== null && e.name === 'ForgetRefused' && (await store.get(sure.handle)) !== null,
            `forget: a confirmed key is refused and stays (${e && e.name}) (V4-140)`);
      e = await refusal('no-such-handle');
      check(e !== null && e.name === 'ForgetRefused' && (await store.list()).length === 2,
            `forget: a handle the store does not hold is refused (${e && e.name}) (V4-140)`);
      // A login in another tab confirms the key while the removal waits for
      // the identity's lock: the removal sees the confirmed key and leaves it.
      let release;
      const held = store.exclusive(unsure.handle, () => new Promise((r) => { release = r; }));
      const waiting = refusal(unsure.handle);
      await new Promise((r) => setTimeout(r, 50));
      try { await store.confirm(unsure.handle); } catch { /* already removed: the check below says so */ }
      release(); await held;
      e = await waiting;
      check(e !== null && e.name === 'ForgetRefused' && (await store.get(unsure.handle)) !== null,
            `forget: a key confirmed while the removal waited for the lock is left (${e && e.name}) (V4-140)`); }
    { const store = new MemoryStore();
      try { await flows.enroll(client, store, want, async () => { throw new Error('HTTP 503'); }); } catch { /* kept */ }
      const [unsure] = await store.list();
      let threw = null;
      try { await flows.forgetUnconfirmed(store, unsure.handle); } catch (e) { threw = e; }
      check(threw === null && (await store.list()).length === 0,
            `forget: a key the site never confirmed is removed (${threw && threw.message}) (V4-140)`); }

    // V4-266 (F409): a key the site never confirmed, which the daemon DID
    // enroll, cannot be forgotten while a login with it is in flight. The
    // forget waits for the login, which confirms the key, and is then
    // refused. It used to remove the record at once, and the login came back
    // with a session for an account whose only key was no longer stored.
    { const store = new MemoryStore();
      let held = null;
      try {
        await flows.enroll(client, store, want, async (id) => { held = id.handle; await enroll(id.handle, id.publicImage); throw new Error('HTTP 503'); });
      } catch { /* enrolled at the daemon, the answer lost: kept, marked */ }
      const before = await store.get(held);
      check(before !== null && before.unconfirmed === true, 'login/forget: the fixture is a key the daemon holds and the store marks unconfirmed');
      // The forget is started from inside the login, when the key is about
      // to be used: another tab pressing Forget at that moment.
      let forgetting = null, early = 'not started';
      const during = Object.create(client);
      during.login = async (...args) => {
        forgetting = flows.forgetUnconfirmed(store, held).then(() => 'removed', (e) => e.name);
        early = await Promise.race([forgetting, new Promise((res) => setTimeout(() => res('not settled'), 300))]);
        return client.login(...args);
      };
      const logged = await flows.login(during, store, paramsOf(held)).then(async (s) => { const ok = s.code.length === 32; await s.close(); return ok; }, (e) => e.message);
      const how = await forgetting;
      const rec = await store.get(held);
      check(logged === true && early === 'not settled' && how === 'ForgetRefused' && rec !== null && rec.unconfirmed === false,
            `login/forget: a forget during a login with an unconfirmed key waits, and then leaves the key the login confirmed ` +
            `(login: ${logged}; during: ${early}; after: ${how}; kept: ${rec !== null}) (F409)`); }

    // V4-266 (F411): a rotation's login is the daemon accepting the key too.
    { const store = new MemoryStore();
      let held = null;
      try {
        await flows.enroll(client, store, want, async (id) => { held = id.handle; await enroll(id.handle, id.publicImage); throw new Error('HTTP 503'); });
      } catch { /* as above */ }
      let rotated = null;
      try { await flows.rotate(client, store, paramsOf(held)); rotated = true; } catch (e) { rotated = e.message; }
      const rec = await store.get(held);
      check(rotated === true && rec !== null && rec.unconfirmed === false,
            `rotate: a rotation the daemon accepted clears the unconfirmed mark (rotated: ${rotated}; unconfirmed: ${rec && rec.unconfirmed}) (F411)`);
      check(await logsIn(store, held), 'rotate: and the rotated key logs in'); } }

  // F555 (V4-317): a put() refused while login copies its arguments in. The
  // passphrase's bytes are zeroed all the same, and the copies already made
  // are dropped. The encoder is watched for the array the passphrase was
  // encoded into; put() is made to refuse the envelope, the second of three.
  { const { store, params } = await fresh();
    const rec = await store.get(params.handle);
    const realEncode = TextEncoder.prototype.encode;
    const realPut = client.put.bind(client), realDrop = client.drop.bind(client);
    let passBytes = null;
    const held = new Set();                 // copies put into the module and not yet dropped
    TextEncoder.prototype.encode = function (s) {
      const a = realEncode.call(this, s);
      if (s === PASS) { passBytes = a; }
      return a;
    };
    client.put = (bytes) => {
      if (bytes === rec.envelope || (bytes.length === rec.envelope.length && bytes.length > 1000)) {
        throw new Error('the client module is out of memory');
      }
      const at = realPut(bytes);
      held.add(at);
      return at;
    };
    client.drop = (p, len) => { held.delete(p); return realDrop(p, len); };
    let got;
    try {
      got = await client.login({ ...params, envelope: rec.envelope })
        .then(() => 'resolved', (e) => `rejected: ${e.message}`);
    } finally { delete client.put; delete client.drop; TextEncoder.prototype.encode = realEncode; }
    check(got === 'rejected: the client module is out of memory' && passBytes !== null,
          `put refused: login is rejected for it, and the passphrase's array was seen (${got}) (the control)`);
    check(passBytes !== null && passBytes.every((b) => b === 0),
          'put refused: the passphrase\'s bytes are zeroed when a copy into the module is refused (F555)');
    check(held.size === 0,
          `put refused: every copy that was made is dropped (${held.size} left in the module) (F555)`);
    const s = await flows.login(client, store, params);
    check(s.code.length === 32, 'put refused: the same identity then logs in (the canary)');
    await s.close();
    // Review 70: the refusal above comes before the passphrase's own copy is
    // made, so nothing there shows that copy being dropped. An ordinary
    // login, watched the same way: every copy put into the module is dropped
    // by the time the session is closed.
    const left = new Set();
    client.put = (bytes) => { const at = realPut(bytes); left.add(at); return at; };
    client.drop = (p, len) => { left.delete(p); return realDrop(p, len); };
    let ok2;
    try {
      const s2 = await client.login({ ...params, envelope: rec.envelope });
      ok2 = s2.code.length === 32;
      await s2.close();
    } finally { delete client.put; delete client.drop; }
    check(ok2 && left.size === 0,
          `login: every copy an ordinary login puts into the module is dropped, the passphrase's included (${left.size} left) (F555)`);
    // F557: checkPassphrase, the same shape. A slot refused after the
    // passphrase was copied in: the copy is dropped and the array zeroed.
    { let seen = null, mallocs = 0;
      const realMalloc = client.M._malloc;
      const held2 = new Set();
      TextEncoder.prototype.encode = function (str) {
        const a = realEncode.call(this, str);
        if (str === PASS) { seen = a; }
        return a;
      };
      client.M._malloc = (n) => { mallocs += 1; return mallocs === 2 ? 0 : realMalloc(n); };
      client.put = (bytes) => { const at = realPut(bytes); held2.add(at); return at; };
      client.drop = (p, len) => { held2.delete(p); return realDrop(p, len); };
      let threw = null;
      try { client.checkPassphrase(PASS); } catch (e) { threw = e; }
      finally { client.M._malloc = realMalloc; delete client.put; delete client.drop; TextEncoder.prototype.encode = realEncode; }
      check(threw !== null && /out of memory/.test(threw.message) && seen !== null,
            `checkPassphrase: a slot refused after the passphrase is copied in is reported (${threw?.message}) (the control)`);
      check(seen !== null && seen.every((b) => b === 0) && held2.size === 0,
            `checkPassphrase: the passphrase's array is zeroed and its copy dropped all the same (${held2.size} left) (F557)`);
      check(client.checkPassphrase(PASS).ok === true, 'checkPassphrase: and it still answers afterwards (the canary)'); } }

  // F578 (V4-322): what the site answered is what enroll reports, whatever
  // the browser's store then does. A store that could not record the
  // confirmation threw, and the page said the enrollment had failed with the
  // site enrolled and the invitation spent; one that could not remove a
  // refused key threw its own error in place of the refusal.
  { const store = new MemoryStore();
    const want = { serverId: info.server_id, serverPub, passphrase: PASS };
    store.confirm = async () => { throw new Error('transaction aborted'); };
    let got = null;
    const yes = await flows.enroll(client, store, want, async () => ({ user: 'u' }))
      .then((r) => { got = r; return `resolved ${typeof r.handle}`; }, (e) => `rejected: ${e.name}: ${e.message}`);
    check(yes === 'resolved string',
          `enroll: an enrollment the site accepted succeeds though the store cannot record the confirmation (${yes}) (F578)`);
    // Review 74: and WHAT is left. The key must still be stored -- it may be
    // the account's only one -- and still marked, and the caller is told the
    // mark could not be cleared (F584) and given the site's answer.
    const kept = got ? await store.get(got.handle) : null;
    check(kept !== null && kept.unconfirmed === true && got.answer?.user === 'u',
          'enroll: that key is still stored, still marked, and the site\'s answer is passed on (F578)');
    check(got !== null && got.confirmed === false,
          'enroll: and the caller is told the confirmation was not recorded (F584)');
    const okStore = new MemoryStore();
    const fine = await flows.enroll(client, okStore, want, async () => ({ user: 'u' }));
    check(fine.confirmed === true && (await okStore.get(fine.handle)).unconfirmed !== true,
          'enroll: with a store that records it, the key is confirmed and the caller is told so (the canary)');
    // V4-324 (F594): a record that is gone when the site answers (storage
    // cleared meanwhile) is not a confirmed one.
    const gone = new MemoryStore();
    const realGet = gone.get.bind(gone);
    let asked = false;
    gone.get = async (h) => (asked ? null : realGet(h));
    const lost = await flows.enroll(client, gone, want, async () => { asked = true; return { user: 'u' }; });
    check(lost.confirmed === false,
          'enroll: a record that is gone when the site answers is not reported as confirmed (F594)');
    // V4-326 (F597): and it is told apart from a key that is stored and only
    // still marked. The page told both users to "log in once"; one of them
    // has no key to log in with.
    check(lost.stored === false && got !== null && got.stored === true && fine.stored === true,
          'enroll: a key that is gone is reported as not stored; one that is only still marked, and one confirmed, as stored (F597)');
    // V4-327 (F603): what a real browser's store does when the origin's
    // storage is cleared is THROW: its connection is closed. Review 77 ran
    // it in a browser: get() threw, enroll reported the key as stored, and
    // the page told the user to log in once. A store that throws is asked
    // again through a fresh connection, and that decides.
    const closedStore = (after) => {
      const st = new MemoryStore();
      const g = st.get.bind(st);
      let closed = false;
      st.get = async (h) => { if (closed) { throw new Error('The database connection is closing'); } return g(h); };
      st.confirm = async () => { throw new Error('The database connection is closing'); };
      st.reread = after;
      return { st, close: () => { closed = true; } };
    };
    const cleared = closedStore(async () => null);
    const c1 = await flows.enroll(client, cleared.st, want, async () => { cleared.close(); return { user: 'u' }; });
    check(c1.stored === false && c1.confirmed === false,
          'enroll: a store that throws, and holds no record when read afresh, is reported as not stored (F603)');
    let kept1 = null;
    const stillThere = closedStore(async (h) => kept1 ?? { handle: h, unconfirmed: true });
    const c2 = await flows.enroll(client, stillThere.st, want, async () => { stillThere.close(); return { user: 'u' }; });
    check(c2.stored === true && c2.confirmed === false,
          'enroll: a store that throws, and still holds the record when read afresh, is stored and not confirmed (F603)');
    const blind = closedStore(async () => { throw new Error('cannot open'); });
    const c3 = await flows.enroll(client, blind.st, want, async () => { blind.close(); return { user: 'u' }; });
    check(c3.stored === true && c3.confirmed === false,
          'enroll: a store that cannot be read at all is not said to have lost the key (F603)');
    // V4-329 (F618): the OTHER way to the second look -- the record was read,
    // and it is the confirmation that threw. Nothing covered it: answering
    // 'marked' there without looking passed every check.
    const readable = (after) => {
      const st = new MemoryStore();
      st.confirm = async () => { throw new Error('The database connection is closing'); };
      if (after !== undefined) { st.reread = after; }
      return st;
    };
    const c4 = await flows.enroll(client, readable(async () => null), want, async () => ({ user: 'u' }));
    check(c4.stored === false && c4.confirmed === false,
          'enroll: a record that was read, could not be confirmed, and is gone when read afresh is reported as not stored (F618)');
    const c5 = await flows.enroll(client, readable(async (h) => ({ handle: h, unconfirmed: true })), want, async () => ({ user: 'u' }));
    check(c5.stored === true && c5.confirmed === false,
          'enroll: one that is still there when read afresh is stored and not confirmed (F618)');
    // A store with no reread at all (anything but the browser's): not known
    // to be gone, in either branch.
    const c6 = await flows.enroll(client, readable(undefined), want, async () => ({ user: 'u' }));
    const noLook = closedStore(undefined); delete noLook.st.reread;
    const c7 = await flows.enroll(client, noLook.st, want, async () => { noLook.close(); return { user: 'u' }; });
    check(c6.stored === true && c6.confirmed === false && c7.stored === true && c7.confirmed === false,
          'enroll: a store that cannot be read afresh is not said to have lost the key, whichever call threw (F618)');
    // V4-329 (F611): the second look ENDS. A fresh connection opened while
    // another tab holds the database through a delete or an upgrade gets no
    // event at all (review 78, in a browser: still pending after 5 s), and
    // enroll never returned, holding the identity's lock, with the site
    // enrolled.
    { let rereads = 0;
      // F621 (V4-330): timed from when the second look BEGINS. From before
      // enroll it included the key derivation, which on a slow machine is
      // 1.5 s by itself, and a 20 ms wait then passed.
      let t0 = 0;
      const never = closedStore(() => { rereads++; t0 = Date.now(); return new Promise(() => {}); });
      const c8 = await Promise.race([
        flows.enroll(client, never.st, want, async () => { never.close(); return { user: 'u' }; }),
        new Promise((r) => setTimeout(() => r('hung'), 6000))]);
      const took = Date.now() - t0;
      check(c8 !== 'hung' && c8.stored === true && c8.confirmed === false && rereads === 1,
            `enroll: a second look that never answers ends, and the key is not said to be lost (${c8 === 'hung' ? 'hung' : took + ' ms'}) (F611)`);
      check(c8 !== 'hung' && took >= 1500,
            `enroll: and it was waited for, about two seconds (${took} ms) (F611)`); }
    const store2 = new MemoryStore();
    store2.remove = async () => { throw new Error('transaction aborted'); };
    const no = await flows.enroll(client, store2, want, async () => { throw new flows.EnrollRefused('user-exists'); })
      .then(() => 'resolved', (e) => e.name);
    check(no === 'EnrollRefused',
          `enroll: a refusal by the site is reported as that though the store cannot remove the key (${no}) (F578)`); }

  // F572 (V4-321): close() is a courtesy and cannot reject. A clock that
  // refused threw out of it, and a caller's next step -- posting the login
  // code, promoting a key the daemon had acknowledged -- did not happen.
  { const { store, params } = await fresh();
    const s = await flows.login(client, store, params);
    s.tick = () => { throw new Error('clock refused'); };
    const how = await s.close().then(() => 'resolved', (e) => `rejected: ${e.message}`);
    check(how === 'resolved' && s.closed === true,
          `close: a session whose clock refuses still closes, and close() does not reject (${how}) (F572)`); }

  // F305: a peer that answers the upgrade and then sends one message far
  // larger than any frame. It is refused as a frame error without being
  // copied into the module: nothing that large is ever handed to put().
  { const { createServer } = await import('node:net');
    const { createHash } = await import('node:crypto');
    const BIG = 1 << 20;
    let sendText = null;                 // when set, the stand-in answers with this TEXT message
    const conns = [];
    const loud = createServer((c) => {
      conns.push(c);
      c.on('error', () => {});
      let buf = '';
      const onData = (d) => {
        buf += d.toString('latin1');
        if (!buf.includes('\r\n\r\n')) { return; }
        c.off('data', onData);
        const key = /sec-websocket-key: *([^\r\n]+)/i.exec(buf)?.[1] ?? '';
        const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
        c.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
        if (sendText !== null) {
          c.write(Buffer.concat([Buffer.from([0x81, sendText.length]), Buffer.from(sendText, 'latin1')]));
          return;
        }
        const head = Buffer.alloc(10);
        head[0] = 0x82; head[1] = 127; head.writeBigUInt64BE(BigInt(BIG), 2);
        c.write(Buffer.concat([head, Buffer.alloc(BIG, 0x41)]));
      };
      c.on('data', onData);
    });
    await new Promise((r) => loud.listen(0, '127.0.0.1', r));
    const { store, params } = await fresh();
    const cap = client.M._ccw_frame_buf_bytes();
    const realPut = client.put.bind(client);
    let largest = 0;
    client.put = (bytes) => { largest = Math.max(largest, bytes.length); return realPut(bytes); };
    let got;
    try {
      got = await flows.login(client, store, { ...params, url: `ws://127.0.0.1:${loud.address().port}/authd/v1`, timeoutMs: 5000 })
        .then(() => 'resolved', (e) => `rejected: ${e.statusName ?? e.message}`);
    } finally { delete client.put; }
    check(/^rejected: /.test(got) && !/timed out/.test(got) && largest > 0 && largest <= cap,
          `frame: a ${BIG}-byte message is refused as a frame error and never copied into the module ` +
          `(${got}; largest copy ${largest} bytes, frame buffer ${cap}) (F305)`);
    // F313: a TEXT message. The page receives a string, and
    // `new Uint8Array("500")` is 500 zero bytes (two billion for a longer
    // number): the old client built that array and handed it to the module.
    sendText = '500';
    let zeros = 0;
    client.put = (bytes) => {
      if (bytes.length === 500 && bytes.every((b) => b === 0)) { zeros += 1; }
      return realPut(bytes);
    };
    try {
      got = await flows.login(client, store, { ...params, url: `ws://127.0.0.1:${loud.address().port}/authd/v1`, timeoutMs: 5000 })
        .then(() => 'resolved', (e) => `rejected: ${e.statusName ?? e.message}`);
    } finally { delete client.put; }
    check(/^rejected: /.test(got) && !/timed out/.test(got) && zeros === 0,
          `frame: a text message is refused as a frame error, and the number it spells is never made into a frame ` +
          `(${got}; ${zeros} such frames) (F313)`);
    const s = await flows.login(client, store, params);
    check(s.code.length === 32, 'frame: the same identity then logs in to the real daemon (the canary)');
    await s.close();
    // F314: a closed session's handle and frame buffer are freed. Every later
    // call is refused before it reaches the module.
    { const cur = await store.get(params.handle);
      const realBuild = client.M._ccw_rotate_build;
      let reached = 0;
      client.M._ccw_rotate_build = (...a) => { reached += 1; return realBuild(...a); };
      let said;
      try {
        said = await s.rotate(cur.envelope, PASS).then(() => 'resolved', (e) => e.message);
      } finally { client.M._ccw_rotate_build = realBuild; }
      let sendSaid = 'no error';
      try { s.send(); } catch (e) { sendSaid = e.message; }
      check(said === 'session is closed' && sendSaid === 'session is closed' && reached === 0,
            `closed: rotate() and send() on a closed session are refused and the module is not called ` +
            `(rotate: ${said}; send: ${sendSaid}; module calls ${reached}) (F314)`);
      await s.close();                   // still a quiet no-op
      const s3 = await flows.login(client, store, params);
      check(s3.code.length === 32, 'closed: the identity still logs in afterwards');
      await s3.close(); }
    for (const c of conns) { c.destroy(); }
    await new Promise((r) => loud.close(r)); }

  // V4-187, F264: a socket that connects and never answers the upgrade. The
  // client's timeout bounded each wait for a FRAME; nothing bounded the wait
  // for the connection to open, so a login stayed pending for as long as the
  // browser's own connect limit (minutes), holding the identity's lock.
  { const { createServer } = await import('node:net');
    const held = [];
    const mute = createServer((c) => { held.push(c); c.on('error', () => {}); });
    await new Promise((r) => mute.listen(0, '127.0.0.1', r));
    const muteUrl = `ws://127.0.0.1:${mute.address().port}/authd/v1`;
    const outcome = (pr) => Promise.race([
      pr.then(() => 'resolved', (e) => `rejected: ${e.message}`),
      new Promise((r) => setTimeout(() => r('still pending after 4 s'), 4000)) ]);
    { const { store, params } = await fresh();
      const t0 = Date.now();
      const got = await outcome(flows.login(client, store, { ...params, url: muteUrl, timeoutMs: 600 }));
      const ms = Date.now() - t0;
      check(/^rejected: timed out waiting for the daemon/.test(got) && ms >= 500 && ms < 3000,
            `open: a login to a socket that never answers the upgrade is given up on at its timeout (${got}, ${ms} ms) (F264)`);
      const s = await flows.login(client, store, params);
      check(s.code.length === 32, 'open: the same identity then logs in to the real daemon (the canary)');
      await s.close(); }
    { // The recovery probes take the same path, and hold the lock while they do.
      const { store, params } = await fresh();
      const stale = client.newIdentity(PASS, params.handle);
      await store.stagePending(params.handle, stale.envelope);
      const t0 = Date.now();
      const got = await outcome(flows.login(client, store, { ...params, url: muteUrl, probeTimeoutMs: 600 }));
      const ms = Date.now() - t0;
      check(/^rejected: .*could not ask the daemon/.test(got) && ms < 3500,
            `open: with a rotation unresolved, both probes of a silent socket end at their timeout (${got.slice(0, 90)}, ${ms} ms) (F264)`); }
    { // The timer is for the OPEN only: a session that opened in time is not
      // closed when that much time has passed.
      const { store, params } = await fresh();
      const s = await client.login({ ...params, envelope: (await store.get(params.handle)).envelope, timeoutMs: 600 });
      await new Promise((r) => setTimeout(r, 1000));
      check(s.ws.readyState === 1, `open: a session that opened inside its timeout is still open after it (readyState ${s.ws.readyState}) (F264)`);
      await s.close(); }
    for (const c of held) { c.destroy(); }
    await new Promise((r) => mute.close(r)); }

  // V4-188, F267: which account names may be typed while a recovery is open.
  { const cases = [['', null], ['   ', null], [undefined, null], ['alice', null], [' alice ', null],
                   ['mallory', /recovering alice/], ['Alice', /recovering alice/], ['alice2', /recovering alice/]];
    const wrong = cases.filter(([typed, want]) => {
      const got = flows.recoveryNameProblem(typed, 'alice');
      return want === null ? got !== null : !(typeof got === 'string' && want.test(got));
    });
    check(wrong.length === 0, `recovery name: ${cases.length - wrong.length}/${cases.length} names judged as expected` +
          (wrong.length ? ` (wrong: ${wrong.map(([t]) => JSON.stringify(t)).join(', ')})` : '') + ' (F267)');
    check(flows.recoveryNameProblem('alice', undefined) !== null && flows.recoveryNameProblem('', undefined) === null,
          'recovery name: with no recovering account named by the site, only an empty name passes (F267)'); }

  // V4-187, F266: Session.rotate copied the passphrase into the module and
  // then read the clock outside any try: a refused clock left the copy there.
  { const { store, params } = await fresh();
    const M = client.M;
    const marker = 'ZQ-rotate-passphrase-marker-7f3a91c2';
    const s = await client.login({ ...params, envelope: (await store.get(params.handle)).envelope, keepForRotate: true });
    const next = client.newIdentity(PASS, params.handle);
    const find = () => { const hay = Buffer.from(M.HEAPU8.buffer, M.HEAPU8.byteOffset, M.HEAPU8.length); return hay.indexOf(marker); };
    // V4-294, F499: the scan can see a copy that IS in the module's memory.
    // The control below only showed the marker absent before the rotation.
    { const probe = client.put(new TextEncoder().encode(marker));
      const seen = find();
      client.drop(probe, marker.length);
      check(seen >= 0 && find() === -1,
            `rotate: the scan finds the passphrase when a copy is in the module, and not once it is wiped (found at ${seen}) (the control, F499)`); }
    const before = find();
    s.tick = () => { throw new Error('clock refused'); };
    let threw = null;
    try { await s.rotate(next.envelope, marker); } catch (e) { threw = e; }
    const after = find();
    check(before === -1 && threw !== null && /clock refused/.test(threw.message),
          'rotate: a refused clock is reported, and the passphrase was not in the module beforehand (the control)');
    check(after === -1, `rotate: no copy of the passphrase is left in the module's memory after a refused clock (found at ${after}) (F266)`);
    s.destroy(); }

  // V4-247, F353: every write of the IndexedDB store asks for a commit that
  // is on disk when `complete` fires. Browsers default to "relaxed": complete
  // fires when the write is handed to the operating system, and a power loss
  // just after could take back a staged key the daemon had already been sent.
  // A fake database stands in here; what is checked is what the store asks.
  { let rec = null;
    const calls = [];
    const db = { name: 't', transaction(_store, mode, opts) {
      calls.push({ mode, opts });
      const tx = { abort() { queueMicrotask(() => tx.onabort?.()); },
                   objectStore() { return {
                     add(v) { rec = { ...v }; }, put(v) { rec = { ...v }; }, delete() { rec = null; },
                     get() { const q = {}; queueMicrotask(() => { q.result = rec ? { ...rec } : undefined; q.onsuccess?.(); }); return q; },
                   }; } };
      if (mode === 'readwrite') { setTimeout(() => tx.oncomplete?.(), 0); }
      return tx; } };
    const st = new IdentityStore(db);
    const env = new Uint8Array([1, 2, 3]), next = new Uint8Array([4, 5, 6]);
    await st.create({ handle: 'd1', serverId: 's', serverPub: new Uint8Array(1), envelope: env, unconfirmed: true });
    await st.confirm('d1');
    await st.stagePending('d1', next);
    await st.promote('d1', next);
    await st.stagePending('d1', env);
    await st.discardPending('d1');
    const got = await st.get('d1');
    await st.remove('d1');
    const writes = calls.filter((c) => c.mode === 'readwrite');
    check(writes.length === 7 && got?.pending === null && hex(got.envelope) === hex(next),
          `durable: the fake database carried create, confirm, stage, promote, stage, discard and remove (${writes.length} writes; not vacuous)`);
    check(writes.length === 7 && writes.every((c) => c.opts?.durability === 'strict'),
          `durable: every write of the identity store asks for strict durability, so "committed" means on disk (${writes.filter((c) => c.opts?.durability === 'strict').length} of ${writes.length}) (F353)`); }

  // V4-247, F354: a frame handed to a socket that has closed is not a frame
  // sent. WebSocket.send() on a closing or closed socket drops the data and
  // does not throw; the session counted it, and a probe whose ClientAuth
  // never left was reported as a key the daemon refused.
  { const stub = (readyState) => {
      const ws = { readyState, n: 0, send() { this.n += 1; } };
      const s = new Session({ M: { HEAPU8: new Uint8Array(16) }, u32: () => 4 }, 0, 0, 16, 0, () => {}, 1000);
      s.ws = ws;
      return { s, ws };
    };
    const open = stub(1);
    open.s.send();
    check(open.s.sent === 1 && open.ws.n === 1, 'send: on an open socket the frame goes and is counted (the control)');
    for (const state of [2, 3]) {
      const shut = stub(state);
      let threw = null;
      try { shut.s.send(); } catch (e) { threw = e; }
      check(threw !== null && threw.name !== 'AuthdError' && shut.s.sent === 0 && shut.ws.n === 0,
            `send: on a socket that is ${state === 2 ? 'closing' : 'closed'} nothing is counted as sent, and the caller is told (sent ${shut.s.sent}) (F354)`);
    } }

  // V4-335 (F638): messages nobody was waiting for are bounded as they
  // arrive, in size and in number.
  { const mk = () => {
      const ws = { readyState: 1, closes: 0, close() { this.closes += 1; } };
      const s = new Session({ M: { HEAPU8: new Uint8Array(16) }, u32: () => 4 }, 0, 0, 16, 0, () => {}, 1000);
      s.ws = ws;
      return { s, ws };
    };
    const two = mk();
    two.s.onMessage(new Uint8Array([1]).buffer);
    two.s.onMessage(new Uint8Array([2]).buffer);
    const a = await two.s.next(), b = await two.s.next();
    check(a instanceof Uint8Array && a[0] === 1 && b instanceof Uint8Array && b[0] === 2 && two.ws.closes === 0,
          'queue: two messages that arrive before they are asked for are kept, in order (the control)');
    const big = mk();
    big.s.onMessage(new ArrayBuffer(17));
    check(big.s.queue.length === 1 && typeof big.s.queue[0] === 'symbol',
          'queue: a message larger than a frame is a frame error where it arrives, and is not copied (F638)');
    big.s.queue = [];
    big.s.onMessage(new ArrayBuffer(16));
    check(big.s.queue.length === 1 && big.s.queue[0] instanceof Uint8Array && big.s.queue[0].length === 16,
          'queue: one of exactly a frame is kept (F638)');
    const many = mk();
    for (let i = 0; i < 1000; i++) { many.s.onMessage(new Uint8Array([i & 255]).buffer); }
    const held = many.s.queue.length;
    const first = await many.s.next();
    check(held === 1 && typeof first === 'symbol' && many.ws.closes === 1,
          `queue: a peer that sends a thousand messages nobody asked for is held to one frame error and closed once (${held} held, ${many.ws.closes} closes) (F638)`);
    const four = mk();
    for (let i = 0; i < 4; i++) { four.s.onMessage(new Uint8Array([i]).buffer); }
    check(four.s.queue.length === 4 && four.ws.closes === 0 && four.s.queue.every((m) => m instanceof Uint8Array),
          'queue: four waiting is still within the bound (F638)');
    // V4-336 (F642): a close that arrives at a full queue is a close, not
    // a flood.
    four.s.wake(null);
    check(four.s.queue.length === 5 && four.s.queue[4] === null && four.ws.closes === 0,
          'queue: a close that arrives when four are waiting is kept, and is not a flood (F642)');
    const five = mk();
    for (let i = 0; i < 4; i++) { five.s.onMessage(new Uint8Array([i]).buffer); }
    five.s.onMessage(new Uint8Array([9]).buffer);
    five.s.onMessage(new Uint8Array([10]).buffer);
    check(five.s.queue.length === 1 && five.ws.closes === 1,
          'queue: the fifth is the flood, and what follows it adds nothing (F638)');
    // F641: the close after a flood is still told, once: a second read used
    // to wait out its timeout.
    five.s.wake(null);
    five.s.wake(null);
    five.s.timeoutMs = 100;             // a read that finds nothing says so here, and is not left to end the test
    const f1 = await five.s.next().catch(() => 'timed out'), f2 = await five.s.next().catch(() => 'timed out');
    check(typeof f1 === 'symbol' && f2 === null && five.s.queue.length === 0,
          'queue: after a flood the frame error is read, and then the close, once (F641)');
    // V4-338 (F650): "once" holds after the close has been READ too, and a
    // close that came before the flood is still told.
    five.s.wake(null);
    check(five.s.queue.length === 0,
          'queue: a further close after the flood\'s close was read is not told again (F650)');
    const early = mk();
    early.s.onMessage(new Uint8Array([1]).buffer);
    early.s.wake(null);
    for (let i = 0; i < 6; i++) { early.s.onMessage(new Uint8Array([i]).buffer); }
    early.s.timeoutMs = 100;
    const e1 = await early.s.next().catch(() => 'timed out'), e2 = await early.s.next().catch(() => 'timed out');
    check(typeof e1 === 'symbol' && e2 === null && early.s.queue.length === 0,
          `queue: a close that arrived before the flood is read after its frame error (${String(e2)}) (F650)`);
    // F641: only an ArrayBuffer is a message.
    const odd = mk();
    let threw = false;
    try { odd.s.onMessage(null); odd.s.onMessage({ size: 3 }); odd.s.onMessage('text'); } catch { threw = true; }
    check(!threw && odd.s.queue.length === 3 && odd.s.queue.every((m) => typeof m === 'symbol'),
          'queue: null, an object with no byteLength, and a string are each a frame error, and none throws (F641)');
    // F641: a wait that timed out does not take the next message.
    const late = mk();
    late.s.timeoutMs = 30;
    const timedOut = await late.s.next().then(() => 'resolved', (e) => e.message);
    late.s.onMessage(new Uint8Array([7]).buffer);
    late.s.timeoutMs = 200;
    const got7 = await late.s.next().catch(() => 'timed out');
    check(/timed out/.test(timedOut) && late.s.waiters.length === 0 && got7 instanceof Uint8Array && got7[0] === 7,
          `queue: a message that arrives after a wait timed out goes to the next reader, not to the one that gave up (${timedOut}) (F641)`); }

  // V4-281, F460: a ROTATE that never left the page cannot have been
  // committed, so the staged key goes -- as when no session was opened
  // (F235). Here the socket closes after the rotation's login and before
  // ROTATE is handed to it, the window F411's await on the store widened.
  { const { store, params } = await fresh();
    const before = await store.get(params.handle);
    let frames = -1;
    const cut = new Proxy(client, { get: (t, k) => (k === 'login'
      ? async (...a) => { const s = await t.login(...a); const real = s.rotate.bind(s);
                          s.rotate = async (...b) => { s.ws.close(); frames = s.sent;
                                                       try { return await real(...b); } finally { frames = s.sent - frames; } };
                          return s; }
      : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    let err = null;
    const said = [];
    try { await flows.rotate(cut, store, params, (e) => said.push(e)); } catch (e) { err = e; }
    const after = await store.get(params.handle);
    check(err !== null && err.notSent === true && frames === 0,
          `rotate, socket closed before ROTATE: it fails, says it was not sent, and no frame left (${err && err.message}; ${frames} frames) (F460)`);
    check(after.pending === null && isDeepStrictEqual(after, before) && said.includes('the rotation was never sent, so the new key is not kept'),
          'rotate, socket closed before ROTATE: no key is left pending, and the store is exactly as it was (F460)');
    const next = [];
    const s = await flows.login(client, store, params, (e) => next.push(e));
    check(s.code.length === 32 && next.length === 0,
          `rotate, socket closed before ROTATE: the next login is an ordinary one, with no interrupted rotation to resolve (${next.join('; ')}) (F460)`);
    await s.close(); }
  // ...while a ROTATE that DID leave keeps proving nothing: the ACK-lost case
  // above keeps its key, and its error carries no notSent.
  { const { id, params } = await fresh();
    const s = await client.login({ ...params, envelope: id.envelope, keepForRotate: true });
    const next = client.newIdentity(PASS, params.handle);
    let err = null;
    const realFeed = s.feed.bind(s);
    s.feed = async () => { s.ws.close(); return realFeed(() => 3); };   // ROTATE sent, then no reply
    try { await s.rotate(next.envelope, PASS); } catch (e) { err = e; }
    check(err !== null && err.notSent !== true && s.sent >= 3,
          `rotate, sent and not answered: the error does not say "not sent" (sent ${s.sent}, notSent ${err && err.notSent}) (F460, not vacuous)`);
    await s.close().catch(() => {}); }

  // V4-281, F462: without Web Locks the lock that keeps a Forget from
  // removing a key another tab is using is this page's only, so a Forget is
  // refused, as a rotation is, and nothing is removed.
  { const st = new MemoryStore();
    await st.create({ handle: 'f462', serverId: 's', serverPub: new Uint8Array(1), envelope: new Uint8Array(4), unconfirmed: true });
    const pageOnly = new Proxy(st, { get: (t, k) => (k === 'sharedLock' ? false : (typeof t[k] === 'function' ? t[k].bind(t) : t[k])) });
    let err = null;
    try { await flows.forgetUnconfirmed(pageOnly, 'f462'); } catch (e) { err = e; }
    check(err !== null && err.name === 'ForgetRefused' && /no Web Locks/.test(err.message) && (await st.get('f462')) !== null,
          `no cross-tab lock: forgetting an unconfirmed key is refused and the key stays (${err && err.message}) (F462)`);
    await flows.forgetUnconfirmed(st, 'f462');
    check((await st.get('f462')) == null, 'with the lock shared: the same Forget removes the key (the control)'); }

  // V4-281, F463: every allocation is checked. A module whose malloc fails
  // (returns 0) is refused by name; u32Slot used to write HEAPU32[0].
  { const heap = new Uint32Array(4); heap[0] = 0xfeedface;
    const oom = new AuthdClient({ _malloc: () => 0, _free: () => {}, HEAPU32: heap, HEAPU8: new Uint8Array(16) });
    const tries = [['u32Slot', () => oom.u32Slot()], ['alloc', () => oom.alloc(32)], ['newHandle', () => oom.newHandle()]];
    const said = tries.map(([n, f]) => { try { f(); return `${n}: no error`; } catch (e) { return /out of memory/.test(e.message) ? null : `${n}: ${e.message}`; } });
    check(said.every((x) => x === null) && heap[0] === 0xfeedface,
          `out of memory: every allocation is refused by name and nothing is written at address 0 (${said.filter(Boolean).join('; ') || 'ok'}) (F463)`);
    const ok = new AuthdClient({ _malloc: () => 8, _free: () => {}, HEAPU32: heap, HEAPU8: new Uint8Array(16) });
    heap[2] = 0xdeadbeef;     // V4-294, F498: so the zeroing can be seen (a fresh array is 0 already)
    check(ok.u32Slot() === 8 && heap[2] === 0, 'out of memory: a malloc that succeeds gives its slot, zeroed (the control)'); }

  // V4-305 (F531, and F512's root): Argon2id's working memory is cleared.
  // libsodium unmapped (natively) or freed (in wasm) it uncleared, and with
  // p = 1 the envelope key is BLAKE2b-256(LE32(32) || its last block): in the
  // module's heap, which never shrinks, the key stayed recoverable for the
  // page's lifetime. The key is computed here independently (node's own
  // Argon2id, from the envelope's salt and parameters) and the heap scanned
  // for a block that hashes to it, after a seal and after an unlock.
  { const pass = 'residue-check-Qx7!vB9#pL2$wz';
    const id = client.newIdentity(pass);
    const env = id.envelope;
    const dv = new DataView(env.buffer, env.byteOffset);
    const ops = dv.getUint32(10), mem = Number(dv.getBigUint64(14)), salt = env.slice(22, 38);
    check(ops === 3 && mem === 64 * 1024 * 1024,
          `argon2 residue: the envelope's parameters parse as the browser's 3 / 64 MiB (${ops} / ${mem}) (the control)`);
    const kek = argon2Sync('argon2id', { message: Buffer.from(pass), nonce: salt, parallelism: 1,
                                         tagLength: 32, memory: mem / 1024, passes: ops });
    const dir = mkdtempSync(join(tmpdir(), 'mldsa-residue-'));
    const scan = (tag) => {
      const f = join(dir, `${tag}.bin`);
      writeFileSync(f, client.M.HEAPU8);
      const py = spawnSync('python3', ['-I', '-c', `
import hashlib, sys
kek = bytes.fromhex(sys.argv[1]); h = open(sys.argv[2], 'rb').read(); pre = (32).to_bytes(4, 'little')
print(sum(1 for o in range(0, len(h) - 1024, 64) if hashlib.blake2b(pre + h[o:o + 1024], digest_size=32).digest() == kek))
`, kek.toString('hex'), f], { encoding: 'utf8' });
      rmSync(f, { force: true });
      return py.status === 0 ? Number(py.stdout.trim()) : `python3 failed: ${py.stderr}`;
    };
    const afterSeal = scan('seal');
    const s = await client.login({ url: `ws://127.0.0.1:9/authd/v1`, serverId: info.server_id, serverPub,
                                   handle: id.handle, passphrase: pass, envelope: env, timeoutMs: 200 })
      .then(() => 'logged in', (e) => e.message);
    const afterOpen = scan('open');
    rmSync(dir, { recursive: true, force: true });
    kek.fill(0);
    check(afterSeal === 0 && afterOpen === 0,
          `argon2 residue: no block of the module's heap gives the envelope key, after a seal (${afterSeal}) or an unlock (${afterOpen}; ${s}) (F531)`); }
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  // F382: a fixture that has ALREADY exited emits no second 'exit', and the
  // wait for one never ended: the run stopped here with no summary line
  // (exit 13, or CTest's timeout). The guard wasm_interop has had since F286.
  const exited = new Promise((r) => {
    if (fx.exitCode !== null || fx.signalCode !== null) { r(true); } else { fx.once('exit', () => r(true)); }
  });
  fx.kill();
  const quick = await Promise.race([exited, new Promise((r) => setTimeout(() => r(false), 3000))]);
  if (!quick) { fx.kill('SIGKILL'); await exited; }
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
