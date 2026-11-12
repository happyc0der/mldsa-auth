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
// enrollment, whatever the page offers.
// The IndexedDB store itself (its transactions) is tested in a real browser.
import { spawn } from 'node:child_process';
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
  const { AuthdClient } = await import(pathToFileURL(`${clientDir}/authd-client.mjs`).href);
  const { MemoryStore } = await import(pathToFileURL(`${clientDir}/store.mjs`).href);
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
    await aHasStaged;
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
    await reached;
    let logged = false;
    try { const s = await flows.login(client, store, params); logged = s.code.length === 32; await s.close(); } catch { logged = false; }
    loginDone();
    const ra = await a;
    check(ra === 'ok' && logged, `a login during a rotation waits for it: the rotation reports success and the login uses its key (rotation: ${ra})`); }

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
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  fx.kill();
  await new Promise((r) => fx.once('exit', r));
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
