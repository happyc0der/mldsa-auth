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

  // F220 (V4-138): the key is stored before the site is asked to enroll it,
  // so what the site then answers decides what becomes of it. Each answer is
  // set up as the page's submit function sees it.
  { const want = { serverId: info.server_id, serverPub, passphrase: PASS };
    const paramsOf = (handle) => ({ url, serverId: info.server_id, serverPub, handle, passphrase: PASS, probeTimeoutMs: 3000 });
    const logsIn = async (store, handle) => {
      try { const s = await flows.login(client, store, paramsOf(handle)); const ok = s.code.length === 32; await s.close(); return ok; }
      catch { return false; }
    };

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

    // A refused passphrase stores nothing and asks the site nothing.
    { const store = new MemoryStore();
      let asked = false, status = null;
      try { await flows.enroll(client, store, { ...want, passphrase: 'password1234' }, async () => { asked = true; }); }
      catch (e) { status = e.statusName; }
      check(status === 'passphrase-policy' && !asked && (await store.list()).length === 0,
            'enroll: a passphrase the policy refuses stores nothing and asks the site nothing'); }

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
            `forget: a key the site never confirmed is removed (${threw && threw.message}) (V4-140)`); } }
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  fx.kill();
  await new Promise((r) => fx.once('exit', r));
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
