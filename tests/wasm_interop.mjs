// V4-13b: the client core compiled to wasm, logging in to the REAL daemon.
//
//   node wasm_interop.mjs FIXTURE MODULE.mjs CLIENT.mjs
//
// FIXTURE is tests/authd_wasm_fixture (the daemon assembled in-process, its
// WebSocket listener on loopback TCP); MODULE.mjs is the browser module
// (web/mldsa_client.mjs) and CLIENT.mjs the JS transport
// (web/client/authd-client.mjs) -- the same two files a page will load.
//
// What a site and a browser would do, end to end: enroll through the site
// socket; log in over ws://; EXCHANGE the code for a token; then the refusals
// that make the design worth having -- a ServerHello from a key other than the
// pinned one leaves no ClientAuth on the wire (spec 4), a wrong passphrase
// sends nothing -- and a rotation after which only the new key logs in.
// Timings are printed against V4-2 S6's measurements.
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { pathToFileURL } from 'node:url';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const [fixturePath, modulePath, clientPath] = process.argv.slice(2);
if (!fixturePath || !modulePath || !clientPath) {
  console.log('usage: wasm_interop.mjs FIXTURE MODULE.mjs CLIENT.mjs');
  process.exit(2);
}
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) fail = 1; };
const hex = (b) => Buffer.from(b).toString('hex');
const PASS = 'correct horse battery staple';

// ---- the fixture ---------------------------------------------------------
const fx = spawn(fixturePath, ['60'], { stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  fx.stdout.on('data', (d) => {
    buf += d;
    const nl = buf.indexOf('\n');
    if (nl >= 0) { resolve(JSON.parse(buf.slice(0, nl))); }
  });
  fx.on('exit', (c) => reject(new Error(`fixture exited ${c} before it was ready`)));
  setTimeout(() => reject(new Error('fixture never became ready')), 20000);
});
const serverPub = Uint8Array.from(Buffer.from(info.server_pub, 'hex'));
// V4-31: the fixture's scratch directory (its store and sockets) is the site
// socket's directory. It must exist while the fixture runs -- the canary --
// and be gone once a SIGTERM has stopped it.
const fxDir = dirname(info.site);
check(existsSync(fxDir), 'fixture: its scratch directory exists while it runs (the canary)');

// One request line on a local socket, one reply line back: site.sock is the
// site's view; admin.sock (beside it in the fixture's directory, allowlisted
// for this uid) the operator's, for the commands only it has (V4-33).
const site = (line) => ask(info.site, line);
const admin = (line) => ask(join(dirname(info.site), 'admin.sock'), line);
function ask(path, line) {
  return new Promise((resolve, reject) => {
    const s = createConnection(path);
    let buf = '';
    s.on('data', (d) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl >= 0) { s.end(); resolve(buf.slice(0, nl)); }
    });
    s.on('error', reject);
    s.write(line + '\n');
  });
}
// The public key is the tail of an MLDSAPK1 image: "MLDSAPK1" || id_len || id || pk.
const pkOf = (img) => img.slice(9 + img[8]);

// Stops the fixture and waits for it -- but not for its 60 s deadline: a
// fixture that caught SIGTERM and served on would clean up at the deadline
// and look tidy, so it must be gone within 3 s (V4-31).
let fxQuick = false;
const done = async () => {
  const exited = new Promise((r) => fx.once('exit', () => r(true)));
  fx.kill();
  fxQuick = await Promise.race([exited, new Promise((r) => setTimeout(() => r(false), 3000))]);
  if (!fxQuick) { fx.kill('SIGKILL'); await exited; }
};
try {
  const { default: createMldsaClient } = await import(pathToFileURL(modulePath).href);
  const { AuthdClient, AuthdError } = await import(pathToFileURL(clientPath).href);
  const client = await AuthdClient.load(createMldsaClient);

  let t0 = performance.now();
  const id = client.newIdentity(PASS);
  const tSeal = performance.now() - t0;
  check(/^d1[0-9a-f]{32}$/.test(id.handle) && id.envelope.length > 0 && id.publicImage.length > 0,
        `identity: a handle, an MLDSAEK1 envelope and an MLDSAPK1 image from wasm (Argon2id 3/64 MiB: ${tSeal.toFixed(1)} ms)`);

  const user = hex(new TextEncoder().encode('u-wasm'));
  const enroll = await site(`ENROLL user=${user} handle=${hex(new TextEncoder().encode(id.handle))} ` +
                           `pk=${hex(pkOf(id.publicImage))} via=site`);
  check(enroll.startsWith('OK fp='), `enroll: the site enrolls the wasm-made key (${enroll.slice(0, 20)}...)`);

  const state = 'st8';
  const url = `ws://127.0.0.1:${info.ws_port}/authd/v1?state=${state}`;
  const base = { url, serverId: info.server_id, serverPub, handle: id.handle, passphrase: PASS };

  t0 = performance.now();
  const s = await client.login({ ...base, envelope: id.envelope });
  const tLogin = performance.now() - t0;
  check(s.code.length === 32 && s.expires > Date.now() / 1000,
        `login: a login code over ws:// from the real daemon (${tLogin.toFixed(1)} ms round trip, key opening included)`);
  const code = hex(s.code);
  await s.close();
  const ex = await site(`EXCHANGE code=${code} state=${hex(new TextEncoder().encode(state))}`);
  check(ex.startsWith('OK token='), 'exchange: the site trades the wasm client\'s code for a token');
  const again = await site(`EXCHANGE code=${code} state=${hex(new TextEncoder().encode(state))}`);
  check(again.startsWith('ERR'), 'exchange: and only once');

  // Spec 4: pin a DIFFERENT key under the server's id. The daemon's genuine
  // ServerHello must be refused with nothing after the ClientHello.
  const decoy = client.newIdentity(PASS, info.server_id);
  try {
    await client.login({ ...base, envelope: id.envelope, serverPub: decoy.publicImage });
    check(false, 'phish: a ServerHello not signed by the pinned key is refused');
  } catch (e) {
    check(e instanceof AuthdError && e.stage === 'server-hello' && e.framesSent === 1,
          `phish: refused at server-hello with only the ClientHello sent (${e.message}; frames sent: ${e.framesSent})`);
  }

  try {
    await client.login({ ...base, envelope: id.envelope, passphrase: 'wrong passphrase' });
    check(false, 'passphrase: a wrong passphrase is refused');
  } catch (e) {
    check(e instanceof AuthdError && e.statusName === 'key-envelope' && /^decryption-failed/.test(e.detail) &&
          e.framesSent === 0, `passphrase: refused before anything is sent (${e.message})`);
  }

  // Rotation: the new envelope is "stored" (held) before ROTATE is sent.
  const next = client.newIdentity(PASS, id.handle);
  const r = await client.login({ ...base, envelope: id.envelope, keepForRotate: true });
  let rotated = false;
  try { await r.rotate(next.envelope, PASS); rotated = true; } catch (e) { console.log(`  rotate: ${e.message}`); }
  await r.close();
  check(rotated, 'rotate: the daemon acknowledges the new key');
  let oldRefused = false;
  try { const o = await client.login({ ...base, envelope: id.envelope, timeoutMs: 3000 }); await o.close(); }
  catch { oldRefused = true; }
  check(oldRefused, 'rotate: the superseded key no longer logs in');
  const n = await client.login({ ...base, envelope: next.envelope });
  check(n.code.length === 32, 'rotate: the new key logs in');
  await n.close();

  // V4-32 (CLAIMS D9, Req 9): revocation closes a LIVE session, observed from
  // outside the daemon. Until now that was checked in-process only
  // (test_authd_localapi). Two devices of the same user each hold a session
  // the daemon keeps open after issuing its code; the site revokes one. Its
  // WebSocket must be closed by the daemon -- seen here, in another process --
  // and the other device's must stay open: the canary that the close was
  // the revoked device's and not everyone's.
  const enc = (t) => new TextEncoder().encode(t);
  const devA = client.newIdentity(PASS), devB = client.newIdentity(PASS);
  const ea = await site(`ENROLL user=${user} handle=${hex(enc(devA.handle))} pk=${hex(pkOf(devA.publicImage))} via=site`);
  const eb = await site(`ENROLL user=${user} handle=${hex(enc(devB.handle))} pk=${hex(pkOf(devB.publicImage))} via=site`);
  check(ea.startsWith('OK fp=') && eb.startsWith('OK fp='), 'revoke: two more devices of the same user are enrolled');
  const sa = await client.login({ ...base, handle: devA.handle, envelope: devA.envelope });
  const sb = await client.login({ ...base, handle: devB.handle, envelope: devB.envelope });
  check(sa.ws.readyState === 1 && sb.ws.readyState === 1, 'revoke: both devices hold a live session');
  const closedWithin = (sess, ms) => new Promise((res) => {
    if (sess.ws.readyState === 3) { res(true); return; }
    const t = setTimeout(() => res(false), ms);
    sess.ws.addEventListener('close', () => { clearTimeout(t); res(true); });
  });
  const rv = await site(`REVOKE-DEVICE handle=${hex(enc(devA.handle))}`);
  check(rv.startsWith('OK'), `revoke: the site revokes the first device (${rv.trim()})`);
  check(await closedWithin(sa, 3000),
        "revoke: the daemon closes the revoked device's live WebSocket, seen from the client's process (Req 9, D9)");
  check(sb.ws.readyState === 1, "revoke: the other device's live session stays open (the canary)");

  // V4-33 (CLAIMS D9, Req 9): the user-wide closes, seen from here too --
  // DISABLE-USER, and RECOVERY-USE with revoke=all. sb, a live session of
  // u-wasm, stays open throughout: the canary that a close reached only the
  // user it named. revoke=none is the canary for the flag itself.
  const live = async (u, n) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const d = client.newIdentity(PASS);
      const e = await site(`ENROLL user=${hex(enc(u))} handle=${hex(enc(d.handle))} pk=${hex(pkOf(d.publicImage))} via=site`);
      if (!e.startsWith('OK fp=')) { throw new Error(`enroll for ${u}: ${e.trim()}`); }
      out.push(await client.login({ ...base, handle: d.handle, envelope: d.envelope }));
    }
    return out;
  };
  const [sx] = await live('u-wasm-x', 1);
  const dis = await admin(`DISABLE-USER user=${hex(enc('u-wasm-x'))}`);
  check(dis.startsWith('OK'), `disable: the operator disables a user with a live session (${dis.trim()})`);
  check(await closedWithin(sx, 3000),
        "disable: the daemon closes the disabled user's live WebSocket, seen from the client's process (Req 9, D9)");
  check(sb.ws.readyState === 1, "disable: another user's live session stays open (the canary)");

  const [sz1, sz2] = await live('u-wasm-z', 2);
  const [sw] = await live('u-wasm-w', 1);
  const firstCode = (resp) => (/codes=([^,\s]+)/.exec(resp) ?? [])[1];
  const iz = await site(`RECOVERY-ISSUE user=${hex(enc('u-wasm-z'))} count=1`);
  const iw = await site(`RECOVERY-ISSUE user=${hex(enc('u-wasm-w'))} count=1`);
  const uw = await site(`RECOVERY-USE user=${hex(enc('u-wasm-w'))} code=${firstCode(iw)} revoke=none`);
  check(uw.startsWith('OK ticket='), `revoke=none: a recovery code is spent without revoking (${uw.split(' ')[0]})`);
  const uz = await site(`RECOVERY-USE user=${hex(enc('u-wasm-z'))} code=${firstCode(iz)} revoke=all`);
  check(uz.startsWith('OK ticket='), `revoke=all: a recovery code is spent, revoking every device (${uz.split(' ')[0]})`);
  const [c1, c2] = await Promise.all([closedWithin(sz1, 3000), closedWithin(sz2, 3000)]);
  check(c1 && c2,
        "revoke=all: the daemon closes BOTH of the user's live WebSockets, seen from the client's process (Req 9, D9)");
  check(sw.ws.readyState === 1, "revoke=none: the user's live session stays open (the canary)");
  check(sb.ws.readyState === 1, "revoke=all: another user's live session stays open (the canary)");
  await sw.close();
  await sb.close();

  console.log(`\ntimings (Node ${process.version}): Argon2id 3/64 MiB ${tSeal.toFixed(1)} ms ` +
              `(V4-2 S6: 111.5 ms); login round trip ${tLogin.toFixed(1)} ms`);
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  await done();
}
check(fxQuick, 'fixture: it exits within 3 s of SIGTERM, not at its deadline (V4-31)');
check(!existsSync(fxDir), 'fixture: stopped with SIGTERM, it removed its scratch directory (V4-31)');
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
