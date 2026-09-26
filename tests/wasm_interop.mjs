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

// One request line on the site socket, one reply line back -- the site's view.
function site(line) {
  return new Promise((resolve, reject) => {
    const s = createConnection(info.site);
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

const done = async () => { fx.kill(); await new Promise((r) => fx.once('exit', r)); };
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

  console.log(`\ntimings (Node ${process.version}): Argon2id 3/64 MiB ${tSeal.toFixed(1)} ms ` +
              `(V4-2 S6: 111.5 ms); login round trip ${tLogin.toFixed(1)} ms`);
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  await done();
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
