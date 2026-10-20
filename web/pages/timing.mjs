// V4-13d: phone timings for spec 14, measured on the phone. Driven by
// tools/phone_timing.mjs, which serves this page with a one-time invite in
// the URL FRAGMENT (#invite=...) -- a fragment is never sent to a server, so
// it appears in no log -- and collects what this page POSTs to /api/timing.
//
// The same two numbers browser_e2e measures in headless Chromium, so the rows
// compare: "seal" is a whole new identity (ML-DSA-65 keygen + Argon2id 3/64 MiB
// + sealing), "login" a whole login (Argon2id to open the key, then the
// handshake over the WebSocket). The throwaway passphrase is a test value.
//
// V4-26 (F119): every row also says which kind of origin it was measured on,
// because V4-25's Safari row was ~21x slow for a reason outside this client.
// Safari 27 runs a page from a NON-secure origin -- plain http on any name but
// localhost and the loopback addresses -- without its optimizing JIT,
// JavaScript and wasm alike, 8-30x slower. The tool serves plain http on an
// address the phone can reach, which is such an origin; a deployment is
// HTTPS, which is not.
//   secure    window.isSecureContext
//   jsLoopMs  a fixed pure-JS loop, timed before any cryptography: whether
//             the JIT is there, measured without the module
// #auto=1 in the fragment starts the measurement on load (desktop browsers
// opened by a script, and tests/phone_timing_tool.mjs); otherwise Measure does.
import { boot, session, loginParams, post, report, bytesToHex, b64url } from './common.mjs';

const PASS = 'tidal-harbor-quilted-lantern';
const LOGINS = 5;
const { client, store } = await boot();
const out = document.getElementById('out');
const line = (s) => { out.textContent += s + '\n'; };
const params = new URLSearchParams(location.hash.slice(1));
if (!window.isSecureContext) {
  line('note: this page is not a secure context, so a WebKit browser runs it without its JIT ' +
       'and its times are not what an HTTPS deployment sees (F119)');
}
document.body.dataset.ready = '1';

// 10^7 xorshift steps, best of three, so the JIT's warm-up is left out.
// Measured on the development Mac (V4-26): Edge 13-14 ms; Safari 62 ms on a
// secure origin and 361 ms on a non-secure one.
function jsLoop() {
  let best = Infinity;
  for (let run = 0; run < 3; run++) {
    let x = 2463534242;
    const t0 = performance.now();
    for (let i = 0; i < 1e7; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; }
    best = Math.min(best, performance.now() - t0);
    if (x === 0) { throw new Error('the calibration loop reached zero'); }   // keeps x live; xorshift never does
  }
  return best;
}

async function measure() {
  const go = document.getElementById('go');
  if (go.disabled) { return; }
  go.disabled = true;
  const invite = params.get('invite') || '';
  let handle = null;
  try {
    const user = `phone${Date.now().toString(36)}`;
    await post('/api/signup', { user, invite });
    line(`device: ${navigator.userAgent}`);
    line(`secure context: ${window.isSecureContext ? 'yes' : 'no'}`);
    const jsLoopMs = jsLoop();
    line(`js loop (10^7 steps, best of 3): ${jsLoopMs.toFixed(1)} ms`);

    let t0 = performance.now();
    const id = client.newIdentity(PASS);
    const seal = performance.now() - t0;
    handle = id.handle;
    line(`seal (keygen + Argon2id 3/64 MiB): ${seal.toFixed(1)} ms`);
    const sess0 = await session();
    await store.create({ handle, serverId: sess0.serverId, serverPub: Uint8Array.from(sess0.serverPub.match(/../g), (x) => parseInt(x, 16)),
                         envelope: id.envelope });
    await post('/api/enroll', { handle, pub: bytesToHex(id.publicImage) });

    const logins = [];
    for (let i = 0; i < LOGINS; i++) {
      const sess = await session();
      const rec = await store.get(handle);
      t0 = performance.now();
      const s = await client.login({ ...loginParams(sess, handle, PASS), envelope: rec.envelope });
      const ms = performance.now() - t0;
      const code = b64url(s.code);
      await s.close();
      await post('/api/login', { code });           // the code works: this was a real login
      logins.push(ms);
      line(`login ${i + 1}: ${ms.toFixed(1)} ms`);
    }
    await post('/api/timing', {
      ua: navigator.userAgent, cores: navigator.hardwareConcurrency ?? null,
      memoryGiB: navigator.deviceMemory ?? null, sealMs: seal, loginMs: logins,
      secure: window.isSecureContext, jsLoopMs,
    });
    report(true, 'Done: the times were sent back. You can close this page.');
  } catch (e) {
    report(false, e.message);
  } finally {
    if (handle) { await store.remove(handle).catch(() => {}); }
    go.disabled = false;
  }
}

document.getElementById('go').addEventListener('click', measure);
if (params.get('auto') === '1') { measure(); }
