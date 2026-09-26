// V4-13d: phone timings for spec 14, measured on the phone. Driven by
// tools/phone_timing.mjs, which serves this page with a one-time invite in
// the URL FRAGMENT (#invite=...) -- a fragment is never sent to a server, so
// it appears in no log -- and collects what this page POSTs to /api/timing.
//
// The same two numbers browser_e2e measures in headless Chromium, so the rows
// compare: "seal" is a whole new identity (ML-DSA-65 keygen + Argon2id 3/64 MiB
// + sealing), "login" a whole login (Argon2id to open the key, then the
// handshake over the WebSocket). The throwaway passphrase is a test value.
import { boot, session, loginParams, post, report, bytesToHex, b64url } from './common.mjs';

const PASS = 'tidal-harbor-quilted-lantern';
const LOGINS = 5;
const { client, store } = await boot();
const out = document.getElementById('out');
const line = (s) => { out.textContent += s + '\n'; };
document.body.dataset.ready = '1';

document.getElementById('go').addEventListener('click', async () => {
  const invite = new URLSearchParams(location.hash.slice(1)).get('invite') || '';
  let handle = null;
  try {
    const user = `phone${Date.now().toString(36)}`;
    await post('/api/signup', { user, invite });
    line(`device: ${navigator.userAgent}`);

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
    });
    report(true, 'Done: the times were sent back. You can close this page.');
  } catch (e) {
    report(false, e.message);
  } finally {
    if (handle) { await store.remove(handle).catch(() => {}); }
  }
});
