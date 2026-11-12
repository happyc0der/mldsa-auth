import { boot, session, loginParams, post, report, val, b64url, secret } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
const meRes = await fetch('/api/me');
const me = meRes.ok ? await meRes.json() : null;
// 503: the site could not ask the daemon (V4-127, F210). The session is kept,
// so this is not "Not logged in" and logging in again is not the remedy.
document.getElementById('who').textContent = me ? `Logged in as ${me.user} (${me.handle})`
  : meRes.status === 503 ? 'The login service is not answering; reload in a moment' : 'Not logged in';
document.body.dataset.ready = '1';

document.getElementById('rotate').addEventListener('click', async () => {
  try {
    if (!me) { throw new Error('log in first'); }
    const sess = await session();
    await flows.rotate(client, store, loginParams(sess, me.handle, secret('passphrase')));
    report(true, 'Rotated: this device has a new key, and the old one no longer authenticates');
  } catch (e) { report(false, e.message); }
});
document.getElementById('codes').addEventListener('click', async () => {
  try {
    if (!me) { throw new Error('log in first'); }
    // V4-62: minting codes needs a login, not only this session -- log in
    // again with this device's key and the passphrase, and send that code.
    const sess = await session();
    const s = await flows.login(client, store, loginParams(sess, me.handle, secret('passphrase')));
    const code = b64url(s.code);
    await s.close();
    const { codes } = await post('/api/recovery-codes', { code });
    document.getElementById('codelist').textContent = codes.join('\n');
    report(true, 'Write these down now: they are shown once and cannot be retrieved');
  } catch (e) { report(false, e.message); }
});
document.getElementById('logout').addEventListener('click', async () => {
  await post('/api/logout'); report(true, 'Logged out');
});
