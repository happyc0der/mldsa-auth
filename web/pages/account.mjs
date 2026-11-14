import { boot, session, loginParams, post, report, b64url, secret, action } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
// A site that cannot be reached is not "Not logged in" either (F240): status 0.
const meRes = await fetch('/api/me').catch(() => ({ ok: false, status: 0 }));
const me = meRes.ok ? await meRes.json().catch(() => null) : null;
// 503: the site could not ask the daemon (V4-127, F210). The session is kept,
// so this is not "Not logged in" and logging in again is not the remedy.
document.getElementById('who').textContent = me ? `Logged in as ${me.user} (${me.handle})`
  : meRes.status === 503 ? 'The login service is not answering; reload in a moment'
  : meRes.status === 0 ? 'The site could not be reached; reload in a moment' : 'Not logged in';
document.body.dataset.ready = '1';

// Why there is no session to act on (F237): "log in first" was said for a 503
// too, one line under the message that the service is not answering.
const needMe = () => {
  if (!me) {
    throw new Error(meRes.status === 503 ? 'the login service is not answering; try again in a moment'
      : meRes.status === 0 ? 'the site could not be reached; reload and try again' : 'log in first');
  }
};
action('rotate', async () => {
  const passphrase = secret('passphrase');     // emptied whatever happens next (F237)
  needMe();
  const sess = await session();
  await flows.rotate(client, store, loginParams(sess, me.handle, passphrase));
  report(true, 'Rotated: this device has a new key, and the old one no longer authenticates');
});
action('codes', async () => {
  const passphrase = secret('passphrase');
  needMe();
  // V4-62: minting codes needs a login, not only this session -- log in
  // again with this device's key and the passphrase, and send that code.
  const sess = await session();
  const s = await flows.login(client, store, loginParams(sess, me.handle, passphrase));
  const code = b64url(s.code);
  await s.close();
  const { codes } = await post('/api/recovery-codes', { code });
  document.getElementById('codelist').textContent = codes.join('\n');
  report(true, 'Write these down now: they are shown once and cannot be retrieved');
});
action('logout', async () => {
  await post('/api/logout'); report(true, 'Logged out');
});
