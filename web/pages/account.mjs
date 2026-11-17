import { boot, session, loginParams, post, report, b64url, secret, action } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
// A site that cannot be reached is not "Not logged in" either (F240): status 0.
const meRes = await fetch('/api/me').catch(() => ({ ok: false, status: 0 }));
let me = meRes.ok ? await meRes.json().catch(() => null) : null;
// F410: only the site's own answer is one. A 200 that is not its JSON (a
// front end's catch-all page) is not "logged in as undefined".
if (me === null || typeof me !== 'object' || typeof me.user !== 'string' || typeof me.handle !== 'string') { me = null; }
// 503: the site could not ask the daemon (V4-127, F210). The session is kept,
// so this is not "Not logged in" and logging in again is not the remedy.
// F410: and "Not logged in" is the site SAYING so, 401. Everything else that
// is not an answer -- the site's own 500, a proxy's 502 or 504 with the site
// down, a 200 that is not its JSON -- used to be shown as "Not logged in"
// over a session that was still live.
let why = meRes.status;   // why there is no session, when there is none
const noAnswer = `The site did not answer as this page expects (HTTP ${meRes.status}); reload in a moment`;
document.getElementById('who').textContent = me ? `Logged in as ${me.user} (${me.handle})`
  : meRes.status === 503 ? 'The login service is not answering; reload in a moment'
  : meRes.status === 0 ? 'The site could not be reached; reload in a moment'
  : meRes.status === 401 ? 'Not logged in' : noAnswer;
document.body.dataset.ready = '1';

// Why there is no session to act on (F237): "log in first" was said for a 503
// too, one line under the message that the service is not answering.
const needMe = () => {
  if (!me) {
    throw new Error(why === 503 ? 'the login service is not answering; try again in a moment'
      : why === 0 ? 'the site could not be reached; reload and try again'
      : why === 401 ? 'log in first' : 'the site did not answer as this page expects; reload and try again');
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
// V4-187, F265: a logout clears what this page was showing. "Logged in as
// ..." and the recovery codes just minted stayed on screen, and in the DOM,
// under "Logged out", and the other buttons still acted for the old user.
// Only after the site has answered: a logout that failed changes nothing.
action('logout', async () => {
  await post('/api/logout');
  me = null;
  why = 401;              // logged out here: the site would now say so
  document.getElementById('codelist').textContent = '';
  document.getElementById('passphrase').value = '';
  document.getElementById('who').textContent = 'Not logged in';
  report(true, 'Logged out');
});
