import { boot, session, loginParams, post, report, b64url, secret, action } from './common.mjs';
import { siteFetch } from './site-fetch.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
// A site that cannot be reached is not "Not logged in" either (F240): status 0.
// V4-293, F491: with a deadline, as every request to the site has had since
// F461. This one was a plain fetch, awaited before any button had a listener,
// so a front end that never answered left every button dead and the page
// silent -- "Log out" on a shared machine did nothing and said nothing.
let meRes, me = null;
try {
  const { r, j } = await siteFetch('/api/me', { cache: 'no-store' });
  meRes = r;
  me = r.ok ? j : null;
} catch { meRes = { ok: false, status: 0 }; }
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
  : meRes.status === 401 ? 'Not logged in'
  // 409: a login in another tab replaced this page's session while it loaded
  // (V4-279, F456); the browser now holds the new one.
  // V4-293: a signup or a recovery in another tab replaces the session too,
  // and ends its login; a login there leaves the browser logged in anew.
  : meRes.status === 409 ? 'This page\'s session was replaced in another tab (a login, sign-up or recovery there); reload this page'
  : noAnswer;
document.body.dataset.ready = '1';

// Why there is no session to act on (F237): "log in first" was said for a 503
// too, one line under the message that the service is not answering.
const needMe = () => {
  if (!me) {
    throw new Error(why === 503 ? 'the login service is not answering; try again in a moment'
      : why === 0 ? 'the site could not be reached; reload and try again'
      : why === 401 ? 'log in first' : why === 409 ? 'reload this page: its session was replaced in another tab'
      : 'the site did not answer as this page expects; reload and try again');
  }
};
action('rotate', async () => {
  const passphrase = secret('passphrase');     // emptied whatever happens next (F237)
  needMe();
  const sess = await session();
  // V4-293, F495: what the flow says happened, as the login page shows it.
  // "The rotation was not acknowledged; the new key is kept pending" was
  // dropped, so an outcome that is unknown read as a plain failure.
  const events = [];
  try {
    await flows.rotate(client, store, loginParams(sess, me.handle, passphrase), (e) => events.push(e));
  } catch (e) {
    throw new Error((e?.message ?? String(e)) + (events.length ? ` (${events.join('; ')})` : ''));
  }
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
  let codes;
  try {
    ({ codes } = await post('/api/recovery-codes', { code }));
  } catch (e) {
    // F430: an answer that is not the site's refusal (a 503, no answer at
    // all) does not say nothing happened. The daemon may have issued the
    // codes after the site stopped waiting, and issuing replaces every code
    // the user already holds.
    if (e.status >= 400 && e.status < 500) { throw e; }
    throw new Error('the site did not confirm new recovery codes, and they may have been issued anyway: ' +
                    'any codes you already hold may no longer work. Issue codes again before relying on them');
  }
  // F302's rule for a 2xx: an answer without the codes is no answer (V4-293).
  if (!Array.isArray(codes) || codes.length === 0 || !codes.every((c) => typeof c === 'string')) {
    throw new Error('the site did not answer with the codes, and they may have been issued anyway: ' +
                    'any codes you already hold may no longer work. Issue codes again before relying on them');
  }
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
