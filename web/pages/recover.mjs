import { boot, post, report, val, secret, action } from './common.mjs';

// V4-293, F492: the browser must be able to keep a key BEFORE a single-use
// code is spent. This page never started the client, so where the storage is
// blocked the code was spent here and the enroll page it led to could not
// start. boot() says so on the page, and stops it, as on the others (F240).
await boot();
document.body.dataset.ready = '1';
action('go', async () => {
  const user = val('user');
  const code = secret('code');
  try {
    await post('/api/recover', { user, code });
  } catch (e) {
    // V4-293, F493: F430's rule for RECOVERY-USE. A 4xx is the site's
    // refusal; anything else -- a 503, no answer in time -- does not say the
    // code was not used: the daemon may have spent it after the site stopped
    // waiting. Retrying it then counts as a wrong code towards the lockout.
    if (e.status >= 400 && e.status < 500) { throw e; }
    throw new Error('the site did not confirm the recovery, and this code may have been used up anyway: ' +
                    'if trying it again is refused, use your next recovery code rather than retrying this one');
  }
  report(true, 'Recovery code accepted; now choose a passphrase to enroll this device');
  // The ticket stays on the site's server; this device now enrolls a new key.
  location.href = '/enroll.html';
});
