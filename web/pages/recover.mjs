import { post, report, val, secret, action } from './common.mjs';

document.body.dataset.ready = '1';
action('go', async () => {
  await post('/api/recover', { user: val('user'), code: secret('code') });
  // The ticket stays on the site's server; this device now enrolls a new key.
  location.href = '/enroll.html';
  report(true, 'Recovery code accepted');
});
