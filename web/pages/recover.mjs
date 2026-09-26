import { post, report, val } from './common.mjs';

document.body.dataset.ready = '1';
document.getElementById('go').addEventListener('click', async () => {
  try {
    await post('/api/recover', { user: val('user'), code: val('code') });
    // The ticket stays on the site's server; this device now enrolls a new key.
    location.href = '/enroll.html';
    report(true, 'Recovery code accepted');
  } catch (e) { report(false, e.message); }
});
