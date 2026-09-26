import { boot, session, loginParams, post, report, val } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
const me = await fetch('/api/me').then((r) => (r.ok ? r.json() : null));
document.getElementById('who').textContent = me ? `Logged in as ${me.user} (${me.handle})` : 'Not logged in';
document.body.dataset.ready = '1';

document.getElementById('rotate').addEventListener('click', async () => {
  try {
    if (!me) { throw new Error('log in first'); }
    const sess = await session();
    await flows.rotate(client, store, loginParams(sess, me.handle, val('passphrase')));
    report(true, 'Rotated: this device has a new key, and the old one no longer authenticates');
  } catch (e) { report(false, e.message); }
});
document.getElementById('codes').addEventListener('click', async () => {
  try {
    const { codes } = await post('/api/recovery-codes');
    document.getElementById('codelist').textContent = codes.join('\n');
    report(true, 'Write these down now: they are shown once and cannot be retrieved');
  } catch (e) { report(false, e.message); }
});
document.getElementById('logout').addEventListener('click', async () => {
  await post('/api/logout'); report(true, 'Logged out');
});
