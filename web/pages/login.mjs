import { boot, session, loginParams, post, report, val, b64url } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
const list = document.getElementById('identity');
for (const r of await store.list()) { list.add(new Option(r.handle, r.handle)); }
document.body.dataset.ready = '1';

document.getElementById('go').addEventListener('click', async () => {
  const events = [];
  try {
    const sess = await session();
    const s = await flows.login(client, store, loginParams(sess, list.value, val('passphrase')), (e) => events.push(e));
    const code = b64url(s.code);
    await s.close();
    // THE HAND-OFF: the code travels in a same-origin POST body, never a URL.
    const me = await post('/api/login', { code });
    report(true, `Logged in as ${me.user}` + (events.length ? ` (${events.join('; ')})` : ''));
  } catch (e) {
    report(false, e.message + (events.length ? ` (${events.join('; ')})` : ''));
  }
});
