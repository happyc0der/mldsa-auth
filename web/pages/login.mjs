import { boot, session, loginParams, post, report, secret, b64url } from './common.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
const list = document.getElementById('identity');
// Keys the site confirmed first; one it never confirmed says so (F220): the
// daemon may not know it, and a login with it is how to find out.
for (const r of (await store.list()).sort((x, y) => Number(x.unconfirmed === true) - Number(y.unconfirmed === true))) {
  const o = new Option(r.unconfirmed === true ? `${r.handle} (enrollment not confirmed)` : r.handle, r.handle);
  if (r.unconfirmed === true) { o.dataset.unconfirmed = '1'; }
  list.add(o);
}
// A key the site never confirmed can be forgotten here (V4-140); a confirmed
// one cannot. The first press says what would be lost, the second removes it.
const forget = document.getElementById('forget');
const offer = () => {
  const chosen = list.selectedOptions[0];
  delete forget.dataset.armed;
  forget.textContent = 'Forget this key';
  forget.hidden = !(chosen && chosen.dataset.unconfirmed === '1');
};
list.addEventListener('change', offer);
offer();
forget.addEventListener('click', async () => {
  const handle = list.value;
  if (forget.dataset.armed !== '1') {
    document.getElementById('status').textContent =
      `The site never confirmed ${handle}. If it did enroll it, forgetting the key leaves this device unable to log in ` +
      'to that account without a recovery code: try to log in with it first. Press again to forget it.';
    forget.textContent = 'Yes, forget it';
    forget.dataset.armed = '1';
    return;
  }
  try {
    await flows.forgetUnconfirmed(store, handle);
    list.remove(list.selectedIndex);
    offer();
    report(true, `Forgot ${handle}`);
  } catch (e) {
    offer();
    report(false, e.message);
  }
});
document.body.dataset.ready = '1';

document.getElementById('go').addEventListener('click', async () => {
  const events = [];
  try {
    const sess = await session();
    const s = await flows.login(client, store, loginParams(sess, list.value, secret('passphrase')), (e) => events.push(e));
    const code = b64url(s.code);
    await s.close();
    // THE HAND-OFF: the code travels in a same-origin POST body, never a URL.
    const me = await post('/api/login', { code });
    report(true, `Logged in as ${me.user}` + (events.length ? ` (${events.join('; ')})` : ''));
  } catch (e) {
    report(false, e.message + (events.length ? ` (${events.join('; ')})` : ''));
  }
});
