import { boot, session, loginParams, post, report, secret, b64url, action } from './common.mjs';
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
// F385: the two presses must be two decisions. The second click of a double
// click arrived a few milliseconds after the first had armed the button and
// removed the key before the warning could be read; so a press within
// FORGET_PAUSE_MS of the arming does nothing. The key removed is the one the
// warning named, and a press while a removal is in flight does nothing.
const FORGET_PAUSE_MS = 800;
let armedAt = 0, armedFor = null, forgetting = false;
const offer = () => {
  const chosen = list.selectedOptions[0];
  delete forget.dataset.armed;
  armedFor = null;
  forget.textContent = 'Forget this key';
  forget.hidden = !(chosen && chosen.dataset.unconfirmed === '1');
};
list.addEventListener('change', offer);
offer();
forget.addEventListener('click', async () => {
  if (forgetting) { return; }
  const handle = list.value;
  if (forget.dataset.armed !== '1' || armedFor !== handle) {
    document.getElementById('status').textContent =
      `The site never confirmed ${handle}. If it did enroll it, forgetting the key leaves this device unable to log in ` +
      'to that account without a recovery code: try to log in with it first. Press again to forget it.';
    forget.textContent = 'Yes, forget it';
    forget.dataset.armed = '1';
    armedFor = handle;
    armedAt = performance.now();
    return;
  }
  if (performance.now() - armedAt < FORGET_PAUSE_MS) { return; }
  forgetting = true;
  forget.disabled = true;
  try {
    await flows.forgetUnconfirmed(store, handle);
    // By handle, not by what is selected now: the selection can change while
    // the removal waits for the store.
    [...list.options].find((o) => o.value === handle)?.remove();
    offer();
    report(true, `Forgot ${handle}`);
  } catch (e) {
    offer();
    report(false, e.message);
  } finally {
    forgetting = false;
    forget.disabled = false;
  }
});
document.body.dataset.ready = '1';

action('go', async () => {
  const events = [];
  // Read, and emptied, before anything can fail (F237): a failure to reach
  // the site used to leave the passphrase sitting in the field.
  const passphrase = secret('passphrase');
  // F562: the identity this login is for, read once. The list can be changed
  // while the login runs, and what follows is about the key that logged in.
  const chosen = list.value;
  const shownAtStart = list.selectedOptions[0];
  try {
    const sess = await session();
    const s = await flows.login(client, store, loginParams(sess, chosen, passphrase), (e) => events.push(e));
    const code = b64url(s.code);
    // V4-293, F494: a login the daemon accepted confirms the key (F220), and
    // the list says so: it kept "(enrollment not confirmed)" and offered to
    // forget a key the account now uses, warning that the site never had it.
    // F567: done here, as soon as the daemon has accepted the key, and not
    // after the hand-off below: a site that failed to take the code left the
    // key marked unconfirmed though the store no longer said so.
    const now = await store.get(chosen).catch(() => null);
    const shown = shownAtStart;
    if (now && now.unconfirmed !== true && shown && shown.dataset.unconfirmed === '1') {
      shown.text = now.handle;
      delete shown.dataset.unconfirmed;
      offer();
    }
    // The daemon has issued the code: a BYE that cannot be sent must not
    // keep it from the site (F567).
    await s.close().catch(() => {});
    // THE HAND-OFF: the code travels in a same-origin POST body, never a URL.
    const me = await post('/api/login', { code });
    report(true, `Logged in as ${typeof me.user === 'string' ? me.user : '(the site did not say)'}` +
                 (events.length ? ` (${events.join('; ')})` : ''));
  } catch (e) {
    report(false, e.message + (events.length ? ` (${events.join('; ')})` : ''));
  }
});
