import { boot, session, post, report, val, bytesToHex, hexToBytes, secret, action } from './common.mjs';
import { IdentityStore } from '/client/store.mjs';
import * as flows from '/client/flows.mjs';

const { client, store } = await boot();
const meter = document.getElementById('meter');
const REASONS = { 1: 'repeated characters', 2: 'a run like abc or 321', 4: 'a keyboard walk',
                  8: 'one piece repeated', 16: 'only one kind of character', 32: 'common words' };
document.getElementById('passphrase').addEventListener('input', () => {
  const v = client.checkPassphrase(val('passphrase'));
  const why = Object.entries(REASONS).filter(([bit]) => v.reasons & Number(bit)).map(([, t]) => t);
  meter.textContent = v.ok ? `acceptable (~${v.bits} bits estimated)`
    : ['', 'not valid text', 'too long', `too short (${v.codePoints} of 12 characters)`,
       'a common password', `too predictable (~${v.bits} bits${why.length ? ': ' + why.join(', ') : ''})`][v.verdict];
});
document.body.dataset.ready = '1';

action('go', async () => {
  const passphrase = secret('passphrase');     // emptied whatever happens next (F237)
  // The invitation is the site's secret: read once and emptied, like the
  // passphrase (V4-188).
  const invite = secret('invite');
  meter.textContent = '';                      // it described a field that is now empty
  try {
    // F386: the policy is asked BEFORE the site is. The sign-up used to go
    // first: a passphrase the policy refuses left the invitation spent on
    // this session and the field empty, and the second attempt, with a good
    // passphrase, was answered "signup refused".
    if (!client.checkPassphrase(passphrase).ok) {
      throw Object.assign(new Error('passphrase-policy'), { statusName: 'passphrase-policy' });
    }
    const sess = await session();
    // V4-188, F267: with a recovery in progress the key goes to the account
    // being recovered -- the site holds that account's ticket -- and the name
    // and invitation typed here were silently ignored. Someone signing up
    // under their own name at a browser where another person's recovery was
    // still open got a device on that person's account. A different name is
    // now refused, before any key is made.
    if (sess.recovering) {
      const problem = flows.recoveryNameProblem(val('user'), sess.recoveringUser);
      if (problem) { throw new Error(problem); }
    } else {
      await post('/api/signup', { user: val('user'), invite });
    }
    // A 4xx is the site's refusal: the key was not enrolled, and flows.enroll
    // removes it. Anything else -- no answer, a 5xx -- says nothing about
    // whether it was, and the key is kept, marked unconfirmed (F220).
    // Asked before the key is made (F413), not after the site said yes: an
    // enrollment the site never answers leaves a key that may be the
    // account's only one, and that is the one case that was never asked for.
    let persisted = false;
    try { persisted = await IdentityStore.persist(); } catch { /* the browser's answer is "no" */ }
    const { handle, answer: r } = await flows.enroll(client, store,
      { serverId: sess.serverId, serverPub: hexToBytes(sess.serverPub), passphrase },
      async (id) => {
        try { return await post('/api/enroll', { handle: id.handle, pub: bytesToHex(id.publicImage) }); }
        catch (e) { throw (e.status >= 400 && e.status < 500) ? new flows.EnrollRefused(e.message) : e; }
      });
    report(true, `Enrolled ${r.user} on this device as ${handle}` +
                 (persisted ? '' : ' (the browser did not promise to keep this storage)'));
  } catch (e) {
    report(false, e.statusName === 'passphrase-policy' ? 'that passphrase is refused by the policy' : e.message);
  }
});
