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
    // Asked before anything is sent (F413, and V4-281's F464): after the
    // signup it ran with the invitation already used, and a browser that
    // holds persist() until its prompt is answered held the page there.
    let persisted = false;
    try { persisted = await IdentityStore.persist(); } catch { /* the browser's answer is "no" */ }
    const sess = await session();
    // V4-188, F267: with a recovery in progress the key goes to the account
    // being recovered -- the site holds that account's ticket -- and the name
    // and invitation typed here were silently ignored. Someone signing up
    // under their own name at a browser where another person's recovery was
    // still open got a device on that person's account. A different name is
    // now refused, before any key is made.
    const intended = sess.recovering ? sess.recoveringUser : val('user').trim();
    if (sess.recovering) {
      const problem = flows.recoveryNameProblem(val('user'), sess.recoveringUser);
      if (problem) { throw new Error(problem); }
    } else {
      // F617: trimmed, as the recovery branch above compares it and as the
      // recover page sends it (F604). A name with a space after it was
      // refused as "signup refused", with both secret fields already emptied.
      await post('/api/signup', { user: val('user').trim(), invite: invite.trim() });
    }
    // A 4xx is the site's refusal: the key was not enrolled, and flows.enroll
    // removes it. Anything else -- no answer, a 5xx -- says nothing about
    // whether it was, and the key is kept, marked unconfirmed (F220).
    // persist() was asked above, before the key is made (F413), not after
    // the site said yes: an enrollment the site never answers leaves a key
    // that may be the account's only one, the case that most needs it.
    const { handle, answer: r, confirmed, stored } = await flows.enroll(client, store,
      { serverId: sess.serverId, serverPub: hexToBytes(sess.serverPub), passphrase },
      async (id) => {
        let j;
        // F737 (V4-352): and WHOSE. The site enrolls into whatever account
        // its session names when this arrives, which another tab can have
        // changed since this page looked (a recovery begun, a signup made):
        // it is told the account this page means, and refuses another.
        try { j = await post('/api/enroll', { handle: id.handle, pub: bytesToHex(id.publicImage), user: intended }); }
        catch (e) { throw (e.status >= 400 && e.status < 500) ? new flows.EnrollRefused(e.message) : e; }
        // F646 (V4-338): an answer without its fields is no answer (F302's
        // rule, which reached the recovery codes and not this). Any 2xx
        // object was taken as "the site enrolled the key": a front end's
        // `{"status":"maintenance"}` confirmed a key the daemon never saw,
        // the page said "Enrolled undefined", and the key could not then be
        // forgotten. Thrown as a plain error, it is "no answer": the key is
        // kept, unconfirmed, and a login settles it.
        if (typeof j?.user !== 'string' || j.handle !== id.handle || j.user !== intended) {
          throw new Error('the site answered, but not with the enrollment it was asked for');
        }
        return j;
      });
    // F584: the site enrolled the key and this browser could not record
    // that. The login page would call the key unconfirmed and offer to
    // forget it; one login clears the mark, so the user is told to make one.
    // F597: the site enrolled the key and this browser no longer has it
    // (its storage was cleared while the site was being asked). That is not
    // a success, and "log in once" would send the user to a key that is not
    // there. The account exists and nothing here can open it.
    if (!stored) {
      report(false, `The site enrolled ${r.user}, but this browser lost the key it made (its storage was ` +
                    'cleared meanwhile). Nothing on this device can log in to that account: use a recovery ' +
                    'code if you have one, or ask the site\'s administrator');
      return;
    }
    report(true, `Enrolled ${r.user} on this device as ${handle}` +
                 (persisted ? '' : ' (the browser did not promise to keep this storage)') +
                 (confirmed ? '' : '. This browser could not record that the site confirmed the key: ' +
                                   'log in once now to finish, and do not use Forget on it'));
  } catch (e) {
    report(false, e.statusName === 'passphrase-policy' ? 'that passphrase is refused by the policy' : e.message);
  }
});
