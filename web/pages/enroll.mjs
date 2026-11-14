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
  try {
    const sess = await session();
    if (!sess.recovering) { await post('/api/signup', { user: val('user'), invite: val('invite') }); }
    // A 4xx is the site's refusal: the key was not enrolled, and flows.enroll
    // removes it. Anything else -- no answer, a 5xx -- says nothing about
    // whether it was, and the key is kept, marked unconfirmed (F220).
    const { handle, answer: r } = await flows.enroll(client, store,
      { serverId: sess.serverId, serverPub: hexToBytes(sess.serverPub), passphrase },
      async (id) => {
        try { return await post('/api/enroll', { handle: id.handle, pub: bytesToHex(id.publicImage) }); }
        catch (e) { throw (e.status >= 400 && e.status < 500) ? new flows.EnrollRefused(e.message) : e; }
      });
    const persisted = await IdentityStore.persist();
    report(true, `Enrolled ${r.user} on this device as ${handle}` +
                 (persisted ? '' : ' (the browser did not promise to keep this storage)'));
  } catch (e) {
    report(false, e.statusName === 'passphrase-policy' ? 'that passphrase is refused by the policy' : e.message);
  }
});
