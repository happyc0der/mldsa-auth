import { boot, session, post, report, val, bytesToHex, hexToBytes } from './common.mjs';
import { IdentityStore } from '/client/store.mjs';

const { client, store } = await boot();
const meter = document.getElementById('meter');
const REASONS = { 1: 'repeated characters', 2: 'a run like abc or 321', 4: 'a keyboard walk',
                  8: 'one piece repeated', 16: 'only one kind of character' };
document.getElementById('passphrase').addEventListener('input', () => {
  const v = client.checkPassphrase(val('passphrase'));
  const why = Object.entries(REASONS).filter(([bit]) => v.reasons & Number(bit)).map(([, t]) => t);
  meter.textContent = v.ok ? `acceptable (~${v.bits} bits estimated)`
    : ['', 'not valid text', 'too long', `too short (${v.codePoints} of 12 characters)`,
       'a common password', `too predictable (~${v.bits} bits${why.length ? ': ' + why.join(', ') : ''})`][v.verdict];
});
document.body.dataset.ready = '1';

document.getElementById('go').addEventListener('click', async () => {
  try {
    const sess = await session();
    if (!sess.recovering) { await post('/api/signup', { user: val('user'), invite: val('invite') }); }
    const id = client.newIdentity(val('passphrase'));          // refused inside wasm if the policy says no
    await store.create({ handle: id.handle, serverId: sess.serverId, serverPub: hexToBytes(sess.serverPub),
                         envelope: id.envelope });
    const r = await post('/api/enroll', { handle: id.handle, pub: bytesToHex(id.publicImage) });
    const persisted = await IdentityStore.persist();
    report(true, `Enrolled ${r.user} on this device as ${id.handle}` +
                 (persisted ? '' : ' (the browser did not promise to keep this storage)'));
  } catch (e) {
    report(false, e.statusName === 'passphrase-policy' ? 'that passphrase is refused by the policy' : e.message);
  }
});
