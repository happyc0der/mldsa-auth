// What a page does with the client and the store (V4-13c): log in -- after
// recovering an interrupted rotation, if there is one -- and rotate.
//
// The rules are the CLI's (client_cli.c), and the decision is literally the
// same function, client_key_plan in the core:
//   * a pending key exists only if a rotation was interrupted;
//   * the CURRENT key logging in proves the daemon never committed the pending
//     one -- only then may the pending one be discarded, and even then a login
//     leaves it alone (rotate discards it, as the CLI's rotate does);
//   * the pending key logging in (and the current one not) means the daemon
//     committed and the ACK was lost -- promote it;
//   * neither -> refuse, and change NOTHING: guessing here destroys the only
//     copy of a live key.
// A probe is a real handshake with the daemon, because "is this key current"
// is a fact only the daemon holds; "the envelope opens" says nothing about it.
//
// `store` is an IdentityStore (IndexedDB) in a page, a MemoryStore in Node.

export const KEY_PLAN = { USE_EK: 0, PROMOTE_NEXT: 1, REFUSE: 2 };

export class RecoveryRefused extends Error {
  constructor(handle) {
    super(`neither the current nor the pending key of ${handle} authenticates; nothing has been changed`);
    this.name = 'RecoveryRefused';
  }
}

// A recovery that could not be decided (V4-147, F226): at least one key never
// reached the daemon's verdict -- it would not open, or the daemon could not
// be asked. That is not the daemon refusing it, and the remedy is to try
// again (the right passphrase, a reachable site), not a new enrollment.
export class RecoveryUnresolved extends Error {
  constructor(message) {
    super(message);
    this.name = 'RecoveryUnresolved';
  }
}

export class PinMismatch extends Error {
  constructor(handle) {
    super(`the server key this page offers is not the one ${handle} pinned at enrollment; nothing was sent`);
    this.name = 'PinMismatch';
  }
}

// The site REFUSED to enroll a key: it answered, and the answer was no. Thrown
// by the `submit` a page hands to enroll(), and by nothing else.
export class EnrollRefused extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'EnrollRefused';
  }
}

// The site did not say whether it enrolled a key. The key is kept (`handle`).
export class EnrollUnconfirmed extends Error {
  constructor(handle, cause) {
    super(`the site did not confirm the enrollment (${cause && cause.message ? cause.message : cause}); ` +
          `${handle} is kept on this device: try to log in with it before enrolling again`);
    this.name = 'EnrollUnconfirmed';
    this.handle = handle;
  }
}

// A key was not forgotten: the store does not hold it, or the site confirmed it.
export class ForgetRefused extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'ForgetRefused';
  }
}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// FORGETTING A KEY THE SITE NEVER CONFIRMED (V4-140). An enrollment the site
// did not answer leaves its key marked unconfirmed, and if the site in fact
// never enrolled it nothing would ever confirm it: it stayed on the login
// page for good. This removes such a key, and no other: a confirmed key is
// an account's key, and this is not the way to give one up. The check and the
// removal run under the identity's lock, so a key that a login in another tab
// has just confirmed is seen confirmed and left.
//
// What it cannot know: whether the daemon enrolled the key. If it did, and
// the person forgets it here without having logged in with it, that account
// needs a recovery code. The page says so before it calls this.
export async function forgetUnconfirmed(store, handle) {
  return store.exclusive(handle, async () => {
    const r = await store.get(handle);
    if (!r) { throw new ForgetRefused(`no identity for ${handle} on this device`); }
    if (r.unconfirmed !== true) { throw new ForgetRefused(`${handle} is an enrolled key; it was not removed`); }
    await store.remove(handle);
  });
}

// The server identity a login or a rotation trusts is the one pinned when the
// identity was enrolled (spec 14, erratum 54, audit F137), not whatever the
// page offers this time. A page that offers another is refused before anything
// is sent: either the server's key changed, which needs a new enrollment, or
// what served the page is not the site this identity was enrolled with. What
// it cannot do: the page's own code also comes over TLS, and code that is not
// the site's need not call this at all (docs/v4/threat-model.md).
async function pinned(store, params) {
  const r = await store.get(params.handle);
  if (!r) { throw new Error(`no identity for ${params.handle}`); }
  if ((params.serverId !== undefined && params.serverId !== r.serverId) ||
      (params.serverPub !== undefined && !sameBytes(params.serverPub, r.serverPub))) {
    throw new PinMismatch(params.handle);
  }
  return { ...params, serverId: r.serverId, serverPub: r.serverPub };
}

// Logs in with a key and says what came of it: 'live' if the daemon accepted
// it (the session is closed), otherwise
//   'refused'   the daemon had the key and did not accept it: both handshake
//               frames went and the core read its answer, or its silence;
//   'unopened'  the key never left: the envelope did not open (a wrong
//               passphrase, a damaged record);
//   'unasked'   anything else -- no connection, no answer in time.
// Only 'refused' is a fact about the key (V4-147, F226). A login code obtained
// this way is simply never used -- it expires on its own, exactly as the CLI's
// probes do.
async function probe(client, params, envelope) {
  try {
    const s = await client.login({ ...params, envelope, timeoutMs: params.probeTimeoutMs ?? 5000 });
    await s.close();
    return { verdict: 'live' };
  } catch (e) {
    const core = e?.name === 'AuthdError';
    const verdict = core && e.framesSent >= 2 ? 'refused' : core && e.framesSent === 0 ? 'unopened' : 'unasked';
    return { verdict, why: String(e?.message ?? e) };
  }
}

// The envelope to log in with, after resolving an interrupted rotation.
// `events` (optional) receives one string per decision, for the page to show.
//
// A pending key is resolved only while holding the identity's lock (V4-136,
// F218): a pending key beside a live current key is what a crashed rotation
// leaves, and also what a rotation running in another tab looks like half way.
// The lock tells them apart -- the running one holds it, so this waits for it
// and then reads the record again.
export async function resolveKey(client, store, handle, params, events = () => {}) {
  const r = await store.get(handle);
  if (!r) { throw new Error(`no identity for ${handle}`); }
  if (!r.pending) { return r.envelope; }
  return store.exclusive(handle, () => resolveHeld(client, store, handle, params, events));
}

// resolveKey for a caller that already holds the identity's lock.
async function resolveHeld(client, store, handle, params, events) {
  const r = await store.get(handle);
  if (!r) { throw new Error(`no identity for ${handle}`); }
  if (!r.pending) { return r.envelope; }

  events('a rotation was interrupted; asking the daemon which key is live');
  const ek = await probe(client, params, r.envelope);
  const next = ek.verdict === 'live' ? { verdict: 'untried' } : await probe(client, params, r.pending);
  switch (client.keyPlan(ek.verdict === 'live', 1, next.verdict === 'live')) {
  case KEY_PLAN.USE_EK:
    events('the current key is live; the pending one was never committed');
    return r.envelope;
  case KEY_PLAN.PROMOTE_NEXT:
    await store.promote(handle, r.pending);
    events('completed the interrupted rotation');
    return r.pending;
  default:
    break;
  }
  if (ek.verdict === 'refused' && next.verdict === 'refused') {
    events('neither key authenticates; nothing has been changed');
    throw new RecoveryRefused(handle);
  }
  // Not both refused, so the daemon's answer is not known (F226).
  const unasked = [ek, next].find((p) => p.verdict === 'unasked');
  let msg;
  if (unasked) {
    msg = `could not ask the daemon which key of ${handle} is live (${unasked.why})`;
  } else if (ek.verdict === 'unopened' && next.verdict === 'unopened') {
    msg = `neither key of ${handle} could be opened (${ek.why}), so the daemon was not asked`;
  } else if (ek.verdict === 'refused') {
    msg = `the current key of ${handle} does not authenticate and the pending key could not be opened (${next.why})`;
  } else {
    msg = `the pending key of ${handle} does not authenticate and the current key could not be opened (${ek.why})`;
  }
  events('the interrupted rotation could not be resolved; nothing has been changed');
  throw new RecoveryUnresolved(`${msg}; nothing has been changed`);
}

// Logs in. `params` = { url, serverId, serverPub, handle, passphrase, ... } as
// AuthdClient.login takes them, minus the envelope, which comes from the store.
// The server identity comes from the store too; one the page offers must match.
export async function login(client, store, params, events) {
  const p = await pinned(store, params);
  const envelope = await resolveKey(client, store, p.handle, p, events);
  const s = await client.login({ ...p, envelope });
  // The daemon accepted the key, so it was enrolled after all (F220). The
  // login has succeeded either way: a store that cannot record that says so
  // the next time.
  try { if ((await store.get(p.handle))?.unconfirmed) { await store.confirm(p.handle); } } catch { /* still unconfirmed */ }
  return s;
}

// Makes a key and has the site enroll it (V4-138, F220).
// `submit({ handle, publicImage })` asks the site; it resolves when the site
// enrolled the key, throws EnrollRefused when the site answered no, and throws
// anything else when there was no answer to read (no connection, a 5xx).
//
// The key is stored BEFORE the site is asked: the other order can enroll a key
// that is then not stored, and an account whose only key is lost has no way
// back in. So what is stored is marked unconfirmed until the site answers:
//   yes        confirmed;
//   no         removed -- the daemon never took this key, and left in the
//              store it was offered at every login beside the real one;
//   no answer  KEPT, still unconfirmed. The daemon may have enrolled it and
//              the answer been lost, and then this is the account's only key.
//              A login with it settles the question (login() confirms it).
export async function enroll(client, store, { serverId, serverPub, passphrase }, submit) {
  const id = client.newIdentity(passphrase);            // refused inside wasm if the policy says no
  await store.create({ handle: id.handle, serverId, serverPub, envelope: id.envelope, unconfirmed: true });
  let answer;
  try {
    answer = await submit({ handle: id.handle, publicImage: id.publicImage });
  } catch (e) {
    if (e instanceof EnrollRefused) { await store.remove(id.handle); throw e; }
    throw new EnrollUnconfirmed(id.handle, e);
  }
  await store.confirm(id.handle);
  return { handle: id.handle, answer };
}

// Rotates to a fresh key under the same passphrase (spec 10.2).
// The whole of it runs holding the identity's lock, so a second rotation -- in
// this tab or another -- starts only when this one has finished, and finds
// this one's result rather than its half-way state (V4-136, F218).
export async function rotate(client, store, offered, events = () => {}) {
  const params = await pinned(store, offered);
  if (!store.sharedLock) {
    throw new Error('this browser cannot keep two tabs from rotating at once (no Web Locks); nothing was changed');
  }
  return store.exclusive(params.handle, () => rotateHeld(client, store, params, events));
}

async function rotateHeld(client, store, params, events) {
  const envelope = await resolveHeld(client, store, params.handle, params, events);
  const r = await store.get(params.handle);
  if (r.pending) {
    // resolveKey returned the CURRENT key and would not have without proving it
    // live, so this pending key is stale. Only now, on that proof, is it discarded.
    await store.discardPending(params.handle);
  }
  const next = client.newIdentity(params.passphrase, params.handle);
  await store.stagePending(params.handle, next.envelope);   // durable BEFORE ROTATE leaves
  const s = await client.login({ ...params, envelope, keepForRotate: true });
  try {
    await s.rotate(next.envelope, params.passphrase);
  } catch (e) {
    // No ACK is not proof that nothing happened: the daemon may have committed
    // and failed to answer. The pending key STAYS; the next login resolves it.
    await s.close();
    events('the rotation was not acknowledged; the new key is kept pending');
    throw e;
  }
  await s.close();
  await store.promote(params.handle, next.envelope);
  events('rotated; the old key no longer authenticates');
  return next.publicImage;
}
