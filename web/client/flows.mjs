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

// Logs in with a key; resolves to 1 if the daemon accepted it (and closes the
// session), 0 if not. A login code obtained this way is simply never used --
// it expires on its own, exactly as the CLI's probes do.
async function probe(client, params, envelope) {
  try {
    const s = await client.login({ ...params, envelope, timeoutMs: params.probeTimeoutMs ?? 5000 });
    await s.close();
    return 1;
  } catch {
    return 0;
  }
}

// The envelope to log in with, after resolving an interrupted rotation.
// `events` (optional) receives one string per decision, for the page to show.
export async function resolveKey(client, store, handle, params, events = () => {}) {
  const r = await store.get(handle);
  if (!r) { throw new Error(`no identity for ${handle}`); }
  if (!r.pending) { return r.envelope; }

  events('a rotation was interrupted; asking the daemon which key is live');
  const ekOk = await probe(client, params, r.envelope);
  const nextOk = ekOk ? 0 : await probe(client, params, r.pending);
  switch (client.keyPlan(ekOk, 1, nextOk)) {
  case KEY_PLAN.USE_EK:
    events('the current key is live; the pending one was never committed');
    return r.envelope;
  case KEY_PLAN.PROMOTE_NEXT:
    await store.promote(handle);
    events('completed the interrupted rotation');
    return r.pending;
  default:
    events('neither key authenticates; nothing has been changed');
    throw new RecoveryRefused(handle);
  }
}

// Logs in. `params` = { url, serverId, serverPub, handle, passphrase, ... } as
// AuthdClient.login takes them, minus the envelope, which comes from the store.
export async function login(client, store, params, events) {
  const envelope = await resolveKey(client, store, params.handle, params, events);
  return client.login({ ...params, envelope });
}

// Rotates to a fresh key under the same passphrase (spec 10.2).
export async function rotate(client, store, params, events = () => {}) {
  const envelope = await resolveKey(client, store, params.handle, params, events);
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
  await store.promote(params.handle);
  events('rotated; the old key no longer authenticates');
  return next.publicImage;
}
