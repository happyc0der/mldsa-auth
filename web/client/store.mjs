// Where a browser keeps its identity (V4-13c): IndexedDB.
//
// One record per handle:
//   { handle, serverId, serverPub, envelope, pending, createdAt, rotatedAt }
// `envelope` is the MLDSAEK1 blob of the key the daemon currently accepts, and
// `pending` -- null except during a rotation -- is the NEW key's envelope.
// Nothing here is a secret in the clear: both envelopes are sealed under the
// passphrase, and the server's public key is public.
//
// THE .ek.next RULE, AS TRANSACTIONS (spec 10.2, erratum 33). The CLI writes
// <handle>.ek.next before sending ROTATE and renames it over <handle>.ek on the
// ACK. IndexedDB has no rename, but it has something better -- transactions
// that commit whole or not at all:
//   stagePending   writes `pending` in its own transaction, and RESOLVES ONLY
//                  WHEN IT HAS COMMITTED, so ROTATE is never sent before the
//                  new key is durable;
//   promote        moves `pending` into `envelope` and clears `pending` in ONE
//                  transaction: there is no moment with two current keys, or none;
//   discardPending clears `pending`, and is called only once the CURRENT key
//                  has been proven live (flows.mjs), never on a failure.
// Which of those to call after an interrupted rotation is client_key_plan's
// decision, the same function the CLI uses (flows.mjs).
//
// MemoryStore has the same five methods and no durability, for tests that
// run where IndexedDB does not (Node).

const DB_NAME = 'mldsa-authd';
const STORE = 'identities';

const done = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});
const committed = (tx) => new Promise((resolve, reject) => {
  tx.oncomplete = () => resolve();
  tx.onerror = () => reject(tx.error);
  tx.onabort = () => reject(tx.error || new Error('transaction aborted'));
});

export class IdentityStore {
  static async open(name = DB_NAME) {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => { req.result.createObjectStore(STORE, { keyPath: 'handle' }); };
    return new IdentityStore(await done(req));
  }

  constructor(db) { this.db = db; }

  // Asks the browser not to evict this origin's storage. Browsers may say no
  // (and headless ones often do); the answer is returned, not assumed.
  static async persist() {
    return navigator.storage && navigator.storage.persist ? navigator.storage.persist() : false;
  }

  async get(handle) {
    const tx = this.db.transaction(STORE, 'readonly');
    return (await done(tx.objectStore(STORE).get(handle))) ?? null;
  }

  async list() {
    const tx = this.db.transaction(STORE, 'readonly');
    return done(tx.objectStore(STORE).getAll());
  }

  // A newly enrolled identity. Refuses to overwrite one: an existing record
  // may hold the only copy of a key the daemon accepts.
  async create({ handle, serverId, serverPub, envelope }) {
    const tx = this.db.transaction(STORE, 'readwrite');
    const os = tx.objectStore(STORE);
    os.add({ handle, serverId, serverPub, envelope, pending: null, createdAt: Date.now(), rotatedAt: null });
    await committed(tx);
  }

  async stagePending(handle, envelope) {
    await this.#update(handle, (r) => {
      if (r.pending) { throw new Error('a rotation is already pending; resolve it first'); }
      r.pending = envelope;
    });
  }

  async promote(handle) {
    await this.#update(handle, (r) => {
      if (!r.pending) { throw new Error('nothing pending to promote'); }
      r.envelope = r.pending;
      r.pending = null;
      r.rotatedAt = Date.now();
    });
  }

  async discardPending(handle) {
    await this.#update(handle, (r) => { r.pending = null; });
  }

  async remove(handle) {
    const tx = this.db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(handle);
    await committed(tx);
  }

  // Read-modify-write inside ONE readwrite transaction; resolves on commit.
  async #update(handle, change) {
    const tx = this.db.transaction(STORE, 'readwrite');
    const os = tx.objectStore(STORE);
    const r = await done(os.get(handle));
    if (!r) { tx.abort(); throw new Error(`no identity for ${handle}`); }
    try { change(r); } catch (e) { tx.abort(); throw e; }
    os.put(r);
    await committed(tx);
  }
}

export class MemoryStore {
  constructor() { this.m = new Map(); }
  async get(handle) { const r = this.m.get(handle); return r ? { ...r } : null; }
  async list() { return [...this.m.values()].map((r) => ({ ...r })); }
  async create(r) {
    if (this.m.has(r.handle)) { throw new Error('exists'); }
    this.m.set(r.handle, { ...r, pending: null, createdAt: Date.now(), rotatedAt: null });
  }
  async stagePending(handle, envelope) {
    const r = this.m.get(handle);
    if (r.pending) { throw new Error('a rotation is already pending; resolve it first'); }
    r.pending = envelope;
  }
  async promote(handle) {
    const r = this.m.get(handle);
    if (!r.pending) { throw new Error('nothing pending to promote'); }
    r.envelope = r.pending; r.pending = null; r.rotatedAt = Date.now();
  }
  async discardPending(handle) { this.m.get(handle).pending = null; }
  async remove(handle) { this.m.delete(handle); }
}
