// tests/web_pages.mjs: '/client/store.mjs' for the pages -- the REAL
// MemoryStore behind IdentityStore.open(), or the browser blocking storage.
export { MemoryStore } from '../../web/client/store.mjs';
export class IdentityStore {
  static async open() {
    if (globalThis.__pageTest.noStorage) { throw new Error('IndexedDB is blocked'); }
    return globalThis.__pageTest.store;
  }
  static async persist() { return false; }
}
