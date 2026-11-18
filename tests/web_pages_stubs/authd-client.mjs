// tests/web_pages.mjs: what a page gets from '/client/authd-client.mjs' --
// the client the test hands it, or the failure it asks for.
export class AuthdError extends Error {}
export class AuthdClient {
  static async load() {
    if (globalThis.__pageTest.noModule) { throw new Error('the module failed to load'); }
    return globalThis.__pageTest.client;
  }
}
