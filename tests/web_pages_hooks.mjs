// tests/web_pages.mjs's module resolver: the pages' absolute imports of
// '/client/...' and '/module/...' -- the site's URL paths -- go to the real
// flows.mjs and to the stubs beside this file.
const REPO = new URL('../', import.meta.url);
const STUB = new URL('./web_pages_stubs/', import.meta.url);
export async function resolve(spec, ctx, next) {
  if (spec === '/client/flows.mjs') { return { url: new URL('web/client/flows.mjs', REPO).href, shortCircuit: true }; }
  if (spec === '/client/authd-client.mjs') { return { url: new URL('authd-client.mjs', STUB).href, shortCircuit: true }; }
  if (spec === '/client/store.mjs') { return { url: new URL('store.mjs', STUB).href, shortCircuit: true }; }
  if (spec === '/module/mldsa_client.mjs') { return { url: new URL('mldsa_client.mjs', STUB).href, shortCircuit: true }; }
  return next(spec, ctx);
}
