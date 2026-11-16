// Shared by every page (V4-13c): boot the client and the store, talk to the
// site. No cryptography here -- that is all in the module (web_no_crypto
// scans web/client; the pages only call into it).
import createMldsaClient from '/module/mldsa_client.mjs';
import { AuthdClient } from '/client/authd-client.mjs';
import { IdentityStore } from '/client/store.mjs';

export const hexToBytes = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
export const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
// base64url, unpadded -- the login code's encoding for the site (spec 13).
export const b64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// A page that cannot start SAYS so (V4-164, F240). This is every page's first
// statement, and it rejected at the top of the module when the browser
// blocked the page's storage or the module did not load: no listener was ever
// attached, the status line stayed empty and every button did nothing. The
// failure is written where the page reports everything else, and thrown on,
// so the page still stops -- with a reason on it.
export async function boot() {
  try {
    const client = await AuthdClient.load(createMldsaClient);
    const store = await IdentityStore.open();
    return { client, store };
  } catch (e) {
    report(false, `This page could not start: ${e?.message ?? String(e)}. Nothing on it will work. ` +
                  'Reload it; if this stays, the browser is blocking the storage or the code the page needs ' +
                  '(a private window, or a setting that blocks site data).');
    throw e;
  }
}

// A FRESH state for every login: the site binds it into the code (Req 5).
// What the site answered is CHECKED (V4-190, F268). The body was read as
// JSON whatever the status, so a proxy's 502 page reached the visitor as a
// JSON parse error, and a refusal -- valid JSON, no state in it -- as "Cannot
// read properties of undefined", thrown from inside the login that followed.
export async function session() {
  const r = await fetch('/api/session', { cache: 'no-store' });
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    throw new Error(j && typeof j.error === 'string' ? `the site refused: ${j.error}`
                                                     : `the site did not answer (HTTP ${r.status}); try again in a moment`);
  }
  if (!j || typeof j.state !== 'string' || typeof j.serverId !== 'string' || typeof j.serverPub !== 'string') {
    throw new Error('the site did not answer with a session; reload the page');
  }
  return j;
}

export function loginParams(sess, handle, passphrase) {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  return { url: `${scheme}://${location.host}/authd/v1?state=${sess.state}`, serverId: sess.serverId,
           serverPub: hexToBytes(sess.serverPub), handle, passphrase };
}

export async function post(path, obj) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(obj ?? {}) });
  const j = await r.json().catch(() => null);
  if (!r.ok) { throw Object.assign(new Error((j && j.error) || `HTTP ${r.status}`), { status: r.status }); }
  // F302: a 2xx that is not the site's JSON is not the site's answer. A
  // front end's catch-all or maintenance page, served 200, was read as `{}`:
  // "Logged out" over a live session, a key marked enrolled that never was.
  // The error carries no status, so callers treat it as no answer at all.
  if (j === null || typeof j !== 'object' || Array.isArray(j)) {
    throw new Error(`the site did not answer as this page expects (HTTP ${r.status}, not its JSON); ` +
                    'nothing is assumed to have happened');
  }
  return j;
}

// The page's outcome, for people (#status) and for the browser test
// (data-result on <body>: "ok" or "error: ...").
export function report(ok, text) {
  document.getElementById('status').textContent = text;
  document.body.dataset.result = ok ? 'ok' : `error: ${text}`;
}
export const val = (id) => document.getElementById(id).value;

// A button's action, ONE run at a time (V4-162, F237). The pages attached
// plain async listeners, so a second click started a second run beside the
// first: on the login page it replaced the state the first run's code was
// bound to and read a passphrase field the first had emptied, and a correct
// login was reported as refused. While a run is in progress the button is
// disabled and further clicks do nothing. Whatever the action throws is
// reported -- a listener that rejected used to leave the page silent, which
// for "Log out" reads as having logged out.
export function action(id, run) {
  const button = document.getElementById(id);
  let busy = false;
  button.addEventListener('click', async () => {
    if (busy) { return; }
    busy = true;
    button.disabled = true;
    try { await run(); }
    catch (e) { report(false, e?.message ?? String(e)); }
    finally { busy = false; button.disabled = false; }
  });
}
// A secret field -- the passphrase, a recovery code -- read ONCE and emptied in
// the same step (V4-76, F144). Left in the field, the passphrase sat in the DOM
// after the login for any script on the origin to read next to the sealed key
// in IndexedDB, which together are the key. Clearing does not stop a script
// that is present while the passphrase is typed; nothing on the page can.
export const secret = (id) => {
  const el = document.getElementById(id);
  const v = el.value;
  el.value = '';
  return v;
};
