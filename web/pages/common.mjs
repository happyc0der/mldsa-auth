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

export async function boot() {
  const client = await AuthdClient.load(createMldsaClient);
  const store = await IdentityStore.open();
  return { client, store };
}

// A FRESH state for every login: the site binds it into the code (Req 5).
export async function session() {
  const r = await fetch('/api/session', { cache: 'no-store' });
  return r.json();
}

export function loginParams(sess, handle, passphrase) {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  return { url: `${scheme}://${location.host}/authd/v1?state=${sess.state}`, serverId: sess.serverId,
           serverPub: hexToBytes(sess.serverPub), handle, passphrase };
}

export async function post(path, obj) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(obj ?? {}) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { throw new Error(j.error || `HTTP ${r.status}`); }
  return j;
}

// The page's outcome, for people (#status) and for the browser test
// (data-result on <body>: "ok" or "error: ...").
export function report(ok, text) {
  document.getElementById('status').textContent = text;
  document.body.dataset.result = ok ? 'ok' : `error: ${text}`;
}
export const val = (id) => document.getElementById(id).value;
