// V4-293: the browser PAGES (web/pages/*.mjs) under node, each loaded fresh
// into a small fake DOM, with the site played by a fetch the test answers.
// The pages and web/client/flows.mjs are the real code; the wasm client and
// IndexedDB are stubs (tests/web_pages_stubs/), so what is checked is what a
// page says and does with what it is answered -- the fifty-seventh review's
// findings, F491 to F495. The cryptography and the store's transactions are
// web_flows' and browser_e2e's.
//
//   node web_pages.mjs REPO
import { register } from 'node:module';
import { pathToFileURL } from 'node:url';
register('./web_pages_hooks.mjs', import.meta.url);

const [repo] = process.argv.slice(2);
if (!repo) { console.log('usage: web_pages.mjs REPO'); process.exit(2); }
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) { fail = 1; } };
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));
const { MemoryStore } = await import(pathToFileURL(`${repo}/web/client/store.mjs`).href);

class El {
  constructor(id) { this.id = id; this.value = ''; this.textContent = ''; this.disabled = false; this.hidden = false; this.dataset = {}; this.listeners = {}; }
  addEventListener(t, f) { (this.listeners[t] ??= []).push(f); }
  async fire(t) { for (const f of this.listeners[t] ?? []) { await f(); } }
}
class Sel extends El {
  constructor(id) { super(id); this.options = []; this.selectedIndex = 0; }
  add(o) { o.parent = this; this.options.push(o); }
  get value() { return this.options[this.selectedIndex]?.value ?? ''; }
  set value(v) { /* the page never sets it */ }
  get selectedOptions() { const o = this.options[this.selectedIndex]; return o ? [o] : []; }
}
globalThis.Option = class { constructor(text, value) { this.text = text; this.value = value; this.dataset = {}; }
  remove() { const p = this.parent; p.options.splice(p.options.indexOf(this), 1); } };
const IDS = { login: [['passphrase', 'go', 'forget', 'status'], ['identity']],
              account: [['who', 'passphrase', 'rotate', 'codes', 'logout', 'codelist', 'status'], []],
              recover: [['user', 'code', 'go', 'status'], []] };
const json = (status, body) => new Response(typeof body === 'string' ? body : JSON.stringify(body),
                                            { status, headers: { 'Content-Type': 'application/json' } });
let loads = 0;
// One page, loaded fresh. `t` is what the stubs read; `site(url, init)` answers fetch.
async function page(name, t, site) {
  const els = {};
  const [ids, sels] = IDS[name];
  for (const id of ids) { els[id] = new El(id); }
  for (const id of sels) { els[id] = new Sel(id); }
  globalThis.document = { getElementById: (id) => els[id], body: { dataset: {} } };
  globalThis.location = { protocol: 'https:', host: 'site.test', set href(v) { t.navigated = v; } };
  globalThis.__pageTest = t;
  t.sent = [];
  globalThis.fetch = (url, init) => { t.sent.push(`${init?.method ?? 'GET'} ${url}`); return site(url, init); };
  let threw = null;
  try { await import(pathToFileURL(`${repo}/web/pages/${name}.mjs`).href + `?load=${++loads}`); } catch (e) { threw = e; }
  return { els, threw };
}
const sess = () => json(200, { state: 'ab'.repeat(16), serverId: 'authd', serverPub: '010203' });
const listeners = (el) => (el.listeners.click ?? []).length;

try {
  // --- F491: the account page's /api/me has a deadline ------------------------
  {
    // The pages wait 30 s for the site (F461); the test shortens the deadline
    // itself, so a request that never ends is given up on in 200 ms.
    const realTimeout = AbortSignal.timeout;
    AbortSignal.timeout = () => realTimeout.call(AbortSignal, 200);
    const t = { store: new MemoryStore(), client: {} };
    const never = (url, init) => new Promise((_, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal.reason));
    });
    const p = page('account', t, never);
    const done = await Promise.race([p.then(() => 'loaded'), tick(3000).then(() => 'hung')]);
    AbortSignal.timeout = realTimeout;
    const { els } = done === 'loaded' ? await p : { els: null };
    check(done === 'loaded' && listeners(els.logout) === 1 && listeners(els.rotate) === 1 &&
          /could not be reached/.test(els.who.textContent) && document.body.dataset.ready === '1',
          `account: /api/me never answering is given up on, the page says so and its buttons work (${done}; ` +
          `${els ? JSON.stringify(els.who.textContent) : ''}) (F491)`);
    const ok = await page('account', { store: new MemoryStore(), client: {} },
                          (url) => url === '/api/me' ? json(200, { user: 'alice', handle: 'h1' }) : json(200, {}));
    check(ok.els.who.textContent === 'Logged in as alice (h1)', 'account: a site that answers is shown as it answered (the control)');
  }

  // --- F492: the recover page starts the client before a code is spent --------
  {
    const t = { noStorage: true, store: null, client: {} };
    const { els, threw } = await page('recover', t, () => json(200, { recovering: true }));
    els.user.value = 'alice'; els.code.value = 'ABCD-EFGH-JKLM-NPQR';
    await els.go.fire('click');
    check(threw !== null && /could not start/.test(els.status.textContent) && listeners(els.go) === 0 &&
          !t.sent.some((s) => s.includes('/api/recover')) && t.navigated === undefined,
          `recover: with the browser's storage blocked the page says it cannot start, and no code is sent (${t.sent.join(', ') || 'nothing sent'}) (F492)`);
    const t2 = { store: new MemoryStore(), client: {} };
    const ok = await page('recover', t2, () => json(200, { recovering: true }));
    ok.els.user.value = 'alice'; ok.els.code.value = 'ABCD-EFGH-JKLM-NPQR';
    await ok.els.go.fire('click');
    check(t2.sent.includes('POST /api/recover') && t2.navigated === '/enroll.html',
          'recover: with storage, the code is sent and the page goes on to enroll (the control)');
  }

  // --- F493: a recovery the site did not confirm may have spent the code -------
  for (const [label, answer, expect] of [
    ['a 503', () => json(503, { error: 'unavailable' }), /may have been used up anyway/],
    ['no answer', () => Promise.reject(new TypeError('fetch failed')), /may have been used up anyway/],
    ['a refusal (403)', () => json(403, { error: 'recover-failed' }), /^recover-failed$/],
  ]) {
    const t = { store: new MemoryStore(), client: {} };
    const { els } = await page('recover', t, (url) => url === '/api/recover' ? answer() : json(200, {}));
    els.user.value = 'alice'; els.code.value = 'ABCD-EFGH-JKLM-NPQR';
    await els.go.fire('click');
    check(expect.test(els.status.textContent) && els.code.value === '',
          `recover: ${label} is reported as ${label.startsWith('a refusal') ? 'the site\'s refusal (the control)' : 'a code that may be spent'} ` +
          `(${JSON.stringify(els.status.textContent)}) (F493)`);
  }

  // --- F494: a login that confirms a key says so in the list -------------------
  {
    const store = new MemoryStore();
    await store.create({ handle: 'h1', serverId: 'authd', serverPub: new Uint8Array([1, 2, 3]), envelope: new Uint8Array([9]), unconfirmed: true });
    const t = { store, client: { login: async () => ({ code: new Uint8Array(32), close: async () => {} }) } };
    const { els } = await page('login', t, (url) => url === '/api/session' ? sess() : json(200, { user: 'alice', handle: 'h1' }));
    const before = [els.identity.options[0].text, els.forget.hidden];
    els.passphrase.value = 'correct horse battery staple';
    await els.go.fire('click');
    const opt = els.identity.options[0];
    check(before[0] === 'h1 (enrollment not confirmed)' && before[1] === false &&
          (await store.get('h1')).unconfirmed === false && opt.text === 'h1' && opt.dataset.unconfirmed === undefined &&
          els.forget.hidden === true && /^Logged in as alice/.test(els.status.textContent),
          `login: a login that confirms the key drops "not confirmed" and the offer to forget it (${JSON.stringify(opt.text)}, forget hidden ${els.forget.hidden}) (F494)`);
  }

  // --- F495: an unacknowledged rotation says what the flow knows ---------------
  {
    const store = new MemoryStore();
    await store.create({ handle: 'h1', serverId: 'authd', serverPub: new Uint8Array([1, 2, 3]), envelope: new Uint8Array([9]) });
    const t = { store, client: {
      newIdentity: () => ({ envelope: new Uint8Array([7]), publicImage: new Uint8Array([8]), handle: 'h1' }),
      login: async () => ({ code: new Uint8Array(32), close: async () => {},
                            rotate: async () => { throw new Error('timed out waiting for the daemon'); } }) } };
    const site = (url) => url === '/api/me' ? json(200, { user: 'alice', handle: 'h1' })
      : url === '/api/session' ? sess() : url === '/api/recovery-codes' ? json(200, {}) : json(200, {});
    const prevLocks = globalThis.navigator;
    Object.defineProperty(globalThis, 'navigator', { value: { locks: { request: (n, f) => f() } }, configurable: true });
    const { els } = await page('account', t, site);
    els.passphrase.value = 'correct horse battery staple';
    await els.rotate.fire('click');
    check(/timed out waiting for the daemon/.test(els.status.textContent) &&
          /the new key is kept pending/.test(els.status.textContent) && (await store.get('h1')).pending !== null,
          `account: a rotation sent and not acknowledged says the new key is kept pending (${JSON.stringify(els.status.textContent)}) (F495)`);
    // F302's rule, for the codes: a 2xx without them is no answer.
    await store.discardPending('h1');
    els.passphrase.value = 'correct horse battery staple';
    await els.codes.fire('click');
    check(/did not answer with the codes, and they may have been issued anyway/.test(els.status.textContent),
          `account: new codes answered 200 with no codes say they may have been issued (${JSON.stringify(els.status.textContent)}) (V4-293)`);
    Object.defineProperty(globalThis, 'navigator', { value: prevLocks, configurable: true });
  }
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
