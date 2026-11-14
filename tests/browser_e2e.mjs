// V4-13c: the browser client in a REAL browser, end to end.
//
//   node browser_e2e.mjs FIXTURE MODULE_DIR [BROWSER]
//
// Three real processes: the daemon (tests/authd_wasm_fixture, in-process
// assembly, WebSocket on loopback TCP), the reference site
// (examples/site-node/server.mjs, which proxies /authd/v1 to it as Caddy does
// in production), and a headless Chromium driven over the DevTools protocol
// (tests/browser/cdp.mjs). The pages, the transport, the store and the wasm
// module are the SAME files a deployment serves.
//
// Each property the step claims, observed from outside the page:
//   hand-off     the login code reaches the site in a POST BODY and in no URL
//                the browser ever requests; the token never reaches the page
//   CSP          an injected inline script does not run, and the violation
//                is reported; the header allows wasm and nothing looser
//   storage      the IndexedDB store's transactions under the .ek.next rule:
//                a lost ACK completed on the next login, a stale pending key
//                left alone by login
//   phishing     a device whose pinned server key is not the daemon's is refused
//   recovery     a fresh browser profile enrolls with a recovery code
//   policy       enrollment under a weak passphrase is refused inside wasm
//   at rest      (V4-27, CLAIMS D10) no key the browser held, and not the
//                passphrase, is anywhere in either profile on disk -- read
//                back by $MLDSA_KEY_SCAN (tests/envelope_key_scan.c), after a
//                canary written into IndexedDB proves the scan sees it
// and it measures Argon2id and a login IN the browser, next to V4-2 S6.
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import { Browser, findBrowser } from './browser/cdp.mjs';

const [fixturePath, moduleDir, browserArg] = process.argv.slice(2);
const browserPath = browserArg || findBrowser();
if (!fixturePath || !moduleDir) { console.log('usage: browser_e2e.mjs FIXTURE MODULE_DIR [BROWSER]'); process.exit(2); }
if (!browserPath) { console.log('FAIL: no Chromium-family browser found (set MLDSA_BROWSER)'); process.exit(1); }
const extra = (process.env.MLDSA_BROWSER_ARGS || '').split(' ').filter(Boolean);

let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) fail = 1; };
const PASS = 'correct horse battery staple';
const INVITE = 'reference-invite';

// ---- at rest (V4-27): the helper, and what it is handed ----
// The envelopes, the passphrase and the canary go to a directory of the
// test's own, never into a profile that is about to be scanned.
const KEY_SCAN = process.env.MLDSA_KEY_SCAN;
check(!!KEY_SCAN && existsSync(KEY_SCAN), `at rest: the profile scan's helper is named and exists (MLDSA_KEY_SCAN=${KEY_SCAN})`);
const work = mkdtempSync(join(tmpdir(), 'mldsa-e2e-'));
writeFileSync(join(work, 'pass'), PASS);
let nfile = 0;
const hexFile = (hex) => { const f = join(work, `n${nfile++}.hex`); writeFileSync(f, hex); return f; };
// Runs the helper; its last line is "found N of M windows; scanned F files, B bytes; ...".
function scan(args) {
  const r = spawnSync(KEY_SCAN, args, { encoding: 'utf8', timeout: 120000 });
  const m = /found (\d+) of (\d+) windows; scanned (\d+) files, (\d+) bytes/.exec(r.stdout || '');
  if (r.status !== 0 || !m) { console.log(`  (scan failed: exit ${r.status}; ${(r.stderr || '').trim()})`); return null; }
  const hits = r.stdout.split('\n').filter((l) => l.startsWith('hit:'));
  if (hits.length) { console.log(hits.slice(0, 3).map((l) => `  (${l})`).join('\n')); }
  return { found: +m[1], of: +m[2], files: +m[3], bytes: +m[4] };
}
const toHex = (a) => Buffer.from(a).toString('hex');
// 4,032 random bytes -- an ML-DSA-65 secret key's length -- put into the
// page origin's IndexedDB the way the store puts an envelope (a Uint8Array
// value), in a database of its own. Written at a profile's first page, so
// it is at least as old as anything the scan looks for.
const writeCanary = (b) => b.eval(`(async () => {
  const bytes = crypto.getRandomValues(new Uint8Array(4032));
  const db = await new Promise((res, rej) => { const q = indexedDB.open('mldsa-canary', 1);
    q.onupgradeneeded = () => q.result.createObjectStore('c'); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
  await new Promise((res, rej) => { const tx = db.transaction('c', 'readwrite'); tx.objectStore('c').put(bytes, 1);
    tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
  db.close();
  return Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
})()`);

const fx = spawn(fixturePath, ['300'], { stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((res, rej) => {
  let buf = '';
  fx.stdout.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { res(JSON.parse(buf.slice(0, nl))); } });
  fx.on('exit', (c) => rej(new Error(`fixture exited ${c}`)));
  setTimeout(() => rej(new Error('fixture never became ready')), 20000);
});

const { startSite, CSP } = await import(pathToFileURL(resolve('examples/site-node/server.mjs')).href);
const site = await startSite({ authdSite: info.site, authdWs: `127.0.0.1:${info.ws_port}`, serverId: info.server_id,
                               serverPub: Buffer.from(info.server_pub, 'hex'), moduleDir, invite: INVITE });
const origin = `http://127.0.0.1:${site.port}`;
console.log(`browser: ${browserPath}`);

// Everything the browser requests, and every POST body it sends.
const requests = [];
const watch = (b) => b.on((method, p) => {
  if (method === 'Network.requestWillBeSent') { requests.push({ url: p.request.url, method: p.request.method, body: p.request.postData ?? '' }); }
});

// Fills the page's fields and clicks, then waits for data-result.
// `first` (optional) is script run in the page before the click.
async function act(b, page, fields, button = 'go', first = '') {
  await b.navigate(`${origin}/${page}`);
  await b.waitFor("document.body.dataset.ready === '1'", `${page} ready`);
  await b.eval(`(() => { delete document.body.dataset.result; ${first} ${Object.entries(fields).map(([k, v]) =>
    `document.getElementById(${JSON.stringify(k)}).value = ${JSON.stringify(v)};`).join(' ')}
    document.getElementById(${JSON.stringify(button)}).click(); })()`);
  await b.waitFor('!!document.body.dataset.result', `${page} result`, 60000);
  return { result: await b.eval('document.body.dataset.result'), status: await b.eval("document.getElementById('status').textContent") };
}
// Runs `body` (an async function's source) in the page with the page's own modules.
const inPage = (b, body) => b.eval(`(async () => {
  const { AuthdClient } = await import('/client/authd-client.mjs');
  const { IdentityStore } = await import('/client/store.mjs');
  const { default: createMldsaClient } = await import('/module/mldsa_client.mjs');
  const client = await AuthdClient.load(createMldsaClient);
  const store = await IdentityStore.open();
  const sess = await (await fetch('/api/session')).json();
  const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  const params = (handle) => ({ url: 'ws://' + location.host + '/authd/v1?state=' + sess.state, serverId: sess.serverId,
                                serverPub: hex(sess.serverPub), handle, passphrase: ${JSON.stringify(PASS)} });
  ${body}
})()`);

let b = null, b2 = null;
try {
  b = await Browser.launch(browserPath, extra);
  await b.send('Network.enable');
  watch(b);
  console.log(`  ${await b.eval('navigator.userAgent')}`);

  // ---- enrollment, and the policy ----
  let r = await act(b, 'enroll.html', { user: 'alice', invite: INVITE, passphrase: 'password1234' });
  check(r.result.startsWith('error') && /refused by the policy/.test(r.status),
        'policy: enrollment under a common passphrase is refused inside wasm');
  const canary1 = await writeCanary(b);
  r = await act(b, 'enroll.html', { user: 'alice', invite: INVITE, passphrase: PASS });
  check(r.result === 'ok' && /Enrolled alice/.test(r.status), `enroll: a key made in the browser is enrolled (${r.status})`);
  const handle = await inPage(b, 'return (await store.list())[0].handle;');
  // F220 (V4-138): the page stores the key before the site is asked, and a
  // key the site then refused stayed in IndexedDB: the login page offered it
  // beside the real one, and the daemon had never seen it. The name is taken,
  // so the site answers 403.
  r = await act(b, 'enroll.html', { user: 'alice', invite: INVITE, passphrase: PASS });
  const kept = await inPage(b, 'return (await store.list()).map((x) => [x.handle, x.unconfirmed]);');
  check(r.result.startsWith('error') && /user-exists/.test(r.status), `enroll: a taken name is refused (the canary) (${r.status})`);
  check(kept.length === 1 && kept[0][0] === handle && kept[0][1] === false,
        `enroll: a key the site refused is not left in the browser, and the enrolled one is confirmed (${JSON.stringify(kept.map((k) => k[1]))}) (F220)`);
  // No answer is not a refusal: the daemon may have enrolled the key and the
  // answer been lost, so the key stays, marked, and the login page says which
  // one it is. The 503 is the site's own answer for a daemon it cannot reach,
  // given here by the page's fetch so the daemon is not disturbed.
  r = await act(b, 'enroll.html', { user: 'bob', invite: INVITE, passphrase: PASS }, 'go',
    `const f = window.fetch; window.fetch = (u, o) => (String(u).endsWith('/api/enroll')
       ? Promise.resolve(new Response('{"error":"unavailable"}', { status: 503 })) : f(u, o));`);
  const unsure = await inPage(b, 'return (await store.list()).filter((x) => x.unconfirmed === true).map((x) => x.handle);');
  check(r.result.startsWith('error') && /did not confirm/.test(r.status) && unsure.length === 1 && r.status.includes(unsure[0]),
        `enroll: a key the site did not answer for is kept, marked, and the page names it (${unsure.length} kept; ${r.status}) (F220)`);
  await b.navigate(`${origin}/login.html`);
  await b.waitFor("document.body.dataset.ready === '1'", 'login.html ready');
  const offered = await b.eval("Array.from(document.getElementById('identity').options, (o) => [o.value, o.text])");
  check(offered.length === 2 && offered[0][0] === handle && offered[0][1] === handle &&
        offered[1][0] === unsure[0] && /not confirmed/.test(offered[1][1]),
        `login: the confirmed key is offered first, and the other says it was never confirmed (${JSON.stringify(offered.map((o) => o[1].replace(/^\S+ ?/, '')))}) (F220)`);
  // V4-140: the page can forget a key the site never confirmed -- only such
  // a key, and only when asked twice.
  const forgetState = () => b.eval(`(() => { const f = document.getElementById('forget');
    return [f.hidden, f.textContent, document.getElementById('status').textContent]; })()`);
  const stored = () => inPage(b, 'return (await store.list()).map((x) => x.handle);');
  const hiddenForConfirmed = (await forgetState())[0];
  await b.eval(`(() => { const l = document.getElementById('identity'); l.value = ${JSON.stringify(unsure[0] ?? '')};
    l.dispatchEvent(new Event('change')); })()`);
  check(hiddenForConfirmed === true && (await forgetState())[0] === false,
        'forget: the button is offered for the unconfirmed key and not for the confirmed one (V4-140)');
  await b.eval("document.getElementById('forget').click()");
  await b.waitFor("document.getElementById('forget').dataset.armed === '1' || !!document.body.dataset.result", 'forget pressed once');
  const asked = await forgetState();
  check((await stored()).length === 2 && /recovery code/.test(asked[2]) && asked[1] !== 'Forget this key',
        `forget: the first press removes nothing and says what would be lost (${asked[1]}) (V4-140)`);
  await b.eval("delete document.body.dataset.result; document.getElementById('forget').click()");
  await b.waitFor('!!document.body.dataset.result', 'forget result');
  const left = await stored();
  const options = await b.eval("Array.from(document.getElementById('identity').options, (o) => o.value)");
  check(left.length === 1 && left[0] === handle && options.length === 1 && options[0] === handle && (await forgetState())[0] === true,
        `forget: the second press removes that key alone, from IndexedDB and from the list (${left.length} left) (V4-140)`);
  // Every key this profile's store holds, as the test sees each one appear.
  const envOf = async (br, h) => toHex(await inPage(br, `return Array.from((await store.get(${JSON.stringify(h)})).envelope);`));
  const held = [['the enrolled key', await envOf(b, handle)]];

  // ---- login and the hand-off ----
  requests.length = 0;
  r = await act(b, 'login.html', { passphrase: PASS });
  check(r.result === 'ok' && /Logged in as alice/.test(r.status), `login: ${r.status}`);

  // V4-162 (F237): a double click. Nothing stopped a handler from running
  // twice at once. The second run asked the site for a new state, which
  // replaced the one the first run's login code was bound to, and read a
  // passphrase field the first had already emptied: the first failed at the
  // site, the second at the key, and a correct login was reported as refused.
  // Each button now runs one action at a time.
  { await b.navigate(`${origin}/login.html`);
    await b.waitFor("document.body.dataset.ready === '1'", 'login.html ready');
    await b.eval(`(() => { delete document.body.dataset.result; window.__results = [];
      new MutationObserver(() => { if (document.body.dataset.result) { window.__results.push(document.body.dataset.result); } })
        .observe(document.body, { attributes: true, attributeFilter: ['data-result'] });
      document.getElementById('passphrase').value = ${JSON.stringify(PASS)};
      const go = document.getElementById('go'); go.click(); go.click(); })()`);
    await b.waitFor('!!document.body.dataset.result', 'a result after a double click', 60000);
    await new Promise((res) => setTimeout(res, 3000));     // room for a second run to report, if there is one
    const results = await b.eval('JSON.stringify(window.__results)');
    const status = await b.eval("document.getElementById('status').textContent");
    const me = await b.eval("fetch('/api/me').then((x) => x.status)");
    check(results === '["ok"]' && /Logged in as alice/.test(status) && me === 200,
          `double click: "Log in" pressed twice runs one login, and it succeeds (${results}; ${status}; /api/me ${me}) (F237)`);
    check(await b.eval("document.getElementById('go').disabled") === false,
          'double click: the button is usable again afterwards (F237)'); }
  // ... the passphrase is emptied even when the action fails before it is
  // used (here the site cannot be reached for a state), and an action that
  // throws is REPORTED: "Log out" had no catch, so a logout that failed left
  // the page silent, which reads as having logged out.
  { const STUB = (path) => `const f = window.fetch; window.fetch = (u, ...a) => (String(u).includes('${path}')
      ? Promise.reject(new Error('the site is unreachable')) : f(u, ...a));`;
    r = await act(b, 'login.html', { passphrase: PASS }, 'go', STUB('/api/session'));
    const left = await b.eval("document.getElementById('passphrase').value");
    check(/^error: the site is unreachable/.test(r.result) && left === '',
          `early failure: a login that could not reach the site reports it and leaves no passphrase in the field (${r.result}; ${left.length} characters left) (F237)`);
    await b.navigate(`${origin}/account.html`);
    await b.waitFor("document.body.dataset.ready === '1'", 'account.html ready');
    await b.eval(`(() => { delete document.body.dataset.result; ${STUB('/api/logout')} document.getElementById('logout').click(); })()`);
    const said = await Promise.race([
      b.waitFor('!!document.body.dataset.result', 'a result after a failed logout', 6000).then(() => true, () => false),
      new Promise((res) => setTimeout(() => res(false), 7000))]);
    const result = said ? await b.eval('document.body.dataset.result') : '(nothing)';
    check(said && /^error: the site is unreachable/.test(result),
          `failed logout: the page says the logout failed (${result}) (F237)`);
    const still = await b.eval("fetch('/api/me').then((x) => x.status)");
    check(still === 200, `failed logout: and the session is in fact still there (/api/me ${still}) (the control)`); }

  // V4-164 (F240): a page that cannot START says so. Each page's first
  // statement is `await boot()`; if the browser blocks its storage (or the
  // module does not load) that rejected at the top of the module, before any
  // listener was attached: an empty status line, and buttons that do nothing
  // when pressed. Storage is blocked here by a script that runs before the
  // page's own.
  { const { identifier } = await b.send('Page.addScriptToEvaluateOnNewDocument', { source:
      `Object.defineProperty(window, 'indexedDB', { get() { return { open() { throw new DOMException('storage is blocked', 'SecurityError'); } }; } });` });
    for (const page of ['login.html', 'enroll.html', 'account.html']) {
      await b.navigate(`${origin}/${page}`);
      const said = await Promise.race([
        b.waitFor('!!document.body.dataset.result', `${page} to say it could not start`, 8000).then(() => true, () => false),
        new Promise((res) => setTimeout(() => res(false), 9000))]);
      const result = said ? await b.eval('document.body.dataset.result') : '(nothing)';
      const status = await b.eval("document.getElementById('status').textContent");
      check(said && /^error: /.test(result) && /could not start/.test(status) && /storage is blocked/.test(status),
            `start-up failure: ${page} with its storage blocked says it could not start, and why (${result}) (F240)`);
    }
    await b.send('Page.removeScriptToEvaluateOnNewDocument', { identifier });
    r = await act(b, 'login.html', { passphrase: PASS });
    check(r.result === 'ok', `start-up failure: with storage back, the login page works (${r.status}) (the control)`); }
  // V4-76, F144: the passphrase does not stay in the page after it is used, where
  // any script on the origin could read it beside the sealed key.
  { const left = await b.eval("document.getElementById('passphrase').value");
    const ac = await b.eval("document.getElementById('passphrase').getAttribute('autocomplete')");
    check(left === '' && ac === 'off', `login: the passphrase field is empty after the login, autocomplete=${ac} (F144)`); }
  const post = requests.find((q) => q.method === 'POST' && q.url.endsWith('/api/login'));
  const code = post ? JSON.parse(post.body).code : null;
  check(!!code && code.length === 43, 'hand-off: the login code reaches the site in the POST body, base64url');
  check(code && requests.every((q) => !q.url.includes(code)),
        `hand-off: the code appears in none of the ${requests.length} URLs the browser requested`);
  check(await b.eval('document.cookie') === '', 'hand-off: the session cookie is HttpOnly -- invisible to page script');
  const me = await b.eval("fetch('/api/me').then((r) => r.text())");
  check(!/token/i.test(me) && /alice/.test(me), 'hand-off: the site answers who is logged in, and never with the token');

  // V4-133, F216: a link on another site to one of the site's API routes
  // logged the visitor out. Chromium withholds the SameSite=Strict cookie
  // from that navigation; the site minted a new session for it, and the
  // browser stored the new cookie over the logged-in one. `localhost` is
  // another site than 127.0.0.1.
  {
    const evil = http.createServer((q, s) => {
      s.writeHead(200, { 'Content-Type': 'text/html' });
      s.end(`<a id="a" href="${origin}${new URL(q.url, 'http://x').searchParams.get('to')}">a link</a>`);
    });
    await new Promise((r) => evil.listen(0, '127.0.0.1', r));
    const sidOf = async () => (await b.send('Network.getCookies', { urls: [origin] })).cookies.find((c) => c.name === 'sid')?.value;
    for (const to of ['/api/me', '/api/session']) {
      const before = await sidOf();
      await b.navigate(`http://localhost:${evil.address().port}/?to=${to}`);
      await b.eval("document.getElementById('a').click()");
      await b.waitFor(`location.origin === ${JSON.stringify(origin)} && location.pathname === ${JSON.stringify(to)}`, `the link to ${to}`);
      const shown = await b.eval('document.body.innerText');
      const after = await sidOf();
      await b.navigate(`${origin}/login.html`);
      const still = await b.eval("fetch('/api/me').then((r) => String(r.status))");
      check(!!before && after === before && still === '200' && /cross-site request refused/.test(shown),
            `cross-site: a link on another site to ${to} leaves the visitor logged in ` +
            `(cookie ${after === before ? 'kept' : 'REPLACED'}, /api/me then ${still}, the link showed ${JSON.stringify(shown.slice(0, 60))}) (F216)`);
    }
    evil.close();
  }

  // ---- CSP ----
  const hdr = (await fetch(`${origin}/login.html`)).headers.get('content-security-policy');
  check(hdr === CSP && /'wasm-unsafe-eval'/.test(hdr) && !/'unsafe-inline'|'unsafe-eval'/.test(hdr),
        "CSP: 'wasm-unsafe-eval' for the module, and no 'unsafe-inline' or 'unsafe-eval'");
  // Resolves on the violation event itself; the deadline only bounds a
  // browser that never reports one.
  const csp = await b.eval(`new Promise((res) => {
    const done = (violated) => res({ ran: window.__csp_leak === 1, violated });
    document.addEventListener('securitypolicyviolation', () => done(true), { once: true });
    const s = document.createElement('script'); s.textContent = 'window.__csp_leak = 1'; document.body.appendChild(s);
    setTimeout(() => done(false), 5000);
  })`);
  check(!csp.ran && csp.violated, 'CSP: an injected inline script does not run, and the browser reports the violation');
  const xo = await fetch(`${origin}/api/login`, { method: 'POST', headers: { Origin: 'http://evil.example', 'Content-Type': 'application/json' }, body: '{}' });
  check(xo.status === 403, 'site: a POST from another origin is refused');

  // ---- storage: the .ek.next rule on IndexedDB ----
  const stale = await inPage(b, `
    const next = client.newIdentity(${JSON.stringify(PASS)}, ${JSON.stringify(handle)});
    await store.stagePending(${JSON.stringify(handle)}, next.envelope);
    return Array.from(next.envelope);`);
  held.push(['the stale pending key', toHex(stale)]);
  r = await act(b, 'login.html', { passphrase: PASS });
  const afterStale = await inPage(b, `const r = await store.get(${JSON.stringify(handle)}); return r.pending !== null;`);
  check(stale && r.result === 'ok' && /never committed/.test(r.status) && afterStale,
        'storage: a stale pending key -- login proves the current key live and leaves the pending one alone');
  await inPage(b, `await store.discardPending(${JSON.stringify(handle)}); return true;`);

  const lost = await inPage(b, `
    const h = ${JSON.stringify(handle)};
    const next = client.newIdentity(${JSON.stringify(PASS)}, h);
    await store.stagePending(h, next.envelope);
    const cur = await store.get(h);
    const s = await client.login({ ...params(h), envelope: cur.envelope, keepForRotate: true });
    await s.rotate(next.envelope, ${JSON.stringify(PASS)});
    await s.close();                         // the ACK arrived, but the page "crashed" before promote()
    return Array.from(next.envelope);`);
  held.push(['the lost-ACK key', toHex(lost)]);
  r = await act(b, 'login.html', { passphrase: PASS });
  const afterLost = await inPage(b, `const r = await store.get(${JSON.stringify(handle)});
    return { pending: r.pending, tail: Array.from(r.envelope.slice(-16)) };`);
  check(r.result === 'ok' && /completed the interrupted rotation/.test(r.status) && afterLost.pending === null &&
        JSON.stringify(afterLost.tail) === JSON.stringify(lost.slice(-16)),
        'storage: a lost ACK -- the next login completes the rotation in ONE IndexedDB transaction');

  // ---- rotation through the account page ----
  r = await act(b, 'account.html', { passphrase: PASS }, 'rotate');
  check(r.result === 'ok' && /Rotated/.test(r.status), `rotate: ${r.status}`);
  held.push(['the account page\'s rotated key', await envOf(b, handle)]);
  r = await act(b, 'login.html', { passphrase: PASS });
  check(r.result === 'ok', 'rotate: the rotated key logs in');

  // ---- V4-136 (F218): one rotation at a time, and the lock is the browser's ----
  // The lock a rotation holds is a Web Lock named for the identity, which the
  // browser shares between every tab of the origin; and two rotations started
  // together on the real IndexedDB store both finish, leaving a key that logs in.
  const lock = await inPage(b, `
    const h = ${JSON.stringify(handle)};
    return store.exclusive(h, async () => {
      const held = (await navigator.locks.query()).held.map((l) => l.name);
      const second = await navigator.locks.request(held[0] ?? 'none', { ifAvailable: true }, async (l) => l !== null);
      return { shared: store.sharedLock, held, second };
    });`);
  check(lock.shared && lock.held.length === 1 && lock.held[0].endsWith(`:${handle}`) && lock.second === false,
        `rotate: the identity's lock is a Web Lock, held, and not available to a second request (${JSON.stringify(lock.held)})`);
  const cas = await inPage(b, `
    const h = ${JSON.stringify(handle)};
    const theirs = client.newIdentity(${JSON.stringify(PASS)}, h), mine = client.newIdentity(${JSON.stringify(PASS)}, h);
    await store.stagePending(h, theirs.envelope);
    const before = JSON.stringify(Array.from((await store.get(h)).envelope));
    let refused = false;
    try { await store.promote(h, mine.envelope); } catch { refused = true; }
    const rec = await store.get(h);
    const same = JSON.stringify(Array.from(rec.envelope)) === before && rec.pending !== null;
    await store.discardPending(h);
    return { refused, same, staged: Array.from(theirs.envelope) };`);
  held.push(['the key staged for the promote check', toHex(cas.staged)]);
  check(cas.refused && cas.same, 'rotate: IndexedDB promotes only the key the caller staged; another is refused and the record is unchanged');
  const both = await inPage(b, `
    const flows = await import('/client/flows.mjs');
    const h = ${JSON.stringify(handle)};
    const one = () => flows.rotate(client, store, params(h)).then(() => 'ok', (e) => e.message);
    const out = await Promise.all([one(), one()]);
    const rec = await store.get(h);
    return { out, pending: rec.pending !== null, env: Array.from(rec.envelope) };`);
  held.push(['the key two rotations at once ended on', toHex(both.env)]);
  r = await act(b, 'login.html', { passphrase: PASS });
  check(both.out.join() === 'ok,ok' && !both.pending && r.result === 'ok',
        `rotate: two rotations started together both finish and the key left logs in (${both.out.join('; ')}; ${r.status})`);

  // ---- timings, in the browser ----
  const t = await inPage(b, `
    let t0 = performance.now(); client.newIdentity(${JSON.stringify(PASS)}, 'd1timing'); const seal = performance.now() - t0;
    const cur = await store.get(${JSON.stringify(handle)});
    t0 = performance.now(); const s = await client.login({ ...params(${JSON.stringify(handle)}), envelope: cur.envelope });
    const login = performance.now() - t0; await s.close();
    return { seal, login };`);
  console.log(`  timings in the browser: Argon2id 3/64 MiB ${t.seal.toFixed(1)} ms (V4-2 S6, Node: 111.5 ms); ` +
              `login round trip ${t.login.toFixed(1)} ms`);
  check(t.seal > 0 && t.login > 0, 'timings: measured in the browser');

  // ---- recovery codes, then a fresh device recovers ----
  // V4-62: minting codes needs a login, not only the session -- so without the
  // passphrase the page cannot get them, and with it, it can.
  r = await act(b, 'account.html', { passphrase: 'not the passphrase at all' }, 'codes');
  check(r.result !== 'ok' && (await b.eval("document.getElementById('codelist').textContent")) === '',
        'recovery: without the passphrase, a logged-in page cannot mint recovery codes');
  r = await act(b, 'account.html', { passphrase: PASS }, 'codes');
  const codes = (await b.eval("document.getElementById('codelist').textContent")).split('\n').filter(Boolean);
  check(r.result === 'ok' && codes.length === 5, 'recovery: five codes are shown once');

  // ---- phishing: a device whose pin is wrong ----
  await inPage(b, `
    const r = await store.get(${JSON.stringify(handle)});
    const decoy = client.newIdentity(${JSON.stringify(PASS)}, r.serverId);  // an MLDSAPK1 for "authd", wrong key
    await store.remove(r.handle);
    await store.create({ ...r, serverPub: decoy.publicImage });
    return true;`);
  // The page pins the server key the SITE sends; the phishing case is the
  // device's own stored pin disagreeing with the daemon, exercised directly:
  const ph = await inPage(b, `
    const r = await store.get(${JSON.stringify(handle)});
    try { await client.login({ ...params(r.handle), serverPub: r.serverPub, envelope: r.envelope }); return 'accepted'; }
    catch (e) { return e.stage + '/' + e.framesSent; }`);
  check(ph === 'server-hello/1', `phishing: a ServerHello not signed by the device's pinned key is refused after one frame (${ph})`);

  b2 = await Browser.launch(browserPath, extra);
  // On success recover.html NAVIGATES to enroll.html (the ticket is in the
  // site's session), so there is no result to wait for on the page itself.
  await b2.navigate(`${origin}/recover.html`);
  await b2.waitFor("document.body.dataset.ready === '1'", 'recover.html ready');
  const canary2 = await writeCanary(b2);
  await b2.eval(`document.getElementById('user').value = 'alice';
                 document.getElementById('code').value = ${JSON.stringify(codes[0])};
                 document.getElementById('go').click();`);
  await b2.waitFor("location.pathname === '/enroll.html' && document.body.dataset.ready === '1'",
                   'the redirect to enroll after a recovery code is accepted');
  r = await act(b2, 'enroll.html', { passphrase: PASS });
  check(r.result === 'ok' && /Enrolled alice/.test(r.status), `recovery: a fresh profile enrolls a new device with a code (${r.status})`);
  r = await act(b2, 'login.html', { passphrase: PASS });
  check(r.result === 'ok' && /Logged in as alice/.test(r.status), 'recovery: and the new device logs in');
  const handle2 = await inPage(b2, 'return (await store.list())[0].handle;');
  const held2 = [['the recovered device\'s key', await envOf(b2, handle2)]];

  // ---- at rest: both profiles, while the browsers still run (V4-27) ----
  // The canary first: unless the scan finds the bytes IndexedDB was given, a
  // clean result below would mean nothing. Chromium's two backends store them
  // differently. LevelDB (Edge on macOS) keeps the value whole. SQLite
  // (Chrome for Testing on Linux) puts a value longer than its in-page share
  // into overflow pages, each starting with a 4-byte pointer, so the 15
  // windows straddling a split are not contiguous on disk: 4,002 of 4,017 in
  // CI 39378680825, one split. A 4,032-byte value crosses at most two on
  // 4 KiB pages. A key in the clear would still show thousands of windows,
  // and one is a failure.
  for (const [br, canary, keys, h, name] of [[b, canary1, held, handle, 'profile 1'], [b2, canary2, held2, handle2, 'profile 2']]) {
    const c = scan(['--dir', br.profile, '--needle', hexFile(canary)]);
    check(c !== null && c.of === 4017 && c.found >= c.of - 30 && c.files > 0,
          `at rest, ${name}: a canary written into IndexedDB is found on disk, every window but at most two page splits' -- ` +
          `the scan sees what IndexedDB writes (${c ? `${c.found}/${c.of}; ${c.files} files, ${c.bytes} bytes` : 'scan failed'})`);
    for (const [what, env] of keys) {
      const k = scan(['--dir', br.profile, '--envelope', hexFile(env), '--pass', join(work, 'pass'), '--handle', h]);
      check(k !== null && k.of > 3800 && k.found === 0,
            `at rest, ${name}: no window of ${what} is anywhere in the profile (${k ? `${k.found} of ${k.of}` : 'scan failed'})`);
    }
    // And the key path's own proof that it can see: the last key, opened and
    // written into the profile in the clear by the helper, is found whole.
    const [lastWhat, lastEnv] = keys[keys.length - 1];
    const pl = scan(['--dir', br.profile, '--envelope', hexFile(lastEnv), '--pass', join(work, 'pass'), '--handle', h,
                     '--plant', join(br.profile, 'planted-key.bin')]);
    check(pl !== null && pl.found === pl.of && pl.of > 3800 && !existsSync(join(br.profile, 'planted-key.bin')),
          `at rest, ${name}: ${lastWhat}, planted in the profile in the clear, is found by the same scan, every window ` +
          `(${pl ? `${pl.found} of ${pl.of}` : 'scan failed'})`);
    const p8 = scan(['--dir', br.profile, '--needle', hexFile(Buffer.from(PASS, 'utf8').toString('hex'))]);
    const p16 = scan(['--dir', br.profile, '--needle', hexFile(Buffer.from(PASS, 'utf16le').toString('hex'))]);
    check(p8 !== null && p16 !== null && p8.found === 0 && p16.found === 0,
          `at rest, ${name}: the passphrase is in no file of the profile, as UTF-8 or UTF-16 ` +
          `(${p8 && p16 ? `${p8.found} of ${p8.of}, ${p16.found} of ${p16.of}` : 'scan failed'})`);
  }
  // V4-63 (audit F134): closing a browser that has died is bounded. A
  // Browser.close nobody answers, or a browser killed by a signal (exitCode
  // null, 'exit' already emitted), left close() waiting for ever, and this
  // test ran into CTest's 600 s limit with every check passed (CI 39820109257).
  {
    const b3 = await Browser.launch(browserPath, extra);
    const died = new Promise((r) => b3.proc.once('exit', r));
    b3.proc.kill('SIGKILL');
    await died;
    const t0 = Date.now();
    const closed = await Promise.race([b3.close().then(() => true), new Promise((r) => setTimeout(() => r(false), 20000))]);
    check(closed && Date.now() - t0 < 20000,
          `teardown: closing a browser that was killed returns, not waits for ever (${Date.now() - t0} ms)`);
  }
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  if (b) { await b.close(); }
  if (b2) { await b2.close(); }
  site.server.close();
  // Bounded too (F134), as wasm_interop's is: a fixture still there after
  // 3 s is killed.
  const exited = new Promise((r) => (fx.exitCode !== null || fx.signalCode !== null) ? r() : fx.once('exit', r));
  fx.kill();
  if (!(await Promise.race([exited.then(() => true), new Promise((r) => setTimeout(() => r(false), 3000))]))) {
    fx.kill('SIGKILL');
    await exited;
  }
  rmSync(work, { recursive: true, force: true });
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
