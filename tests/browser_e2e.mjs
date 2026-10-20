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
async function act(b, page, fields, button = 'go') {
  await b.navigate(`${origin}/${page}`);
  await b.waitFor("document.body.dataset.ready === '1'", `${page} ready`);
  await b.eval(`(() => { delete document.body.dataset.result; ${Object.entries(fields).map(([k, v]) =>
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
  // Every key this profile's store holds, as the test sees each one appear.
  const envOf = async (br, h) => toHex(await inPage(br, `return Array.from((await store.get(${JSON.stringify(h)})).envelope);`));
  const held = [['the enrolled key', await envOf(b, handle)]];

  // ---- login and the hand-off ----
  requests.length = 0;
  r = await act(b, 'login.html', { passphrase: PASS });
  check(r.result === 'ok' && /Logged in as alice/.test(r.status), `login: ${r.status}`);
  const post = requests.find((q) => q.method === 'POST' && q.url.endsWith('/api/login'));
  const code = post ? JSON.parse(post.body).code : null;
  check(!!code && code.length === 43, 'hand-off: the login code reaches the site in the POST body, base64url');
  check(code && requests.every((q) => !q.url.includes(code)),
        `hand-off: the code appears in none of the ${requests.length} URLs the browser requested`);
  check(await b.eval('document.cookie') === '', 'hand-off: the session cookie is HttpOnly -- invisible to page script');
  const me = await b.eval("fetch('/api/me').then((r) => r.text())");
  check(!/token/i.test(me) && /alice/.test(me), 'hand-off: the site answers who is logged in, and never with the token');

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
  r = await act(b, 'account.html', {}, 'codes');
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
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  if (b) { await b.close(); }
  if (b2) { await b2.close(); }
  site.server.close();
  fx.kill();
  await new Promise((r) => fx.once('exit', r));
  rmSync(work, { recursive: true, force: true });
}
console.log(fail ? '\nFAILED' : '\nAll checks passed');
process.exit(fail);
