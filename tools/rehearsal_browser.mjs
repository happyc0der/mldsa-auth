// V4-100: a person in a browser, against the DEPLOYED stack.
//
//   node tools/rehearsal_browser.mjs ORIGIN INVITE_FILE USER BROWSER
//
// tools/rehearse_runbook.py runs this after the runbook's Part II, so what it
// reaches is the deployment itself: Caddy on :443 with its own certificate,
// the reference site as www-data behind it, and the daemon under systemd on
// the far side of PROXY v2 -- not the in-process fixture CI's wasm job uses.
// The pages, the transport and the module are the files step 14 installed.
//
// It enrolls USER with a key made in the browser, logs in with it, and asks
// the site who is logged in. Each is a PASS/FAIL line; exit 1 on any FAIL.
//
// --ignore-certificate-errors is the one concession: Caddy's internal CA for
// `localhost` is not in this throwaway browser's trust store. It changes
// what the browser trusts, not what the page does: the origin is still
// https, the page is still a secure context, the WebSocket is still wss.
import { readFileSync } from 'node:fs';
import { Browser } from '../tests/browser/cdp.mjs';

const [origin, inviteFile, user, browserPath] = process.argv.slice(2);
if (!origin || !inviteFile || !user || !browserPath) {
  console.log('usage: rehearsal_browser.mjs ORIGIN INVITE_FILE USER BROWSER'); process.exit(2);
}
const invite = readFileSync(inviteFile, 'utf8').trim();
const PASS = 'rehearsal: correct horse battery staple, deployed';
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: BROWSER: ${what}`); if (!ok) { fail = 1; } };

async function act(b, page, fields, button = 'go') {
  await b.navigate(`${origin}/${page}`);
  await b.waitFor("document.body.dataset.ready === '1'", `${page} ready`);
  await b.eval(`(() => { delete document.body.dataset.result; ${Object.entries(fields).map(([k, v]) =>
    `document.getElementById(${JSON.stringify(k)}).value = ${JSON.stringify(v)};`).join(' ')}
    document.getElementById(${JSON.stringify(button)}).click(); })()`);
  await b.waitFor('!!document.body.dataset.result', `${page} result`, 90000);
  return { result: await b.eval('document.body.dataset.result'),
           status: await b.eval("document.getElementById('status').textContent") };
}

let b = null, b2 = null;
try {
  b = await Browser.launch(browserPath, ['--ignore-certificate-errors']);
  const ws = [];
  b.on((method, p) => { if (method === 'Network.webSocketCreated') { ws.push(p.url); } });
  await b.send('Network.enable');
  await b.navigate(`${origin}/login.html`);
  check(await b.eval('window.isSecureContext') === true && (await b.eval('location.protocol')) === 'https:',
        `the page is a secure context on ${origin}`);
  let r = await act(b, 'enroll.html', { user, invite, passphrase: PASS });
  check(r.result === 'ok' && new RegExp(`Enrolled ${user}`).test(r.status), `enroll through the deployment: ${r.status}`);
  r = await act(b, 'login.html', { passphrase: PASS });
  check(r.result === 'ok' && new RegExp(`Logged in as ${user}`).test(r.status), `login through the deployment: ${r.status}`);
  check(ws.length > 0 && ws.every((u) => u.startsWith('wss://')), `every WebSocket was wss (${ws.length}: ${ws[0] || 'none'})`);
  const me = await b.eval("fetch('/api/me').then((r) => r.text())");
  check(new RegExp(user).test(me) && !/token/i.test(me), 'the site knows who logged in, and never says the token');

  // ---- recovery, through the deployment (V4-106) ----
  // Codes need a login, not only the session (V4-62): the page logs in again.
  r = await act(b, 'account.html', { passphrase: PASS }, 'codes');
  const codes = (await b.eval("document.getElementById('codelist').textContent")).split('\n').filter(Boolean);
  check(r.result === 'ok' && codes.length === 5, `recovery: five codes are issued after a fresh login (${codes.length})`);
  // A fresh browser -- a lost device's replacement -- recovers with one.
  b2 = await Browser.launch(browserPath, ['--ignore-certificate-errors']);
  await b2.navigate(`${origin}/recover.html`);
  await b2.waitFor("document.body.dataset.ready === '1'", 'recover.html ready');
  await b2.eval(`document.getElementById('user').value = ${JSON.stringify(user)};
                 document.getElementById('code').value = ${JSON.stringify(codes[0] || '')};
                 document.getElementById('go').click();`);
  await b2.waitFor("location.pathname === '/enroll.html' && document.body.dataset.ready === '1'",
                   'the redirect to enroll after the recovery code is accepted', 60000);
  r = await act(b2, 'enroll.html', { passphrase: PASS });
  const enrolled = r.result === 'ok' && new RegExp(`Enrolled ${user}`).test(r.status);
  r = await act(b2, 'login.html', { passphrase: PASS });
  const loggedIn = r.result === 'ok' && new RegExp(`Logged in as ${user}`).test(r.status);
  check(enrolled && loggedIn, `recovery: the new device enrolled (${enrolled}) and logged in (${loggedIn})`);
  // The same code again is refused: a code is single-use.
  await b2.navigate(`${origin}/recover.html`);
  await b2.waitFor("document.body.dataset.ready === '1'", 'recover.html ready again');
  await b2.eval(`delete document.body.dataset.result;
                 document.getElementById('user').value = ${JSON.stringify(user)};
                 document.getElementById('code').value = ${JSON.stringify(codes[0] || '')};
                 document.getElementById('go').click();`);
  await b2.waitFor('!!document.body.dataset.result', 'the reused code\'s result', 60000);
  const again = await b2.eval('document.body.dataset.result');
  check(again !== 'ok' && (await b2.eval('location.pathname')) === '/recover.html',
        `recovery: the same code a second time is refused (${again})`);
  if (enrolled && loggedIn && again !== 'ok') {
    console.log('PASS: BROWSER: recovery: a fresh browser recovered with a code, enrolled a new device and logged in');
  }
} catch (e) {
  check(false, `the browser run stopped: ${e && e.message}`);
} finally {
  if (b) { await b.close(); }
  if (b2) { await b2.close(); }
}
console.log(fail ? 'FAIL: BROWSER: see above' : 'PASS: BROWSER: a person enrolled and logged in through the deployed stack');
process.exit(fail);
