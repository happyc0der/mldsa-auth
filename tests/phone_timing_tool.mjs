// V4-26 (F119): tools/phone_timing.mjs and its page, run for real.
//
//   node phone_timing_tool.mjs FIXTURE MODULE_DIR [BROWSER]
//
// V4-25 recorded Safari 21x slower than Edge on the same Mac. The cause was
// the ORIGIN, not the client: the tool serves plain http on an address a
// phone can reach, and Safari runs a page from a non-secure origin without
// its JIT. Nothing in a row said which kind of origin it came from. Now every
// row does, and this test pins that by running the REAL tool, and a real
// headless Chromium through two origins of the same server:
//   http://127.0.0.1:P    loopback: a secure context
//   http://timing.test:P  a name that is not localhost, mapped to 127.0.0.1
//                         by --host-resolver-rules: NOT a secure context
// Chromium keeps its JIT on both. What is checked is that each row says which
// origin it was, not how fast it was.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Browser, findBrowser } from './browser/cdp.mjs';

const [fixturePath, moduleDir, browserArg] = process.argv.slice(2);
const browserPath = browserArg || findBrowser();
if (!fixturePath || !moduleDir) { console.log('usage: phone_timing_tool.mjs FIXTURE MODULE_DIR [BROWSER]'); process.exit(2); }
if (!browserPath) { console.log('FAIL: no Chromium-family browser found (set MLDSA_BROWSER)'); process.exit(1); }
const extra = (process.env.MLDSA_BROWSER_ARGS || '').split(' ').filter(Boolean);
const TOOL = join(resolve(fileURLToPath(new URL('.', import.meta.url)), '..'), 'tools', 'phone_timing.mjs');

let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) { fail = 1; } };
const work = mkdtempSync(join(tmpdir(), 'mldsa-timing-'));

// The tool as a process, bound to loopback on a free port.
function runTool(args) {
  const p = spawn(process.execPath, [TOOL, '--fixture', fixturePath, '--module-dir', moduleDir,
                                     '--host', '127.0.0.1', '--port', '0', ...args],
                  { stdio: ['ignore', 'pipe', 'inherit'] });
  const t = { p, out: '' };
  p.stdout.on('data', (d) => { t.out += d; });
  t.exited = new Promise((r) => p.on('exit', (code) => r(code)));
  return t;
}
const until = async (cond, what, ms) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) { throw new Error(`timed out waiting for ${what}`); }
    await new Promise((r) => setTimeout(r, 50));
  }
};

let tool = null;
let b = null;
try {
  // 1. A run that measures nothing must not look like success.
  const idle = runTool(['--count', '1', '--minutes', '0.05', '--out', join(work, 'none.jsonl')]);
  const idleCode = await idle.exited;
  check(idleCode === 1 && /time is up/.test(idle.out), `with no result before --minutes, the tool says "time is up" and exits 1 (exit ${idleCode})`);
  check(!existsSync(join(work, 'none.jsonl')), 'and it wrote no row');

  // 2. The real run: two results, one per origin.
  const rows = join(work, 'rows.jsonl');
  tool = runTool(['--count', '2', '--minutes', '4', '--auto', '--out', rows]);
  await until(() => /^open on the phone:\s+\S+$/m.test(tool.out) || tool.p.exitCode !== null, 'the URL', 30000);
  const url = (/^open on the phone:\s+(\S+)$/m.exec(tool.out) ?? [])[1];
  check(!!url, 'the tool printed a URL');
  if (!url) { throw new Error('no URL'); }
  check(/^http:\/\/127\.0\.0\.1:\d+\/timing\.html#invite=[0-9a-f]{32}&auto=1$/.test(url),
        'the URL is the page on loopback, with the invite and auto=1 in its FRAGMENT');
  check(!/is not a secure context/.test(tool.out), 'for --host 127.0.0.1 the tool prints no insecure-origin note');

  b = await Browser.launch(browserPath, ['--host-resolver-rules=MAP timing.test 127.0.0.1', ...extra]);
  const leg = async (u, n) => {
    await b.navigate(u);
    await b.waitFor('!!document.body.dataset.result', `leg ${n}'s result`, 120000);
    const result = await b.eval('document.body.dataset.result');
    check(result === 'ok', `leg ${n}: the page measured, enrolled, logged in five times and reported (${result})`);
    await until(() => new RegExp(`^result ${n}:`, 'm').test(tool.out) || tool.p.exitCode !== null, `the tool's result ${n}`, 10000);
    return b.eval("document.getElementById('out').textContent");
  };

  const page1 = await leg(url, 1);
  check(/^secure context: yes$/m.test(page1), 'leg 1 (127.0.0.1): the page says it is a secure context');
  check(!/not a secure context/.test(page1), 'leg 1: and shows no insecure-origin note');
  check(/^js loop \(10\^7 steps, best of 3\): \d+\.\d ms$/m.test(page1), 'leg 1: the page shows its JS loop time');

  // The route refuses a row whose new fields are missing or mistyped. Sent
  // from the page (same origin, its cookie) while the tool still waits for
  // its second result; a refused row must not count as one.
  const codes = await b.eval(`(async () => {
    const base = { ua: 'x', cores: 1, memoryGiB: null, sealMs: 1, loginMs: [1], secure: true, jsLoopMs: 1 };
    // A refused row leaves the tool waiting; an ACCEPTED one could be its last
    // result, after which the site is gone -- recorded, so the check below
    // names what happened instead of the run dying on a failed fetch.
    const st = async (o) => {
      try {
        return (await fetch('/api/timing', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                             body: JSON.stringify(o) })).status;
      } catch { return 'no response'; }
    };
    return [await st({ ...base, secure: 'yes' }), await st({ ...base, secure: undefined }),
            await st({ ...base, jsLoopMs: -1 }), await st({ ...base, jsLoopMs: undefined })];
  })()`);
  check(codes.every((c) => c === 400), `a row with secure "yes" or missing, or jsLoopMs -1 or missing, is refused 400 (${codes.join(', ')})`);
  check(!/^result 2:/m.test(tool.out), 'and none of them counted as a result');

  const page2 = await leg(url.replace('//127.0.0.1:', '//timing.test:'), 2);
  check(/^secure context: no$/m.test(page2), 'leg 2 (timing.test, mapped to loopback): the page says it is NOT a secure context');
  check(/^note: this page is not a secure context, so a WebKit browser runs it without its JIT/m.test(page2),
        'leg 2: and shows the insecure-origin note');

  const code = await Promise.race([tool.exited, new Promise((r) => setTimeout(() => r('still running'), 15000))]);
  check(code === 0, `after --count results the tool exits 0 (${code})`);

  const lines = existsSync(rows) ? readFileSync(rows, 'utf8').trim().split('\n').filter(Boolean) : [];
  check(lines.length === 2, `the tool wrote exactly two rows (${lines.length})`);
  const [r1, r2] = lines.map((l) => JSON.parse(l));
  const shaped = (r) => r && typeof r.ua === 'string' && r.sealMs > 0 && Array.isArray(r.loginMs) && r.loginMs.length === 5 &&
                        r.loginMs.every((x) => x > 0) && typeof r.jsLoopMs === 'number' && r.jsLoopMs > 0;
  check(shaped(r1) && shaped(r2), 'each row has a seal time, five login times and a JS loop time, all positive');
  check(r1?.secure === true, 'row 1 records secure: true');
  check(r2?.secure === false, 'row 2 records secure: false');
  const yes = tool.out.indexOf('secure context: yes'), no = tool.out.indexOf('secure context: no');
  check(yes >= 0 && no > yes, 'the tool printed "secure context: yes" for result 1 and "no" for result 2');
  console.log(`(Chromium here: JS loop ${r1?.jsLoopMs?.toFixed(1)} and ${r2?.jsLoopMs?.toFixed(1)} ms, ` +
              `seal ${r1?.sealMs?.toFixed(1)} and ${r2?.sealMs?.toFixed(1)} ms)`);
} catch (e) {
  check(false, `the run completed (${e.message})`);
} finally {
  if (b) { await b.close(); }
  if (tool && tool.p.exitCode === null) { tool.p.kill('SIGTERM'); await tool.exited; }
  rmSync(work, { recursive: true, force: true });
}
console.log(fail ? 'phone_timing_tool: FAILED' : 'phone_timing_tool: all checks passed');
process.exit(fail);
