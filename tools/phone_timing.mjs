#!/usr/bin/env node
// Phone timings for spec 14 (V4-13d): the browser client measured ON A PHONE.
//
//   node tools/phone_timing.mjs --fixture build/tests/authd_wasm_fixture \
//        --module-dir build-wasm/web --host <address the phone can reach> \
//        [--port 8099] [--count 1] [--minutes 15] [--out phone-timings.json] [--auto]
//
// It starts the test daemon (tests/authd_wasm_fixture, the one wasm_interop
// and browser_e2e use) and the reference site, bound to --host, and prints a
// URL to open on the phone. The page (web/pages/timing.html) makes one
// throwaway identity, enrolls it, logs in five times with real login codes,
// POSTs the times back here and deletes the identity. Each result is printed
// and appended to --out; the tool stops after --count results, or exits 1 if
// --minutes run out first. --auto puts auto=1 in the URL's fragment, so the
// page starts by itself (a browser opened by a script, or a test).
//
// Which origin was measured matters (V4-26, F119). Safari runs a page from a
// non-secure origin -- plain http on any name but localhost and the loopback
// addresses -- without its JIT, 8-30x slower. Every row says whether the page
// was a secure context and how long a fixed JS loop took. For a browser on
// this machine, use --host 127.0.0.1: a secure context, as HTTPS is.
//
// What is exposed, and to whom: plain http on --host:--port for at most
// --minutes, serving the test daemon's throwaway store. Sign-up needs an
// invite that is fresh per run and travels in the URL's FRAGMENT, which a
// browser never sends, so it is in no request log. Use an address only your
// own devices reach -- a Tailscale address (100.x) or your home Wi-Fi's.
//
// http, not https, is deliberate: WebAssembly, IndexedDB and getRandomValues
// all work without a secure context, and a certificate for a LAN address is a
// step this measurement does not need. `navigator.storage.persist()` does need
// one; the page does not call it.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (!a.startsWith('--')) { continue; }
  const v = process.argv[i + 1];
  if (v === undefined || v.startsWith('--')) { args[a.slice(2)] = true; } else { args[a.slice(2)] = v; i++; }
}
const REPO = resolve(fileURLToPath(new URL('.', import.meta.url)), '..');
if (!args.fixture || !args['module-dir'] || !args.host) {
  const addrs = Object.values(networkInterfaces()).flat()
    .filter((n) => n && n.family === 'IPv4' && !n.internal).map((n) => n.address);
  console.log('usage: phone_timing.mjs --fixture PATH --module-dir DIR --host ADDR [--port N] ' +
              '[--count N] [--minutes M] [--out FILE] [--auto]');
  console.log(`addresses on this machine: ${addrs.join(', ') || '(none)'}`);
  process.exit(2);
}
const count = Number(args.count ?? 1);
const minutes = Number(args.minutes ?? 15);
const outFile = resolve(args.out ?? 'phone-timings.json');

const fx = spawn(resolve(args.fixture), [String(minutes * 60 + 30)], { stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((res, rej) => {
  let buf = '';
  fx.stdout.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { res(JSON.parse(buf.slice(0, nl))); } });
  fx.on('exit', (c) => rej(new Error(`fixture exited ${c}`)));
  setTimeout(() => rej(new Error('fixture never became ready')), 20000);
});

// Stopped from outside (a test's SIGTERM, or kill): take the fixture along,
// rather than leave it serving for --minutes more.
for (const sig of ['SIGTERM', 'SIGINT']) { process.on(sig, () => { fx.kill('SIGTERM'); process.exit(1); }); }

const invite = randomBytes(16).toString('hex');
let got = 0;
let finish;
const done = new Promise((r) => { finish = r; });
const { startSite } = await import(pathToFileURL(resolve(REPO, 'examples/site-node/server.mjs')).href);
const site = await startSite({
  authdSite: info.site, authdWs: `127.0.0.1:${info.ws_port}`, serverId: info.server_id,
  serverPub: Buffer.from(info.server_pub, 'hex'), moduleDir: args['module-dir'], invite,
  host: args.host, port: Number(args.port ?? 8099),
  onTiming: (t) => {
    const row = { at: new Date().toISOString(), ...t };
    appendFileSync(outFile, JSON.stringify(row) + '\n');
    const med = [...t.loginMs].sort((x, y) => x - y)[Math.floor(t.loginMs.length / 2)];
    console.log(`result ${++got}: seal ${t.sealMs.toFixed(1)} ms; logins ${t.loginMs.map((x) => x.toFixed(1)).join(', ')} ms ` +
                `(median ${med.toFixed(1)}); cores ${t.cores ?? '?'}; memory ${t.memoryGiB ?? '?'} GiB`);
    console.log(`          secure context: ${t.secure ? 'yes' : 'no'}; js loop ${t.jsLoopMs.toFixed(1)} ms`);
    console.log(`          ${t.ua}`);
    if (got >= count) { finish(); }
  },
});

const loopback = /^(localhost|.*\.localhost|127\.\d+\.\d+\.\d+|::1|\[::1\])$/i.test(args.host);
if (!loopback) {
  console.log(`note: http://${args.host} is not a secure context. Safari on a Mac runs such a page without its ` +
              'JIT (F119; iPhones, also WebKit, are unmeasured). For a browser on this machine use --host 127.0.0.1.');
}
console.log(`open on the phone:  http://${args.host}:${site.port}/timing.html#invite=${invite}${args.auto ? '&auto=1' : ''}`);
console.log(`then tap Measure. Results go to ${outFile}; stopping after ${count} result(s) or ${minutes} min.`);
const timer = setTimeout(() => { console.log('time is up'); finish(); }, minutes * 60 * 1000);
await done;
clearTimeout(timer);
site.server.close();
fx.kill('SIGTERM');
process.exit(got >= count ? 0 : 1);
