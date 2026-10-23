// V4-58: the reference site's session table, against the real daemon and the
// real wasm client (audit F131, F132).
//
//   node site_sessions.mjs FIXTURE MODULE.mjs REPO
//
// F131: the site kept a session id across a login. Each check below holds an
// id issued BEFORE a login, signup or recovery, and requires that it hold
// nothing afterwards.
//
// F132: the session table had no bound. The checks below require a cap on
// sessions nobody has logged into, idle expiry, and removal at logout.
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { pathToFileURL } from 'node:url';

const [fixturePath, modulePath, repo] = process.argv.slice(2);
if (!fixturePath || !modulePath || !repo) {
  console.log('usage: site_sessions.mjs FIXTURE MODULE.mjs REPO');
  process.exit(2);
}
let fail = 0;
const check = (ok, what) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${what}`); if (!ok) { fail = 1; } };
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => new TextEncoder().encode(s);
const PASS = 'correct horse battery staple';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const fx = spawn(fixturePath, ['120'], { stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  fx.stdout.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { resolve(JSON.parse(buf.slice(0, nl))); } });
  fx.on('exit', (c) => reject(new Error(`fixture exited ${c}`)));
  setTimeout(() => reject(new Error('fixture never became ready')), 20000);
});
const siteLine = (line) => new Promise((resolve, reject) => {
  const s = createConnection(info.site);
  let buf = '';
  s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { s.end(); resolve(buf.slice(0, nl)); } });
  s.on('error', reject);
  s.write(line + '\n');
});
const pkOf = (img) => img.slice(9 + img[8]);      // MLDSAPK1: magic(8) id_len(1) id pk

const servers = [];
try {
  const serverPub = Uint8Array.from(Buffer.from(info.server_pub, 'hex'));
  const { default: createMldsaClient } = await import(pathToFileURL(modulePath).href);
  const { AuthdClient } = await import(pathToFileURL(`${repo}/web/client/authd-client.mjs`).href);
  const { startSite } = await import(pathToFileURL(`${repo}/examples/site-node/server.mjs`).href);
  const client = await AuthdClient.load(createMldsaClient);
  const start = async (extra = {}) => {
    const st = await startSite({ authdSite: info.site, authdWs: `127.0.0.1:${info.ws_port}`, serverId: info.server_id,
                                 serverPub, moduleDir: `${repo}/web`, invite: 'the-invite', ...extra });
    servers.push(st.server);
    return st;
  };

  // A site, and a visitor with an enrolled key.
  const { port, sessions } = await start();
  const base = `http://127.0.0.1:${port}`;
  const idOf = (res, name = 'sid') => new RegExp(`(?:^|,\\s*)${name}=([0-9a-f]{64})`).exec(res.headers.get('set-cookie') || '')?.[1];
  const get = (path, sid) => fetch(`${base}${path}`, { headers: sid ? { Cookie: `sid=${sid}` } : {} });
  const post = (path, obj, sid) => fetch(`${base}${path}`, {
    method: 'POST', body: JSON.stringify(obj),
    headers: { ...(sid ? { Cookie: `sid=${sid}` } : {}), Origin: base, 'Content-Type': 'application/json' } });
  const user = 'victim';
  const vid = client.newIdentity(PASS);
  const enrolled = await siteLine(`ENROLL user=${hex(enc(user))} handle=${hex(enc(vid.handle))} pk=${hex(pkOf(vid.publicImage))} via=site`);
  check(enrolled.startsWith('OK fp='), 'setup: the visitor\'s key is enrolled');
  // Logs a key in through the site's own WebSocket and POSTs the code, as login.mjs does.
  const login = async (sid, id, pass) => {
    const st = await (await get('/api/session', sid)).json();
    const s = await client.login({ url: `ws://127.0.0.1:${port}/authd/v1?state=${st.state}`, serverId: info.server_id,
                                   serverPub, handle: id.handle, passphrase: pass, envelope: id.envelope });
    const code = Buffer.from(s.code).toString('base64url');      // before close(): it wipes s.code
    await s.close();
    return post('/api/login', { code }, sid);
  };

  // --- F131, step by step -------------------------------------------------
  // 1. The attacker gets an id from the site and puts it in the visitor's browser.
  const planted = idOf(await get('/api/session'));
  check(/^[0-9a-f]{64}$/.test(planted || ''), 'fixation: the site hands out an id to anyone (the id an attacker would plant)');
  // 2. The visitor logs in carrying it.
  const lr = await login(planted, vid, PASS);
  const fresh = idOf(lr);
  check(lr.status === 200 && fresh !== undefined && fresh !== planted,
        'fixation: a login answers with a NEW session id, not the one the browser came with');
  check((await get('/api/me', fresh)).status === 200, 'fixation: the new id is the logged-in session (the canary)');
  // 3. The attacker, holding only the planted id.
  check((await get('/api/me', planted)).status === 401,
        'fixation: the id issued before the login is NOT logged in after it');
  const rc = await post('/api/recovery-codes', {}, planted);
  check(rc.status === 401, 'fixation: the planted id cannot mint the visitor\'s recovery codes');
  check(!sessions.has(planted), 'fixation: the pre-login id is gone from the table, not just logged out');

  // A signup and a recovery change what a session may do, so each gets a new id
  // too: a planted id must not carry the visitor's new account or recovery
  // ticket to an attacker who then enrolls a key of their own.
  {
    const before = idOf(await get('/api/session'));
    const su = await post('/api/signup', { user: 'newcomer', invite: 'the-invite' }, before);
    const after = idOf(su);
    check(su.status === 200 && after !== undefined && after !== before, 'signup: answers with a new session id');
    const atk = client.newIdentity('an attacker passphrase, long enough');
    const en = await post('/api/enroll', { handle: atk.handle, pub: hex(atk.publicImage) }, before);
    check(en.status === 403, 'signup: the id from before the signup cannot enroll a key into the new account');
  }
  // V4-62 (the owner's decision): minting recovery codes needs a LOGIN -- the
  // device key and the passphrase -- not only a logged-in session.
  const stepUp = async (sid, id, pass) => {
    const st = await (await get('/api/session', sid)).json();
    const s = await client.login({ url: `ws://127.0.0.1:${port}/authd/v1?state=${st.state}`, serverId: info.server_id,
                                   serverPub, handle: id.handle, passphrase: pass, envelope: id.envelope });
    const code = Buffer.from(s.code).toString('base64url');      // before close(): it wipes s.code
    await s.close();
    return code;
  };
  let minted = [];
  {
    const bare = await post('/api/recovery-codes', {}, fresh);
    check(bare.status === 401, 'mint: a logged-in session alone cannot mint recovery codes -- a login is required');
    const other = client.newIdentity('another passphrase, long enough');
    const oe = await siteLine(`ENROLL user=${hex(enc('someone-else'))} handle=${hex(enc(other.handle))} pk=${hex(pkOf(other.publicImage))} via=site`);
    const ocode = await stepUp(fresh, other, 'another passphrase, long enough');
    const mo = await post('/api/recovery-codes', { code: ocode }, fresh);
    check(oe.startsWith('OK fp=') && mo.status === 403, 'mint: a login by another user does not mint this user\'s codes');
    const code = await stepUp(fresh, vid, PASS);
    const r = await post('/api/recovery-codes', { code }, fresh);
    minted = (await r.json()).codes || [];
    check(r.status === 200 && minted.length === 5, 'mint: a fresh login by the session\'s own user mints five codes (the canary)');
    await get('/api/session', fresh);                              // a new state: the replay below is refused by the daemon
    const again = await post('/api/recovery-codes', { code }, fresh);
    check(again.status === 403, 'mint: one login mints once -- its code cannot be replayed');
  }
  {
    const codes = minted;
    check(codes.length === 5, 'recovery: the visitor mints recovery codes on their own session (the canary)');
    const before = idOf(await get('/api/session'));
    const rv = await post('/api/recover', { user, code: codes[0] }, before);
    const after = idOf(rv);
    check(rv.status === 200 && after !== undefined && after !== before, 'recovery: spending a code answers with a new session id');
    const atk = client.newIdentity('an attacker passphrase, long enough');
    const en = await post('/api/enroll', { handle: atk.handle, pub: hex(atk.publicImage) }, before);
    check(en.status === 403, 'recovery: the id from before the recovery cannot use its ticket to enroll a key');
    const devices = await siteLine(`LIST-DEVICES user=${hex(enc(user))}`);
    check(devices.startsWith('OK count=1'), `recovery: the visitor still has exactly one device (${devices.split(' ').slice(0, 2).join(' ')})`);
  }

  // Logout forgets the session and the cookie.
  {
    const lo = await post('/api/logout', {}, fresh);
    check(lo.status === 200 && /(?:^|,\s*)sid=;\s*Max-Age=0/.test(lo.headers.get('set-cookie') || ''),
          'logout: the response tells the browser to forget the cookie');
    check(!sessions.has(fresh) && (await get('/api/me', fresh)).status === 401, 'logout: the session is gone from the table');
  }

  // --- the cookie ------------------------------------------------------------
  {
    const plain = (await get('/api/session')).headers.get('set-cookie') || '';
    check(/^sid=[0-9a-f]{64}; HttpOnly; SameSite=Strict; Path=\/$/.test(plain),
          'cookie: without --secure it is sid, HttpOnly, SameSite=Strict, Path=/ (tests run over http)');
    const { port: sp } = await start({ secure: true });
    const sb = `http://127.0.0.1:${sp}`;
    const r1 = await fetch(`${sb}/api/session`);
    const c1 = r1.headers.get('set-cookie') || '';
    check(/^__Host-sid=[0-9a-f]{64}; HttpOnly; SameSite=Strict; Path=\/; Secure$/.test(c1),
          'cookie: with --secure it is __Host-sid, Secure, Path=/ and no Domain -- no other host can plant it');
    const id1 = /__Host-sid=([0-9a-f]{64})/.exec(c1)[1];
    const r2 = await fetch(`${sb}/api/session`, { headers: { Cookie: `sid=${id1}` } });
    check(/^__Host-sid=/.test(r2.headers.get('set-cookie') || '') && !(r2.headers.get('set-cookie') || '').includes(id1),
          'cookie: with --secure a plain sid cookie is not accepted, even carrying a live id');
    const r3 = await fetch(`${sb}/api/session`, { headers: { Cookie: `__Host-sid=${id1}` } });
    check(r3.headers.get('set-cookie') === null, 'cookie: ...and __Host-sid carrying it is (the canary)');
  }

  // --- F132: a bounded table ------------------------------------------------
  {
    const { port: bp, sessions: bs } = await start({ maxAnonSessions: 50 });
    const bb = `http://127.0.0.1:${bp}`;
    // One visitor logged in before the flood.
    const pre = idOf(await fetch(`${bb}/api/session`));
    const st = await (await fetch(`${bb}/api/session`, { headers: { Cookie: `sid=${pre}` } })).json();
    const s = await client.login({ url: `ws://127.0.0.1:${bp}/authd/v1?state=${st.state}`, serverId: info.server_id,
                                   serverPub, handle: vid.handle, passphrase: PASS, envelope: vid.envelope });
    const code = Buffer.from(s.code).toString('base64url');
    await s.close();
    const li = await fetch(`${bb}/api/login`, { method: 'POST', body: JSON.stringify({ code }),
                                                headers: { Cookie: `sid=${pre}`, Origin: bb, 'Content-Type': 'application/json' } });
    const kept = idOf(li);
    check(li.status === 200 && kept !== undefined, 'bound: a visitor logs in before the flood (the canary)');
    for (let i = 0; i < 1000; i++) { await (await fetch(`${bb}/api/session`)).arrayBuffer(); }
    check(bs.size <= 51, `bound: 1,000 cookieless requests leave at most the cap plus the logged-in session (${bs.size} sessions)`);
    check((await fetch(`${bb}/api/me`, { headers: { Cookie: `sid=${kept}` } })).status === 200,
          'bound: the flood evicted no logged-in session');
  }
  {
    const { port: ip, sessions: is } = await start({ sessionIdleMs: 150 });
    const ib = `http://127.0.0.1:${ip}`;
    const old = idOf(await fetch(`${ib}/api/session`));
    const again = await fetch(`${ib}/api/session`, { headers: { Cookie: `sid=${old}` } });
    check(again.headers.get('set-cookie') === null, 'idle: a session used within its idle time is kept (the canary)');
    await sleep(400);
    const late = await fetch(`${ib}/api/session`, { headers: { Cookie: `sid=${old}` } });
    check(idOf(late) !== undefined && idOf(late) !== old && !is.has(old),
          'idle: a session idle past its limit is gone, and the visitor gets a new one');
  }

  // --- F136: a malformed request is the client's error, not the process's ----
  {
    // The site runs in a child process here: what F136 did was end the site's
    // process, and a check cannot report from a process that has ended.
    const CHILD = `
      const o = JSON.parse(process.env.SITE_CHILD);
      const { startSite } = await import(o.server);
      const { port } = await startSite({ authdSite: o.site, authdWs: o.ws, serverId: o.serverId,
                                         serverPub: Buffer.from(o.serverPub, 'hex'), moduleDir: o.moduleDir,
                                         invite: 'the-invite' });
      console.log(JSON.stringify({ port }));`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', CHILD], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, SITE_CHILD: JSON.stringify({
        server: pathToFileURL(`${repo}/examples/site-node/server.mjs`).href, site: info.site,
        ws: `127.0.0.1:${info.ws_port}`, serverId: info.server_id, serverPub: info.server_pub, moduleDir: `${repo}/web` }) } });
    let childErr = '';
    child.stderr.on('data', (d) => { childErr += d; });
    try {
      const cp = await new Promise((resolve, reject) => {
        child.stdout.once('data', (d) => resolve(JSON.parse(String(d)).port));
        child.on('exit', (c) => reject(new Error(`the site's child exited ${c} before it listened: ${childErr}`)));
      });
      const cb = `http://127.0.0.1:${cp}`;
      const alive = () => child.exitCode === null && child.signalCode === null;
      const raw = (path, payload) => fetch(`${cb}${path}`, {
        method: 'POST', body: payload, headers: { Origin: cb, 'Content-Type': 'application/json' } })
        .then((r) => r.status, (e) => `no response (${e.cause?.code || e.message})`);
      const rawUpgrade = (target) => new Promise((resolve) => {
        const u = createConnection(cp, '127.0.0.1');
        u.on('error', () => {});
        u.on('close', resolve);
        u.on('connect', () => u.write(`GET ${target} HTTP/1.1\r\nHost: 127.0.0.1:${cp}\r\n` +
                                      'Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n'));
        setTimeout(() => u.destroy(), 2000);
      });
      check((await fetch(`${cb}/api/session`)).status === 200, 'malformed: the site in its own process serves (the canary)');
      for (const [path, payload, want, what] of [
        ['/api/login', '{', 400, 'a body that is not JSON'],
        ['/api/login', 'null', 400, 'a JSON null'],
        ['/api/signup', '[1]', 400, 'a JSON array'],
        ['/api/recover', 'x'.repeat(20000), 413, 'a body over 16 KiB'],
      ]) {
        const got = await raw(path, payload);
        await sleep(100);
        check(got === want && alive(),
              `malformed: ${what}, POSTed to ${path}, is answered ${want} and the site lives (${got}${alive() ? '' : '; the site EXITED'})`);
      }
      for (const target of ['http://[', '//[::1']) {
        await rawUpgrade(target);
        await sleep(100);
        check(alive(), `malformed: an upgrade to ${JSON.stringify(target)}, which the URL parser refuses, is closed and the site lives`);
      }
      check(alive() && (await fetch(`${cb}/api/session`)).status === 200, 'malformed: the site still serves after all of them');
    } finally {
      child.kill('SIGKILL');
    }
  }
} catch (e) {
  check(false, `unexpected: ${e.stack || e}`);
} finally {
  for (const s of servers) { s.close(); s.closeAllConnections?.(); }
  fx.kill();
}
console.log(`${fail ? 'FAIL' : 'PASS'}: site_sessions`);
process.exit(fail);
