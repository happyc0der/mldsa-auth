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
import { readFileSync } from 'node:fs';
import { createConnection, createServer } from 'node:net';
import { dirname, join } from 'node:path';
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
  const { startSite, limiterKey } = await import(pathToFileURL(`${repo}/examples/site-node/server.mjs`).href);
  // V4-78, F155: the recovery limiter keys an IPv6 client on its /64, so one
  // subscriber's prefix is one bucket, and an IPv4-mapped address on its IPv4.
  { const cases = [['203.0.113.7', '203.0.113.7'], ['::ffff:203.0.113.7', '203.0.113.7'],
                   ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'], ['2001:db8:1:2::9', '2001:db8:1:2::/64'],
                   ['2001:DB8:0001:0002:ffff::1', '2001:db8:1:2::/64'], ['[2001:db8::1]', '2001:db8:0:0::/64'],
                   ['fe80::1%en0', 'fe80:0:0:0::/64'], ['garbage', '?'], ['', '?']];
    const bad = cases.filter(([i, w]) => limiterKey(i) !== w);
    check(bad.length === 0, `limiter: ${cases.length - bad.length}/${cases.length} addresses keyed as expected` +
          (bad.length ? ` (wrong: ${bad.map(([i]) => i).join(', ')})` : '')); }
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

  // V4-96, F166: a refused login answers one word, whatever the daemon's reason.
  {
    const s0 = idOf(await get('/api/session'));
    const st = await (await get('/api/session', s0)).json();
    const ls = await client.login({ url: `ws://127.0.0.1:${port}/authd/v1?state=${st.state}`, serverId: info.server_id,
                                    serverPub, handle: vid.handle, passphrase: PASS, envelope: vid.envelope });
    const code = Buffer.from(ls.code).toString('base64url');
    await ls.close();
    const first = await post('/api/login', { code }, s0);
    const s1 = idOf(first);
    check(first.status === 200 && s1 !== undefined, 'refusal: a login code logs in once (the canary)');
    await get('/api/session', s1);                     // a fresh state for the second try
    const again = await post('/api/login', { code }, s1);
    const ab = await again.json();
    check(again.status === 403 && ab.error === 'login-failed' && Object.keys(ab).length === 1,
          `refusal: the same code again is refused as login-failed, and nothing more (${again.status} ${JSON.stringify(ab)}) (F166)`);
  }

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

  // V4-84, F160: a WebSocket upgrade from another origin is refused; the
  // site's own origin, and a client that sends no Origin, are upgraded.
  {
    const upgradeStatus = (origin, host = `127.0.0.1:${port}`) => new Promise((resolve) => {
      const c = createConnection(port, '127.0.0.1');
      let buf = '';
      c.on('data', (d) => { buf += d; const nl = buf.indexOf('\r\n'); if (nl >= 0) { c.destroy(); resolve(Number(buf.split(' ')[1])); } });
      c.on('error', () => resolve(-1));
      c.on('close', () => resolve(Number(buf.split(' ')[1]) || -1));
      c.write(`GET /authd/v1?state=00 HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
              'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n' +
              (origin ? `Origin: ${origin}\r\n` : '') + '\r\n');
    });
    const foreign = await upgradeStatus('http://attacker.example');
    const own = await upgradeStatus(`http://127.0.0.1:${port}`);
    const none = await upgradeStatus(null);
    check(foreign === 403 && own === 101 && none === 101,
          `ws: a foreign Origin is refused, the site's own and none are upgraded (${foreign}, ${own}, ${none}) (F160)`);
    // V4-88, F177: a DNS-rebinding page sends Host and Origin both naming
    // itself, which the Origin check alone passes.
    const rebound = await upgradeStatus(`http://rebind.example:${port}`, `rebind.example:${port}`);
    const local = await upgradeStatus(`http://localhost:${port}`, `localhost:${port}`);
    check(rebound === 403 && local === 101,
          `ws: a rebound Host is refused, localhost is upgraded (${rebound}, ${local}) (F177)`);
  }

  // V4-130, F214: a login code that is not 32 bytes is a refused login. The
  // site answered it 503 `unavailable` -- the daemon being away -- because the
  // conversion threw an error that was not one of the daemon's refusals.
  {
    const offer = async (code) => {
      const sid = idOf(await get('/api/session'));
      const r = await post('/api/login', { code }, sid);
      return `${r.status} ${await r.text()}`;
    };
    const refused = '403 {"error":"login-failed"}';
    const unknown = await offer(Buffer.alloc(32, 7).toString('base64url'));
    check(unknown === refused, `code: a well-formed code the daemon never issued is ${refused} (the canary) (${unknown})`);
    for (const [what, code] of [['one character', 'x'], ['the empty string', ''],
                                ['31 bytes', Buffer.alloc(31, 7).toString('base64url')],
                                ['33 bytes', Buffer.alloc(33, 7).toString('base64url')],
                                ['64 hex digits', '07'.repeat(32)]]) {
      const got = await offer(code);
      check(got === refused, `code: a login code of ${what} is ${refused}, not the daemon being away (${got}) (F214)`);
    }
    // The same conversion serves the second login that mints recovery codes.
    const lr2 = await login(idOf(await get('/api/session')), vid, PASS);
    const sid2 = idOf(lr2);
    await get('/api/session', sid2);
    const rc = await post('/api/recovery-codes', { code: 'x' }, sid2);
    const rcGot = `${rc.status} ${await rc.text()}`;
    check(lr2.status === 200 && rcGot === refused,
          `code: a malformed code offered for recovery codes is ${refused} (${rcGot}) (F214)`);
    check((await get('/api/me', sid2)).status === 200, 'code: and the session that offered it is kept (F214)');
  }

  // V4-88, F177: the HTTP routes refuse a Host that is neither an IP literal,
  // localhost, nor the site's own name; Origin agreeing with it does not help.
  {
    const { hostAllowed } = await import(pathToFileURL(`${repo}/examples/site-node/server.mjs`).href);
    const cases = [['127.0.0.1:1', {}, true], ['[::1]:1', {}, true], ['localhost:1', {}, true],
                   ['a.localhost', {}, true], ['rebind.example:1', {}, false], ['', {}, false],
                   ['localhost.rebind.example', {}, false], ['127.0.0.1.rebind.example', {}, false],
                   ['rebind.example', { trustProxy: true }, true], ['mac.ts.net:8099', { host: 'mac.ts.net' }, true],
                   ['rebind.example', { host: 'mac.ts.net' }, false], ['a.example', { hostNames: ['A.example'] }, true]];
    const bad = cases.filter(([h, o, w]) => hostAllowed(h, o) !== w);
    check(bad.length === 0, `host: ${cases.length - bad.length}/${cases.length} Host values classified as expected` +
          (bad.length ? ` (wrong: ${bad.map(([h]) => JSON.stringify(h)).join(', ')})` : '') + ' (F177)');
    const { request } = await import('node:http');
    const rawPost = (host) => new Promise((resolve) => {
      const r = request({ host: '127.0.0.1', port, path: '/api/recover', method: 'POST',
                          headers: { Host: host, Origin: `http://${host}`, 'Content-Type': 'application/json' } },
                        (x) => { x.resume(); x.on('end', () => resolve(x.statusCode)); });
      r.on('error', () => resolve(-1));
      r.end(JSON.stringify({ user: 'nobody', code: 'x' }));
    });
    const reb = await rawPost(`rebind.example:${port}`);
    check(reb === 421, `http: a POST whose Host and Origin both name a rebound page is refused, 421 (${reb}) (F177)`);
  }

  // V4-76, F143: /api/recover gives every refusal ONE reply, so it does not say
  // which usernames exist; and it is rate-limited per client.
  {
    const ghost = await post('/api/recover', { user: 'nobody-by-this-name', code: '0000000000000000' });
    const wrong = await post('/api/recover', { user, code: '0000000000000000' });
    const gb = await ghost.json(), wb = await wrong.json();
    check(ghost.status === 403 && wrong.status === 403 && gb.error === 'recover-failed' && wb.error === 'recover-failed',
          `recover: an unknown user and a wrong code get the same reply (${gb.error}, ${wb.error})`);
    const lim = await start({ recoverBurst: 2, recoverRefillMs: 60 * 60 * 1000 });
    const lbase = `http://127.0.0.1:${lim.port}`;
    const lpost = (obj) => fetch(`${lbase}/api/recover`, { method: 'POST', body: JSON.stringify(obj),
                                                           headers: { Origin: lbase, 'Content-Type': 'application/json' } });
    const st = [];
    for (let i = 0; i < 3; i++) { st.push((await lpost({ user: 'nobody-by-this-name', code: '0000000000000000' })).status); }
    check(st[0] === 403 && st[1] === 403 && st[2] === 429, `recover: the third attempt past a burst of two is 429 (${st.join(', ')})`);
    // V4-79, F159: behind a proxy the key is the RIGHTMOST X-Forwarded-For
    // entry, the proxy's; a client rotating the entries it prepends stays in
    // its own bucket.
    const tp = await start({ recoverBurst: 2, recoverRefillMs: 60 * 60 * 1000, trustProxy: true });
    const tbase = `http://127.0.0.1:${tp.port}`;
    const tst = [];
    for (let i = 0; i < 3; i++) {
      tst.push((await fetch(`${tbase}/api/recover`, { method: 'POST',
        body: JSON.stringify({ user: 'nobody-by-this-name', code: '0000000000000000' }),
        headers: { Origin: tbase, 'Content-Type': 'application/json',
                   'X-Forwarded-For': `198.51.100.${i + 1}, 203.0.113.9` } })).status);
    }
    check(tst[2] === 429, `recover: a client rotating the X-Forwarded-For entries it prepends is still limited (${tst.join(', ')})`);
  }

  // V4-129, F212: the invite is the site's signup secret and was compared with
  // `!==`, which stops at the first differing character. The comparison is
  // now of two SHA-256 digests in constant time. Timing is not measured here
  // (a test cannot time one comparison through HTTP); what is checked is every
  // way the new comparison could accept or throw where the old one refused.
  {
    const wrong = [
      ['the same length, last character wrong', 'the-invitf'],
      ['the same length, first character wrong', 'uhe-invite'],
      ['a prefix', 'the-invit'],
      ['the invite and one more character', 'the-invite0'],
      ['empty', ''],
      ['a number', 7],
      ['null', null],
      ['an array holding it', ['the-invite']],
      ['an object', { length: 10 }],
      ['absent', undefined],
    ];
    for (const [what, invite] of wrong) {
      const r = await post('/api/signup', { user: 'guesser', invite });
      const t = await r.text();
      check(r.status === 403 && t === '{"error":"signup refused"}',
            `invite: ${what} is refused as any other (${r.status} ${t}) (F212)`);
    }
    const ok = await post('/api/signup', { user: 'guesser', invite: 'the-invite' });
    check(ok.status === 200, `invite: the invite itself is accepted (${ok.status}) (the canary)`);
    // A site given no invite: the old comparison was undefined !== undefined,
    // so a signup offering none was accepted. It must not start at all.
    for (const [what, inv] of [['no invite', undefined], ['an empty invite', ''], ['a non-string invite', 7]]) {
      let outcome = 'refused to start';
      try {
        const st = await start({ invite: inv });
        const r = await fetch(`http://127.0.0.1:${st.port}/api/signup`, { method: 'POST',
          headers: { 'content-type': 'application/json', origin: `http://127.0.0.1:${st.port}` },
          body: JSON.stringify({ user: 'anyone' }) });
        outcome = `started, and a signup offering no invite answered ${r.status}`;
      } catch (e) { if (!/invite is required/.test(String(e.message))) { outcome = `threw ${e.message}`; } }
      check(outcome === 'refused to start', `invite: a site given ${what} ${outcome} (F212)`);
    }
    const src = readFileSync(join(repo, 'examples/site-node/server.mjs'), 'utf8');
    const direct = src.split('\n').filter((l) => !/^\s*(\/\/|\*)/.test(l) && /\b(invite|offered)\b\s*[!=]==\s*(?!''|'string')['\w.]|[!=]==\s*(opt\.)?(invite|offered)\b/.test(l));
    check(direct.length === 0 && /timingSafeEqual/.test(src),
          `invite: the site compares it in constant time, never with === or !== (${direct.length} direct comparison(s)) (F212)`);
  }

  // V4-76, F145: a signup naming an EXISTING user cannot add a device to it.
  {
    const su = await post('/api/signup', { user, invite: 'the-invite' });
    const sid = idOf(su);
    check(su.status === 200 && sid !== undefined, 'signup: the invite passes the site\'s check (the canary)');
    const atk = client.newIdentity('an attacker passphrase, long enough');
    const en = await post('/api/enroll', { handle: atk.handle, pub: hex(atk.publicImage) }, sid);
    const eb = await en.json();
    check(en.status === 403 && eb.error === 'user-exists', `signup: enrolling into an existing account is refused (${en.status} ${eb.error})`);
    const devices = await siteLine(`LIST-DEVICES user=${hex(enc(user))}`);
    check(devices.startsWith('OK count=1'), 'signup: the existing account still has exactly one device');
  }

  // Logout forgets the session and the cookie.
  {
    const lo = await post('/api/logout', {}, fresh);
    check(lo.status === 200 && /(?:^|,\s*)sid=;\s*Max-Age=0/.test(lo.headers.get('set-cookie') || ''),
          'logout: the response tells the browser to forget the cookie');
    check(!sessions.has(fresh) && (await get('/api/me', fresh)).status === 401, 'logout: the session is gone from the table');
  }

  // V4-127, F210: the daemon being away is not the daemon refusing a token.
  // The site reaches the daemon through a relay here, which can be taken
  // down (no socket), made to hang (accepts, never answers) or made to drop
  // every connection -- what a daemon restart looks like from the site.
  {
    const relayPath = join(dirname(info.site), 'relay.sock');
    let mode = 'up';
    const held = new Set();
    const relay = createServer((c) => {
      held.add(c);
      c.on('close', () => held.delete(c));
      c.on('error', () => {});
      if (mode === 'drop') { c.destroy(); return; }
      if (mode === 'hang') { return; }
      const u = createConnection(info.site);
      u.on('error', () => c.destroy());
      c.on('close', () => u.destroy());
      c.pipe(u); u.pipe(c);
    });
    const up = () => new Promise((r) => relay.listen(relayPath, r));
    const down = () => new Promise((r) => { relay.close(r); for (const c of held) { c.destroy(); } });
    await up();
    try {
      const o = await start({ authdSite: relayPath, authdTimeoutMs: 400 });
      const ob = `http://127.0.0.1:${o.port}`;
      const oget = (path, sid) => fetch(`${ob}${path}`, { headers: sid ? { Cookie: `sid=${sid}` } : {} });
      const opost = (path, obj, sid) => fetch(`${ob}${path}`, {
        method: 'POST', body: JSON.stringify(obj),
        headers: { ...(sid ? { Cookie: `sid=${sid}` } : {}), Origin: ob, 'Content-Type': 'application/json' } });
      const ocode = async (sid) => {
        const st = await (await oget('/api/session', sid)).json();
        const s = await client.login({ url: `ws://127.0.0.1:${o.port}/authd/v1?state=${st.state}`, serverId: info.server_id,
                                       serverPub, handle: vid.handle, passphrase: PASS, envelope: vid.envelope });
        const code = Buffer.from(s.code).toString('base64url');
        await s.close();
        return code;
      };
      const s0 = idOf(await oget('/api/session'));
      const li = await opost('/api/login', { code: await ocode(s0) }, s0);
      const sid = idOf(li);
      check(li.status === 200 && sid !== undefined && (await oget('/api/me', sid)).status === 200,
            'outage: a visitor logs in through the relay and /api/me answers 200 (the canary)');
      // What every outage must look like: 503 `unavailable`, nothing else in
      // the body, the cookie untouched and the session still in the table.
      const away = async (what) => {
        const t0 = Date.now();
        let r;
        try { r = await fetch(`${ob}/api/me`, { headers: { Cookie: `sid=${sid}` }, signal: AbortSignal.timeout(10000) }); }
        catch (e) { check(false, `outage: ${what}: /api/me gave no answer in 10 s (${e.name}) (F210)`); return Date.now() - t0; }
        const b = await r.json();
        check(r.status === 503 && b.error === 'unavailable' && Object.keys(b).length === 1,
              `outage: ${what}: /api/me answers 503 unavailable and nothing more (${r.status} ${JSON.stringify(b)}) (F210)`);
        check(r.headers.get('set-cookie') === null && typeof o.sessions.get(sid)?.token === 'string',
              `outage: ${what}: the session and its cookie are kept (F210)`);
        return Date.now() - t0;
      };
      await down();
      await away('the daemon\'s socket is gone');
      // The other routes say `unavailable` too, not a refusal and not Node's
      // error name.
      {
        const su = await opost('/api/signup', { user: 'during-outage', invite: 'the-invite' });
        const id2 = client.newIdentity('a passphrase for the outage leg');
        const en = await opost('/api/enroll', { handle: id2.handle, pub: hex(id2.publicImage) }, idOf(su));
        const eb = await en.json();
        check(en.status === 503 && eb.error === 'unavailable',
              `outage: an enrollment while the daemon is away is 503 unavailable (${en.status} ${JSON.stringify(eb)}) (F210)`);
        const rv = await opost('/api/recover', { user, code: '0000000000000000' });
        const rb = await rv.json();
        check(rv.status === 503 && rb.error === 'unavailable',
              `outage: a recovery while the daemon is away is 503 unavailable (${rv.status} ${JSON.stringify(rb)}) (F210)`);
      }
      await up();
      {
        // A login whose code the site could not exchange: 503, and the code
        // was never shown to the daemon.
        const s1 = idOf(await oget('/api/session'));
        const code = await ocode(s1);
        await down();
        const lr2 = await opost('/api/login', { code }, s1);
        const lb = await lr2.json();
        check(lr2.status === 503 && lb.error === 'unavailable',
              `outage: a login while the daemon is away is 503 unavailable (${lr2.status} ${JSON.stringify(lb)}) (F210)`);
        await up();
      }
      mode = 'drop';
      await away('the daemon closes the connection (a restart mid-request)');
      mode = 'hang';
      const took = await away('the daemon accepts and never answers');
      check(took >= 300 && took < 5000, `outage: a daemon that never answers is given up on (${took} ms against a 400 ms limit) (F210)`);
      for (const c of held) { c.destroy(); }
      mode = 'up';
      const back = await oget('/api/me', sid);
      check(back.status === 200 && back.headers.get('set-cookie') === null,
            `outage: the daemon back, the same cookie is logged in again (${back.status}) (F210)`);
      {
        // Minting recovery codes: the fresh login's code cannot be exchanged.
        const code = await ocode(sid);
        await down();
        const mr = await opost('/api/recovery-codes', { code }, sid);
        const mb = await mr.json();
        check(mr.status === 503 && mb.error === 'unavailable' && o.sessions.has(sid),
              `outage: minting recovery codes while the daemon is away is 503 unavailable (${mr.status} ${JSON.stringify(mb)}) (F210)`);
        await up();
      }
      // The canary for all of the above: when the DAEMON says the token is
      // dead, the session does end.
      const lo = await siteLine(`LOGOUT token=${o.sessions.get(sid)?.token}`);
      const dead = await oget('/api/me', sid);
      const db = await dead.json();
      check(lo.startsWith('OK') && dead.status === 401 && db.error === 'unknown' && !o.sessions.has(sid) &&
            /(?:^|,\s*)sid=;\s*Max-Age=0/.test(dead.headers.get('set-cookie') || ''),
            `outage: a token the daemon refuses still ends the session and the cookie (${dead.status} ${JSON.stringify(db)}) (the canary)`);
    } finally {
      await down().catch(() => {});
    }
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
    // V4-132, F215: two more visitors, neither logged in, each holding
    // something the flood must not take: a recovery ticket (the single-use
    // code behind it is already spent) and a signup the site has vouched for.
    const bpost = (path, obj, sid) => fetch(`${bb}${path}`, {
      method: 'POST', body: JSON.stringify(obj),
      headers: { ...(sid ? { Cookie: `sid=${sid}` } : {}), Origin: bb, 'Content-Type': 'application/json' } });
    const bsess = async (sid) => {
      const r = await fetch(`${bb}/api/session`, { headers: { Cookie: `sid=${sid}` } });
      return { ...(await r.json()), reissued: r.headers.get('set-cookie') !== null };
    };
    const rv = await bpost('/api/recover', { user, code: minted[1] });
    const recovering = idOf(rv);
    const su = await bpost('/api/signup', { user: 'mid-signup', invite: 'the-invite' });
    const signing = idOf(su);
    check(rv.status === 200 && su.status === 200 && (await bsess(recovering)).recovering === true &&
          (await bsess(signing)).signupUser === 'mid-signup',
          `bound: before the flood one visitor holds a recovery ticket and one a vouched signup (the canary) (${rv.status}, ${su.status})`);
    for (let i = 0; i < 1000; i++) { await (await fetch(`${bb}/api/session`)).arrayBuffer(); }
    { const r = await bsess(recovering);
      check(r.recovering === true && !r.reissued,
            `bound: the flood did not evict the session holding a recovery ticket (recovering=${r.recovering}, new cookie=${r.reissued}) (F215)`);
      const g = await bsess(signing);
      check(g.signupUser === 'mid-signup' && !g.reissued,
            `bound: the flood did not evict the session holding a vouched signup (signupUser=${g.signupUser}, new cookie=${g.reissued}) (F215)`); }
    check(bs.size <= 51, `bound: 1,000 cookieless requests leave at most the cap plus the logged-in session (${bs.size} sessions)`);
    check((await fetch(`${bb}/api/me`, { headers: { Cookie: `sid=${kept}` } })).status === 200,
          'bound: the flood evicted no logged-in session');
    // Holding something is not a way round the cap: an invite's holder can
    // make as many vouched sessions as they like, and the table stays bounded.
    for (let i = 0; i < 200; i++) { await (await bpost('/api/signup', { user: `flood-${i}`, invite: 'the-invite' })).arrayBuffer(); }
    check(bs.size <= 51, `bound: 200 vouched signups leave at most the cap plus the logged-in session (${bs.size} sessions) (F215)`);
    check((await fetch(`${bb}/api/me`, { headers: { Cookie: `sid=${kept}` } })).status === 200,
          'bound: and they evicted no logged-in session (F215)');
    { const r = await bsess(recovering);
      check(r.recovering === true && !r.reissued,
            `bound: nor the session holding a recovery ticket, which an invite does not buy (recovering=${r.recovering}, new cookie=${r.reissued}) (F215)`); }
    // A table full of tickets is still bounded. Fifty recovery codes are not
    // to hand, so every session not logged in is given a ticket in the table
    // itself, which startSite returns for this.
    for (const x of bs.values()) { if (!x.token) { x.ticket = { user: 'x', ticket: '00' }; x.signupUser = null; } }
    for (let i = 0; i < 20; i++) { await (await fetch(`${bb}/api/session`)).arrayBuffer(); }
    check(bs.size <= 51, `bound: with every session holding a ticket, 20 more requests still leave the cap (${bs.size} sessions) (F215)`);
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
      // V4-130, F213: a refused upgrade is answered 403 on a socket that had no
      // 'error' listener, so a client that reset the connection after reading
      // the refusal ended the site's process (ECONNRESET, uncaught). And the
      // site only half-closed that socket: a client that never closed its own
      // half held it open for as long as it liked.
      const refusedUpgrade = (headers, then) => new Promise((resolve) => {
        const u = createConnection({ port: cp, host: '127.0.0.1', allowHalfOpen: true });
        let buf = '';
        let done = false;
        let seen = false;
        const finish = (v) => { if (!done) { done = true; u.destroy(); resolve(v); } };
        u.on('error', (e) => finish(`error ${e.code}`));
        u.on('close', () => finish('closed'));
        u.on('data', (d) => {
          buf += d;
          if (buf.includes('\r\n\r\n') && !seen) { seen = true; then(u, Number(buf.split(' ')[1]), finish); }
        });
        u.on('connect', () => u.write(`GET /authd/v1?state=00 HTTP/1.1\r\n${headers}` +
                                      'Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n'));
        setTimeout(() => finish('no answer in 5 s'), 5000);
      });
      for (const [what, headers] of [
        ['a foreign Origin', `Host: 127.0.0.1:${cp}\r\nOrigin: http://attacker.example\r\n`],
        ['a rebound Host', `Host: rebind.example:${cp}\r\n`],
      ]) {
        const st = await refusedUpgrade(headers, (u, status, finish) => { u.resetAndDestroy(); finish(status); });
        await sleep(300);
        check(st === 403 && alive(),
              `malformed: an upgrade refused for ${what}, then reset by the client, leaves the site alive (${st}${alive() ? '' : '; the site EXITED'}) (F213)`);
      }
      if (alive()) {
        // The client keeps its half open and writes 1.5 s after the refusal: a
        // site that has closed the socket answers that write with a reset.
        const t0 = Date.now();
        const held = await refusedUpgrade(`Host: 127.0.0.1:${cp}\r\nOrigin: http://attacker.example\r\n`, (u, status, finish) => {
          const poke = () => { if (!u.destroyed) { u.write('x'); setTimeout(poke, 250); } };
          setTimeout(poke, 1500);
          setTimeout(() => finish(`still open ${Date.now() - t0} ms after the ${status}`), 4000);
        });
        check(/^(error (ECONNRESET|EPIPE)|closed)$/.test(held) && alive(),
              `malformed: a refused upgrade's socket is closed by the site, whatever the client does (${held}) (F213)`);
      } else {
        check(false, 'malformed: a refused upgrade\'s socket is closed by the site (not run: the site had exited) (F213)');
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
