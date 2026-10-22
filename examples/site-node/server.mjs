/*
 * A reference SITE for the browser client (V4-13c) -- the site's code, not the
 * daemon's, like authd.mjs beside it. node:http only; no dependencies.
 *
 *   node server.mjs --authd-site /run/mldsa-authd/site.sock \
 *                   --authd-ws 127.0.0.1:8443   (or --authd-ws-unix /run/.../p.sock)
 *                   --server-id authd --server-pub server.pub \
 *                   --module-dir build-wasm/web --invite-file <0600 file> \
 *                   [--port 0] [--secure]
 *
 * --secure is REQUIRED behind a TLS proxy: it marks the cookie Secure and makes
 * the Origin check expect https://, which is what a browser sends there --
 * without it every POST is refused as cross-origin. The invite is read from a
 * file because argv is readable by every process on the host (spec 12's rule
 * for passphrases, applied to the site's own secret); --invite remains for
 * tests. Behind Caddy, /authd/v1 is routed to the daemon before it reaches
 * this process, so --authd-ws/--authd-ws-unix are used only without a proxy.
 *
 * (opt.host and opt.onTiming exist for tools/phone_timing.mjs only.)
 *
 * What it demonstrates, because a site gets each of these wrong at its peril:
 *
 *   * THE LOGIN CODE ARRIVES IN A REQUEST BODY (spec 14, erratum 34). The page
 *     POSTs it to /api/login on this origin; the code never appears in a URL,
 *     so never in a proxy log, a Referer or browser history. This server
 *     EXCHANGEs it over the local socket with the state it put in the session,
 *     and keeps the token SERVER-SIDE: page JavaScript never sees it.
 *   * THE STATE IS PER LOGIN. /api/session issues a fresh random `state` for the
 *     page to put in the WebSocket URL; the daemon binds it into the login code
 *     and EXCHANGE must present it (Req 5), so a code cannot be replayed into
 *     somebody else's session (login-CSRF).
 *   * EVERY POST MUST COME FROM THIS ORIGIN (the Origin header), on top of a
 *     SameSite=Strict, HttpOnly session cookie -- `__Host-sid` behind TLS.
 *   * A NEW SESSION ID AT EVERY CHANGE OF PRIVILEGE (a login, a signup, a
 *     recovery), and a BOUNDED session table (V4-58, audit F131 and F132; see
 *     the table's own comment below).
 *   * A STRICT CSP on every response. `'wasm-unsafe-eval'` is required for any
 *     page that compiles WebAssembly and allows nothing else; there is no
 *     inline script anywhere, and no eval.
 *   * The /authd/v1 WebSocket is proxied to the daemon here, the job Caddy does
 *     in production (deploy/Caddyfile.example), so the page is same-origin with
 *     its WebSocket in tests exactly as it is when deployed.
 *   * Enrollment is gated by the site's own account check -- here an invite
 *     secret, in a real site whatever it already uses -- because the site, not
 *     the daemon, decides who may have an account (spec 10.1).
 */
import http from 'node:http';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Authd, exchange, enroll, verify, logout, recoveryIssue, recoveryUse } from './authd.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const REPO = resolve(HERE, '..', '..');

export const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const MIME = { '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
               '.js': 'text/javascript; charset=utf-8', '.wasm': 'application/wasm',
               '.css': 'text/css; charset=utf-8' };

const FLAGS = new Set(['secure']);
function args(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) { continue; }
    const k = argv[i].slice(2);
    if (FLAGS.has(k)) { a[k] = true; } else { a[k] = argv[i + 1]; i++; }
  }
  return a;
}

export async function startSite(opt) {
  const sessions = new Map();       // sid -> { sid, seen, state, user, token, signupUser, ticket }, least recently used first
  const csp = opt.csp ?? CSP;
  const serverPubHex = Buffer.from(opt.serverPub).toString('hex');
  // Static roots: the pages, the transport, the wasm module. Nothing else is served.
  const ROOTS = {
    '/': join(REPO, 'web', 'pages'),
    '/client/': join(REPO, 'web', 'client'),
    '/module/': resolve(opt.moduleDir),
  };

  const withAuthd = async (fn) => {
    const a = new Authd(opt.authdSite);
    await a.connect();
    try { return await fn(a); } finally { a.close(); }
  };

  // The session table (V4-58, audit F131 and F132). What a site's sessions need,
  // which this one lacked:
  //   * A NEW ID AT EVERY CHANGE OF PRIVILEGE -- a login, a signup, a recovery
  //     -- with the old id dropped (session fixation, F131).
  //   * `__Host-sid` behind TLS: the prefix makes a browser accept the cookie
  //     only if it is Secure, host-only and Path=/. (Plain `sid` without
  //     --secure: the prefix needs Secure, and tests run over http.)
  //   * A BOUNDED TABLE (F132). An idle session expires, a logout removes its
  //     own, and sessions nobody has logged into are capped, the least
  //     recently used evicted first; logged-in sessions are never evicted. A
  //     visitor whose pre-login session is evicted under load simply starts
  //     the login again. A deployment also rate-limits per client in front of
  //     the site.
  const COOKIE = opt.secure ? '__Host-sid' : 'sid';
  const COOKIE_RE = new RegExp(`(?:^|;\\s*)${COOKIE}=([0-9a-f]{64})(?=;|$)`);
  const IDLE_MS = opt.sessionIdleMs ?? 30 * 60 * 1000;
  const MAX_ANON = opt.maxAnonSessions ?? 10000;
  let anon = 0;                     // sessions with no token: the ones the cap bounds

  const drop = (s) => {
    if (sessions.delete(s.sid) && !s.token) { anon--; }
  };
  const create = (res) => {
    const now = Date.now();
    // The table is in least-recently-used order, so the expired ones are at the
    // front: dropping them costs nothing per request that is not reclaimed.
    for (const old of sessions.values()) {
      if (now - old.seen <= IDLE_MS) { break; }
      drop(old);
    }
    if (anon >= MAX_ANON) {
      for (const old of sessions.values()) {
        if (anon < MAX_ANON) { break; }
        if (!old.token) { drop(old); }
      }
    }
    const sid = randomBytes(32).toString('hex');
    const s = { sid, seen: now, state: null, user: null, token: null, signupUser: null, ticket: null };
    sessions.set(sid, s);
    anon++;
    res.setHeader('Set-Cookie', `${COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/${opt.secure ? '; Secure' : ''}`);
    return s;
  };
  const session = (req, res) => {
    const m = COOKIE_RE.exec(req.headers.cookie || '');
    const s = m ? sessions.get(m[1]) : undefined;
    if (s && Date.now() - s.seen <= IDLE_MS) {
      sessions.delete(s.sid);         // to the back: most recently used
      sessions.set(s.sid, s);
      s.seen = Date.now();
      return s;
    }
    if (s) { drop(s); }
    return create(res);
  };
  // A new id for what the session is about to become; the old id is dropped
  // with everything it held (F131).
  const rotate = (res, s) => {
    drop(s);
    return create(res);
  };
  const authenticate = (s, user, token) => {
    if (!s.token) { anon--; }
    s.user = user;
    s.token = token;
  };
  // Forgets the session, and tells the browser to forget its cookie.
  const end = (res, s) => {
    drop(s);
    res.setHeader('Set-Cookie', `${COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/${opt.secure ? '; Secure' : ''}`);
  };

  const send = (res, code, body, type = 'application/json; charset=utf-8') => {
    res.writeHead(code, {
      'Content-Type': type, 'Content-Security-Policy': csp, 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };

  const body = (req) => new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (d) => { b += d; if (b.length > 16384) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch (e) { reject(e); } });
  });

  const api = {
    // Only for tools/phone_timing.mjs (V4-13d), and only when it asked: a
    // site without opt.onTiming has no such route. The page's numbers are
    // checked for shape and nothing else -- they are a measurement report
    // from a device the operator is holding, not an input to anything.
    ...(opt.onTiming ? { 'POST /api/timing': async (req, res) => {
      const t = await body(req);
      const num = (x) => typeof x === 'number' && Number.isFinite(x) && x >= 0 && x < 600000;
      // V4-26: `secure` (was the page a secure context?) and `jsLoopMs` (the
      // page's no-crypto JIT probe) are what make a row readable (F119), so a
      // row without them, or with them mistyped, is refused rather than kept.
      if (!num(t.sealMs) || !Array.isArray(t.loginMs) || t.loginMs.length < 1 || t.loginMs.length > 10 ||
          !t.loginMs.every(num) || typeof t.ua !== 'string' || t.ua.length > 512 ||
          typeof t.secure !== 'boolean' || !num(t.jsLoopMs)) {
        return send(res, 400, { error: 'malformed timing' });
      }
      opt.onTiming({ ua: t.ua, cores: Number.isInteger(t.cores) ? t.cores : null,
                     memoryGiB: num(t.memoryGiB) ? t.memoryGiB : null, sealMs: t.sealMs, loginMs: t.loginMs,
                     secure: t.secure, jsLoopMs: t.jsLoopMs });
      send(res, 200, { ok: true });
    } } : {}),
    // The page's starting point: a FRESH state for its next login, and the
    // server identity to pin (a real site would ship the pin in the page itself).
    'GET /api/session': async (req, res, s) => {
      s.state = randomBytes(16).toString('hex');
      send(res, 200, { state: s.state, serverId: opt.serverId, serverPub: serverPubHex,
                       user: s.user, signupUser: s.signupUser, recovering: !!s.ticket });
    },
    'POST /api/login': async (req, res, s) => {
      const { code } = await body(req);
      if (!s.state || typeof code !== 'string') { return send(res, 400, { error: 'no login in progress' }); }
      const state = s.state;
      s.state = null;               // one state, one login
      try {
        const r = await withAuthd((a) => exchange(a, code, state));
        authenticate(rotate(res, s), r.user, r.token);     // F131: a new id for the logged-in session
        send(res, 200, { user: r.user, handle: r.handle, role: r.role });
      } catch (e) { send(res, 403, { error: e.code || 'exchange-failed' }); }
    },
    'GET /api/me': async (req, res, s) => {
      if (!s.token) { return send(res, 401, { error: 'not logged in' }); }
      try { const r = await withAuthd((a) => verify(a, s.token)); send(res, 200, { user: r.user, handle: r.handle }); }
      catch (e) { end(res, s); send(res, 401, { error: e.code || 'verify-failed' }); }
    },
    'POST /api/logout': async (req, res, s) => {
      if (s.token) { try { await withAuthd((a) => logout(a, s.token)); } catch { /* already gone */ } }
      end(res, s);
      send(res, 200, { ok: true });
    },
    // The site's own account check. Here: an invite secret. A real site uses
    // whatever it already trusts (a verified e-mail, an admin approval...).
    'POST /api/signup': async (req, res, s) => {
      const { user, invite } = await body(req);
      if (typeof user !== 'string' || !/^[a-z0-9._-]{1,32}$/.test(user) || invite !== opt.invite) {
        return send(res, 403, { error: 'signup refused' });
      }
      rotate(res, s).signupUser = user;                    // F131: the account a planted id must not be able to claim
      send(res, 200, { user });
    },
    // The page generated the key; the site enrolls its PUBLIC half for the
    // account it has vouched for -- or, during recovery, with the ticket it
    // holds server-side.
    'POST /api/enroll': async (req, res, s) => {
      const { handle, pub } = await body(req);
      const user = s.ticket ? s.ticket.user : s.signupUser;
      if (!user || typeof handle !== 'string' || typeof pub !== 'string') { return send(res, 403, { error: 'nothing to enroll' }); }
      const img = Buffer.from(pub, 'hex');
      const pk = img.subarray(9 + img[8]);            // MLDSAPK1: magic(8) id_len(1) id pk
      try {
        await withAuthd((a) => enroll(a, { user, handle, pk, ticket: s.ticket ? s.ticket.ticket : undefined }));
        s.signupUser = null; s.ticket = null;
        send(res, 200, { user, handle });
      } catch (e) { send(res, 403, { error: e.code || 'enroll-failed' }); }
    },
    'POST /api/recovery-codes': async (req, res, s) => {
      if (!s.token) { return send(res, 401, { error: 'not logged in' }); }
      try { send(res, 200, { codes: await withAuthd((a) => recoveryIssue(a, s.user, 5)) }); }
      catch (e) { send(res, 403, { error: e.code || 'issue-failed' }); }
    },
    'POST /api/recover': async (req, res, s) => {
      const { user, code } = await body(req);
      try {
        const t = await withAuthd((a) => recoveryUse(a, user, code));
        rotate(res, s).ticket = { user, ticket: t.ticket };  // stays on the server, under a new id (F131)
        send(res, 200, { user });
      } catch (e) { send(res, 403, { error: e.code || 'recover-failed' }); }
    },
  };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      if (req.method === 'POST') {
        const origin = req.headers.origin;
        const self = `${opt.secure ? 'https' : 'http'}://${req.headers.host}`;
        if (origin !== self) { return send(res, 403, { error: 'cross-origin POST refused' }); }
      }
      const route = api[`${req.method} ${url.pathname}`];
      if (route) { return route(req, res, session(req, res)); }
      if (req.method !== 'GET') { return send(res, 405, { error: 'method' }); }
      if (url.pathname === '/') { res.writeHead(302, { Location: '/login.html' }); return res.end(); }
      for (const [prefix, root] of Object.entries(ROOTS).sort((x, y) => y[0].length - x[0].length)) {
        if (!url.pathname.startsWith(prefix)) { continue; }
        const path = normalize(join(root, url.pathname.slice(prefix.length)));
        if (!path.startsWith(root + sep) || !MIME[extname(path)]) { break; }
        try { return send(res, 200, await readFile(path), MIME[extname(path)]); } catch { break; }
      }
      send(res, 404, { error: 'not found' });
    } catch (e) {
      send(res, 500, { error: 'internal' });
    }
  });

  // The WebSocket to the daemon, proxied byte for byte after the upgrade
  // request -- Caddy's job in production.
  server.on('upgrade', (req, sock, head) => {
    if (!new URL(req.url, 'http://x').pathname.startsWith('/authd/v1')) { sock.destroy(); return; }
    const up = opt.authdWsUnix ? net.connect(opt.authdWsUnix)
                               : net.connect(Number(opt.authdWs.split(':')[1]), opt.authdWs.split(':')[0]);
    up.on('connect', () => {
      let h = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (let i = 0; i < req.rawHeaders.length; i += 2) { h += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`; }
      up.write(h + '\r\n');
      if (head && head.length) { up.write(head); }
      up.pipe(sock); sock.pipe(up);
    });
    up.on('error', () => sock.destroy());
    sock.on('error', () => up.destroy());
  });

  // Loopback unless told otherwise; only the phone timing tool says otherwise.
  await new Promise((r) => server.listen(opt.port ?? 0, opt.host ?? '127.0.0.1', r));
  return { server, port: server.address().port, sessions };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const a = args(process.argv.slice(2));
  const pubImage = readFileSync(a['server-pub']);
  const invite = a['invite-file'] ? readFileSync(a['invite-file'], 'utf8').replace(/\r?\n$/, '') : a.invite;
  if (!invite) { console.error('server.mjs: --invite-file is required'); process.exit(2); }
  const { port } = await startSite({
    authdSite: a['authd-site'], authdWs: a['authd-ws'], authdWsUnix: a['authd-ws-unix'],
    serverId: a['server-id'], serverPub: pubImage, moduleDir: a['module-dir'], invite,
    port: a.port ? Number(a.port) : 0, secure: a.secure === true,
  });
  console.log(JSON.stringify({ port }));
}
