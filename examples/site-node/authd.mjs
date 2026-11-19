/*
 * Reference site handler for mldsa-authd (V4-9a), spec mldsa-authd §8.
 *
 * This is the SITE's code, not the daemon's -- which is why it lives under
 * examples/ rather than apps/. Copy it, or read it and write your own; the
 * protocol is deliberately small enough that either is reasonable.
 *
 * What the site actually does:
 *
 *   1. The browser (or the operator's CLI) completes the PQ handshake with the
 *      daemon and receives a single-use LOGIN CODE. That is all it ever gets.
 *   2. The site receives that code through its own form/endpoint and calls
 *      exchange(code, state) HERE, over the local socket.
 *   3. It gets back an opaque TOKEN, which it stores in its own server-side
 *      session. The token never reaches browser JavaScript.
 *
 * The consequence worth understanding: an XSS that steals the login code
 * cannot exchange it, because EXCHANGE is only reachable from the local
 * socket, which the browser has no path to.
 */
import net from 'node:net';
import { Buffer } from 'node:buffer';

/** Commands whose reply is a list terminated by an `END` line.
 *  The response prefix alone cannot tell you: REVOKE-TOKENS also answers
 *  `OK count=N`, as a single line. The CALLER knows which command it sent, so
 *  that is what decides. */
const LIST_COMMANDS = new Set(['LIST-DEVICES', 'LIST-USERS', 'AUDIT-TAIL']);

const MAX_LINE = 8192;

const hex = (b) => Buffer.from(b).toString('hex');

/** The client receives its login code as base64url (spec §13); the socket
 *  speaks hex. Converting here keeps the protocol single-encoding: one
 *  decoder in the daemon, and therefore one decoder to fuzz. */
export function codeToHex(codeBase64url) {
  // Exactly the 43 characters the client prints, and a string (F536): the
  // decoder skips what is outside its alphabet, so a code with spaces, with
  // `+/=`, or an array of 32 numbers each passed as the same code, and a
  // non-string threw a TypeError the site reads as the daemon being away.
  if (typeof codeBase64url !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(codeBase64url)) {
    throw new AuthdError('bad-request-field');
  }
  const b = Buffer.from(codeBase64url, 'base64url');
  if (b.length !== 32) {
    // The caller's input is at fault, not the daemon: an AuthdError, as for
    // every other value this module refuses to send (V4-130, F214). A plain
    // Error here was read by the site as the daemon being away.
    throw new AuthdError('bad-request-field');
  }
  return b.toString('hex');
}

export class AuthdError extends Error {
  constructor(code) {
    super(`authd: ${code}`);
    this.code = code;          // the spec §8 error name, e.g. 'state-mismatch'
  }
}

export class Authd {
  #sock;
  #buf = '';
  #queue = [];
  // Whether a request can still be answered (V4-175, F249). False before
  // connect() and from the moment the connection is closed from either end.
  #open = false;

  constructor(socketPath) {
    this.socketPath = socketPath;
  }

  async connect() {
    // One connection per object at a time (F532). A second connect() left
    // the first socket's listeners attached: its 'close' failed requests in
    // flight on the second, and bytes the first had left unread were taken
    // for the replies to the second's requests.
    if (this.#sock && !this.#sock.destroyed) {
      throw new AuthdError('already-connected');
    }
    // What the last connection left unread is nobody's reply (F532): kept,
    // it answered this connection's requests, one user's identity for
    // another user's token. Here and not in 'close', which a destroy()
    // followed at once by connect() has not delivered yet.
    this.#buf = '';
    await new Promise((resolve, reject) => {
      const sock = net.createConnection(this.socketPath);
      this.#sock = sock;
      sock.setEncoding('utf8');
      sock.once('connect', () => { if (sock === this.#sock) { this.#open = true; } resolve(); });
      // Listened to for the socket's whole life: 'close' follows every error
      // and is what fails the queue, and an 'error' with no listener ends
      // the process.
      sock.on('error', reject);
      sock.on('data', (chunk) => { if (sock === this.#sock) { this.#onData(chunk); } });
      sock.on('close', () => {
        // A connect() still waiting is told (F534): destroy() before the
        // connection was made raises 'close' and no 'error', and the promise
        // never settled. After 'connect' this reject is a no-op.
        reject(new AuthdError('connection-closed'));
        if (sock !== this.#sock) { return; }
        // Fail everything still waiting rather than leaving a promise pending
        // forever if the daemon restarts mid-request.
        this.#open = false;
        this.#failQueue();
      });
    });
    return this;
  }

  #failQueue() {
    for (const { reject: rj } of this.#queue.splice(0)) {
      rj(new AuthdError('connection-closed'));
    }
  }

  // A request made after close() is refused, and one still waiting its turn
  // is failed here: nothing would ever write it. The one already written
  // keeps its place until its reply or the socket's 'close'.
  close() {
    this.#open = false;
    const head = this.#queue[0];
    const inFlight = head && head.sent ? this.#queue.shift() : null;
    this.#failQueue();
    if (inFlight) { this.#queue.push(inFlight); }
    this.#sock?.end();
  }

  // For a daemon that has stopped answering (V4-127, F210): end() waits for
  // the peer, and a peer that is hung never lets the descriptor go.
  // (A request made after destroy() is failed by the 'close' it causes.)
  destroy() {
    this.#sock?.destroy();
  }

  #onData(chunk) {
    this.#buf += chunk;
    for (;;) {
      const pending = this.#queue[0];
      // Bytes nobody asked for (F532): the daemon answers one request with
      // one reply, so a line with no request written is a peer out of step,
      // and every later reply would be read against the wrong request. The
      // connection is ended; what was waiting fails as connection-closed.
      if (!pending || !pending.sent) {
        if (this.#buf.length > 0) { this.#buf = ''; this.#sock?.destroy(); }
        return;
      }

      const nl = this.#buf.indexOf('\n');
      if (nl < 0) return;

      // A REFUSED list command answers a single `ERR code=` line with no END,
      // so a handler that always waits for END would hang forever on it. That
      // is not hypothetical: it hung this file's own test suite for 24s until
      // the daemon exited.
      const firstLine = this.#buf.slice(0, nl);
      // A list is a reply whose first line is `OK` (F535): anything else --
      // `ERR code=`, or a line that is neither -- is one line, for the caller
      // to refuse. Waiting for END on `ERR internal` never ended.
      const isList = pending.wantList && (firstLine === 'OK' || firstLine.startsWith('OK '));
      if (!isList) {
        this.#buf = this.#buf.slice(nl + 1);
        this.#queue.shift();
        pending.resolve([firstLine]);
        this.#sendHead();
        continue;
      }
      // A list: collect until the END line arrives.
      const endAt = this.#buf.indexOf('\nEND\n');
      if (endAt < 0) return;
      const block = this.#buf.slice(0, endAt);
      this.#buf = this.#buf.slice(endAt + 5);
      this.#queue.shift();
      pending.resolve(block.split('\n'));
      this.#sendHead();
    }
  }

  // ONE request in flight (spec §8; V4-94): the next line is written only
  // once the previous reply has arrived. The daemon refuses a line that
  // arrives behind an unanswered one on the site socket, so concurrent HTTP
  // requests wait their turn here instead of being pipelined.
  #sendHead() {
    const head = this.#queue[0];
    if (head && !head.sent) {
      head.sent = true;
      this.#sock.write(head.line + '\n');
    }
  }

  /** Sends one request and resolves with its response lines. */
  // Every command, key and value is ONE printable token (V4-89, F178): the
  // socket's grammar is space-separated key=value on one line, so a space, an
  // '=' or a line break inside a value would be read as more of the request,
  // or as another request made with the site's authority. Values are hex,
  // digits, a few fixed words, a recovery code as typed, or empty; anything else is
  // refused here, before a byte is written.
  request(cmd, params = {}) {
    if (!/^[A-Z][A-Z-]*$/.test(String(cmd))) {
      return Promise.reject(new AuthdError('bad-request-field'));
    }
    const parts = [cmd];
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      const val = String(v);
      if (!/^[a-z][a-z_]*$/.test(k) || !/^[\x21-\x3c\x3e-\x7e]*$/.test(val)) {
        return Promise.reject(new AuthdError('bad-request-field'));
      }
      parts.push(`${k}=${val}`);
    }
    const line = parts.join(' ');
    if (line.length + 1 > MAX_LINE) {
      return Promise.reject(new AuthdError('request-too-long'));
    }
    // V4-175, F249: a connection that is closed, or was never opened, cannot
    // answer. The request used to be queued all the same and written to a
    // socket nobody read: its promise never settled, so a site that keeps one
    // connection waited for ever on every request after a daemon restart.
    if (!this.#open) {
      return Promise.reject(new AuthdError('connection-closed'));
    }
    return new Promise((resolve, reject) => {
      this.#queue.push({ resolve, reject, wantList: LIST_COMMANDS.has(cmd), line, sent: false });
      this.#sendHead();
    });
  }
}

/** Parses `key=value key=value` into an object. Values are hex or plain. */
function fields(line) {
  const out = {};
  for (const tok of line.split(' ').slice(1)) {
    const i = tok.indexOf('=');
    if (i > 0) out[tok.slice(0, i)] = tok.slice(i + 1);
  }
  return out;
}

function ensureOk(lines) {
  const first = lines[0] ?? '';
  if (first.startsWith('ERR code=')) {
    throw new AuthdError(first.slice('ERR code='.length).trim());
  }
  // `OK` alone or followed by a space (spec 8, erratum 105; F301). A prefix
  // test took `OKAY` and anything else that began with the two letters.
  if (first !== 'OK' && !first.startsWith('OK ')) {
    throw new AuthdError('malformed-response');
  }
  return first;
}

// The fields a reply must carry to be that reply (F301). An `OK` without its
// token is not a login and an `OK` without its ticket is not a recovery: each
// was returned to the site as one, with `undefined` where the value belongs.
function need(f, ...keys) {
  for (const k of keys) {
    if (typeof f[k] !== 'string' || f[k] === '') { throw new AuthdError('malformed-response'); }
  }
  return f;
}

/**
 * Exchange a login code for a session token.
 *
 * `state` MUST be the same value the login URL carried, and is what stops a
 * login-CSRF at this step (Req 5). On milestone A's tunnel listener the
 * daemon binds the EMPTY state, so pass '' there.
 */
export async function exchange(authd, codeBase64url, state = '') {
  const lines = await authd.request('EXCHANGE', {
    code: codeToHex(codeBase64url),
    state: hex(Buffer.from(state, 'utf8')),
  });
  const f = need(fields(ensureOk(lines)), 'token', 'user', 'handle');
  return {
    token: f.token,                                        // keep SERVER-SIDE only
    user: Buffer.from(f.user, 'hex').toString('utf8'),
    handle: Buffer.from(f.handle, 'hex').toString('utf8'),
    role: f.role,
    issued: Number(f.issued),
    expires: Number(f.expires),
  };
}

/** Verify a token on each request. Also slides its idle window. */
export async function verify(authd, token) {
  const f = need(fields(ensureOk(await authd.request('VERIFY', { token }))), 'user', 'handle');
  return {
    user: Buffer.from(f.user, 'hex').toString('utf8'),
    handle: Buffer.from(f.handle, 'hex').toString('utf8'),
    role: f.role,
    issued: Number(f.issued),
    expires: Number(f.expires),
  };
}

export async function logout(authd, token) {
  const f = fields(ensureOk(await authd.request('LOGOUT', { token })));
  return Number(f.deleted) === 1;
}

/** Enroll a device's public key. `pk` is a Buffer/Uint8Array of 1952 bytes.
 *  Pass `ticket` (hex, from recoveryUse) to enroll a REPLACEMENT device after
 *  the user has lost the old one; without it this is an ordinary site-driven
 *  enrollment. The two are not interchangeable: `via=site` with a ticket, and
 *  `via=recovery` without one, are both refused as malformed. */
// `signup: true` is a NEW account (via=signup, V4-76, F145): the daemon refuses
// it `user-exists` if the user is known. Without it and without a ticket the
// enrollment is via=site, the site vouching for an existing person (spec 10).
export async function enroll(authd, { user, handle, pk, label, ticket, signup }) {
  // F301: a ticket that was GIVEN makes this a recovery, whatever it holds.
  // The path used to be chosen by the ticket's truthiness, so a recovery whose
  // ticket had come back empty was sent as via=site: the path that adds a
  // device with no proof of continuity. An empty ticket is now a recovery the
  // daemon refuses.
  const recovery = ticket !== undefined && ticket !== null;
  if (recovery && (typeof ticket !== 'string' || ticket === '')) { throw new AuthdError('bad-request-field'); }
  const f = need(fields(ensureOk(await authd.request('ENROLL', {
    user: hex(Buffer.from(user, 'utf8')),
    handle: hex(Buffer.from(handle, 'utf8')),
    pk: hex(pk),
    label: label ? hex(Buffer.from(label, 'utf8')) : undefined,
    via: recovery ? 'recovery' : (signup ? 'signup' : 'site'),
    ticket: recovery ? ticket : undefined,
  }))), 'fp');
  return { fp: f.fp, idempotent: f.idempotent === '1' };
}

/*
 * Recovery (spec §10.3). The flow, end to end:
 *
 *   1. At enrollment, call recoveryIssue() and SHOW THE CODES ONCE. They are
 *      never retrievable again -- the daemon keeps only Argon2id hashes.
 *   2. The user loses their device. They type one code into your site.
 *   3. recoveryUse() returns a single-use ticket valid ten minutes.
 *   4. The new device generates a keypair; enroll(..., { ticket }) registers it.
 *
 * Pass the code THROUGH VERBATIM. Do not upper-case it, strip its hyphens or
 * "fix" its O/0 and l/1 -- the daemon normalises, and what it hashes is its own
 * canonical form. A site that normalises differently would lock its users out
 * of their own recovery codes.
 *
 * Note that recoveryIssue() and recoveryUse() BLOCK the daemon while they run
 * (roughly 0.1 s per code, single-threaded by design), so do not call them on
 * a hot path, and never expose recoveryUse() without your own rate limit in
 * front of it -- the daemon's five-failures-per-hour lockout is a backstop,
 * not a substitute.
 */

/** Generate `count` (1..16) fresh recovery codes, invalidating any previous
 *  generation. Returns the plaintext codes -- THE ONLY TIME THEY EXIST. */
export async function recoveryIssue(authd, user, count = 10) {
  const f = need(fields(ensureOk(await authd.request('RECOVERY-ISSUE', {
    user: hex(Buffer.from(user, 'utf8')),
    count: String(count),
  }))), 'codes');
  return f.codes.split(',');
}

/** Spend a recovery code for an enrollment ticket. `revoke: 'all'` also
 *  revokes every existing device of that user and closes their live sessions
 *  -- the right choice when the device was stolen rather than mislaid. */
export async function recoveryUse(authd, user, code, { revoke = 'none' } = {}) {
  const f = need(fields(ensureOk(await authd.request('RECOVERY-USE', {
    user: hex(Buffer.from(user, 'utf8')),
    code,                                   // base32 text, passed through as typed
    revoke,
  }))), 'ticket');
  return { ticket: f.ticket, expires: Number(f.expires) };
}

export async function listDevices(authd, user) {
  const lines = await authd.request('LIST-DEVICES', { user: hex(Buffer.from(user, 'utf8')) });
  ensureOk(lines);
  return lines.slice(1).filter((l) => l.startsWith('DEVICE ')).map((l) => {
    const f = fields(l);
    return {
      handle: Buffer.from(f.handle, 'hex').toString('utf8'),
      label: f.label ? Buffer.from(f.label, 'hex').toString('utf8') : '',
      status: f.status,
      enrolled: Number(f.enrolled),
      lastSeen: Number(f.last_seen),
      fp: f.fp,
    };
  });
}

export async function revokeDevice(authd, handle, reason = '') {
  ensureOk(await authd.request('REVOKE-DEVICE', {
    handle: hex(Buffer.from(handle, 'utf8')),
    reason: hex(Buffer.from(reason, 'utf8')),
  }));
  return true;
}

export async function ping(authd) {
  return fields(ensureOk(await authd.request('PING')));
}
