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
  const b = Buffer.from(codeBase64url, 'base64url');
  if (b.length !== 32) {
    throw new Error(`login code must be 32 bytes, got ${b.length}`);
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

  constructor(socketPath) {
    this.socketPath = socketPath;
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.#sock = net.createConnection(this.socketPath);
      this.#sock.setEncoding('utf8');
      this.#sock.once('connect', resolve);
      this.#sock.once('error', reject);
      this.#sock.on('data', (chunk) => this.#onData(chunk));
      this.#sock.on('close', () => {
        // Fail everything still waiting rather than leaving a promise pending
        // forever if the daemon restarts mid-request.
        for (const { reject: rj } of this.#queue.splice(0)) {
          rj(new AuthdError('connection-closed'));
        }
      });
    });
    return this;
  }

  close() {
    this.#sock?.end();
  }

  #onData(chunk) {
    this.#buf += chunk;
    for (;;) {
      const pending = this.#queue[0];
      if (!pending) return;

      const nl = this.#buf.indexOf('\n');
      if (nl < 0) return;

      // A REFUSED list command answers a single `ERR code=` line with no END,
      // so a handler that always waits for END would hang forever on it. That
      // is not hypothetical: it hung this file's own test suite for 24s until
      // the daemon exited.
      const firstLine = this.#buf.slice(0, nl);
      if (!pending.wantList || firstLine.startsWith('ERR code=')) {
        this.#buf = this.#buf.slice(nl + 1);
        this.#queue.shift();
        pending.resolve([firstLine]);
        continue;
      }
      // A list: collect until the END line arrives.
      const endAt = this.#buf.indexOf('\nEND\n');
      if (endAt < 0) return;
      const block = this.#buf.slice(0, endAt);
      this.#buf = this.#buf.slice(endAt + 5);
      this.#queue.shift();
      pending.resolve(block.split('\n'));
    }
  }

  /** Sends one request and resolves with its response lines. */
  request(cmd, params = {}) {
    const parts = [cmd];
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      parts.push(`${k}=${v}`);
    }
    const line = parts.join(' ');
    if (line.length + 1 > MAX_LINE) {
      return Promise.reject(new AuthdError('request-too-long'));
    }
    return new Promise((resolve, reject) => {
      this.#queue.push({ resolve, reject, wantList: LIST_COMMANDS.has(cmd) });
      this.#sock.write(line + '\n');
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
  if (!first.startsWith('OK')) {
    throw new AuthdError('malformed-response');
  }
  return first;
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
  const f = fields(ensureOk(lines));
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
  const f = fields(ensureOk(await authd.request('VERIFY', { token })));
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
export async function enroll(authd, { user, handle, pk, label, ticket }) {
  const f = fields(ensureOk(await authd.request('ENROLL', {
    user: hex(Buffer.from(user, 'utf8')),
    handle: hex(Buffer.from(handle, 'utf8')),
    pk: hex(pk),
    label: label ? hex(Buffer.from(label, 'utf8')) : undefined,
    via: ticket ? 'recovery' : 'site',
    ticket: ticket || undefined,
  })));
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
  const f = fields(ensureOk(await authd.request('RECOVERY-ISSUE', {
    user: hex(Buffer.from(user, 'utf8')),
    count: String(count),
  })));
  return f.codes.split(',');
}

/** Spend a recovery code for an enrollment ticket. `revoke: 'all'` also
 *  revokes every existing device of that user and closes their live sessions
 *  -- the right choice when the device was stolen rather than mislaid. */
export async function recoveryUse(authd, user, code, { revoke = 'none' } = {}) {
  const f = fields(ensureOk(await authd.request('RECOVERY-USE', {
    user: hex(Buffer.from(user, 'utf8')),
    code,                                   // base32 text, passed through as typed
    revoke,
  })));
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
