// The mldsa-authd client transport (V4-13b).
//
// Moves bytes between a WebSocket and the client core compiled to wasm
// (web/mldsa_client.mjs). It does NO cryptography -- every key, signature,
// KDF and AEAD is inside the module (spec 14: "No cryptography in
// JavaScript"; tests/web_no_crypto.mjs enforces it on this directory) -- and
// it makes no protocol decision: which frame to send next, whether a reply is
// acceptable and when the key is released are all client_core's.
//
// Deliberately minimal (V4-13b decision): enough for Node and, later, a page
// to create an identity, log in, rotate and say goodbye. Storage (IndexedDB),
// the passphrase UX and the pages are V4-13c's.
//
//   const client = await AuthdClient.load(createMldsaClient);
//   const id = client.newIdentity(passphrase);            // { handle, envelope, publicImage }
//   const s = await client.login({ url, serverId, serverPub, handle, envelope, passphrase });
//   s.code  -> Uint8Array(32), for the site to EXCHANGE
//   await s.close();
//
// Every WebSocket message is ONE whole frame (len4 || payload), in both
// directions, as the daemon's WebSocket listener sends and expects.

const te = new TextEncoder();

export class AuthdError extends Error {
  constructor(status, statusName, stage, detail, framesSent) {
    super(`${statusName}${stage ? ` at ${stage}` : ''}${detail ? `: ${detail}` : ''}`);
    this.name = 'AuthdError';
    this.status = status;
    this.statusName = statusName;
    this.stage = stage;
    this.detail = detail;
    this.framesSent = framesSent;
  }
}

export class AuthdClient {
  static async load(factory) {
    const M = await factory();
    if (M._ccw_init() !== 0) { throw new Error('the client module failed to initialise'); }
    return new AuthdClient(M);
  }

  constructor(M) { this.M = M; }

  // ---- wasm memory: copy in, copy out, zero on the way out --------------
  put(bytes) {
    const p = this.M._malloc(Math.max(bytes.length, 1));
    // F305: a refused allocation is 0, and writing there overwrote the
    // module's own low memory.
    if (!p) { throw new Error('the client module is out of memory'); }
    this.M.HEAPU8.set(bytes, p);
    return p;
  }
  drop(p, len) {
    if (p) { this.M.HEAPU8.fill(0, p, p + len); this.M._free(p); }
  }
  // Every allocation is checked (V4-281, F463), as put() has been since
  // F305: u32Slot wrote HEAPU32[0] when malloc returned 0, F305's shape.
  alloc(n) {
    const p = this.M._malloc(n);
    if (!p) { throw new Error('the client module is out of memory'); }
    return p;
  }
  u32Slot() { const p = this.alloc(8); this.M.HEAPU32[p >> 2] = 0; return p; }
  u32(p) { return this.M.HEAPU32[p >> 2]; }
  str(p) { return this.M.UTF8ToString(p); }

  fail(h, st, framesSent) {
    return new AuthdError(st, this.str(this.M._ccw_status_name(st)),
                          h ? this.str(this.M._ccw_diag_stage(h)) : '',
                          h ? this.str(this.M._ccw_diag_detail(h)) : '', framesSent);
  }

  // The .ek.next decision (spec 10.2), client_key_plan in the core, so the
  // browser follows the CLI's rule exactly: 0 use the current key, 1 promote
  // the pending one, 2 refuse and touch nothing.
  keyPlan(ekOk, nextPresent, nextOk) {
    return this.M._ccw_key_plan(ekOk ? 1 : 0, nextPresent ? 1 : 0, nextOk ? 1 : 0);
  }

  // The passphrase policy (passphrase.h): { verdict, name, codePoints, bits, reasons }.
  checkPassphrase(passphrase) {
    const M = this.M;
    const pass = te.encode(passphrase);
    // F557: allocated INSIDE the try, as login() does since F555. A slot
    // that was refused after the passphrase had been copied in left the copy
    // in the module and the array unzeroed; the enrollment page calls this
    // on every keystroke.
    let pp = 0, cps = 0, bits = 0, rs = 0;
    try {
      pp = this.put(pass); cps = this.u32Slot(); bits = this.u32Slot(); rs = this.u32Slot();
      const verdict = M._ccw_passphrase_check(pp, pass.length, cps, bits, rs);
      return { verdict, ok: verdict === 0, codePoints: this.u32(cps), bits: this.u32(bits), reasons: this.u32(rs) };
    } finally {
      this.drop(pp, pass.length); pass.fill(0); this.drop(cps, 8); this.drop(bits, 8); this.drop(rs, 8);
    }
  }

  newHandle() {
    const p = this.alloc(64);
    this.M._ccw_new_handle(p);
    const s = this.str(p);
    this.drop(p, 64);
    return s;
  }

  // A new identity for `handle` (a fresh one when omitted), sealed inside the
  // module at the browser's Argon2id parameters.
  newIdentity(passphrase, handle) {
    const M = this.M;
    const hid = te.encode(handle ?? this.newHandle());
    const pass = te.encode(passphrase);
    const ekCap = M._ccw_sealed_len(hid.length), pubCap = M._ccw_public_len(hid.length);
    let ph = 0, pp = 0, pe = 0, pu = 0, el = 0, ul = 0;
    try {
      ph = this.put(hid); pp = this.put(pass);
      pe = this.alloc(ekCap); pu = this.alloc(pubCap);
      el = this.u32Slot(); ul = this.u32Slot();
      const st = M._ccw_seal_new_identity(ph, hid.length, pp, pass.length, pe, ekCap, el, pu, pubCap, ul);
      if (st !== 0) { throw this.fail(0, st, 0); }
      return {
        handle: new TextDecoder().decode(hid),
        envelope: M.HEAPU8.slice(pe, pe + this.u32(el)),
        publicImage: M.HEAPU8.slice(pu, pu + this.u32(ul)),
      };
    } finally {
      this.drop(ph, hid.length); this.drop(pp, pass.length); pass.fill(0);
      this.drop(pe, ekCap); this.drop(pu, pubCap); this.drop(el, 8); this.drop(ul, 8);
    }
  }

  // Logs in. Resolves to a Session holding the login code; rejects with an
  // AuthdError naming the core's status, stage and detail.
  async login({ url, serverId, serverPub, handle, envelope, passphrase, keepForRotate = false,
                now = () => performance.now(), timeoutMs = 20000 }) {
    const M = this.M;
    const h = M._ccw_new();
    if (!h) { throw new Error('ccw_new failed'); }
    const tick = () => { if (M._ccw_set_now_ms(h, now()) !== 0) { throw new Error('clock refused'); } };
    let frame;
    try { frame = this.alloc(M._ccw_frame_buf_bytes()); } catch (e) { M._ccw_free(h); throw e; }
    const cap = M._ccw_frame_buf_bytes();
    let outLen;
    try { outLen = this.u32Slot(); } catch (e) { this.drop(frame, cap); M._ccw_free(h); throw e; }   // F557
    let sent = 0;
    const session = new Session(this, h, frame, cap, outLen, tick, timeoutMs);
    try {
      tick();
      const sid = te.encode(serverId);
      let ps = 0, pi = 0, st;
      try {
        ps = this.put(serverPub); pi = this.put(sid);
        st = M._ccw_pin_server_pub(h, ps, serverPub.length, pi, sid.length);
      } finally {
        this.drop(ps, serverPub.length); this.drop(pi, sid.length);   // F557: the first copy too, when the second is refused
      }
      if (st !== 0) { throw this.fail(h, st, sent); }

      const hid = te.encode(handle), pass = te.encode(passphrase);
      // F555: the copies are dropped and the passphrase's bytes zeroed on
      // every way out. A put() that was refused (the module out of memory)
      // used to skip both: the passphrase stayed in this array, and the
      // copies already made stayed in the module.
      let ph = 0, pe = 0, pp = 0;
      try {
        ph = this.put(hid); pe = this.put(envelope); pp = this.put(pass);
        st = M._ccw_login_begin(h, ph, hid.length, pe, envelope.length, pp, pass.length,
                                keepForRotate ? 1 : 0, frame, cap, outLen);
      } finally {
        this.drop(ph, hid.length); this.drop(pe, envelope.length); this.drop(pp, pass.length); pass.fill(0);
      }
      if (st !== 0) { throw this.fail(h, st, sent); }

      await session.open(url);
      session.send(); sent = session.sent;
      st = await session.feed((p, n) => M._ccw_on_server_hello(h, p, n, frame, cap, outLen));
      if (st !== 0) { throw this.fail(h, st, session.sent); }
      session.send(); sent = session.sent;

      let code = 0, flags = 0, exp = 0;
      try {
        code = this.alloc(32); flags = this.u32Slot(); exp = this.alloc(8);   // F557
        st = await session.feed((p, n) => M._ccw_on_record(h, p, n, code, flags, exp));
        if (st !== 0) { throw this.fail(h, st, session.sent); }
        session.code = M.HEAPU8.slice(code, code + 32);
        session.flags = this.u32(flags);
        session.expires = M.HEAPF64[exp >> 3];
      } finally {
        this.drop(code, 32); this.drop(flags, 8); this.drop(exp, 8);
      }
      return session;
    } catch (e) {
      session.destroy();
      if (e instanceof AuthdError && e.framesSent === undefined) { e.framesSent = sent; }
      throw e;
    }
  }
}

// What a text message is queued as: feed() answers it as a frame error.
const BAD_FRAME = Symbol('bad-frame');

export class Session {
  constructor(client, h, frame, cap, outLen, tick, timeoutMs) {
    Object.assign(this, { client, h, frame, cap, outLen, tick, timeoutMs });
    this.sent = 0;
    this.queue = [];
    this.waiters = [];
    this.ws = null;
    this.closed = false;
  }

  // Bounded by the same timeout as each frame (V4-187, F264). A socket that
  // connects and never answers the upgrade fires neither onopen nor onerror
  // until the browser's own limit, minutes later: the login stayed pending
  // with no message, holding the identity's lock against every other tab.
  open(url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      const t = setTimeout(() => {
        reject(new Error('timed out waiting for the daemon'));
        try { ws.close(); } catch { /* never opened */ }
      }, this.timeoutMs);
      ws.onopen = () => { clearTimeout(t); resolve(); };
      ws.onerror = () => { clearTimeout(t); reject(new Error(`WebSocket error on ${url}`)); this.wake(null); };
      ws.onclose = () => this.wake(null);
      // The daemon sends binary messages only (spec 7.1). A text message
      // arrives as a string, and `new Uint8Array("2000000000")` is two
      // billion zero bytes: it is a frame error where it arrives (F313).
      ws.onmessage = (ev) => this.wake(typeof ev.data === 'string' ? BAD_FRAME : new Uint8Array(ev.data));
      this.ws = ws;
    });
  }

  wake(msg) {
    const w = this.waiters.shift();
    if (w) { w(msg); } else { this.queue.push(msg); }
  }

  next() {
    if (this.queue.length) { return Promise.resolve(this.queue.shift()); }
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timed out waiting for the daemon')), this.timeoutMs);
      this.waiters.push((m) => { clearTimeout(t); resolve(m); });
    });
  }

  // Sends the frame the core just wrote (its length is in outLen).
  send() {
    this.live();
    // F354: send() on a closing or closed socket drops the data and does not
    // throw. Counting it made a probe whose ClientAuth never left look like
    // a key the daemon had refused (flows.mjs reads `sent`).
    if (this.ws?.readyState !== 1) { throw new Error('the connection closed before the frame could be sent'); }
    const M = this.client.M;
    const n = this.client.u32(this.outLen);
    this.ws.send(M.HEAPU8.slice(this.frame, this.frame + n));
    this.sent += 1;
  }

  // Receives one frame and hands it to the core via `call(ptr, len)`.
  async feed(call) {
    this.live();
    const msg = await this.next();
    this.live();                       // closed while this was waiting
    if (msg === null) { return 3; /* CC_ERR_FRAME: the daemon closed without answering */ }
    if (msg === BAD_FRAME) { return 3; }
    // F305: no frame of this protocol is larger than the frame buffer, so a
    // larger message is refused HERE, as the frame error it is. It used to be
    // copied into the module first, whatever its size, and the module's
    // memory grows and never shrinks.
    if (msg.length > this.cap) { return 3; }
    const p = this.client.put(msg);
    try { this.tick(); return call(p, msg.length); } finally { this.client.drop(p, msg.length); }
  }

  // Rotation (spec 10.2): `newEnvelope` must ALREADY be stored durably by the
  // caller. Resolves only on a ROTATE_ACK naming this handle and that key.
  async rotate(newEnvelope, passphrase) {
    this.live();
    const c = this.client, M = c.M;
    const pass = te.encode(passphrase);
    let st;
    // A failure before the frame was handed to the socket says so: `notSent`
    // (V4-281, F460). It is the proof F235 and F438 act on -- a ROTATE that
    // never left cannot have been committed -- and flows.rotate discards the
    // staged key on it. Every failure after that proves nothing.
    const before = this.sent;
    try {
      let pe = 0, pp = 0;
      // The copies are wiped whatever tick() does (V4-187, F266): it throws on
      // a refused clock, and it used to run between the copy and the wipe.
      // F557: and whatever the second copy does; refused, it left the first.
      try {
        pe = c.put(newEnvelope); pp = c.put(pass);
        this.tick();
        st = M._ccw_rotate_build(this.h, pe, newEnvelope.length, pp, pass.length, this.frame, this.cap, this.outLen);
      } finally {
        c.drop(pe, newEnvelope.length); c.drop(pp, pass.length);
      }
      if (st !== 0) { throw c.fail(this.h, st, this.sent); }
      this.send();
    } catch (e) {
      if (this.sent === before && e !== null && typeof e === 'object') { e.notSent = true; }
      throw e;
    } finally {
      pass.fill(0);
    }
    const ec = c.u32Slot();
    try {
      st = await this.feed((p, n) => M._ccw_rotate_on_reply(this.h, p, n, ec));
      if (st !== 0) { const e = c.fail(this.h, st, this.sent); e.errorCode = c.u32(ec); throw e; }
    } finally { c.drop(ec, 8); }
  }

  // Once destroyed, the handle and the frame buffer are freed: nothing may
  // reach the module through this object again (F314). close() and destroy()
  // stay quiet no-ops.
  live() {
    if (this.closed) { throw new Error('session is closed'); }
  }

  // BYE (best effort), then close and wipe. It never rejects (F572): the BYE
  // is a courtesy, and a clock that refused or a send that threw made the
  // caller's next step -- posting the login code, promoting a key the daemon
  // had acknowledged -- not happen.
  async close() {
    if (this.closed) { return; }
    const M = this.client.M;
    try {
      this.tick();
      if (M._ccw_bye(this.h, this.frame, this.cap, this.outLen) === 0 && this.ws?.readyState === 1) { this.send(); }
    } catch { /* best effort */ } finally { this.destroy(); }
  }

  destroy() {
    if (this.closed) { return; }
    this.closed = true;
    try { this.ws?.close(); } catch { /* already closed */ }
    const c = this.client;
    c.M._ccw_free(this.h);
    c.drop(this.frame, this.cap);
    c.drop(this.outLen, 8);
    if (this.code) { this.code.fill(0); }
  }
}
