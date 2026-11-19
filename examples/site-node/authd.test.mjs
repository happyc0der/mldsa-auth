/*
 * The reference handler, against a REAL daemon (V4-9a).
 *
 * tests/authd_node_fixture.c starts the actual daemon in-process, enrolls a
 * device, completes a genuine PQ handshake and prints the resulting login
 * code. Everything below therefore exercises the real protocol: a mock would
 * prove only that this file agrees with itself.
 *
 *   node --test examples/site-node/authd.test.mjs
 *
 * AUTHD_FIXTURE must point at the built fixture binary (CTest sets it). If it
 * is missing the tests SKIP with a named reason rather than passing quietly.
 */
import { test, skip } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { dirname, join } from 'node:path';

import { Authd, AuthdError, exchange, verify, logout, ping, listDevices, enroll, recoveryUse, recoveryIssue } from './authd.mjs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const FIXTURE = process.env.AUTHD_FIXTURE;

/** Starts the fixture and waits for its JSON line. */
async function startDaemon(seconds = 25) {
  const proc = spawn(FIXTURE, [String(seconds)], { stdio: ['ignore', 'pipe', 'inherit'] });
  const info = await new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('fixture did not announce itself')), 20000);
    proc.stdout.setEncoding('utf8');
    proc.stdout.on('data', (c) => {
      buf += c;
      const nl = buf.indexOf('\n');
      if (nl >= 0) {
        clearTimeout(timer);
        resolve(JSON.parse(buf.slice(0, nl)));
      }
    });
    proc.once('error', reject);
    proc.once('exit', (code) => { clearTimeout(timer); reject(new Error(`fixture exited: ${code}`)); });
  });
  return { proc, info };
}

// V4-31: stopped with SIGTERM, as every other caller stops a fixture, and
// waited for. It used to be SIGKILL, which no handler can catch, so every test
// here left the fixture's directory -- a store and two sockets -- behind.
async function withDaemon(fn) {
  const { proc, info } = await startDaemon();
  const dir = dirname(info.sock);
  assert.ok(existsSync(dir), "the fixture's scratch directory exists while it runs (the canary)");
  const authd = await new Authd(info.sock).connect();
  let quick = false;
  try {
    await fn(authd, info);
  } finally {
    authd.close();
    const exited = once(proc, 'exit');
    proc.kill('SIGTERM');
    // Not its deadline: a fixture that caught SIGTERM and served on would
    // clean up then and look tidy.
    quick = await Promise.race([exited.then(() => true), new Promise((r) => setTimeout(() => r(false), 3000))]);
    if (!quick) { proc.kill('SIGKILL'); await exited; }
  }
  assert.ok(quick, 'the fixture exits within 3 s of SIGTERM, not at its deadline (V4-31)');
  assert.ok(!existsSync(dir), 'the fixture, stopped with SIGTERM, removed its scratch directory (V4-31)');
}

if (FIXTURE && !existsSync(FIXTURE)) {
  // F383: named but not there is a failure, not a skip. CTest sets
  // AUTHD_FIXTURE, and after a build that did not make the fixture this file
  // "passed" with one skip and none of the daemon tests run.
  test('the fixture AUTHD_FIXTURE names exists', () => {
    assert.fail(`AUTHD_FIXTURE=${FIXTURE} does not exist: build authd_node_fixture`);
  });
} else if (!FIXTURE) {
  skip('AUTHD_FIXTURE is not set: build the project first (cmake --build build) and name its authd_node_fixture');
} else {
  test('PING reports the daemon version and schema', async () => {
    await withDaemon(async (authd) => {
      const p = await ping(authd);
      assert.equal(p.version, '1');
      assert.equal(p.schema, '1');
    });
  });

  test('a login code exchanges for a token bound to the right identity', async () => {
    await withDaemon(async (authd, info) => {
      const s = await exchange(authd, info.code, '');
      assert.equal(s.user, info.user);
      assert.equal(s.handle, info.handle);
      assert.equal(s.role, 'user');
      assert.match(s.token, /^[0-9a-f]{64}$/);
      assert.ok(s.expires > s.issued, 'the token expires after it was issued');
    });
  });

  test('the wrong state is refused, and the code survives to be used correctly', async () => {
    await withDaemon(async (authd, info) => {
      await assert.rejects(
        () => exchange(authd, info.code, 'some-other-state'),
        (e) => e instanceof AuthdError && e.code === 'state-mismatch',
      );
      // The refusal must not have consumed it.
      const s = await exchange(authd, info.code, '');
      assert.match(s.token, /^[0-9a-f]{64}$/);
    });
  });

  test('a login code is single-use', async () => {
    await withDaemon(async (authd, info) => {
      await exchange(authd, info.code, '');
      await assert.rejects(
        () => exchange(authd, info.code, ''),
        (e) => e instanceof AuthdError && e.code === 'used',
      );
    });
  });

  test('a token verifies, then stops verifying after logout', async () => {
    await withDaemon(async (authd, info) => {
      const { token } = await exchange(authd, info.code, '');
      const v = await verify(authd, token);
      assert.equal(v.handle, info.handle);

      assert.equal(await logout(authd, token), true);
      assert.equal(await logout(authd, token), false, 'a second logout deletes nothing');
      await assert.rejects(
        () => verify(authd, token),
        (e) => e instanceof AuthdError && e.code === 'unknown',
      );
    });
  });

  test('LIST-DEVICES returns the enrolled device with its fingerprint', async () => {
    await withDaemon(async (authd, info) => {
      const devices = await listDevices(authd, info.user);
      assert.equal(devices.length, 1);
      assert.equal(devices[0].handle, info.handle);
      assert.equal(devices[0].status, 'active');
      assert.match(devices[0].fp, /^[0-9a-f]{64}$/);
    });
  });

  test('administrative commands are not reachable from the site socket', async () => {
    await withDaemon(async (authd) => {
      // LIST-USERS exists only in the admin table (Req 11, by construction).
      const lines = await authd.request('LIST-USERS');
      assert.match(lines[0], /^ERR code=not-permitted/);
    });
  });

  test('a field that is not one token is refused before any socket write (F178)', async () => {
    await withDaemon(async (authd) => {
      for (const bad of ['a b', 'a\nPING', 'a\rb', 'a=b', 'caf\u00e9']) {
        await assert.rejects(() => authd.request('PING', { x: bad }),
                             (e) => e instanceof AuthdError && e.code === 'bad-request-field', JSON.stringify(bad));
      }
      await assert.rejects(() => authd.request('PING\nLIST-USERS'),
                           (e) => e instanceof AuthdError && e.code === 'bad-request-field');
      // Nothing was written: the next request's reply is its own.
      const lines = await authd.request('PING');
      assert.match(lines[0], /^OK/);
    });
  });

  test('concurrent requests on one connection are sent one at a time, and all are served (V4-94)', async () => {
    await withDaemon(async (authd) => {
      // The daemon refuses a line that arrives behind an unanswered one on the
      // site socket (erratum 73), so a client that wrote all of these at once
      // would get ERR code=pipelined and a closed connection.
      const all = await Promise.all([
        authd.request('PING'), authd.request('LIST-USERS'), authd.request('PING'),
        authd.request('PING'), authd.request('PING'),
      ]);
      assert.equal(all.length, 5);
      assert.match(all[0][0], /^OK version=/);
      assert.match(all[1][0], /^ERR code=not-permitted/);
      for (const r of all.slice(2)) assert.match(r[0], /^OK version=/);
    });
  });

  // V4-175, F249. Each wait is raced against two seconds: before the fix
  // these promises never settled, and a test that only awaited them would
  // hang instead of failing.
  const settled = (pr) => Promise.race([
    pr.then(() => 'resolved', (e) => (e instanceof AuthdError ? e.code : `threw ${e.message}`)),
    new Promise((r) => setTimeout(() => r('never settled'), 2000)),
  ]);

  test('a request on a connection that is closed, or never opened, is refused (F249)', async () => {
    assert.equal(await settled(new Authd('/nonexistent').request('PING')), 'connection-closed',
                 'before connect()');
    await withDaemon(async (authd, info) => {
      assert.equal(await settled(authd.request('PING')), 'resolved', 'an open connection answers (the canary)');
      authd.close();
      assert.equal(await settled(authd.request('PING')), 'connection-closed', 'after close()');
      const b = await new Authd(info.sock).connect();
      b.destroy();
      assert.equal(await settled(b.request('PING')), 'connection-closed', 'after destroy()');
      // close() fails what was still waiting its turn and keeps the request
      // already written: its reply arrives. Against a peer that answers late
      // and never closes its own side, so that nothing but close() itself can
      // have failed the second request.
      const path = join(dirname(info.sock), 'late.sock');
      const held = [];
      const late = createServer({ allowHalfOpen: true }, (conn) => {
        held.push(conn);
        conn.on('error', () => {});
        conn.once('data', () => setTimeout(() => conn.write('OK late=1\n'), 300));
      });
      await new Promise((r) => late.listen(path, r));
      try {
        const c = await new Authd(path).connect();
        const first = c.request('PING'), second = c.request('PING');
        c.close();
        assert.equal(await settled(second), 'connection-closed', 'queued behind another at close()');
        assert.equal(await settled(first), 'resolved', 'already written at close()');
      } finally {
        for (const conn of held) { conn.destroy(); }
        await new Promise((r) => late.close(r));
        rmSync(path, { force: true });
      }
    });
  });

  test('a request after the daemon went away is refused, not left waiting (F249)', async () => {
    const { proc, info } = await startDaemon();
    const authd = await new Authd(info.sock).connect();
    assert.equal(await settled(authd.request('PING')), 'resolved', 'the daemon answers (the canary)');
    const exited = once(proc, 'exit');
    proc.kill('SIGTERM');
    await exited;
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(await settled(authd.request('PING')), 'connection-closed');
    assert.equal(await settled(authd.request('PING')), 'connection-closed', 'and the one after it');
  });

  test('a malformed login code is rejected client-side, before any socket write', async () => {
    await withDaemon(async (authd) => {
      // As an AuthdError (V4-130, F214): a plain Error is what the site reads as
      // the daemon being away.
      await assert.rejects(() => exchange(authd, 'AAAA', ''),
                           (e) => e instanceof AuthdError && e.code === 'bad-request-field');
    });
  });
}

// F301: replies that are not the protocol's, from a stand-in that plays one
// line per connection. No daemon sends these; a wrong socket path does, and
// each used to be returned to the site as a success.
test('a reply that is not the protocol\'s is malformed-response, not a success (F301)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'authd-f301-'));
  const path = join(dir, 's.sock');
  let reply = 'OK\n';
  const seen = [];
  const srv = createServer((conn) => {
    conn.on('error', () => {});
    conn.once('data', (d) => { seen.push(String(d)); conn.end(reply); });
  });
  await new Promise((r) => srv.listen(path, r));
  const call = async (line, fn) => {
    reply = line;
    const a = await new Authd(path).connect();
    try { await fn(a); return 'resolved'; } catch (e) { return e instanceof AuthdError ? e.code : `threw ${e}`; } finally { a.destroy(); }
  };
  const CODE = Buffer.alloc(32, 7).toString('base64url');
  const PK = Buffer.alloc(1952, 1);
  try {
    assert.equal(await call('OK\n', (a) => logout(a, 'ab')), 'resolved', 'a bare OK is an answer (the canary)');
    assert.equal(await call('OK deleted=1\n', (a) => logout(a, 'ab')), 'resolved', 'OK and a space is an answer (the canary)');
    for (const line of ['OKAY\n', 'OKdeleted=1\n', 'ERR\n', 'HTTP/1.1 400 Bad Request\r\n', '\n']) {
      assert.equal(await call(line, (a) => logout(a, 'ab')), 'malformed-response', JSON.stringify(line));
    }
    assert.equal(await call('OK token=aa user=75 handle=68 role=user issued=1 expires=2\n', (a) => exchange(a, CODE, '')),
                 'resolved', 'a whole EXCHANGE reply (the canary)');
    assert.equal(await call('OK user=75 handle=68 role=user issued=1 expires=2\n', (a) => exchange(a, CODE, '')),
                 'malformed-response', 'EXCHANGE without a token is not a login');
    assert.equal(await call('OK role=user\n', (a) => verify(a, 'ab')), 'malformed-response', 'VERIFY without a user');
    assert.equal(await call('OK ticket=ab expires=9\n', (a) => recoveryUse(a, 'u', 'CODE')), 'resolved', 'a whole RECOVERY-USE reply (the canary)');
    assert.equal(await call('OK\n', (a) => recoveryUse(a, 'u', 'CODE')), 'malformed-response', 'RECOVERY-USE without a ticket');
    assert.equal(await call('OK ticket=\n', (a) => recoveryUse(a, 'u', 'CODE')), 'malformed-response', 'RECOVERY-USE with an empty ticket');
    assert.equal(await call('OK\n', (a) => recoveryIssue(a, 'u', 1)), 'malformed-response', 'RECOVERY-ISSUE without codes');
    assert.equal(await call('OK\n', (a) => enroll(a, { user: 'u', handle: 'h', pk: PK })), 'malformed-response', 'ENROLL without a fingerprint');
    // The path is the caller's intent, not the ticket's truthiness.
    const before = seen.length;
    assert.equal(await call('OK fp=ab\n', (a) => enroll(a, { user: 'u', handle: 'h', pk: PK, ticket: '' })),
                 'bad-request-field', 'an empty ticket is refused');
    assert.equal(seen.length, before, 'and nothing was sent for it');
    assert.equal(await call('OK fp=ab\n', (a) => enroll(a, { user: 'u', handle: 'h', pk: PK, ticket: 'abcd' })), 'resolved');
    assert.match(seen.at(-1), / via=recovery ticket=abcd\n$/, 'a ticket given is a recovery');
    assert.equal(await call('OK fp=ab\n', (a) => enroll(a, { user: 'u', handle: 'h', pk: PK })), 'resolved');
    assert.match(seen.at(-1), / via=site\n$/, 'no ticket and no signup is via=site (the canary)');
  } finally {
    await new Promise((r) => srv.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});

// V4-311, review 67: a stand-in daemon that answers line by line, for what a
// real one cannot be made to do on demand.
async function standIn(prefix, onLine) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const path = join(dir, 's.sock');
  let n = 0;
  const conns = new Set();
  const srv = createServer((conn) => {
    const id = ++n;
    let b = '';
    conns.add(conn);
    conn.on('close', () => conns.delete(conn));
    conn.on('error', () => {});
    conn.on('data', (d) => {
      b += d;
      let i;
      while ((i = b.indexOf('\n')) >= 0) { const l = b.slice(0, i); b = b.slice(i + 1); onLine(conn, l, id); }
    });
  });
  await new Promise((r) => srv.listen(path, r));
  // Every connection is ended here: a failed assertion must not leave a
  // socket open, which keeps the test process alive until CTest's timeout.
  const stop = async () => {
    for (const c of conns) { c.destroy(); }
    await new Promise((r) => srv.close(r));
    rmSync(dir, { recursive: true, force: true });
  };
  return { path, stop };
}
const settled = (p, ms = 2000) => Promise.race([
  p.then(() => 'resolved', (e) => (e instanceof AuthdError ? e.code : `threw ${e}`)),
  new Promise((r) => setTimeout(() => r('NEVER SETTLED'), ms)),
]);
const hexOf = (s) => Buffer.from(s).toString('hex');
// Whose identity a VERIFY returned, or the error's code: a value to assert
// on, so a wrong answer and a thrown error are both a named assertion.
const whose = (p) => settled2(p.then((v) => v.user, (e) => (e instanceof AuthdError ? e.code : `threw ${e}`)));
const settled2 = (p, ms = 2000) => Promise.race([p, new Promise((r) => setTimeout(() => r('NEVER SETTLED'), ms))]);

// F532: what one connection left unread is not the next connection's reply.
// A list reply cut short left `OK count=2`, a DEVICE line and half another in
// the buffer; connect() again on the same object kept them, three requests
// were answered malformed-response from the stale lines, and from then on
// every reply was three requests late -- alice's identity for bob's token.
test('a second connection does not read the first one\'s leftovers: bob\'s token is bob (F532)', async () => {
  const users = { aa: 'alice', bb: 'bob' };
  const s = await standIn('authd-f532-', (c, l, id) => {
    if (l.startsWith('LIST-DEVICES') && id === 1) {
      c.write(`OK count=2\nDEVICE handle=${hexOf('h1')} status=active\nDEVICE ha`);
      setTimeout(() => c.destroy(), 30);
      return;
    }
    const m = /^VERIFY token=(\w+)/.exec(l);
    if (m) { c.write(`OK user=${hexOf(users[m[1]])} handle=${hexOf('dev-' + users[m[1]])} role=user issued=1 expires=2\n`); }
  });
  const a = await new Authd(s.path).connect();
  try {
    assert.equal(await settled(listDevices(a, 'alice')), 'connection-closed', 'the cut list is a closed connection');
    await a.connect();
    assert.equal(await whose(verify(a, 'aa')), 'alice', 'the first request on the new connection gets its own reply (F532)');
    assert.equal(await whose(verify(a, 'bb')), 'bob', 'and bob\'s token is bob (F532)');
    // While that connection is open, connect() again is refused: the first
    // socket's 'close' would otherwise fail requests in flight on the second.
    assert.equal(await settled(a.connect()), 'already-connected', 'connect() on an open connection is refused (F532)');
    assert.equal(await whose(verify(a, 'bb')), 'bob', 'and the open connection still answers (the canary)');
  } finally {
    a.destroy();
    await s.stop();
  }
});

// F532, the other half: a line nobody asked for ends the connection. Kept in
// the buffer it became the reply to the next request.
test('a line the daemon sends unasked ends the connection, it does not answer the next request (F532)', async () => {
  const s = await standIn('authd-f532b-', (c, l) => {
    if (l.startsWith('PING')) { c.write('OK version=1 schema=1 uptime=1\nOK user=616c696365 handle=68 role=user issued=1 expires=2\n'); }
    else if (l.startsWith('VERIFY')) { c.write(`OK user=${hexOf('bob')} handle=68 role=user issued=1 expires=2\n`); }
  });
  const a = await new Authd(s.path).connect();
  try {
    await ping(a);
    const got = await whose(verify(a, 'bb'));
    assert.equal(got, 'connection-closed', 'a line sent unasked ends the connection; it is not bob\'s answer (F532)');
  } finally {
    a.destroy();
    await s.stop();
  }
});

// F540 (V4-314, review 68): destroy() and then connect() at once, with a
// request in flight. The old socket's 'close' arrives after it has been
// replaced and is ignored, so the request stayed at the head of the queue,
// marked sent: it never settled, and nothing asked on the new connection was
// ever written. A site that reconnects after a hung daemon waited for ever.
test('destroy() then connect() with a request in flight fails it and the new connection answers (F540)', async () => {
  const s = await standIn('authd-f540-', (c, l, id) => {
    if (id === 1) { return; }                       // the first connection never answers
    if (l.startsWith('PING')) { c.write('OK version=1 schema=1 uptime=1\n'); }
  });
  const a = await new Authd(s.path).connect();
  try {
    const hung = settled(ping(a));
    await new Promise((r) => setTimeout(r, 30));    // written, and unanswered
    a.destroy();
    await a.connect();
    assert.equal(await hung, 'connection-closed', 'the request in flight at destroy() is failed, not left waiting (F540)');
    assert.equal(await settled(ping(a)), 'resolved', 'a request on the new connection is written and answered (F540)');
  } finally {
    a.destroy();
    await s.stop();
  }
});

// F542 (V4-314, review 68): F532's guard looked for a line nobody had asked
// for only when nothing was queued. With a second request waiting, the first
// reply's surplus line was read as the second's answer.
test('a surplus line is not the answer to the request queued behind it (F542)', async () => {
  const s = await standIn('authd-f542-', (c, l) => {
    if (l.startsWith('PING')) { c.write(`OK version=1 schema=1 uptime=1\nOK user=${hexOf('alice')} handle=68 role=user issued=1 expires=2\n`); }
    else if (l.startsWith('VERIFY')) { c.write(`OK user=${hexOf('bob')} handle=68 role=user issued=1 expires=2\n`); }
  });
  const a = await new Authd(s.path).connect();
  try {
    const first = settled(ping(a));
    const second = whose(verify(a, 'bb'));          // queued behind the PING
    assert.equal(await first, 'resolved', 'the request that was asked gets its reply (the canary)');
    assert.equal(await second, 'connection-closed', 'a surplus line ends the connection; it is not the queued request\'s answer (F542)');
  } finally {
    a.destroy();
    await s.stop();
  }
});

// F542, after a list: the same surplus behind an END line.
test('a surplus line after a list is not the answer to the request queued behind it (F542)', async () => {
  const s = await standIn('authd-f542l-', (c, l) => {
    if (l.startsWith('LIST-DEVICES')) { c.write(`OK count=0\nEND\nOK user=${hexOf('alice')} handle=68 role=user issued=1 expires=2\n`); }
    else if (l.startsWith('VERIFY')) { c.write(`OK user=${hexOf('bob')} handle=68 role=user issued=1 expires=2\n`); }
  });
  const a = await new Authd(s.path).connect();
  try {
    const first = settled(listDevices(a, 'alice'));
    const second = whose(verify(a, 'bb'));
    assert.equal(await first, 'resolved', 'the list that was asked for is returned (the canary)');
    assert.equal(await second, 'connection-closed', 'a surplus line after a list ends the connection; it is not the queued request\'s answer (F542)');
  } finally {
    a.destroy();
    await s.stop();
  }
});

// F534: destroy() before the connection is made raised 'close' and no
// 'error', and connect() never settled.
test('connect() settles when the socket is destroyed before it connects (F534)', async () => {
  const s = await standIn('authd-f534-', (c) => c.write('OK version=1 schema=1 uptime=1\n'));
  try {
    const a = new Authd(s.path);
    const p = a.connect();
    a.destroy();
    assert.equal(await settled(p), 'connection-closed', 'connect() rejects when destroyed first, it does not hang (F534)');
    const b = await new Authd(s.path).connect();
    assert.equal(await settled(ping(b)), 'resolved', 'a connection left alone still connects and answers (the canary)');
    b.destroy();
  } finally {
    await s.stop();
  }
});

// F535: a list command answered by one line that is neither OK nor
// `ERR code=` waited for an END that never came, and so did everything
// queued behind it.
test('a list command answered by a line that is not the protocol\'s is refused, not waited on (F535)', async () => {
  let reply = 'ERR internal\n';
  const s = await standIn('authd-f535-', (c) => c.write(reply));
  try {
    for (const line of ['ERR internal\n', 'OKAY\n', 'HTTP/1.1 400 Bad Request\r\n']) {
      reply = line;
      const a = await new Authd(s.path).connect();
      const got = await settled(listDevices(a, 'alice'));
      a.destroy();
      assert.equal(got, 'malformed-response', `a list answered ${JSON.stringify(line)} is refused, not waited on (F535)`);
    }
    reply = `OK count=1\nDEVICE handle=${hexOf('h1')} label=${hexOf('l')} status=active enrolled=1 last_seen=2 fp=ab\nEND\n`;
    const a = await new Authd(s.path).connect();
    const whole = await settled(listDevices(a, 'alice'));
    a.destroy();
    assert.equal(whole, 'resolved', 'a whole list is still a list (the canary)');
  } finally {
    await s.stop();
  }
});

// F536: one login code has one spelling, and a non-string is the caller's
// fault, said as every other refused value is.
test('codeToHex takes exactly the 43 base64url characters of a code (F536)', async () => {
  const { codeToHex } = await import('./authd.mjs');
  const raw = Buffer.alloc(32, 0xfb);
  const url = raw.toString('base64url');
  assert.equal(codeToHex(url), raw.toString('hex'), 'the code as the client prints it (the canary)');
  const refused = (v) => { try { codeToHex(v); return 'accepted'; } catch (e) { return e instanceof AuthdError ? e.code : `threw ${e.constructor.name}`; } };
  for (const [label, v] of [
    ['standard base64 with +/=', raw.toString('base64')],
    ['spaces and a newline inside', ` ${url.slice(0, 10)}\n ${url.slice(10)}`],
    ['other characters inside', `${url.slice(0, 5)}!*$${url.slice(5)}`],
    ['one character short', url.slice(1)],
    ['one character long', `${url}A`],
    ['undefined', undefined],
    ['a number', 5],
    ['an array of 32 numbers', Array(32).fill(0xfb)],
  ]) {
    assert.equal(refused(v), 'bad-request-field', `codeToHex refuses ${label} (F536)`);
  }
});
