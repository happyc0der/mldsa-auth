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
