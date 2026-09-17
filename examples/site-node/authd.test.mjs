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
import { existsSync } from 'node:fs';

import { Authd, AuthdError, exchange, verify, logout, ping, listDevices } from './authd.mjs';

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

async function withDaemon(fn) {
  const { proc, info } = await startDaemon();
  const authd = await new Authd(info.sock).connect();
  try {
    await fn(authd, info);
  } finally {
    authd.close();
    proc.kill('SIGKILL');
  }
}

if (!FIXTURE || !existsSync(FIXTURE)) {
  skip('AUTHD_FIXTURE is not set or not built: build the project first (cmake --build build)');
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

  test('a malformed login code is rejected client-side, before any socket write', async () => {
    await withDaemon(async (authd) => {
      await assert.rejects(() => exchange(authd, 'AAAA', ''), /32 bytes/);
    });
  });
}
