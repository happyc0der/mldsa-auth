/*
 * The stub site for tests/authd_e2e.sh.
 *
 * It is the SITE half of milestone A: it takes the login code a human pasted
 * out of `authd_client login`, exchanges it for a token over site.sock, and
 * verifies that token -- using examples/site-node/authd.mjs unchanged, because
 * the point is to exercise the handler a real site would import rather than a
 * second implementation written to agree with it.
 *
 *   node e2e_site.mjs <site.sock> <code-base64url>
 *   node e2e_site.mjs <site.sock> --revoke <handle>
 *   node e2e_site.mjs <site.sock> --recover-all <user> <recovery-code>
 *   node e2e_site.mjs <site.sock> --hold <code-base64url> <dir>
 *
 * The second form is the site's REVOKE-DEVICE (spec §8, Req 9): the device
 * and its key are revoked and its live sessions closed. authd_admin has no
 * revoke command -- revoking a device is the site's call -- so this is how
 * the e2e drives it (V4-15a).
 *
 * The third is RECOVERY-USE with `revoke: 'all'` (spec §10.3), the stolen-
 * device recovery, through the library's own recoveryUse: every device the
 * user has is revoked in the same transaction that spends the code (V4-22a).
 * The ticket it returns is a secret and is not printed.
 *
 * The fourth holds a token across a daemon restart (V4-127, F210): it
 * exchanges the code, verifies the token, closes its connection and creates
 * <dir>/hold.ready; when <dir>/hold.down appears it tries the (stopped)
 * daemon, records how that failed and creates <dir>/hold.down.seen; when
 * <dir>/hold.up appears it verifies the SAME token again and logs it out.
 * The token is not printed.
 *
 * Prints one JSON line on stdout and exits 0, or a reason on stderr and exits 1.
 */
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Authd, AuthdError, exchange, verify, logout, recoveryUse } from '../examples/site-node/authd.mjs';

const [sock, code, revokeHandle, recoveryCode] = process.argv.slice(2);
if (!sock || !code || (code === '--revoke' && !revokeHandle) ||
    (code === '--recover-all' && (!revokeHandle || !recoveryCode)) ||
    (code === '--hold' && (!revokeHandle || !recoveryCode))) {
  console.error('usage: e2e_site.mjs <site.sock> <code-base64url>\n' +
                '       e2e_site.mjs <site.sock> --revoke <handle>\n' +
                '       e2e_site.mjs <site.sock> --recover-all <user> <recovery-code>\n' +
                '       e2e_site.mjs <site.sock> --hold <code-base64url> <dir>');
  process.exit(2);
}

let authd;
try {
  authd = await new Authd(sock).connect();

  if (code === '--revoke') {
    const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
    const lines = await authd.request('REVOKE-DEVICE', { handle: hex(revokeHandle), reason: hex('e2e') });
    if (!(lines[0] ?? '').startsWith('OK')) {
      throw new Error(`REVOKE-DEVICE answered ${lines[0]}`);
    }
    console.log(JSON.stringify({ revoked: revokeHandle }));
    process.exit(0);
  }

  if (code === '--recover-all') {
    const { ticket } = await recoveryUse(authd, revokeHandle, recoveryCode, { revoke: 'all' });
    if (!/^[0-9a-f]{64}$/.test(ticket)) {
      throw new Error('RECOVERY-USE revoke=all returned no ticket');
    }
    console.log(JSON.stringify({ recovered_all: revokeHandle }));
    process.exit(0);
  }

  if (code === '--hold') {
    const dir = recoveryCode;
    const appears = async (name) => {
      for (let i = 0; i < 1200; i++) {
        if (existsSync(join(dir, name))) { return; }
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error(`${name} never appeared`);
    };
    const session = await exchange(authd, revokeHandle, '');
    await verify(authd, session.token);
    authd.close();                // an open site connection would hold the daemon's drain
    authd = undefined;
    writeFileSync(join(dir, 'hold.ready'), '');
    await appears('hold.down');
    let whileDown = 'answered';
    try { (await new Authd(sock).connect()).close(); }
    catch (e) { whileDown = e instanceof AuthdError ? `authd-${e.code}` : String(e.code); }
    writeFileSync(join(dir, 'hold.down.seen'), '');
    await appears('hold.up');
    authd = await new Authd(sock).connect();
    const again = await verify(authd, session.token);
    if (again.handle !== session.handle) { throw new Error('VERIFY after the restart named another device'); }
    await logout(authd, session.token);
    console.log(JSON.stringify({ held: again.user, handle: again.handle, while_down: whileDown }));
    process.exit(0);
  }

  /* Milestone A's raw and Unix protocol listeners bind SHA-256("") as the
   * state, because `state` rides the WebSocket URL and those listeners have no
   * URL. V4-10 makes it real. */
  const session = await exchange(authd, code, '');
  const checked = await verify(authd, session.token);

  if (checked.handle !== session.handle || checked.user !== session.user) {
    throw new Error('VERIFY disagreed with EXCHANGE about who this is');
  }
  /* A login code is single-use (Req 5). Proving the second attempt fails is
   * the difference between "the exchange worked" and "the exchange worked
   * once", and only the second is the property. */
  let reused = null;
  try {
    await exchange(authd, code, '');
  } catch (e) {
    reused = e.code ?? 'no-code';
  }
  if (reused !== 'used') {
    throw new Error(`a reused login code gave ${reused}, expected code=used`);
  }

  const deleted = await logout(authd, session.token);
  if (!deleted) {
    throw new Error('LOGOUT did not delete the token it was given');
  }
  let after = null;
  try {
    await verify(authd, session.token);
  } catch (e) {
    after = e.code ?? 'no-code';
  }
  if (after !== 'unknown') {
    throw new Error(`VERIFY after LOGOUT gave ${after}, expected code=unknown`);
  }

  // `issued` is the daemon's own clock at EXCHANGE (V4-36): authd_e2e compares
  // two of them, seconds apart, to see the real daemon's clock advance.
  console.log(JSON.stringify({ user: session.user, handle: session.handle,
                               role: session.role, ttl: session.expires - session.issued,
                               issued: session.issued }));
  process.exit(0);
} catch (e) {
  console.error(`site: ${e.message}${e.code ? ` (code=${e.code})` : ''}`);
  process.exit(1);
} finally {
  authd?.close();
}
