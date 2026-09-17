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
 *
 * Prints one JSON line on stdout and exits 0, or a reason on stderr and exits 1.
 */
import { Authd, exchange, verify, logout } from '../examples/site-node/authd.mjs';

const [sock, code] = process.argv.slice(2);
if (!sock || !code) {
  console.error('usage: e2e_site.mjs <site.sock> <code-base64url>');
  process.exit(2);
}

let authd;
try {
  authd = await new Authd(sock).connect();

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

  console.log(JSON.stringify({ user: session.user, handle: session.handle,
                               role: session.role, ttl: session.expires - session.issued }));
  process.exit(0);
} catch (e) {
  console.error(`site: ${e.message}${e.code ? ` (code=${e.code})` : ''}`);
  process.exit(1);
} finally {
  authd?.close();
}
