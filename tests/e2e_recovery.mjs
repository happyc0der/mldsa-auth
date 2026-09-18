/*
 * The recovery half of tests/authd_e2e.sh (spec §10.3).
 *
 * There is deliberately no CLI for recovery -- §13 gives neither authd_admin
 * nor authd_client a subcommand for it, because the SITE drives recovery, not
 * an operator at a terminal. So this exercises the same path a real site
 * takes: examples/site-node/authd.mjs, unchanged.
 *
 *   node e2e_recovery.mjs <site.sock> <user> <first.pub> <first-handle> \
 *                        <new-handle> <new-device.pub> <codes-out> <operator>
 *
 * <codes-out> receives the issued plaintext codes, one per line, so the shell
 * can prove they never reached the daemon's journal. That file is the only
 * place they are written, and it lives in the test's temporary directory.
 *
 * Prints one JSON line on stdout and exits 0, or a reason on stderr and exits 1.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';
import { Authd, recoveryIssue, recoveryUse, enroll, AuthdError } from '../examples/site-node/authd.mjs';

const [sock, user, firstPub, firstHandle, handle, pubPath, codesOut, operator] = process.argv.slice(2);
if (!sock || !user || !firstPub || !firstHandle || !handle || !pubPath || !codesOut || !operator) {
  console.error('usage: e2e_recovery.mjs <site.sock> <user> <first.pub> <first-handle> ' +
                '<new-handle> <new-device.pub> <codes-out> <operator>');
  process.exit(2);
}

/* demo_keys.h: "MLDSAPK1" || id_len(1) || id || public_key(1952) */
function publicKeyFromFile(path) {
  const b = readFileSync(path);
  if (b.length < 9 || b.subarray(0, 8).toString('latin1') !== 'MLDSAPK1') {
    throw new Error(`${path} is not an MLDSAPK1 file`);
  }
  const idLen = b[8];
  const pk = b.subarray(9 + idLen);
  if (pk.length !== 1952) { throw new Error(`public key is ${pk.length} bytes, expected 1952`); }
  return pk;
}

/* How a human actually retypes a code off paper: lower case, in groups, and
 * with the letter O for the digit zero. The daemon normalises; a site that
 * "helpfully" normalised differently would lock its own users out, which is
 * why this passes the mangled form through verbatim. */
function mangle(code) {
  let out = '';
  for (let i = 0; i < code.length; i++) {
    if (i > 0 && i % 4 === 0) { out += '-'; }
    let c = code[i].toLowerCase();
    if (c === '0') { c = 'o'; }
    if (c === '1') { c = 'l'; }
    out += c;
  }
  return out;
}

let authd;
try {
  authd = await new Authd(sock).connect();

  /* A site-driven enrollment, which also creates the user (spec 10.1: the site
   * is the trusted enroller). This is an ordinary `user`, not an operator --
   * see the operator check at the end for why that distinction matters. */
  await enroll(authd, { user, handle: firstHandle, pk: publicKeyFromFile(firstPub), label: 'first' });

  const codes = await recoveryIssue(authd, user, 2);
  if (codes.length !== 2) { throw new Error(`expected 2 codes, got ${codes.length}`); }
  writeFileSync(codesOut, codes.join('\n') + '\n', { mode: 0o600 });
  for (const c of codes) {
    if (!/^[0-9A-HJKMNP-TV-Z]{16}$/.test(c)) {
      throw new Error(`code is not 16 Crockford base32 characters: ${c}`);
    }
  }

  /* A wrong code must be refused before anything else is believed. */
  let wrongRejected = null;
  try {
    await recoveryUse(authd, user, '0000000000000000');
  } catch (e) {
    wrongRejected = e instanceof AuthdError ? e.code : String(e);
  }
  if (wrongRejected !== 'invalid') {
    throw new Error(`a wrong recovery code gave ${wrongRejected}, expected invalid`);
  }

  const typed = mangle(codes[0]);
  if (typed === codes[0]) { throw new Error('the mangled code did not actually differ'); }
  const { ticket, expires } = await recoveryUse(authd, user, typed);
  if (!/^[0-9a-f]{64}$/.test(ticket)) { throw new Error(`ticket is not 32 bytes of hex: ${ticket}`); }

  /* The ticket enrolls the replacement device. */
  const pk = publicKeyFromFile(pubPath);
  const { fp } = await enroll(authd, { user, handle, pk, label: 'recovered', ticket });
  if (!/^[0-9a-f]{64}$/.test(fp)) { throw new Error(`enroll returned no fingerprint: ${fp}`); }

  /* ...once. */
  let reuse = null;
  try {
    await enroll(authd, { user, handle: handle.replace(/.$/, '9'), pk, ticket });
  } catch (e) {
    reuse = e instanceof AuthdError ? e.code : String(e);
  }
  if (reuse !== 'ticket-invalid') {
    throw new Error(`a reused ticket gave ${reuse}, expected ticket-invalid`);
  }

  /* And the spent code cannot be spent again. */
  let respend = null;
  try {
    await recoveryUse(authd, user, codes[0]);
  } catch (e) {
    respend = e instanceof AuthdError ? e.code : String(e);
  }
  if (respend !== 'invalid') {
    throw new Error(`a spent code gave ${respend}, expected invalid`);
  }

  /* Req 11 extended to recovery: an OPERATOR's codes must not be mintable from
   * the site socket. Without this the site could issue itself an operator's
   * recovery codes and redeem the ticket for a device it controls -- the same
   * escalation that keeping ENROLL-OPERATOR out of the site table prevents. */
  let opRefused = null;
  try {
    await recoveryIssue(authd, operator, 1);
  } catch (e) {
    opRefused = e instanceof AuthdError ? e.code : String(e);
  }
  if (opRefused !== 'not-permitted') {
    throw new Error(`RECOVERY-ISSUE for an operator on site.sock gave ${opRefused}, ` +
                    'expected not-permitted');
  }

  console.log(JSON.stringify({
    ok: true, issued: codes.length, fp, expires,
    mangled_accepted: true, ticket_single_use: true, code_single_use: true,
    operator_recovery_refused_on_site: true,
  }));
  process.exit(0);
} catch (err) {
  console.error(String(err && err.message ? err.message : err));
  process.exit(1);
} finally {
  if (authd) { try { authd.close(); } catch { /* closing is best-effort */ } }
}
