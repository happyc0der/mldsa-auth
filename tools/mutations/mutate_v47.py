#!/usr/bin/env python3
"""V4-7 mutations for the store (apps/authd/store/store.c).
Each must make test_authd_store fail on the named check.
Usage: mutate_v47.py <repo> <ID>

S1 is the step's centrepiece: it removes the transaction from the ONE
multi-row operation, so the injected mid-rotation fault leaves the handle with
its old key superseded and no new key -- the half-rotation Req 14 / spec 9.3
forbids. It is killed by the reopen check, not by an in-process assertion,
because the point is durability, not a cached view.

Deliberately NOT mutated: the duplicate-public-key rule. It is enforced twice
-- by pk_exists() in C and by `pk BLOB UNIQUE` in the schema -- so removing
either one alone leaves the other catching it and the mutant survives while the
invariant still holds. That is defense in depth working as intended, not a gap;
it is recorded here rather than papered over with a mutation that proves
nothing.
S6's anchor was re-pointed in V4-9b: V4-9a turned store_consume_login_code into
the _ex form that reports a VERDICT, so the lines S6 patched changed shape. The
property is unchanged and so is its check.

RETIRED, with the reason recorded rather than the line quietly deleted:

  S8 mutated the SQL of the token lookup, which used to filter on expires_at
  and idle_expires_at inside the SELECT. V4-9a rewrote store_verify_token to
  return a VERDICT and to make that decision in C, so the string S8 patched no
  longer exists anywhere -- the runner reported `FATAL apply: anchor for S8
  matched 0 times`, which is exactly what a rotted anchor should do. The
  property it guarded did not disappear with it: v49a's T3 mutates the
  replacement check and is killed by the same assertion, "verify_token past its
  absolute lifetime is EXPIRED". Re-pointing S8 there would have made it a
  duplicate of T3, which proves nothing twice.

S1's anchors were RE-POINTED in V4-9c's bring-up, and how that was found is the
point. V4-9c rewrote store_rotate_key -- it gained the device/user-active
predicate, a caller-supplied clock, an expected-old-key pin and two out-params
-- and S1's anchor text went with it. The step's OWN campaign (v49c) could not
notice: a step runs its own campaign, and v47 is not its own. The nightly
bring-up branch ran v47 against the new tree and turned red, which is the second
time in three steps that the only thing standing between a silently weakened
gate and main was running EVERY campaign rather than the step's.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"
M = {
 # no transaction around the rotation: begin and commit both neutered
 "S1": (ST, [("    store_status_t r = tx_begin(s);\n    if (r != STORE_OK) { return r; }\n\n    int live = 0;",
              "    store_status_t r = STORE_OK; /* MUTATION S1: rotation without a transaction */\n\n    int live = 0;"),
             ("    r = tx_commit(s);\n    if (r == STORE_OK && rotated_at_out != NULL) { *rotated_at_out = now; }\n    return r;",
              "    if (rotated_at_out != NULL) { *rotated_at_out = now; }\n    return r; /* MUTATION S1: no commit */")]),
 # the chain link is not covered by the MAC on append (but is still stored)
 "S2": (ST, [("    uint8_t inbuf[1024];\n    size_t in_len = audit_mac_input(inbuf, sizeof inbuf, prev_mac, seq, at, event,\n                                    user_id, user_id_len, handle, handle_len, detail);",
              "    uint8_t inbuf[1024];\n    uint8_t zprev[STORE_AUDIT_MAC_BYTES]; memset(zprev, 0, sizeof zprev); /* MUTATION S2 */\n    size_t in_len = audit_mac_input(inbuf, sizeof inbuf, zprev, seq, at, event,\n                                    user_id, user_id_len, handle, handle_len, detail);")]),
 # the lookup stops checking that the USER is active (invariant 3, one join short)
 "S3": (ST, [("            \"   AND d.status='active' AND u.status='active' LIMIT 1;\",",
              "            \"   AND d.status='active' LIMIT 1;\", /* MUTATION S3 */")]),
 # disabling a user no longer drops that user's tokens
 "S4": (ST, [("    return set_user_status(s, user_id, user_id_len, \"disabled\", by, reason, reason_len, 1, \"user-disable\");",
              "    return set_user_status(s, user_id, user_id_len, \"disabled\", by, reason, reason_len, 0, \"user-disable\"); /* MUTATION S4 */")]),
 # revoking a device no longer deletes its tokens (&st is unique to revoke)
 "S5": (ST, [("\"DELETE FROM tokens WHERE handle=?1;\", -1, &st, NULL)",
              "\"DELETE FROM tokens WHERE handle=?1 AND 0;\", -1, &st, NULL) /* MUTATION S5 */")]),
 # the login code is no longer bound to the `state` it was issued against
 "S6": (ST, [("    if (n_state != STORE_HASH_BYTES ||\n        sodium_memcmp(stored_state, state_hash, STORE_HASH_BYTES) != 0) {\n        tx_rollback(s);\n        *verdict = STORE_CODE_STATE_MISMATCH;   /* the login-CSRF binding (Req 5) */\n        return STORE_OK;\n    }",
              "    if (0) {\n        tx_rollback(s);\n        *verdict = STORE_CODE_STATE_MISMATCH;\n        return STORE_OK;\n    } /* MUTATION S6: state binding off */")]),
 # a consumed login code is never marked used, so it is replayable
 "S7": (ST, [("\"UPDATE login_codes SET used_at=?2 WHERE code_hash=?1;\"",
              "\"UPDATE login_codes SET used_at=?2 WHERE code_hash=?1 AND 0;\" /* MUTATION S7 */")]),
 # token verification ignores both expiry columns
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
