#!/usr/bin/env python3
"""V4-9c mutations for key rotation.
Usage: mutate_v49c.py <repo> <ID>

Letter W: R is already taken by v27 and v49b, and while IDs only have to be
unique within a spec file, a campaign log that says "R1" twice is a campaign
log nobody can grep.

Two things about ROTATE make its mutations unusual.

FIRST, the digest cannot be tested by a round trip. The client that signs and
the daemon that verifies share ONE implementation (authmsg_rotate_digest), so
any error in it moves both sides together and they still agree. W2 and W5
mutate fields out of the digest and are killed only by the hand-built literal
vector in test_authd_conn, or by a test that transmits something different from
what was signed. A "rotation works end to end" test kills neither.

SECOND, several of the spec's acceptance steps are subsumed. pk_exists is
`SELECT 1 FROM device_keys WHERE pk=?1` across ALL states, so it already covers
both "pk_new unused anywhere" and, because pk_old is a row, "pk_new != pk_old".
A daemon-side pre-check for either would be a branch no end-to-end test could
distinguish -- delete it and the request still fails, with the same coarse code,
closing the same way. So the daemon has neither, and neither is mutated. That
is the v48a-D7 / v48b-C8 register: a documented equivalent mutant is recorded,
not campaigned.

NOT MUTATED, and the reason stated rather than left implied:

  * "the ROTATE body is not wiped after dispatch". on_record has ONE exit and
    ONE sodium_memzero precisely so this cannot be forgotten per-branch -- but
    that also means nothing observable changes when the single wipe is removed:
    the buffer is a local that goes out of scope, and no test can read it. The
    single-exit shape is the mitigation; a mutation here would be unkillable.

  * "sodium_memcmp -> memcmp on the handle". No functional test can tell them
    apart, and tools/audit/constant_time_inventory.sh is a report, not a gate.
    Declared, not campaigned.

RETIRED AFTER THE FIRST RUN, with the reason recorded rather than the line
quietly deleted:

  W6 removed the explicit handle-equality check and SURVIVED. The reason is a
  property worth having: the daemon digests `c->handle` -- the handle that
  AUTHENTICATED this session -- not `m.handle` from the message. A ROTATE
  naming a different handle therefore produces a digest over the session's
  handle, which the peer's signature (made over the handle it named) cannot
  match, so it is rejected one step later by sig_old. The handle binding is
  CRYPTOGRAPHIC, not a comparison; the explicit check is defence in depth and a
  clearer journal line, and no test can distinguish its absence. The check
  stays in the code. Same register as v48a's D7 and v48b's C8.

  The mutation that WOULD be meaningful here -- digesting `m.handle` instead of
  `c->handle` -- is not a defect in the current code but a different design,
  and one that breaks the binding rather than merely duplicating it.

W15 pins a defect that was FOUND BY RUNNING THE THING, not by reading it: the
first working `rotate` left the device's own .pub naming the superseded key (and
wrote the new one into the SERVER's directory). Nothing in a C test could see
it -- the rotation succeeds, the daemon is correct, the next login works. Only
the end-to-end script, which compares the .pub's fingerprint against what the
store reports, can. It is the one v49c mutation killed by authd_e2e.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
AM = "apps/authd/authmsg.c"
CN = "apps/authd/authd_conn.c"
ST = "apps/authd/store/store.c"
CL = "apps/authd/authd_cli.c"
CC = "apps/authd/client_core.c"
M = {
 # flags leaves the signed tuple, so changing it after signing goes unnoticed
 "W1": (AM, [("    (void)crypto_hash_sha256_update(&st, &flags, 1u);",
              "    /* MUTATION W1: flags not bound into the digest */")]),
 # the label stops separating the two signatures
 "W2": (AM, [("    (void)crypto_hash_sha256_update(&st, (const unsigned char *)label, strlen(label));",
              "    (void)crypto_hash_sha256_update(&st, (const unsigned char *)\"x\", 1u); /* MUTATION W2 */")]),
 # sig_new verified against the OLD key: no proof of possession of the incoming key
 "W3": (CN, [("    if (mldsa_verify(digest, sizeof digest, m.sig_new, m.sig_new_len, m.pk_new) != 0) {",
              "    if (mldsa_verify(digest, sizeof digest, m.sig_new, m.sig_new_len, pk_old) != 0) { /* MUTATION W3 */")]),
 # the store no longer pins WHICH key is being replaced
 "W4": (CN, [("                                                   m.pk_new, pk_old, c->handshake_id,",
              "                                                   m.pk_new, NULL, c->handshake_id, /* MUTATION W4 */")]),
 # handshake_id leaves the digest, so a captured ROTATE replays
 "W5": (AM, [("    (void)crypto_hash_sha256_update(&st, handshake_id, AUTHMSG_HANDSHAKE_ID_BYTES);",
              "    /* MUTATION W5: handshake_id not bound into the digest */")]),
 # the handle in the message is no longer required to be the authenticated one
 "W6": (CN, [("    if (m.handle_len != c->handle_len ||\n        sodium_memcmp(m.handle, c->handle, c->handle_len) != 0) {",
              "    if (0) { /* MUTATION W6: any handle accepted */")]),
 # the device/user active predicate leaves the transaction
 "W7": (ST, [("    r = device_and_user_active(s, handle, handle_len, &live);\n    if (r != STORE_OK) { tx_rollback(s); return r; }",
              "    live = 1; /* MUTATION W7: revoked and disabled can rotate */")]),
 # the store stamps its own wall clock again instead of the caller's
 "W8": (ST, [("    if (r == STORE_OK && rotated_at_out != NULL) { *rotated_at_out = now; }",
              "    if (r == STORE_OK && rotated_at_out != NULL) { *rotated_at_out = now_unix(); } /* MUTATION W8 */")]),
 # a session may rotate more than once
 "W9": (CN, [("    if (c->rotated) {\n        return fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED, \"rotate-already-done\");\n    }",
              "    /* MUTATION W9: unlimited rotations per session */")]),
 # "that key is already enrolled" gets its own code, and becomes an oracle
 "W11": (CN, [("            why = (rs == STORE_ERR_DB) ? \"rotate-store-error\" : \"rotate-store-refused\";\n            if (rs == STORE_ERR_DB) { code = AUTHMSG_ERR_INTERNAL; }",
               "            why = \"rotate-store-refused\";\n            code = (rs == STORE_ERR_CONFLICT) ? AUTHMSG_ERR_RATE_LIMITED : AUTHMSG_ERR_REJECTED; /* MUTATION W11 */")]),
 # the login code reaches the journal through the fingerprint sink
 "W12": (CN, [("    randombytes_buf(m.code, sizeof m.code);",
               "    randombytes_buf(m.code, sizeof m.code);\n    authd_log_fp(AUTHD_LOG_INFO, \"login-code\", m.code); /* MUTATION W12 */")]),
 # the decoder stops requiring full consumption
 "W13": (AM, [("    if (o != len) {\n        return AUTHMSG_ERR_BAD_LENGTH;\n    }",
               "    if (o > len) {\n        return AUTHMSG_ERR_BAD_LENGTH;\n    } /* MUTATION W13: trailing bytes tolerated */")]),
 # a failed probe is taken as licence to delete the other key
 # V4-13a: moved with client_key_plan into client_core.c, and RE-AUTHORED.
 # The original replacement (`if (next_present)`) left next_ok unused, so
 # -Werror refused to build it and W14 scored KILLED(compile) every night
 # since V4-9c without a test ever running against it (audit F79). This form
 # compiles -- next_ok is still read, just no longer decides anything.
 "W14": (CC, [("    if (next_present && next_ok) {\n        return KEY_PLAN_PROMOTE_NEXT;\n    }\n    return KEY_PLAN_REFUSE;",
               "    if (next_present && next_ok >= 0) {\n        return KEY_PLAN_PROMOTE_NEXT;   /* MUTATION W14 */\n    }\n    return KEY_PLAN_REFUSE;")]),
 # rotate leaves the device's .pub naming the superseded key
 "W15": (CL, [("        if (rename(pub_tmp, pub_path) != 0) {\n            fprintf(stderr, \"%s rotate: the key rotated but %s could not be updated; \"\n                            \"it still names the OLD key\\n\", prog, pub_path);\n        }",
               "        /* MUTATION W15: the device .pub is never updated */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
