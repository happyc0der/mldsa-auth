#!/usr/bin/env python3
"""V4-8b mutations for the daemon's connection state machine.
Each must make test_authd_conn fail on the named check.
Usage: mutate_v48b.py <repo> <ID>

C1 is the one the whole step turns on: without the decoy pin an unknown
identity is refused by the library at accept_client_hello() and never receives
a ServerHello -- which is exactly the enumeration channel spec 7.3 exists to
close, and exactly what the uniform-responder test measures.

Not mutated, because it is UNREPRESENTABLE rather than merely correct: "log
the login code". authd_log.h offers no function that takes a byte buffer, so
there is no edit to authd_conn.c that would leak the code to the log without
also changing the logging API. That is the point of shaping the API that way,
and it is recorded here so nobody adds a mutation for it and concludes the
gate is missing.

C8 (the `c->decoy || c->user_id_len == 0` guard before a code is issued) is
also ABSENT, as a documented EQUIVALENT MUTANT in the sense N7 and v48a's D7
are. The guard is genuine defense in depth, but it protects a state the rest
of the design makes unreachable: a decoy pin has no secret key, so no sig_A
over it can ever verify, and store_lookup_active never returns OK with an
empty user id. Nothing reachable through the daemon's own interface can
distinguish its removal, and a documented survivor must not be a pass
criterion. The guard stays in the code."""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
CN = "apps/authd/authd_conn.c"
M = {
 # the decoy is never pinned: an unknown identity is refused outright
 "C1": (CN, [("        c->decoy = 1;\n        c->user_id_len = 0;\n        app->decoy_pins++;",
              "        c->decoy = 1;\n        c->user_id_len = 0;\n        app->decoy_pins++;\n        return EV_ACTION_CLOSE; /* MUTATION C1: no decoy, unknown id refused */")]),
 # the login code is stored in the clear instead of as SHA-256 (Req 4)
 "C2": (CN, [("    crypto_hash_sha256(code_hash, m.code, sizeof m.code);",
              "    memcpy(code_hash, m.code, sizeof code_hash); /* MUTATION C2: code stored unhashed */")]),
 # the code lives for an hour instead of Req 5's 60-second ceiling
 "C3": (CN, [("    m.code_expires = (uint64_t)(app->now_unix + (int64_t)app->code_ttl_s);",
              "    m.code_expires = (uint64_t)(app->now_unix + 3600); /* MUTATION C3: TTL far over Req 5 */")]),
 # the code is not bound to `state`: login-CSRF at the exchange
 "C4": (CN, [("    crypto_hash_sha256(state_hash, (const uint8_t *)\"\", 0u);",
              "    memset(state_hash, 0, sizeof state_hash); /* MUTATION C4: state binding broken */")]),
 # the confirmation record is empty, as in the demo -- no login code at all
 "C5": (CN, [("        if (authmsg_encode_login_code(content, sizeof content, &n, &m) == AUTHMSG_OK &&\n            queue_sealed(slot, &c->sess, content, n) == 0) {",
              "        n = 0; /* MUTATION C5: empty confirmation record */\n        if (queue_sealed(slot, &c->sess, content, n) == 0) {")]),
 # a released connection keeps its handshake (and its ledger entry)
 "C6": (CN, [("    if (c->hs_live) {\n        handshake_ctx_wipe(&c->hs);\n        c->hs_live = 0;\n    }",
              "    /* MUTATION C6: handshake not wiped on release */")]),
 # anything after the login code is served rather than refused
 "C7": (CN, [("    return fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED,\n                           (op == AUTHMSG_OP_ROTATE) ? \"rotate-not-implemented\" : \"op-not-permitted\");",
              "    (void)op; return EV_ACTION_CONTINUE; /* MUTATION C7: unexpected op served */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
