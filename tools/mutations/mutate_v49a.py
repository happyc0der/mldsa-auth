#!/usr/bin/env python3
"""V4-9a mutations for the local API and tokens.
Each must make test_authd_localapi fail on the named check.
Usage: mutate_v49a.py <repo> <ID>

A1 is the one Req 11 rests on: it serves the ADMIN table on the site socket.
Nothing about the site socket's own behaviour changes, so only a test that
asks for an administrative command on it can see the difference -- which is
why that test exists and why the refusal is indistinguishable from an unknown
command.

Not mutated, because it is UNREPRESENTABLE rather than merely correct: "log
the token" and "log the login code". authd_log.h still offers no function that
takes an arbitrary buffer -- authd_log_fp is fixed at 32 bytes by its
prototype -- so there is no edit to localapi.c that leaks either to the
journal without also changing the logging API."""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LA = "apps/authd/localapi.c"
TK = "apps/authd/tokens.c"
ST = "apps/authd/store/store.c"
M = {
 # the token is stored in the clear instead of as SHA-256 (Req 4)
 "T1": (TK, [("    crypto_hash_sha256(token_hash, token_out, TOKEN_BYTES);",
              "    memcpy(token_hash, token_out, STORE_HASH_BYTES); /* MUTATION T1: token unhashed */")]),
 # VERIFY never slides the idle window, so a busy session dies on the idle clock
 "T2": (LA, [("        (void)store_verify_token(app->store, token_hash, app->now_unix,\n                                 tokens_idle_ttl_s(info.role), &v, &info);",
              "        /* MUTATION T2: idle window never refreshed */")]),
 # the absolute lifetime stops being enforced
 "T3": (ST, [("    if (now >= expires) {\n        *verdict = STORE_TOKEN_EXPIRED;\n        return STORE_OK;\n    }",
              "    if (0) {\n        *verdict = STORE_TOKEN_EXPIRED;\n        return STORE_OK;\n    } /* MUTATION T3 */")]),
 # LOGOUT reports success without deleting anything
 "T4": (LA, [("    const store_status_t s = store_delete_token(app->store, token_hash, &n);",
              "    const store_status_t s = STORE_OK; n = 1u; /* MUTATION T4: logout deletes nothing */")]),
 # the sweep never removes anything
 "T5": (ST, [('    if ((r = sweep_one(s, "DELETE FROM tokens WHERE expires_at<=?1 OR idle_expires_at<=?1;",\n                       now, &counts->tokens)) == STORE_OK &&\n        (r = sweep_one(s, "DELETE FROM login_codes WHERE expires_at<=?1;",\n                       now, &counts->login_codes)) == STORE_OK) {\n        r = sweep_one(s, "DELETE FROM enroll_tickets WHERE expires_at<=?1;", now, &counts->tickets);\n    }',
              '    r = STORE_OK; /* MUTATION T5: sweep removes nothing */')]),
 # the admin table is served on the site socket (Req 11)
 "A1": (LA, [("    const entry_t *table = slot->is_admin ? ADMIN_TABLE : SITE_TABLE;\n    const size_t n = slot->is_admin ? (sizeof ADMIN_TABLE / sizeof ADMIN_TABLE[0])\n                                    : (sizeof SITE_TABLE / sizeof SITE_TABLE[0]);",
              "    const entry_t *table = ADMIN_TABLE; /* MUTATION A1: admin table everywhere */\n    const size_t n = sizeof ADMIN_TABLE / sizeof ADMIN_TABLE[0];")]),
 # requests are logged without the peer's uid and pid (spec 8)
 "A2": (LA, [('    authd_log_local(AUTHD_LOG_INFO, "local-request", req.cmd, slot->peer.uid, slot->peer.pid,\n                    slot->is_admin ? "admin" : "site");',
              '    /* MUTATION A2: request not logged with uid/pid */')]),
 # a duplicate key is accepted, last one winning
 "X1": (LA, [("        for (size_t j = 0; j < r->n_kv; j++) {\n            if (r->kv[j].key_len == klen && memcmp(r->kv[j].key, tok, klen) == 0) {\n                return -1;                   /* duplicate key */\n            }\n        }",
              "        /* MUTATION X1: duplicate keys allowed */")]),
 # unknown keys are ignored rather than refused
 "X2": (LA, [("        if (!ok) {\n            return 0;\n        }\n    }\n    return 1;\n}",
              "        (void)ok;\n    }\n    return 1; /* MUTATION X2: unknown keys ignored */\n}")]),
 # revoking a device leaves its live sessions running (Req 9)
 "V1": (LA, [("    const size_t closed = authd_app_close_handle(app, handle, handle_len);",
              "    const size_t closed = 0u; /* MUTATION V1: live sessions left open */")]),
 # a byte-identical re-enrollment is not reported as idempotent
 "V2": (LA, [("        if (sodium_memcmp(cur, pk, STORE_PK_BYTES) == 0) {\n            idempotent = 1;",
              "        if (0) {\n            idempotent = 1; /* MUTATION V2 */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
