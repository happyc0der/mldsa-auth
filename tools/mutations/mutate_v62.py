#!/usr/bin/env python3
"""V4-20 mutations: an audit row's clock (F45) and whose handle it is (F48).

Usage: mutate_v62.py <repo> <ID>

Two-letter IDs: AO = V4-20's Audit clock and Ownership. Every mutation changes
a value and keeps every use (F79), and every spec line names the check that
must catch it (F90).

  F45 -- an audit row is stamped with its transaction's clock (store.c)
    AO1   audit_append reads the wall clock again, whatever `now` it is given
    AO2   revoke=all revokes each device on the wall clock, not the recovery's
    AO3   the rotation's audit row alone is stamped with the wall clock
  F48 -- only the handle's own user re-enrolls it idempotently
    AO4   the store's ownership query matches every user (store.c); seen at
          the store, and through the daemon on via=recovery, which reaches
          only the store
    AO5   the daemon's pre-check keeps idempotent=1 on an owner mismatch
          (localapi.c); the store would refuse it, but the pre-check answers
          first -- so only the site-path checks can see this one

AO4 and AO5 together show that both layers carry the fix: neither is an
equivalent mutant of the other.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"
LA = "apps/authd/localapi.c"

M = {
 "AO1": (ST, [("    int64_t at = now;",
               "    int64_t at = (now > 0) ? now_unix() : now; /* MUTATION AO1 */")]),
 "AO2": (ST, [('                                 (const uint8_t *)"recovery revoke=all", 19u, now);',
               '                                 (const uint8_t *)"recovery revoke=all", 19u, now_unix()); /* MUTATION AO2 */')]),
 "AO3": (ST, [('                     handle, handle_len, drop_tokens ? "tokens-dropped" : "tokens-kept", now);',
               '                     handle, handle_len, drop_tokens ? "tokens-dropped" : "tokens-kept", now_unix()); /* MUTATION AO3 */')]),
 "AO4": (ST, [('            "SELECT 1 FROM devices WHERE handle=?1 AND user_id=?2 LIMIT 1;",',
               '            "SELECT 1 FROM devices WHERE handle=?1 AND (user_id=?2 OR 1) LIMIT 1;", /* MUTATION AO4 */')]),
 "AO5": (LA, [("            if (owner_len != user_len || sodium_memcmp(owner, user, user_len) != 0) {\n"
               "                idempotent = 0;",
               "            if (owner_len != user_len || sodium_memcmp(owner, user, user_len) != 0) {\n"
               "                idempotent = 1; /* MUTATION AO5 */")]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
