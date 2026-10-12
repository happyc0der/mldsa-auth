#!/usr/bin/env python3
"""V4-22c mutations: a fault on every write (CLAIMS D14).

Usage: mutate_v66.py <repo> <ID>

Two-letter IDs: FW = V4-22c's Fault on every Write. Every mutation changes a
value and keeps every use (F79), and every spec line names the check that must
catch it (F90). Both passed V4-22b's whole suite: neither primitive had a
fault point, and nothing else fails one of their writes.

    FW1   store_recovery_replace commits after superseding the old codes and
          begins again before inserting the new ones (the GA15-19 shape). A
          fault on an insert then leaves the user with every old code spent
          and no new one -- the sweep sees the committed database change
          after the fault at write 1.
    FW2   one of store_add_token's error paths returns without tx_rollback.
          Nothing is committed, so the database looks unchanged after the
          fault -- but the transaction stays open, and the sweep's NEXT
          attempt on the same handle fails with the fault unfired. Reopening
          the store between attempts would have hidden it.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"

M = {
 "FW1": (ST, [("    for (size_t i = 0; i < n && r == STORE_OK; i++) {",
               "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION FW1 */\n"
               "    for (size_t i = 0; i < n && r == STORE_OK; i++) {")]),
 "FW2": (ST, [("        sqlite3_bind_int64(st, 7, idle_expires_at) != SQLITE_OK) {\n"
               "        r = STORE_ERR_DB;\n"
               "    } else {\n"
               "        int rc = sqlite3_step(st);\n"
               "        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }\n"
               "        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }",
               "        sqlite3_bind_int64(st, 7, idle_expires_at) != SQLITE_OK) {\n"
               "        r = STORE_ERR_DB;\n"
               "    } else {\n"
               "        int rc = sqlite3_step(st);\n"
               "        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }\n"
               "        else if (rc != SQLITE_DONE)  { sqlite3_finalize(st); return STORE_ERR_DB; } /* MUTATION FW2 */")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID}")
