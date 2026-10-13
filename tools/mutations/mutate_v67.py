#!/usr/bin/env python3
"""V4-23 mutations: a failed COMMIT is rolled back (audit F112, CLAIMS D14).

Usage: mutate_v67.py <repo> <ID>

Two-letter IDs: FC = V4-23's Failed Commit. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90). Both passed V4-22c's whole suite: nothing before V4-23 failed a COMMIT.

    FC1   tx_commit no longer rolls back when COMMIT fails -- F112 restored.
          The commit hook fails a COMMIT with its transaction still open, as
          SQLite leaves it on SQLITE_BUSY; the handle then stays inside it, a
          second store cannot take the write lock, and the same handle's next
          BEGIN fails. Every one of the 18 commit checks fails.
    FC2   Req 7's refusal path commits with a raw exec_simple("COMMIT;"),
          around tx_commit, so that one path keeps F112. The commit hook
          lives in tx_commit and never fires: only commit(enroll-req7) fails,
          naming a call that reached no COMMIT through the helper.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"

M = {
 "FC1": (ST, [("    if (STORE_COMMIT_FAULT() || exec_simple(s->db, \"COMMIT;\") != STORE_OK) {\n"
               "        tx_rollback(s);\n",
               "    if (STORE_COMMIT_FAULT() || exec_simple(s->db, \"COMMIT;\") != STORE_OK) {\n"
               "        (void)s; /* MUTATION FC1 */\n")]),
 "FC2": (ST, [("        /* Req 7's audit row was written above and must survive the refusal. */\n"
               "        (void)tx_commit(s);\n",
               "        /* Req 7's audit row was written above and must survive the refusal. */\n"
               "        (void)exec_simple(s->db, \"COMMIT;\"); /* MUTATION FC2 */\n")]),
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
