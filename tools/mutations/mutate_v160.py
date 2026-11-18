#!/usr/bin/env python3
"""V4-285 mutations: the local API's journal, read whole again (F473 to F477).

Usage: mutate_v160.py <repo> <ID>

Two-letter IDs: RQ = ReQ 7, RI = Recovery Issue, US = User Status, LK =
LocKed, CN = Command Name. The spec line names the check that must catch
it (F90).

    RQ1   An unknown user's ENROLL via=recovery hides Req 7 again.
    RQ2   A missing ticket hides Req 7 again.
    RI1   A site asking for an operator's codes leaves no line again.
    US1   An enable writes no user-enabled line.
    LK1   A locked RECOVERY-USE names no user.
    CN1   A long command name is malformed again.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "RQ1": [(LA, "             * a known handle with a different key, named by an unknown user. */\n            note_req7_before_refusal(app, slot, handle, handle_len, pk);\n",
             "             * a known handle with a different key, named by an unknown user. */\n            /* MUTATION RQ1 */\n")],
    "RQ2": [(LA, "             * ticket used to hide a different key on a known handle. */\n            note_req7_before_refusal(app, slot, handle, handle_len, pk);\n",
             "             * ticket used to hide a different key on a known handle. */\n            /* MUTATION RQ2 */\n")],
    "RI1": [(LA, "        authd_log_slot_detail(AUTHD_LOG_WARN, \"recovery-issue\", slot->index, \"not-permitted\");\n",
             "        /* MUTATION RI1 */\n")],
    "US1": [(LA, "        authd_log_slot_id(AUTHD_LOG_WARN, \"user-enabled\", slot->index, user, user_len);\n",
             "        (void)0; /* MUTATION US1 */\n")],
    "LK1": [(LA, "        authd_log_slot_id(AUTHD_LOG_WARN, \"recovery-use\", slot->index, user, user_len);   /* F476 */\n",
             "        /* MUTATION LK1 */\n")],
    "CN1": [(LA, "        memcpy(r->cmd, \"?\", 2u);\n",
             "        return -1; /* MUTATION CN1 */\n")],
}

def main():
    repo, mid = pathlib.Path(sys.argv[1]), sys.argv[2]
    if mid not in M:
        sys.exit("unknown mutation id: " + mid)
    texts = {}
    for path, old, new in M[mid]:
        t = texts.get(path, (repo / path).read_text())
        n = t.count(old)
        if n != 1:
            sys.exit(f"{mid}: expected exactly 1 occurrence in {path}, found {n}")
        texts[path] = t.replace(old, new, 1)
    for path, t in texts.items():
        (repo / path).write_text(t)
    print(f"{mid}: applied")


if __name__ == "__main__":
    main()
