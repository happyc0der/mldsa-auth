#!/usr/bin/env python3
"""V4-46 mutations: the daemon's record path (audit F122 item 5).

Usage: mutate_v78.py <repo> <ID>

Two-letter IDs: RP = Record Path. V4-40's coverage run found two of its
branches had never run: a ROTATE with the drop-tokens flag, for a device that
holds tokens, and a BYE of the wrong length. Every spec line names the check
that must catch it (F90).

    RP1   the daemon ignores the drop-tokens flag: the tokens survive.
    RP2   the journal stops saying how many tokens a rotation dropped.
    RP3   the journal's count is off by one.
    RP4   the store drops EVERY token, not only the rotated device's.
    RP5   a BYE of the wrong length is taken as a goodbye.
"""
import sys, pathlib
CONN = "apps/authd/authd_conn.c"
ST = "apps/authd/store/store.c"

M = {
    "RP1": [(CONN, "        const int drop = (m.flags & AUTHMSG_FLAG_ROTATE_DROP_TOKENS) != 0;\n",
                   "        const int drop = (m.flags & AUTHMSG_FLAG_ROTATE_DROP_TOKENS) != 0 && 0; /* MUTATION RP1: flag ignored */\n")],
    "RP2": [(CONN, "    if (dropped > 0u) {\n        authd_log_num(AUTHD_LOG_INFO, \"rotate-tokens-dropped\", \"count\", (uint64_t)dropped);\n",
                   "    if (dropped > 0u && 0) { /* MUTATION RP2: not logged */\n        authd_log_num(AUTHD_LOG_INFO, \"rotate-tokens-dropped\", \"count\", (uint64_t)dropped);\n")],
    "RP3": [(CONN, "        authd_log_num(AUTHD_LOG_INFO, \"rotate-tokens-dropped\", \"count\", (uint64_t)dropped);\n",
                   "        authd_log_num(AUTHD_LOG_INFO, \"rotate-tokens-dropped\", \"count\", (uint64_t)dropped + 1u); /* MUTATION RP3: off by one */\n")],
    "RP4": [(ST, "        if (sqlite3_prepare_v2(s->db, \"DELETE FROM tokens WHERE handle=?1;\", -1, &dt, NULL) != SQLITE_OK) {\n",
                 "        if (sqlite3_prepare_v2(s->db, \"DELETE FROM tokens WHERE handle=?1 OR 1;\", -1, &dt, NULL) != SQLITE_OK) { /* MUTATION RP4: every token */\n")],
    "RP5": [(CONN, "        if (pt_len != AUTHMSG_BYE_CONTENT_LEN) {\n",
                   "        if (pt_len != AUTHMSG_BYE_CONTENT_LEN && 0) { /* MUTATION RP5: any BYE length */\n")],
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
