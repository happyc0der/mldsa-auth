#!/usr/bin/env python3
"""V4-345 mutations: what the eighty-ninth review found (F691 to F699).

Usage: mutate_v187.py <repo> <ID>

    RB1   a READY=1 that could not be sent is not sent again.
    (RB2, the log not closed when a stop interrupts a line, went in V4-347: with
    that step's timer each line of a shutdown waits a quarter of a second at
    most, closed log or not, and the mutant differs only in how long a stop takes.)
    RB3   the daemon's open follows a link at the store's path.
    RB4   the daemon opens a store it cannot write.
    RB5   a start that is stopped with its sockets bound leaves the proxy-facing one.
"""
import sys, pathlib
A = "apps/authd/authd_main.c"
ST = "apps/authd/store/store.c"

M = {
    "RB1": [(A, "        if (ready_pending && !g_stop && authd_sd_notify(\"READY=1\") > 0) {\n",
             "        if (0 && ready_pending && !g_stop && authd_sd_notify(\"READY=1\") > 0) { /* MUTATION RB1 */\n")],
    "RB3": [(ST, "        if (!existing && lstat(path, &lk) == 0 && S_ISLNK(lk.st_mode)) {\n",
             "        if (0 && !existing && lstat(path, &lk) == 0 && S_ISLNK(lk.st_mode)) { /* MUTATION RB3 */\n")],
    "RB4": [(ST, "    if (!existing && sqlite3_db_readonly(s->db, \"main\") == 1) {\n",
             "    if (0 && !existing && sqlite3_db_readonly(s->db, \"main\") == 1) { /* MUTATION RB4 */\n")],
    "RB5": [(A, "    listener_close(&tcp_fd, NULL);\n    listener_close(&unix_fd, unix_path);\n    handshake_pending_store_wipe(&pending);\n    /* The log's pseudonym callback",
             "    listener_close(&tcp_fd, NULL);\n    if (early_rc != 0) { listener_close(&unix_fd, unix_path); } /* MUTATION RB5 */\n    handshake_pending_store_wipe(&pending);\n    /* The log's pseudonym callback")],
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
