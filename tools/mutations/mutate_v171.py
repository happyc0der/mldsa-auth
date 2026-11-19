#!/usr/bin/env python3
"""V4-315 mutations: the watchdog through a backup (F541).

Usage: mutate_v171.py <repo> <ID>

    BT1   The store does not call back while it copies.
    BT2   The callback is left installed after the copy.
    WT1   A ping is sent on every call, due or not.
    WT2   A ping is sent with no watchdog set.
    WT3   The time of the ping is not noted.

F544 (the limiter's table) is v166's TS4, rewritten in this step.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
SD = "apps/authd/sdnotify.c"

M = {
    "BT1": [(ST, "    sqlite3_progress_handler(s->db, STORE_BACKUP_TICK_OPS, backup_progress, s);\n",
             "    sqlite3_progress_handler(s->db, 0, backup_progress, s); /* MUTATION BT1: never called */\n")],
    "BT2": [(ST, "    sqlite3_progress_handler(s->db, 0, NULL, NULL);\n",
             "    /* MUTATION BT2 */\n")],
    "WT1": [(SD, "    if (t == NULL || t->period_ms == 0u || now_ms - t->last_ms < (uint64_t)t->period_ms) {\n",
             "    if (t == NULL || t->period_ms == 0u) { /* MUTATION WT1 */\n")],
    "WT2": [(SD, "    if (t == NULL || t->period_ms == 0u || now_ms - t->last_ms < (uint64_t)t->period_ms) {\n",
             "    if (t == NULL || now_ms - t->last_ms < (uint64_t)t->period_ms) { /* MUTATION WT2 */\n")],
    "WT3": [(SD, "    (void)authd_sd_notify(\"WATCHDOG=1\");\n    t->last_ms = now_ms;\n",
             "    (void)authd_sd_notify(\"WATCHDOG=1\"); /* MUTATION WT3 */\n")],
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
