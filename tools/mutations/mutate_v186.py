#!/usr/bin/env python3
"""V4-344 mutations: what the eighty-eighth review found in V4-342 (F679 to F690).

Usage: mutate_v186.py <repo> <ID>

    (RA1, the handlers still restarting calls once the daemon runs, went in V4-348:
    the stop signal's handler now times a line that is in flight, so the mutant
    differs only by the quarter second that takes.)
    RA2   a stop is not looked for before the store is opened.
    RA3   a created store is removed whatever has been written to it since.
    RA4   a populated store that lost a meta value is given a new one.
    RA9   ... is refused only after the switch to WAL.
    RA5   a file that was there and empty keeps its mode.
    RA6   "as created" does not count the meta values.
    RA7   systemd's notify socket is written to with a call that waits.
    RA8   a short hard limit leaves the soft limit where it was.
"""
import sys, pathlib
A = "apps/authd/authd_main.c"
ST = "apps/authd/store/store.c"
SD = "apps/authd/sdnotify.c"
FD = "apps/authd/fdlimit.c"

M = {
    "RA2": [(A, "    if (g_stop) {\n        authd_log_say(\"mldsa-authd: stopped by a signal before it had started\\n\");\n        secure_mem_free(kek, STORE_KEK_BYTES);\n",
             "    if (0 && g_stop) { /* MUTATION RA2 */\n        authd_log_say(\"mldsa-authd: stopped by a signal before it had started\\n\");\n        secure_mem_free(kek, STORE_KEK_BYTES);\n")],
    "RA3": [(A, "    if (store_created && !store_is_as_created(store)) {\n",
             "    if (0 && store_created && !store_is_as_created(store)) { /* MUTATION RA3 */\n")],
    "RA4": [(ST, "            if (!none && !whole) {\n",
             "            if (0 && !none && !whole) { /* MUTATION RA4 */\n")],
    "RA9": [(ST, "        if (objects > 0) {\n            int none = 0, whole = 0;\n",
             "        if (objects > 0) {\n            (void)exec_simple(s->db, \"PRAGMA journal_mode=WAL;\"); /* MUTATION RA9 */\n            int none = 0, whole = 0;\n")],
    "RA5": [(ST, "        if (objects == 0 && was_there) {\n            const int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);\n",
             "        if (0 && objects == 0 && was_there) { /* MUTATION RA5 */\n            const int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);\n")],
    "RA6": [(ST, "            \"SELECT (SELECT count(*) FROM meta) = 3 AND \"\n",
             "            \"SELECT 1 AND \" /* MUTATION RA6 */\n")],
    "RA7": [(SD, "    const ssize_t w = sendto(g_notify_fd, msg, ml, MSG_DONTWAIT, (const struct sockaddr *)&a, alen);\n",
             "    const ssize_t w = sendto(g_notify_fd, msg, ml, 0, (const struct sockaddr *)&a, alen); /* MUTATION RA7 */\n")],
    "RA8": [(FD, "        if (rl.rlim_cur < rl.rlim_max) {\n",
             "        if (0 && rl.rlim_cur < rl.rlim_max) { /* MUTATION RA8 */\n")],
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
