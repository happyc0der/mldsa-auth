#!/usr/bin/env python3
"""V4-120 mutations: the daemon has a descriptor for every slot or says it
has not, and a failed accept() is counted, logged once and not retried in a
loop (F205).

Usage: mutate_v96.py <repo> <ID>

Two-letter IDs: FD = File Descriptor limit, AF = Accept Failed. Every spec
line names the check that must catch it (F90).

    FD1   the daemon never looks at its limit (what F205 reported, start-up
          half).
    FD2   a short hard limit is logged but not explained on standard error.
    FD3   the requirement leaves no descriptor beside the slots.
    FD4   a soft limit equal to the need is treated as short.
    FD5   a hard limit equal to the need is treated as short.
    FD6   the raise is reported and not made.
    FD7   the soft limit is raised to the hard limit, not to the need.
    FD8   a short limit is logged at INFO.
    AF1   a failed accept() sets no retry time (the loop that never sleeps).
    AF2   every failed accept() is logged.
    AF3   a successful accept() does not end the run of failures, so the
          next run is never logged.
    AF4   accept-failed is logged at INFO.
    AF5   a failed accept() is not counted.
    AF6   the poll set ignores the retry time.
    AF7   the listener is retried one millisecond late (< became <=).
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"
FH = "apps/authd/fdlimit.h"
FC = "apps/authd/fdlimit.c"
EV = "apps/authd/evloop.c"

M = {
    "FD1": [(MAIN, "        const fdlimit_status_t fs = fdlimit_ensure(need, &lim);\n",
                   "        const fdlimit_status_t fs = (0) ? fdlimit_ensure(need, &lim) : FDLIMIT_OK; /* MUTATION FD1 */\n")],
    "FD2": [(MAIN, "        if (fs == FDLIMIT_LOW) {\n",
                   "        if (0 && fs == FDLIMIT_LOW) { /* MUTATION FD2 */\n")],
    "FD3": [(FH, "#define FDLIMIT_OVERHEAD 32u\n",
                 "#define FDLIMIT_OVERHEAD 0u /* MUTATION FD3 */\n")],
    "FD4": [(FC, "    if ((uint64_t)rl.rlim_cur >= need) {\n",
                 "    if ((uint64_t)rl.rlim_cur > need) { /* MUTATION FD4 */\n")],
    "FD5": [(FC, "    if (rl.rlim_max != RLIM_INFINITY && (uint64_t)rl.rlim_max < need) {\n",
                 "    if (rl.rlim_max != RLIM_INFINITY && (uint64_t)rl.rlim_max <= need) { /* MUTATION FD5 */\n")],
    "FD6": [(FC, "    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {\n",
                 "    if (0 && setrlimit(RLIMIT_NOFILE, &rl) != 0) { /* MUTATION FD6 */\n")],
    "FD7": [(FC, "    rl.rlim_cur = (rlim_t)need;\n",
                 "    rl.rlim_cur = rl.rlim_max; /* MUTATION FD7 */\n")],
    "FD8": [(FC, "    return (st == FDLIMIT_LOW) ? AUTHD_LOG_WARN : AUTHD_LOG_INFO;\n",
                 "    return (st == FDLIMIT_LOW) ? AUTHD_LOG_INFO : AUTHD_LOG_INFO; /* MUTATION FD8 */\n")],
    "AF1": [(EV, "            ev->accept_retry_ms[li] = now_ms + (uint64_t)EVLOOP_ACCEPT_RETRY_MS;\n",
                 "            ev->accept_retry_ms[li] = now_ms; /* MUTATION AF1 */\n")],
    "AF2": [(EV, "            if (!ev->accept_failing[li]) {\n",
                 "            if (1 || !ev->accept_failing[li]) { /* MUTATION AF2 */\n")],
    "AF3": [(EV, "        ev->accept_failing[li] = 0;\n",
                 "        (void)0; /* MUTATION AF3 */\n")],
    "AF4": [(EV, "                authd_log_event(AUTHD_LOG_WARN, \"accept-failed\");\n",
                 "                authd_log_event(AUTHD_LOG_INFO, \"accept-failed\"); /* MUTATION AF4 */\n")],
    "AF5": [(EV, "            ev->accept_failed++;\n",
                 "            (void)0; /* MUTATION AF5 */\n")],
    "AF6": [(EV, "                all[npfd].events = (now_ms < ev->accept_retry_ms[i]) ? 0 : POLLIN;\n",
                 "                all[npfd].events = POLLIN; /* MUTATION AF6 */\n")],
    "AF7": [(EV, "                all[npfd].events = (now_ms < ev->accept_retry_ms[i]) ? 0 : POLLIN;\n",
                 "                all[npfd].events = (now_ms <= ev->accept_retry_ms[i]) ? 0 : POLLIN; /* MUTATION AF7 */\n")],
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
