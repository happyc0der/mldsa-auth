#!/usr/bin/env python3
"""V4-113 mutations: the daemon's start reports a short memlock limit at
WARN, and says so on standard error (spec 16).

Usage: mutate_v92.py <repo> <ID>

Two-letter IDs: ML = MemLock. v51 Z4 pins memlock_log_level(); these pin
that authd_main uses it, which only the runbook rehearsal read before, and
its pattern was blind from V4-99 to V4-111 (F201). Every spec line names the
check that must catch it (F90).

    ML1   the memlock-limit event is always logged at INFO.
    ML2   the standard-error explanation of a short limit is never printed.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "ML1": [(MAIN, "        authd_log_num(memlock_log_level(ms), \"memlock-limit\", \"need\", need);\n",
                   "        authd_log_num(AUTHD_LOG_INFO, \"memlock-limit\", \"need\", need); /* MUTATION ML1 */\n")],
    "ML2": [(MAIN, "        if (ms == MEMLOCK_LOW) {\n",
                   "        if (ms == MEMLOCK_LOW && need == 0) { /* MUTATION ML2 */\n")],
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
