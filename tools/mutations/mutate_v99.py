#!/usr/bin/env python3
"""V4-124 mutations: a daemon whose event loop fails exits 1, so systemd
starts it again (F208).

Usage: mutate_v99.py <repo> <ID>

Two-letter IDs: LF = Loop Failed. Every spec line names the check that must
catch it (F90).

Both are killed by authd_e2e on Linux only. Nothing portable makes poll()
fail in a running daemon; Linux's prlimit does, by lowering the daemon's
RLIMIT_NOFILE below its listeners. On macOS that leg is skipped and both
survive -- as v75's KC5 and v58's GA13 and GA14 do. The nightly runs them
on Linux.

    LF1   a failed loop is not remembered: the daemon exits 0 after
          loop-failed (what F208 reported).
    LF2   every stop is a failure: a daemon stopped by SIGTERM exits 1.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "LF1": [(MAIN, "            loop_failed = 1;\n",
                   "            loop_failed = 0; /* MUTATION LF1 */\n")],
    "LF2": [(MAIN, "    return loop_failed ? 1 : 0;\n",
                   "    return loop_failed ? 1 : (draining ? 1 : 0); /* MUTATION LF2 */\n")],
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
