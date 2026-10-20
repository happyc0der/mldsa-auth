#!/usr/bin/env python3
"""V4-36 mutations: the real daemon's clock (CLAIMS D5).

Usage: mutate_v74.py <repo> <ID>

Two-letter IDs: CK = ClocK. Every expiry the daemon enforces is now_unix plus a
constant, and every C test drives now_unix itself, so nothing had watched
authd_main advance it. Every spec line names the check that must catch it (F90).

    CK1   the main loop stops updating now_unix: the daemon keeps its start
          time, so a login code or a token never expires. Every other check,
          the C suites included, passed it before V4-36.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "CK1": [(MAIN, "        app.now_unix = (int64_t)time(NULL);\n",
                   "        app.now_unix = app.now_unix + 0; /* MUTATION CK1: the clock stops at start-up */\n")],
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
