#!/usr/bin/env python3
"""V4-350 mutations: what the ninety-third review found (F726 to F732).

Usage: mutate_v191.py <repo> <ID>

    RF1   every stop signal starts the waiting line's quarter second again.
"""
import sys, pathlib
LG = "apps/authd/authd_log.c"

M = {
    "RF1": [(LG, "    if (g_in_line && !g_timer_armed) {\n",
             "    if (g_in_line) { /* MUTATION RF1 */\n")],
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
