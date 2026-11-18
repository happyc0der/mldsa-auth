#!/usr/bin/env python3
"""V4-299 mutations: a stored recovery code at the daemon's parameters only (F513).

Usage: mutate_v163.py <repo> <ID>

    RP1   A stored code is computed at whatever parameters its row names.
"""
import sys, pathlib
RC = "apps/authd/recovery.c"

M = {
    "RP1": [(RC, "                if (o != ops || m != mem) {\n",
             "                if (0) { /* MUTATION RP1 */\n")],
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
