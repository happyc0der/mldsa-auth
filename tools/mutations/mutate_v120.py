#!/usr/bin/env python3
"""V4-179 mutations: a leftover temporary file does not stop a key write (F253).

Usage: mutate_v120.py <repo> <ID>

Two-letter IDs: ST = Stale Temporary. Every spec line names the check that
must catch it (F90).

    ST1   The sealed key file's writer stops at a leftover temporary file.
    ST2   The .pub writer does.
"""
import sys, pathlib

M = {
    "ST1": [("apps/authd/keyfile.c",
             "        if (fd < 0 && (errno != EEXIST || unlink(tmp) != 0)) {\n",
             "        if (fd < 0) { /* MUTATION ST1 */\n")],
    "ST2": [("apps/demo_keys.c",
             "    if (fd < 0 && errno == EEXIST && unlink(path) == 0) {\n",
             "    if (0 && fd < 0 && errno == EEXIST && unlink(path) == 0) { /* MUTATION ST2 */\n")],
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
