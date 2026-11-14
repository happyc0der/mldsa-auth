#!/usr/bin/env python3
"""V4-172 mutations: opening an in-memory store creates no file (F246).

Usage: mutate_v117.py <repo> <ID>

Two-letter IDs: MM = MeMory. Every spec line names the check that must
catch it (F90). (F245, the fuzz gate, is shell and workflow text: its
controls are the fixtures in tests/fuzz_log_gate.sh and hand mutations.)

    MM1   The pre-creation is made for ":memory:" as for any path. F246.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "MM1": [(ST,
             "    if (!existing && strcmp(path, \":memory:\") != 0) {\n",
             "    if (!existing) { /* MUTATION MM1 */\n")],
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
