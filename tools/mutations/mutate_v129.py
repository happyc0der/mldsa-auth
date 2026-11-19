#!/usr/bin/env python3
"""V4-205 mutations: a local peer waits at a full pool (F282, erratum 103).

Usage: mutate_v129.py <repo> <ID>

Two-letter IDs: LW = Local Wait. Every spec line names the check that must
catch it (F90).

    LW1   A local peer is accepted with the pool full, and so closed at once.
    LW2   The full pool's listener stays in the poll set: the loop spins.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "LW1": [(EV,
             "        if (kind == SLOT_KIND_LOCAL && take_slot_for(ev, li) == NULL) {\n            return;\n",
             "        if (0 && kind == SLOT_KIND_LOCAL && take_slot_for(ev, li) == NULL) { /* MUTATION LW1 */\n            return;\n")],
    "LW2": [(EV,
             "                                       take_slot_for(ev, i) == NULL;   /* F421: per listener */\n",
             "                                       0 && take_slot_for(ev, i) == NULL; /* MUTATION LW2 */\n")],
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
