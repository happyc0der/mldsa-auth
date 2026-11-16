#!/usr/bin/env python3
"""V4-217 mutations: one run at a time beside a device's key (F293).

Usage: mutate_v132.py <repo> <ID>

Two-letter IDs: KL = Key Lock. Every spec line names the check that must
catch it (F90).

    KL1   A ".ek.next" name that did not fit is used as it came out.
    KL2   The directory's lock is never asked for.
    KL3   A run that found the lock taken says it will wait and does not.
    KL4   A login that finds a .ek.next does not take the lock.
"""
import sys, pathlib
CC = "apps/authd/client_cli.c"

M = {
    "KL1": [(CC,
             "    if (nn < 0 || (size_t)nn >= next_cap) {\n",
             "    if (nn < 0 || (size_t)nn >= next_cap + 8u) { /* MUTATION KL1 */\n")],
    "KL2": [(CC,
             "    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {\n",
             "    if (0) { /* MUTATION KL2 */\n")],
    "KL3": [(CC,
             "            r = flock(fd, LOCK_EX);\n",
             "            r = 0; /* MUTATION KL3 */\n")],
    "KL4": [(CC,
             "    if (!have_lock && path_exists(next_path)) {\n",
             "    if (!have_lock && path_exists(next_path) && prog == NULL) { /* MUTATION KL4 */\n")],
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
