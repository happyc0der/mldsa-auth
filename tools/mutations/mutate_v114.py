#!/usr/bin/env python3
"""V4-167 mutations: a device added to an existing user on the site's word
is logged at WARN as enroll-without-continuity, and only then (F242).

Usage: mutate_v114.py <repo> <ID>

Two-letter IDs: EC = Enroll Continuity. Every spec line names the check that
must catch it (F90).

    EC1   The event is never written. F242 itself.
    EC2   It is written for every enrollment, a new user's first included.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "EC1": [(LA,
             "    if (added_to_existing) {\n",
             "    if (added_to_existing && 0) { /* MUTATION EC1 */\n")],
    "EC2": [(LA,
             "        added_to_existing = (!created && !store_idem);\n",
             "        added_to_existing = 1; (void)created; /* MUTATION EC2 */\n")],
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
