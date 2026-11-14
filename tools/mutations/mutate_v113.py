#!/usr/bin/env python3
"""V4-166 mutations: a token whose user's role cannot be read is not
verified, least of all as an operator's (F241).

Usage: mutate_v113.py <repo> <ID>

Two-letter IDs: VT = Verify Token. Every spec line names the check that must
catch it (F90).

    VT1   The role conversion's status is discarded. F241 itself.
    VT2   An unreadable row is verified all the same.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "VT1": [(ST,
             "                if (role_t != NULL && role_from_text(role_t, &info->role) != STORE_OK) {\n",
             "                if (role_t != NULL && role_from_text(role_t, &info->role) != STORE_OK && 0) { /* MUTATION VT1 */\n")],
    "VT2": [(ST,
             "    if (unreadable) {\n        if (info != NULL) {\n",
             "    if (unreadable && 0) { /* MUTATION VT2 */\n        if (info != NULL) {\n")],
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
