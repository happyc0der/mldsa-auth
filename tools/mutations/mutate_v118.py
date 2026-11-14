#!/usr/bin/env python3
"""V4-176 mutations: an insert at an unreadable clock stores nothing (F250).

Usage: mutate_v118.py <repo> <ID>

Two-letter IDs: UC = Unreadable Clock. Every spec line names the check
that must catch it (F90).

    UC1   The ledger inserts at an unreadable clock as at any other. F250.
    UC2   It stores nothing but answers that it did.
"""
import sys, pathlib
HS = "src/protocol/handshake.c"

M = {
    "UC1": [(HS,
             "    if (now == UINT64_MAX) {\n        return PENDING_ERR_EXPIRED;\n",
             "    if (0 && now == UINT64_MAX) { /* MUTATION UC1 */\n        return PENDING_ERR_EXPIRED;\n")],
    "UC2": [(HS,
             "    if (now == UINT64_MAX) {\n        return PENDING_ERR_EXPIRED;\n",
             "    if (now == UINT64_MAX) {\n        return PENDING_OK; /* MUTATION UC2 */\n")],
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
