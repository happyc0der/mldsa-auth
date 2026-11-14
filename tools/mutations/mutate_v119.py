#!/usr/bin/env python3
"""V4-178 mutations: a uid list ending in a comma is refused (F252).

Usage: mutate_v119.py <repo> <ID>

Two-letter IDs: TC = Trailing Comma. Every spec line names the check that
must catch it (F90).

    TC1   The list may end in a comma again. F252.
    TC2   A comma is refused only when it ends a list of ONE uid.
"""
import sys, pathlib
CF = "apps/authd/authd_config.c"

M = {
    "TC1": [(CF,
             "            if (i == n) {\n                return AUTHD_CFG_ERR_VALUE;\n",
             "            if (0 && i == n) { /* MUTATION TC1 */\n                return AUTHD_CFG_ERR_VALUE;\n")],
    "TC2": [(CF,
             "            if (i == n) {\n                return AUTHD_CFG_ERR_VALUE;\n",
             "            if (i == n && *n_out == 1u) { /* MUTATION TC2 */\n                return AUTHD_CFG_ERR_VALUE;\n")],
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
