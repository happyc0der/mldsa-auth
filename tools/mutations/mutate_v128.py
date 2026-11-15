#!/usr/bin/env python3
"""V4-201 mutations: descriptors 0, 1 and 2 are open before anything else is
(F280).

Usage: mutate_v128.py <repo> <ID>

Two-letter IDs: SF = Standard Fds. Every spec line names the check that must
catch it (F90).

    SF1   stdfds_ensure_open reports the closed ones and opens nothing.
    SF2   authd_client goes on with standard output closed.
    SF3   authd_admin goes on with standard output closed.
    SF4   The daemon does not look at its descriptors at all.
"""
import sys, pathlib

M = {
    "SF1": [("apps/authd/stdfds.c",
             "        const int got = open(\"/dev/null\", (fd == 0) ? O_RDONLY : O_WRONLY);\n        if (got != fd) {\n",
             "        const int got = fd; /* MUTATION SF1: nothing is opened */\n        if (got != fd) {\n")],
    "SF2": [("apps/authd_client.c",
             "    if ((closed & STDFDS_STDOUT_WAS_CLOSED) != 0) {\n",
             "    if (0 && (closed & STDFDS_STDOUT_WAS_CLOSED) != 0) { /* MUTATION SF2 */\n")],
    "SF3": [("apps/authd/authd_admin.c",
             "    if ((closed & STDFDS_STDOUT_WAS_CLOSED) != 0) {\n",
             "    if (0 && (closed & STDFDS_STDOUT_WAS_CLOSED) != 0) { /* MUTATION SF3 */\n")],
    "SF4": [("apps/authd/authd_main.c",
             "    if (stdfds_ensure_open() < 0) {\n",
             "    if (0 && stdfds_ensure_open() < 0) { /* MUTATION SF4 */\n")],
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
