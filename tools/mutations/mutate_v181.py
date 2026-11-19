#!/usr/bin/env python3
"""V4-332 mutations: authd_admin's warning for a backup under /tmp (F624).

Usage: mutate_v181.py <repo> <ID>

    BW1   /var/tmp is not warned of.
    BW2   any path that begins with /tmp is.

F623's and F625's mutations are campaign v180's LT1 and LT5 to LT7.
"""
import sys, pathlib
CLI = "apps/authd/authd_cli.c"

M = {
    "BW1": [(CLI, "    if (strncmp(path, \"/tmp/\", 5u) == 0 || strncmp(path, \"/var/tmp/\", 9u) == 0) {\n",
             "    if (strncmp(path, \"/tmp/\", 5u) == 0) { /* MUTATION BW1 */\n")],
    "BW2": [(CLI, "    if (strncmp(path, \"/tmp/\", 5u) == 0 || strncmp(path, \"/var/tmp/\", 9u) == 0) {\n",
             "    if (strncmp(path, \"/tmp\", 4u) == 0 || strncmp(path, \"/var/tmp/\", 9u) == 0) { /* MUTATION BW2 */\n")],
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
