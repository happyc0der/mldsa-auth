#!/usr/bin/env python3
"""V4-332 mutations: authd_admin's warning for a backup under /tmp (F624).

Usage: mutate_v181.py <repo> <ID>

    BW1   /var/tmp is not warned of.
    BW2   any path that begins with /tmp is.
    BW3   /run is not warned of (V4-333).
    BW4   a `.` segment hides the destination.
    BW5   a `..` segment does.
    BW6   any path that begins with /run is warned of.
    BW7   /var/run is not warned of (V4-335).
    BW8   any path that begins with /var/lock is.

F623's and F625's mutations are campaign v180's LT1 and LT5 to LT7.
"""
import sys, pathlib
CLI = "apps/authd/authd_cli.c"

M = {
    "BW1": [(CLI, "    if (strncmp(seen, \"/tmp/\", 5u) == 0 || strncmp(seen, \"/var/tmp/\", 9u) == 0) {\n",
             "    if (strncmp(seen, \"/tmp/\", 5u) == 0) { /* MUTATION BW1 */\n")],
    "BW2": [(CLI, "    if (strncmp(seen, \"/tmp/\", 5u) == 0 || strncmp(seen, \"/var/tmp/\", 9u) == 0) {\n",
             "    if (strncmp(seen, \"/tmp\", 4u) == 0 || strncmp(seen, \"/var/tmp/\", 9u) == 0) { /* MUTATION BW2 */\n")],
    "BW3": [(CLI, "    } else if (strncmp(seen, \"/run/\", 5u) == 0 || strncmp(seen, \"/var/run/\", 9u) == 0 ||\n",
             "    } else if (strncmp(seen, \"/rum/\", 5u) == 0 || strncmp(seen, \"/var/run/\", 9u) == 0 || /* MUTATION BW3 */\n")],
    "BW7": [(CLI, "    } else if (strncmp(seen, \"/run/\", 5u) == 0 || strncmp(seen, \"/var/run/\", 9u) == 0 ||\n",
             "    } else if (strncmp(seen, \"/run/\", 5u) == 0 || /* MUTATION BW7 */\n")],
    "BW8": [(CLI, "               strncmp(seen, \"/var/lock/\", 10u) == 0) {\n",
             "               strncmp(seen, \"/var/lock\", 9u) == 0) { /* MUTATION BW8 */\n")],
    "BW4": [(CLI, "        if (len == 0u || (len == 1u && seg[0] == '.')) {\n",
             "        if (len == 0u) { /* MUTATION BW4 */\n")],
    "BW5": [(CLI, "        if (len == 2u && seg[0] == '.' && seg[1] == '.') {\n",
             "        if (len == 2u && seg[0] == '.' && seg[1] == '/') { /* MUTATION BW5 */\n")],
    "BW6": [(CLI, "    } else if (strncmp(seen, \"/run/\", 5u) == 0 || strncmp(seen, \"/var/run/\", 9u) == 0 ||\n",
             "    } else if (strncmp(seen, \"/run\", 4u) == 0 || strncmp(seen, \"/var/run/\", 9u) == 0 || /* MUTATION BW6 */\n")],
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
