#!/usr/bin/env python3
"""V4-273 mutations: a rotation that reaches no daemon keeps no .ek.next (F438).

Usage: mutate_v156.py <repo> <ID>

Two-letter ID: TN = Trust Nothing staged. The spec line names the check that
must catch it (F90).

    TN1   The staged key is kept whatever the session's failure, as before.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "TN1": [(CL, "        } else if (unlink(next_path) != 0) {\n            rotate_say_kept(prog, next_path);   /* F645 */\n",
             "        } else if (1 || unlink(next_path) != 0) { /* MUTATION TN1 */\n            rotate_say_kept(prog, next_path);   /* F645 */\n")],
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
