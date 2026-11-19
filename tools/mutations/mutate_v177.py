#!/usr/bin/env python3
"""V4-324 mutations: a rotation while .ek.next holds the live key (F591).

Usage: mutate_v177.py <repo> <ID>

    KR1   rotate goes on to seal a new key though .ek.next was not promoted.
    KR2   The login that could not promote does not say so to rotate.

The site's handler (F593) and the browser's flow (F594) are JavaScript,
which no campaign compiles; their controls were run with hand_control.py
--interpreted and are listed in docs/decisions.md under V4-324.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "KR1": [(CL, "    if (g_resolve_kept_next) {\n        authd_secret_free(pass, pass_len);\n",
             "    if (g_resolve_kept_next && 0) { /* MUTATION KR1 */\n        authd_secret_free(pass, pass_len);\n")],
    "KR2": [(CL, "            g_resolve_kept_next = 1;\n",
             "            g_resolve_kept_next = 0; /* MUTATION KR2 */\n")],
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
