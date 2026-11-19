#!/usr/bin/env python3
"""V4-326 mutations: the other side of F591's stop.

Usage: mutate_v178.py <repo> <ID>

    KR3   rotate also stops when .ek.next WAS promoted.

The site's handler (F599, F600) and the browser's flow (F597) are
JavaScript, which no campaign compiles; their controls were run with
hand_control.py --interpreted and are listed in docs/decisions.md under
V4-326. F598 is campaign v89's OE6, whose spec line this step changed.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "KR3": [(CL, "        fprintf(stderr, \"%s %s: completed the interrupted rotation; %s now holds the live key\\n\",\n                prog, sub, a->key_path);\n",
             "        fprintf(stderr, \"%s %s: completed the interrupted rotation; %s now holds the live key\\n\",\n                prog, sub, a->key_path);\n        g_resolve_kept_next = 1; /* MUTATION KR3 */\n")],
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
