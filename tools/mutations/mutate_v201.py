#!/usr/bin/env python3
"""V4-365 mutations: what the hundred-and-fourth review found (F790, F791).

Usage: mutate_v201.py <repo> <ID>

    SB1   a re-offered key whose ROTATE cannot be written is removed.
    SB2   a copy of the live key at .ek.next is offered again like a staged
          key, so every rotate is refused.
    SB3   a re-offered key the daemon refuses is kept without a word of what
          ends it.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "SB1": [(CL, "        const int unsent = reoffer ? -1 : rotate_drop_unsent(prog, next_path, next_digest);\n        if (reoffer) {\n",
             "        const int unsent = rotate_drop_unsent(prog, next_path, next_digest);\n        if (0 && reoffer) { /* MUTATION SB1 */\n")],
    "SB2": [(CL, "            if (same) {\n                if (unlink(next_path) != 0 && errno != ENOENT) {\n",
             "            if (0 && same) { /* MUTATION SB2 */\n                if (unlink(next_path) != 0 && errno != ENOENT) {\n")],
    "SB3": [(CL, "            if (reoffer) {\n                /* F790: the daemon had the session and would not take this\n",
             "            if (0 && reoffer) { /* MUTATION SB3 */\n                /* F790: the daemon had the session and would not take this\n")],
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
