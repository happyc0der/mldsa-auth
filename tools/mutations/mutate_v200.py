#!/usr/bin/env python3
"""V4-364 mutations: a ROTATE that arrives late (F787).

Usage: mutate_v200.py <repo> <ID>

    SA1   rotate removes a staged key it finds beside a live one and makes a
          new key, as before V4-364.
    SA2   a rotation offering a staged key again removes it when its session
          does not open.
    SA3   a staged key that does not open is removed.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "SA1": [(CL, "    int reoffer = stale_next;\n",
             "    int reoffer = 0; if (stale_next) { (void)unlink(next_path); } /* MUTATION SA1 */\n")],
    "SA2": [(CL, "        if (reoffer) {\n            /* F787: not this run's key to remove. This is the very case: the\n",
             "        if (0 && reoffer) { /* MUTATION SA2 */\n            /* F787: not this run's key to remove. This is the very case: the\n")],
    "SA3": [(CL, "        if (reoffer) {\n            /* F787: an earlier rotation's key that this passphrase does not\n",
             "        if (0 && reoffer) { /* MUTATION SA3 */\n            /* F787: an earlier rotation's key that this passphrase does not\n")],
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
