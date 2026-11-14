#!/usr/bin/env python3
"""V4-186 mutations: audit-tail sends the count it parsed (F263).

Usage: mutate_v123.py <repo> <ID>

Two-letter IDs: AT = Audit Tail. Every spec line names the check that must
catch it (F90).

    AT1   The CLI sends the argument's text again, not the parsed number.
"""
import sys, pathlib

M = {
    "AT1": [("apps/authd/authd_cli.c",
             "                argv[i + 1] = n_canon;\n",
             "                /* MUTATION AT1: the text as typed */\n")],
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
