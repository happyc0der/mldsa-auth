#!/usr/bin/env python3
"""V4-227 mutations: an ERROR code this build does not know is a refusal (F312).

Usage: mutate_v137.py <repo> <ID>

Two-letter IDs: UC = Unknown Code. Every spec line names the check that must
catch it (F90).

    UC1   An unknown code is a decode failure again.
    UC2   Only codes above the known ones are mapped; zero passes as itself.
"""
import sys, pathlib
AM = "apps/authd/authmsg.c"

M = {
    "UC1": [(AM,
             "        *code_out = AUTHMSG_ERR_REJECTED;\n        return AUTHMSG_OK;\n",
             "        return AUTHMSG_ERR_BAD_FIELD; /* MUTATION UC1 */\n")],
    "UC2": [(AM,
             "    if (in[2] < AUTHMSG_ERR_MALFORMED || in[2] > AUTHMSG_ERR_INTERNAL) {\n        *code_out",
             "    if (in[2] > AUTHMSG_ERR_INTERNAL) { /* MUTATION UC2 */\n        *code_out")],
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
