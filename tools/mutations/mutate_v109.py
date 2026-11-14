#!/usr/bin/env python3
"""V4-155 mutations: authd_admin pseudonym refuses a server key the store
was not written with (F231).

Usage: mutate_v109.py <repo> <ID>

Two-letter IDs: PS = PSeudonym. Every spec line names the check that must
catch it (F90).

    PS1   The answer of the tail check is ignored. The defect itself.
    PS2   The refusal names the status and not what it means here.
"""
import sys, pathlib
CL = "apps/authd/authd_cli.c"

M = {
    "PS1": [(CL,
             "        if (ts != STORE_OK) {\n"
             "            store_close(store);\n"
             "            if (ts == STORE_ERR_CORRUPT) {\n",
             "        if (ts != STORE_OK && 0) { /* MUTATION PS1 */\n"
             "            store_close(store);\n"
             "            if (ts == STORE_ERR_CORRUPT) {\n")],
    "PS2": [(CL,
             "        if (ts != STORE_OK) {\n"
             "            store_close(store);\n"
             "            if (ts == STORE_ERR_CORRUPT) {\n",
             "        if (ts != STORE_OK) {\n"
             "            store_close(store);\n"
             "            if (ts == STORE_ERR_CORRUPT && 0) { /* MUTATION PS2 */\n")],
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
