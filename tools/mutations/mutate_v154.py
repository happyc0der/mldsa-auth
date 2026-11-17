#!/usr/bin/env python3
"""V4-270 mutations: two product defects whose checks could not fail until
V4-270 (F422, F428).

Usage: mutate_v154.py <repo> <ID>

Two-letter IDs: RC = Recovery Code, ER = ERror code. Every spec line names the
check that must catch it (F90).

    RC1   A spent recovery code is tried again and can be spent again: used_at
          is asked neither when the codes are listed nor when one is spent.
    ER1   The client core reports every ERROR reply as 0x03.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
CC = "apps/authd/client_core.c"

M = {
    "RC1": [(ST, "            \" WHERE user_id=?1 AND used_at IS NULL ORDER BY code_id DESC;\",\n",
             "            \" WHERE user_id=?1 ORDER BY code_id DESC;\", /* MUTATION RC1 */\n"),
            (ST, "            \" WHERE code_id=?1 AND used_at IS NULL AND user_id=?3;\", -1, &st, NULL) != SQLITE_OK) {\n",
             "            \" WHERE code_id=?1 AND user_id=?3;\", -1, &st, NULL) != SQLITE_OK) { /* MUTATION RC1 */\n")],
    "ER1": [(CC, "        if (err_code != NULL) {\n            *err_code = code;\n        }\n        set_diag(&cc->diag, CC_DIAG_IO, \"rotate-reply\", NULL);\n",
             "        if (err_code != NULL) {\n            *err_code = AUTHMSG_ERR_REJECTED; /* MUTATION ER1 */\n        }\n        set_diag(&cc->diag, CC_DIAG_IO, \"rotate-reply\", NULL);\n")],
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
