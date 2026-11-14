#!/usr/bin/env python3
"""V4-150 mutations: EXCHANGE answers `internal` when the user's role cannot
be read, and issues no token on a guessed role (F228).

Usage: mutate_v106.py <repo> <ID>

Two-letter IDs: EX = EXchange. Every spec line names the check that must
catch it (F90).

    EX1   The status of the role lookup is ignored. The defect itself.
    EX2   The failure is answered as a verdict, `unknown`, not `internal`.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "EX1": [(LA,
             "    if (store_get_user(app->store, user, user_len, &role, NULL, 0u) != STORE_OK) {\n"
             "        return send_err(slot, \"internal\");\n",
             "    if (store_get_user(app->store, user, user_len, &role, NULL, 0u) != STORE_OK && 0) { /* MUTATION EX1 */\n"
             "        return send_err(slot, \"internal\");\n")],
    "EX2": [(LA,
             "    if (store_get_user(app->store, user, user_len, &role, NULL, 0u) != STORE_OK) {\n"
             "        return send_err(slot, \"internal\");\n",
             "    if (store_get_user(app->store, user, user_len, &role, NULL, 0u) != STORE_OK) {\n"
             "        return send_err(slot, \"unknown\"); /* MUTATION EX2 */\n")],
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
