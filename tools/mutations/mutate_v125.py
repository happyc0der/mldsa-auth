#!/usr/bin/env python3
"""V4-197 mutations: a revocation closes sessions, not claims (F275).

Usage: mutate_v125.py <repo> <ID>

Two-letter IDs: RS = Revocation closes Sessions. Every spec line names the
check that must catch it (F90).

    RS1   Every connection naming the handle is closed again, proven or not.
    RS2   No connection is closed: the revoked device's session lives on.
"""
import sys, pathlib
CONN = "apps/authd/authd_conn.c"

M = {
    "RS1": [(CONN,
             "        if (c->stage != CONN_STAGE_SERVING) {\n            continue;\n        }\n        const uint8_t *have = by_user",
             "        if (c->stage == CONN_STAGE_FREE) { /* MUTATION RS1 */\n            continue;\n        }\n        const uint8_t *have = by_user")],
    "RS2": [(CONN,
             "        if (c->stage != CONN_STAGE_SERVING) {\n            continue;\n        }\n        const uint8_t *have = by_user",
             "        if (c->stage != CONN_STAGE_FREE) { /* MUTATION RS2 */\n            continue;\n        }\n        const uint8_t *have = by_user")],
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
