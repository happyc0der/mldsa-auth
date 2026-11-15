#!/usr/bin/env python3
"""V4-213 mutations: a reader changes nothing, and the schema version is an
unsigned number from 1 (F290, F291).

Usage: mutate_v130.py <repo> <ID>

Two-letter IDs: RD = ReaDer. Every spec line names the check that must catch
it (F90).

    RD1   A reader opens read-write and sets the journal mode and the schema,
          as a creating open does.
    RD2   A reader that finds no decoy key generates one.
    RD3   The schema version is compared as a signed number.
    RD4   Version 0 is accepted.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "RD1": [(ST,
             "                        existing ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),\n",
             "                        existing ? SQLITE_OPEN_READWRITE : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE), /* MUTATION RD1 */\n"),
            (ST,
             "    if (!existing) {\n        if (exec_simple(s->db, \"PRAGMA journal_mode=WAL;\") != STORE_OK ||\n",
             "    if (1) {\n        if (exec_simple(s->db, \"PRAGMA journal_mode=WAL;\") != STORE_OK ||\n")],
    "RD2": [(ST,
             "                        existing ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),\n",
             "                        existing ? SQLITE_OPEN_READWRITE : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE), /* MUTATION RD2 */\n"),
            (ST,
             "    if (!found && existing) {\n        r = STORE_ERR_DAMAGED;    /* a reader creates nothing (F290) */\n        goto fail_tx;\n    }\n    if (!found) {\n        mldsa_keypair_t kp;\n",
             "    if (!found) {\n        mldsa_keypair_t kp;\n")],
    "RD3": [(ST,
             "        if (v == 0u || v > (uint64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; }\n",
             "        if (v == 0u || (int64_t)v > (int64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; } /* MUTATION RD3 */\n")],
    "RD4": [(ST,
             "        if (v == 0u || v > (uint64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; }\n",
             "        if (v > (uint64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; } /* MUTATION RD4 */\n")],
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
