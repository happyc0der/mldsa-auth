#!/usr/bin/env python3
"""V4-151 mutations: the daemon does not start on a store whose last audit
entry its own key did not write (F229).

Usage: mutate_v107.py <repo> <ID>

Two-letter IDs: TC = Tail Check. Every spec line names the check that must
catch it (F90).

    TC1   The daemon ignores the tail check's answer. The defect itself.
    TC2   The tail check never compares the MAC it computed.
    TC3   The tail check reads the FIRST entry, not the last.
    TC4   The refusal does not say what is wrong with the store.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
MN = "apps/authd/authd_main.c"

M = {
    "TC1": [(MN,
             "        if (ts != STORE_OK) {\n",
             "        if (ts != STORE_OK && 0) { /* MUTATION TC1 */\n")],
    "TC2": [(ST,
             "        } else if (sodium_memcmp(want, stored_mac, STORE_AUDIT_MAC_BYTES) != 0) {\n",
             "        } else if (sodium_memcmp(want, stored_mac, STORE_AUDIT_MAC_BYTES) != 0 && 0) { /* MUTATION TC2 */\n")],
    "TC3": [(ST,
             "            \"ORDER BY seq DESC LIMIT 1;\", -1, &st, NULL) != SQLITE_OK) {\n",
             "            \"ORDER BY seq ASC LIMIT 1;\", -1, &st, NULL) != SQLITE_OK) { /* MUTATION TC3 */\n")],
    "TC4": [(MN,
             "                    (ts == STORE_ERR_CORRUPT)\n",
             "                    (ts == STORE_ERR_CORRUPT && 0) /* MUTATION TC4 */\n")],
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
