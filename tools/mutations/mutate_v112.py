#!/usr/bin/env python3
"""V4-163 mutations: a store read that fails at ClientHello is logged as an
error and still answered with the decoy (F239).

Usage: mutate_v112.py <repo> <ID>

Two-letter IDs: SR = Store Read. Every spec line names the check that must
catch it (F90).

    SR1   The failed read is not logged. F239 itself.
    SR2   It is logged at INFO, where an operator's error filter misses it.
    SR3   The connection is closed instead of answered with the decoy: the
          wire now says something an unknown handle's does not.
    SR4   A failed read at ClientAuth is reported as a changed key again.
"""
import sys, pathlib
CC = "apps/authd/authd_conn.c"

M = {
    "SR1": [(CC,
             "    if (g_pin_lookup != STORE_OK && g_pin_lookup != STORE_ERR_NOT_FOUND) {\n",
             "    if (g_pin_lookup != STORE_OK && g_pin_lookup != STORE_ERR_NOT_FOUND && 0) { /* MUTATION SR1 */\n")],
    "SR2": [(CC,
             "        authd_log_slot_detail(AUTHD_LOG_ERROR, \"store-read-failed\", slot->index, store_status_name(g_pin_lookup));\n",
             "        authd_log_slot_detail(AUTHD_LOG_INFO, \"store-read-failed\", slot->index, store_status_name(g_pin_lookup)); /* MUTATION SR2 */\n")],
    "SR3": [(CC,
             "        authd_log_slot_detail(AUTHD_LOG_ERROR, \"store-read-failed\", slot->index, store_status_name(g_pin_lookup));\n",
             "        authd_log_slot_detail(AUTHD_LOG_ERROR, \"store-read-failed\", slot->index, store_status_name(g_pin_lookup));\n"
             "        return EV_ACTION_CLOSE; /* MUTATION SR3 */\n")],
    "SR4": [(CC,
             "        if (ls != STORE_OK && ls != STORE_ERR_NOT_FOUND) {\n",
             "        if (ls != STORE_OK && ls != STORE_ERR_NOT_FOUND && 0) { /* MUTATION SR4 */\n")],
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
