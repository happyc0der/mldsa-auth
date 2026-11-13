#!/usr/bin/env python3
"""V4-143 mutations: a store write that fails in VERIFY or RECOVERY-USE is
answered `internal`, never a verdict (F222, F223).

Usage: mutate_v102.py <repo> <ID>

Two-letter IDs: SW = Store Write. Every spec line names the check that must
catch it (F90).

    SW1   VERIFY drops the status of the call that slides the idle window:
          a valid token is answered `unknown`. The defect itself (F222).
    SW2   VERIFY sees the failure and still answers `unknown`.
    SW3   VERIFY treats a SUCCESSFUL slide as the failure: every valid
          token is `internal`.
    SW4   RECOVERY-USE drops the status of the write that counts a wrong
          code, and answers `invalid`. The defect itself (F223).
    SW5   RECOVERY-USE sees the failure and still answers `invalid`.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

V_OLD = ("        if (store_verify_token(app->store, token_hash, app->now_unix,\n"
         "                               tokens_idle_ttl_s(info.role), &v, &info) != STORE_OK) {\n"
         "            sodium_memzero(token_hash, sizeof token_hash);\n"
         "            return send_err(slot, \"internal\");\n")
R_OLD = ("                                        &now_locked, &until) != STORE_OK) {\n"
         "            return send_err(slot, \"internal\");\n")

M = {
    "SW1": [(LA, V_OLD,
             "        if (store_verify_token(app->store, token_hash, app->now_unix,\n"
             "                               tokens_idle_ttl_s(info.role), &v, &info) != STORE_OK && 0) { /* MUTATION SW1 */\n"
             "            sodium_memzero(token_hash, sizeof token_hash);\n"
             "            return send_err(slot, \"internal\");\n")],
    "SW2": [(LA, V_OLD,
             "        if (store_verify_token(app->store, token_hash, app->now_unix,\n"
             "                               tokens_idle_ttl_s(info.role), &v, &info) != STORE_OK) {\n"
             "            sodium_memzero(token_hash, sizeof token_hash);\n"
             "            return send_err(slot, \"unknown\"); /* MUTATION SW2 */\n")],
    "SW3": [(LA, V_OLD,
             "        if (store_verify_token(app->store, token_hash, app->now_unix,\n"
             "                               tokens_idle_ttl_s(info.role), &v, &info) == STORE_OK) { /* MUTATION SW3 */\n"
             "            sodium_memzero(token_hash, sizeof token_hash);\n"
             "            return send_err(slot, \"internal\");\n")],
    "SW4": [(LA, R_OLD,
             "                                        &now_locked, &until) != STORE_OK && 0) { /* MUTATION SW4 */\n"
             "            return send_err(slot, \"internal\");\n")],
    "SW5": [(LA, R_OLD,
             "                                        &now_locked, &until) != STORE_OK) {\n"
             "            return send_err(slot, \"invalid\"); /* MUTATION SW5 */\n")],
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
