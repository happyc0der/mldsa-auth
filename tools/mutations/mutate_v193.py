#!/usr/bin/env python3
"""V4-355 mutations: three things the journal said wrongly (F742, F745, F746).

Usage: mutate_v193.py <repo> <ID>

    RH1   every refused peer is logged.
    RH2   REVOKE-TOKENS logs nothing.
    RH3   the store says it revoked a device that was revoked already.
    RH4   REVOKE-DEVICE logs a revocation whatever the store says.
    RH5   REVOKE-TOKENS logs a revocation that ended no token.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
ST = "apps/authd/store/store.c"
LA = "apps/authd/localapi.c"

M = {
    "RH1": [(EV, "            if (evloop_peer_reject_may_say(ev, li, (peer.uid",
             "            if (1 || /* MUTATION RH1 */ evloop_peer_reject_may_say(ev, li, (peer.uid")],
    "RH2": [(LA, "    if (n > 0u) {\n        authd_log_slot_id(AUTHD_LOG_WARN, \"tokens-revoked\", slot->index, user, user_len);\n",
             "    if (0 && n > 0u) { /* MUTATION RH2 */\n        authd_log_slot_id(AUTHD_LOG_WARN, \"tokens-revoked\", slot->index, user, user_len);\n")],
    "RH3": [(ST, "        if (revoked == 1) { return STORE_OK; }\n    }\n    /* F742 (V4-355)",
             "        if (revoked == 1) { if (changed != NULL) { *changed = 1; } return STORE_OK; } /* MUTATION RH3 */\n    }\n    /* F742 (V4-355)")],
    "RH4": [(LA, "    if (revoked_now) {\n",
             "    if (1) { /* MUTATION RH4 */\n")],
    "RH5": [(LA, "    if (n > 0u) {\n        authd_log_slot_id(AUTHD_LOG_WARN, \"tokens-revoked\", slot->index, user, user_len);\n",
             "    if (1) { /* MUTATION RH5 */\n        authd_log_slot_id(AUTHD_LOG_WARN, \"tokens-revoked\", slot->index, user, user_len);\n")],
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
