#!/usr/bin/env python3
"""V4-356 mutations: what the ninety-sixth review found (F750, F753).

Usage: mutate_v194.py <repo> <ID>

    RU1   a refused uid is taken for whichever uid was named first.
    RU2   a listener names any number of new uids in a second.
    RU3   a uid named again does not start its second again.
    RU4   the daemon's last line gives the accepted count as the refused.
    RU5   a login opens an envelope at whatever cost its header asks.
    RU6   the ceiling is on the passes only.
    RU7   a rotation opens the new envelope at whatever cost its header asks.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
MA = "apps/authd/authd_main.c"
CW = "apps/authd/client_wasm.c"

M = {
    "RU1": [(EV, "        if (ev->peer_reject[li][i].used && ev->peer_reject[li][i].uid == uid) {\n",
             "        if (ev->peer_reject[li][i].used && (1 || ev->peer_reject[li][i].uid == uid)) { /* MUTATION RU1 */\n")],
    "RU2": [(EV, "    if (ev->peer_reject[li][oldest].used &&\n        now_ms - ev->peer_reject[li][oldest].said_ms < (uint64_t)EVLOOP_PEER_REJECT_LOG_MS) {\n",
             "    if (0 && ev->peer_reject[li][oldest].used && /* MUTATION RU2 */\n        now_ms - ev->peer_reject[li][oldest].said_ms < (uint64_t)EVLOOP_PEER_REJECT_LOG_MS) {\n")],
    "RU3": [(EV, "            ev->peer_reject[li][i].said_ms = now_ms;\n            return 1;\n",
             "            /* MUTATION RU3 */\n            return 1;\n")],
    "RU4": [(MA, "    authd_log_num(AUTHD_LOG_INFO, \"stopped\", \"refused\", ev.closed_peer);\n",
             "    authd_log_num(AUTHD_LOG_INFO, \"stopped\", \"refused\", ev.accepted); /* MUTATION RU4 */\n")],
    "RU5": [(CW, "    if (envelope_cost_refused(h, ek, ek_len)) {\n",
             "    if (0 && envelope_cost_refused(h, ek, ek_len)) { /* MUTATION RU5 */\n")],
    "RU6": [(CW, "    if (hdr.opslimit <= CC_KDF_OPS_BROWSER_MAX && hdr.memlimit <= (uint64_t)CC_KDF_MEM_BROWSER_MAX) {\n",
             "    if (hdr.opslimit <= CC_KDF_OPS_BROWSER_MAX) { /* MUTATION RU6 */\n")],
    "RU7": [(CW, "    if (envelope_cost_refused(h, new_ek, new_ek_len)) {\n",
             "    if (0 && envelope_cost_refused(h, new_ek, new_ek_len)) { /* MUTATION RU7 */\n")],
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
