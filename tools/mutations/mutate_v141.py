#!/usr/bin/env python3
"""V4-238 mutations: one request in flight, asked of the socket; the client's WebSocket checks (F333 to F335).

Usage: mutate_v141.py <repo> <ID>

Two-letter IDs: PL = PipeLined, WK = Websocket checK (the 101), WR =
Websocket Reader. Every spec line names the check that must catch it (F90).

    PL1   Only the buffer is asked whether more was sent, as before F333.
    PL2   The peer's close counts as a second request.
    WK1   A status that only begins with 101 is accepted.
    WK2   An accept value with bytes after it is accepted.
    WK3   The last of two accept headers decides.
    WR1   A 16-bit length for a payload 7 bits would hold is accepted.
    WR2   A control frame without FIN is skipped, not refused.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"
WS = "apps/authd/ws.c"

M = {
    "PL1": [(LA,
             "    if (!slot->is_admin && (conn_io_line_rest(&slot->io) > 0u || more_is_waiting(slot))) {\n",
             "    if (!slot->is_admin && (conn_io_line_rest(&slot->io) > 0u || (more_is_waiting(slot) && 0))) { /* MUTATION PL1 */\n")],
    "PL2": [(LA,
             "    return r > 0;\n",
             "    return r >= 0; /* MUTATION PL2 */\n")],
    "WK1": [(WS,
             "    if (memcmp(resp, \"HTTP/1.1 101\", 12) != 0 || (resp[12] != ' ' && resp[12] != '\\r')) {\n",
             "    if (memcmp(resp, \"HTTP/1.1 101\", 12) != 0) { /* MUTATION WK1 */\n")],
    "WK2": [(WS,
             "            accept_ok = (vn == elen && memcmp(v, expect, elen) == 0);\n",
             "            accept_ok = (vn >= elen && memcmp(v, expect, elen) == 0); /* MUTATION WK2 */\n")],
    "WK3": [(WS,
             "    return (accepts == 1 && accept_ok && upgrade_ok && connection_ok) ? 0 : -1;\n",
             "    return (accepts >= 1 && accept_ok && upgrade_ok && connection_ok) ? 0 : -1; /* MUTATION WK3 */\n")],
    "WR1": [(WS,
             "            if (len < 126u) { return WS_CLIENT_PROTOCOL; }\n",
             "            if (0) { return WS_CLIENT_PROTOCOL; } /* MUTATION WR1 */\n")],
    "WR2": [(WS,
             "        if ((op & 0x08u) != 0u && (b0 & 0x80u) == 0u) { return WS_CLIENT_PROTOCOL; }\n",
             "        if (0) { return WS_CLIENT_PROTOCOL; } /* MUTATION WR2 */\n")],
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
