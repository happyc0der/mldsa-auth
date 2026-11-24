#!/usr/bin/env python3
"""V4-184 mutations: a WebSocket Close ends the connection, and control
replies queue (F261, F262).

Usage: mutate_v122.py <repo> <ID>

Two-letter IDs: WC = WebSocket Control. Every spec line names the check that
must catch it (F90).

    WC1   The loop keeps a slot whose peer sent a Close. F261.
    WC2   A control reply is dropped while an earlier one is unsent. F262.
    WC3   A Pong may take the room kept for a Close echo.
    WC4   A reply queued behind a half-written one overwrites its tail.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
WS = "apps/authd/ws.c"

M = {
    "WC1": [(EV,
             "    if (s->state != SLOT_ACTIVE || !conn_io_ws_ended(&s->io)) {\n        return;\n",
             "    if (1 || s->state != SLOT_ACTIVE || !conn_io_ws_ended(&s->io)) { /* MUTATION WC1 */\n        return;\n")],
    "WC2": [(WS,
             "    if (n > WS_CTRL_MAX) { n = WS_CTRL_MAX; }\n    uint8_t hdr[WS_SRV_HDR_MAX];\n",
             "    if (w->reply_len != 0u) { return; } /* MUTATION WC2 */\n    if (n > WS_CTRL_MAX) { n = WS_CTRL_MAX; }\n    uint8_t hdr[WS_SRV_HDR_MAX];\n")],
    "WC3": [(WS,
             "    const size_t keep = (opcode == WS_OP_CLOSE) ? 0u : WS_CLOSE_ECHO_MAX;\n",
             "    const size_t keep = 0u; /* MUTATION WC3 */\n")],
    "WC4": [(WS,
             "        memmove(w->reply, w->reply + w->reply_sent, w->reply_len - w->reply_sent);\n        w->reply_len -= w->reply_sent;\n",
             "        w->reply_len = 0u; /* MUTATION WC4 */\n")],
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
