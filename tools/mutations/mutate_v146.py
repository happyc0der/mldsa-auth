#!/usr/bin/env python3
"""V4-245 mutations: the order of what a WebSocket connection writes (F351),
and authd_client options that could not take effect (F352).

Usage: mutate_v146.py <repo> <ID>

Two-letter IDs: PO = Pipelined Order (conn_io level), PL = the same through
the loop, CS = Client State. Every spec line names the check that must catch
it (F90).

    PO1   The old rule: the reply goes first whenever nothing of ws.reply has
          been sent -- ahead of an unsent 101.
    PO2   The Close echo is marked as starting at the front of the buffer.
    PO3   A refusal keeps the mark of a Close read behind the request.
    PO4   An echo is held back only before its turn, not at it: it is written
          ahead of the reply (F343 again).
    PL1   PO1, seen by a client of the event loop.
    CS1   --state / --proxy-v2 over the raw listener are accepted again.
    CS2   Only --state is refused there; --proxy-v2 is ignored.
    CS3   A --state with '&' is sent as it stands.
    CS4   A --state of 65 bytes passes.
    CS5   An empty --state passes.
"""
import sys, pathlib
CIO = "apps/authd/conn_io.c"
WS = "apps/authd/ws.c"
CC = "apps/authd/client_cli.c"

M = {
    "PO1": [(CIO, "        return c->ws.close_at - c->ws.reply_sent;\n",
             "        return (c->ws.reply_sent == 0u) ? 0u : c->ws.reply_len - c->ws.reply_sent; /* MUTATION PO1 */\n")],
    "PO2": [(WS, "        w->close_at = w->reply_len;\n",
             "        w->close_at = 0u; /* MUTATION PO2 */\n")],
    "PO3": [(WS, "    w->close_queued = 0u;   /* a Close read behind the request went with the 101 */\n",
             "    /* MUTATION PO3 */\n")],
    "PO4": [(CIO, "    if (c->ws.close_queued && c->out_len > c->out_sent && c->ws.reply_sent <= c->ws.close_at) {\n",
             "    if (c->ws.close_queued && c->out_len > c->out_sent && c->ws.reply_sent < c->ws.close_at) { /* MUTATION PO4 */\n")],
    "PL1": [(CIO, "        return c->ws.close_at - c->ws.reply_sent;\n",
             "        return (c->ws.reply_sent == 0u) ? 0u : c->ws.reply_len - c->ws.reply_sent; /* MUTATION PL1 */\n")],
    "CS1": [(CC, "    if (a->unix_path == NULL && !a->ws && (a->state != NULL || a->proxy_v2)) {\n",
             "    if (a->unix_path == NULL && !a->ws && (a->state != NULL || a->proxy_v2) && 0) { /* MUTATION CS1 */\n")],
    "CS2": [(CC, "    if (a->unix_path == NULL && !a->ws && (a->state != NULL || a->proxy_v2)) {\n",
             "    if (a->unix_path == NULL && !a->ws && (a->state != NULL)) { /* MUTATION CS2 */\n")],
    "CS3": [(CC, "            if (ch < 0x21u || ch > 0x7eu || ch == '&') { ok = 0; }\n",
             "            if (ch < 0x21u || ch > 0x7eu) { ok = 0; } /* MUTATION CS3 */\n")],
    "CS4": [(CC, "        int ok = (sl >= 1u && sl <= WS_STATE_MAX);\n",
             "        int ok = (sl >= 1u && sl <= WS_STATE_MAX + 1u); /* MUTATION CS4 */\n")],
    "CS5": [(CC, "        int ok = (sl >= 1u && sl <= WS_STATE_MAX);\n",
             "        int ok = (sl <= WS_STATE_MAX); /* MUTATION CS5 */\n")],
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
