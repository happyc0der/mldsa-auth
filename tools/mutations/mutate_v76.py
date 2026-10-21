#!/usr/bin/env python3
"""V4-43 mutations: the CLI client's WebSocket frame reader (audit F122 item 2).

Usage: mutate_v76.py <repo> <ID>

Two-letter IDs: WC = WebSocket Client. ws_client_read_message parses what a
server sends the CLI; V4-40's coverage run found none of its refusals had ever
run. Every spec line names the check that must catch it (F90).

    WC1   RSV bits are no longer refused.
    WC2   a masked server frame is accepted.
    WC3   a 64-bit length's top bit is allowed (on a Close it reports CLOSED).
    WC4   a control frame's length is not bounded: a 126-byte ping is read
          into the 125-byte drain on the stack.
    WC5   a text frame (or a continuation) is accepted as a message.
    WC6   a binary frame without FIN (a fragment) is accepted.
    WC7   a frame is not bounded by the caller's buffer: its payload is read
          past `out`. (`&& 0`, not `if (0)`: deleting the only use of `cap`
          is refused by -Werror, a compile kill F79 does not count.)
    WC8   a ping is returned as an empty message instead of being skipped.
    WC9   a clean EOF at a frame boundary reports IO instead of CLOSED.
"""
import sys, pathlib
WS = "apps/authd/ws.c"

M = {
    "WC1": [(WS, "        if ((h[0] & 0x70u) != 0u) { return WS_CLIENT_PROTOCOL; }   /* RSV: no extensions */\n",
                 "        if (0) { return WS_CLIENT_PROTOCOL; }   /* MUTATION WC1: RSV ignored */\n")],
    "WC2": [(WS, "        if ((h[1] & 0x80u) != 0u) { return WS_CLIENT_PROTOCOL; }   /* §5.1: server frames are UNMASKED */\n",
                 "        if (0) { return WS_CLIENT_PROTOCOL; }   /* MUTATION WC2: masked server frames accepted */\n")],
    "WC3": [(WS, "            if ((len >> 63) != 0u) { return WS_CLIENT_PROTOCOL; }\n",
                 "            if (0) { return WS_CLIENT_PROTOCOL; } /* MUTATION WC3: top bit allowed */\n")],
    "WC4": [(WS, "            if (len > sizeof drain) { return WS_CLIENT_PROTOCOL; }\n",
                 "            if (0) { return WS_CLIENT_PROTOCOL; } /* MUTATION WC4: control length unbounded */\n")],
    "WC5": [(WS, "        if (op != WS_OP_BINARY || (b0 & 0x80u) == 0u) {\n",
                 "        if ((b0 & 0x80u) == 0u) { /* MUTATION WC5: any data opcode accepted */\n")],
    "WC6": [(WS, "        if (op != WS_OP_BINARY || (b0 & 0x80u) == 0u) {\n",
                 "        if (op != WS_OP_BINARY) { /* MUTATION WC6: fragments accepted */\n")],
    "WC7": [(WS, "        if (len > (uint64_t)cap) { return WS_CLIENT_PROTOCOL; }\n",
                 "        if (len > (uint64_t)cap && 0) { return WS_CLIENT_PROTOCOL; } /* MUTATION WC7: no bound against the buffer */\n")],
    "WC8": [(WS, "            continue;                        /* control frames carry no protocol bytes */\n",
                 "            return WS_CLIENT_OK;             /* MUTATION WC8: a ping is a message */\n")],
    "WC9": [(WS, "        if (first > 0)  { return WS_CLIENT_CLOSED; }     /* clean EOF at a boundary */\n",
                 "        if (first > 0)  { return WS_CLIENT_IO; }     /* MUTATION WC9: clean EOF is an error */\n")],
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
