#!/usr/bin/env python3
"""V4-358 mutations: requests buffered ahead of a WebSocket Close (F760).

Usage: mutate_v196.py <repo> <ID>

    RW1   the Close echo counts as a reply to wait for.
    RW2   a slot whose peer sent Close drains with a request still buffered.
    RW3   the rest is served only once nothing at all is pending.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "RW1": [(EV, "        if (conn_io_ws_ended(&s->io) ? conn_io_out_unsent(&s->io) > 0u : conn_io_pending(&s->io) > 0u) {\n",
             "        if (conn_io_pending(&s->io) > 0u) { /* MUTATION RW1 */\n")],
    "RW2": [(EV, "    if (conn_io_out_unsent(&s->io) > 0u && conn_io_next_frame(&s->io, &p, &l)) {\n",
             "    if (0 && conn_io_out_unsent(&s->io) > 0u && conn_io_next_frame(&s->io, &p, &l)) { /* MUTATION RW2 */\n")],
    "RW3": [(EV, "                       (conn_io_ws_ended(&s->io) ? conn_io_out_unsent(&s->io) == 0u\n                                                 : conn_io_pending(&s->io) == 0u)) {\n",
             "                       (conn_io_pending(&s->io) == 0u)) { /* MUTATION RW3 */\n")],
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
