#!/usr/bin/env python3
"""V4-54 mutations: the event loop against peers that pipeline or never read.

Usage: mutate_v83.py <repo> <ID>

Two-letter IDs: BP = Back-Pressure. The loop is half-duplex: once a served
frame's reply is queued it neither polls for nor consumes input until the
reply has gone out. V4-54's coverage run showed none of that had been driven,
and the tests that drive it found F127 (a pipelined frame waited for more
input; a read past the buffer's room closed the connection). Every spec line
names the check that must catch it (F90).

    BP1   the half-duplex stop removed: a second frame is served over an unsent
          reply, whose own reply is then refused as BUSY and lost.
    BP2   input polled while a reply waits: a peer that never reads is served
          anyway, its replies lost.
    BP3   a partial write counted as whole: the rest of the reply is skipped.
    BP4   the deadline skipped while a reply is pending: a peer that never
          reads keeps its slot for ever.
    BP5   F127 again: the frame pipelined behind a reply waits for more input.
    BP6   F127 again: a read takes a whole chunk past the input buffer's room.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "BP1": [(EV, "        if (conn_io_pending(&s->io) > 0u) {\n            break;\n",
                 "        if (conn_io_pending(&s->io) > 0u && 0) { /* MUTATION BP1: served over an unsent reply */\n            break;\n")],
    "BP2": [(EV, "            } else if (s->state == SLOT_ACTIVE) {\n",
                 "            }\n            if (s->state == SLOT_ACTIVE) { /* MUTATION BP2: input polled while a reply waits */\n")],
    "BP3": [(EV, "    conn_io_sent(&s->io, (size_t)n);\n",
                 "    conn_io_sent(&s->io, pending); /* MUTATION BP3: a partial write counted as whole */\n")],
    "BP4": [(EV, "            if (s->state == SLOT_FREE || s->deadline_ms == 0u) {\n",
                 "            if (s->state == SLOT_FREE || s->deadline_ms == 0u || conn_io_pending(&s->io) > 0u) { /* MUTATION BP4: a stalled peer outlives its deadline */\n")],
    "BP5": [(EV, "            } else if (s->state == SLOT_ACTIVE && conn_io_pending(&s->io) == 0u) {\n",
                 "            } else if (s->state == SLOT_ACTIVE && conn_io_pending(&s->io) == 0u && 0) { /* MUTATION BP5: F127, a pipelined frame waits */\n")],
    "BP6": [(EV, "        n = read(s->fd, buf, (room < sizeof buf) ? room : sizeof buf);\n",
                 "        n = read(s->fd, buf, sizeof buf); /* MUTATION BP6: F127, a read past the buffer's room */\n")],
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
