#!/usr/bin/env python3
"""V4-224 mutations: one turn's accepts are bounded (F306), listeners are
served in turn (F307), and a hang-up does not close a slot that still had
input to read (F308).

Usage: mutate_v135.py <repo> <ID>

Two-letter IDs: AB = Accept Burst, LT = Listener Turns, HU = Hang-Up. Every
spec line names the check that must catch it (F90).

    AB1   The bound on one turn's accepts is far above any queue.
    LT1   Listeners are served in registration order.
    LT2   The listener that accepted last is not remembered.
    HU1   A hang-up closes the slot although input was read this turn.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "AB1": [(EV,
             "    for (unsigned taken = 0; taken < EVLOOP_ACCEPT_BURST; taken++) {   /* F306 */\n",
             "    for (unsigned taken = 0; taken < 100000u; taken++) { /* MUTATION AB1 */\n")],
    "LT1": [(EV,
             "        const size_t i = (ev->last_accept_li + 1u + k) % listener_count;\n",
             "        const size_t i = k; /* MUTATION LT1 */\n")],
    "LT2": [(EV,
             "        ev->last_accept_li = li;   /* F307 */\n",
             "        /* MUTATION LT2: not remembered */\n")],
    "HU1": [(EV,
             "        if (!closed && (re & POLLHUP) != 0 && (re & POLLIN) == 0 && conn_io_pending(&s->io) == 0u) {\n",
             "        if (!closed && (re & POLLHUP) != 0 && conn_io_pending(&s->io) == 0u) { /* MUTATION HU1 */\n")],
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
