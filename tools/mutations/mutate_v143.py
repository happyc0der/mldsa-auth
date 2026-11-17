#!/usr/bin/env python3
"""V4-241 mutations: the loop's idle wait and the watchdog; a run of accept() failures; an illegal header behind a served frame (F340, F341, F342).

Usage: mutate_v143.py <repo> <ID>

Two-letter IDs: LT = Loop Turn. Every spec line names the check that must
catch it (F90).

    LT1   The idle wait ignores how long ago the last ping was.
    LT2   A peer refused by the uid rule leaves the run of accept() failures going.
    LT3   An illegal header behind a served frame is left for the deadline.
    LT4   It closes the connection, but is not counted.
"""
import sys, pathlib
SDN = "apps/authd/sdnotify.c"
EVL = "apps/authd/evloop.c"

M = {
    "LT1": [(SDN, "    return (left < (uint64_t)idle_ms) ? (int)left : idle_ms;\n",
                  "    return (left < (uint64_t)idle_ms && since_ms == 0u) ? (int)left : idle_ms; /* MUTATION LT1 */\n")],
    "LT2": [(EVL, "        if (st == LISTENER_OK || st == LISTENER_ERR_PEER) {\n",
                  "        if (st == LISTENER_OK) { /* MUTATION LT2 */\n")],
    "LT3": [(EVL, "    if (s->state == SLOT_ACTIVE && s->io.failed) {\n",
                  "    if (s->state == SLOT_ACTIVE && s->io.failed && 0) { /* MUTATION LT3 */\n")],
    "LT4": [(EVL, "    if (s->state == SLOT_ACTIVE && s->io.failed) {\n        ev->closed_protocol++;\n",
                  "    if (s->state == SLOT_ACTIVE && s->io.failed) {\n        /* MUTATION LT4 */\n")],
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
