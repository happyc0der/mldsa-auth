#!/usr/bin/env python3
"""V4-137 mutations: the daemon's stop waits for the local pool too, so a
reply queued for the site or for an operator is written before the loop
ends (F219).

Usage: mutate_v101.py <repo> <ID>

Two-letter IDs: DR = DRain. Every spec line names the check that must
catch it (F90).

    DR1   the drain is finished once the protocol pool is empty: a reply
          queued on a local connection is dropped. The defect itself.
    DR2   a loop that was never stopped reports a finished drain.
    DR3   the daemon's loop asks evloop_active() again, not
          evloop_drained(): the library is right and the daemon is not.
    DR4   the drain is finished once the LOCAL pool is empty: a protocol
          reply is dropped instead.
    DR5   a stop leaves local connections ACTIVE: an idle site connection
          holds the stop until its deadline.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
MAIN = "apps/authd/authd_main.c"

M = {
    "DR1": [(EV, "    return ev->in_use == 0u && ev->local_in_use == 0u;\n",
                 "    return ev->in_use == 0u; /* MUTATION DR1 */\n")],
    "DR2": [(EV, "    if (ev == NULL || !ev->stopping) {\n        return 0;\n    }\n    /* Both pools",
                 "    if (ev == NULL) { /* MUTATION DR2 */\n        return 0;\n    }\n    /* Both pools")],
    "DR3": [(MAIN, "        if (draining && evloop_drained(&ev)) {\n",
                   "        if (draining && evloop_active(&ev) == 0u) { /* MUTATION DR3 */\n")],
    "DR4": [(EV, "    return ev->in_use == 0u && ev->local_in_use == 0u;\n",
                 "    return ev->local_in_use == 0u; /* MUTATION DR4 */\n")],
    "DR5": [(EV, "        if (ev->local_slots[i].state == SLOT_ACTIVE) {\n            ev->local_slots[i].state = SLOT_DRAINING;\n",
                 "        if (ev->local_slots[i].state == SLOT_ACTIVE) {\n            ev->local_slots[i].state = SLOT_ACTIVE; /* MUTATION DR5 */\n")],
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
