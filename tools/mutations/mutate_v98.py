#!/usr/bin/env python3
"""V4-123 mutations: a daemon with fewer descriptors than slots holds fewer
connections, so the admin socket keeps one (F207).

Usage: mutate_v98.py <repo> <ID>

Two-letter IDs: SC = Slot Cap. Every spec line names the check that must
catch it (F90).

    SC1   the loop ignores the cap and fills the whole table.
    SC2   the daemon computes the cap and never applies it (what F207
          reported).
    SC3   the cap does not set the local slots aside.
    SC4   a limit that covers every slot still caps the table.
    SC5   a limit below the overhead gives a cap of zero.
    SC6   a cap above the table's size is accepted.
    SC7   standard error names max_slots where the cap belongs.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"
EV = "apps/authd/evloop.c"
FD = "apps/authd/fdlimit.c"

M = {
    "SC1": [(EV, "    const size_t n = (kind == SLOT_KIND_LOCAL) ? ev->n_local_slots : ev->slot_cap;\n",
                 "    const size_t n = (kind == SLOT_KIND_LOCAL) ? ev->n_local_slots : ev->n_slots; /* MUTATION SC1 */\n")],
    "SC2": [(MAIN, "            if (evloop_set_slot_cap(&ev, (size_t)cap) != 0) {\n",
                   "            if (0 != 0) { /* MUTATION SC2 */\n")],
    "SC3": [(FD, "    const uint64_t aside = (uint64_t)max_local_slots + (uint64_t)FDLIMIT_OVERHEAD;\n",
                 "    const uint64_t aside = (uint64_t)FDLIMIT_OVERHEAD; (void)max_local_slots; /* MUTATION SC3 */\n")],
    "SC4": [(FD, "    return (fit >= (uint64_t)max_slots) ? max_slots : (uint32_t)fit;\n",
                 "    return (fit > (uint64_t)max_slots) ? max_slots - 1u : (uint32_t)fit; /* MUTATION SC4 */\n")],
    "SC5": [(FD, "    if (limit <= aside) {\n        return 1u;\n",
                 "    if (limit <= aside) {\n        return 0u; /* MUTATION SC5 */\n")],
    "SC6": [(EV, "    if (ev == NULL || cap == 0u || cap > ev->n_slots) {\n",
                 "    if (ev == NULL || cap == 0u) { /* MUTATION SC6 */\n")],
    "SC7": [(MAIN, "                    (unsigned long long)need, cap);\n",
                   "                    (unsigned long long)need, cfg.max_slots); /* MUTATION SC7 */\n")],
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
