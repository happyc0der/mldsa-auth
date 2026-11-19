#!/usr/bin/env python3
"""V4-308 mutations: the limiter's table is sized from the configuration (F338).

Usage: mutate_v166.py <repo> <ID>

    TS1   The rates are ignored: the size is the larger of 1024 and max_slots.
    TS2   The quarter's headroom is dropped.
    TS3   The ceiling is not applied to the size.
    TS4   max_slots is ignored.
    TS5   The daemon gives its limiter 1024 entries whatever was computed.
    TS6   --check-config no longer warns when the ceiling binds.
    TS7   Making room for a new address probes only the first 1024 entries.
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"
AM = "apps/authd/authd_main.c"

M = {
    "TS1": [(RL, "    const uint64_t held = (gl * 60u + pm - 1u) / pm;       /* rounded up */\n",
             "    const uint64_t held = 0u * (gl + pm); /* MUTATION TS1 */\n")],
    "TS2": [(RL, "    uint64_t want = held + (held + 3u) / 4u;               /* a quarter's headroom */\n",
             "    uint64_t want = held; /* MUTATION TS2 */\n")],
    "TS3": [(RL, "    return (want > (uint64_t)RATELIMIT_ENTRIES_MAX) ? (size_t)RATELIMIT_ENTRIES_MAX : (size_t)want;\n",
             "    return (size_t)want; /* MUTATION TS3 */\n")],
    "TS4": [(RL, "    if (want < (uint64_t)max_slots) {\n        want = (uint64_t)max_slots;\n    }\n",
             "    if (want < (uint64_t)max_slots && 0) { /* MUTATION TS4 */\n        want = (uint64_t)max_slots;\n    }\n")],
    "TS5": [(AM, "        ratelimit_init(&limiter, limiter_table, table_n,\n",
             "        ratelimit_init(&limiter, limiter_table, (table_n > 0u) ? (size_t)RATELIMIT_ENTRIES : 0u, /* MUTATION TS5 */\n")],
    "TS6": [(AM, "            if (want > (uint64_t)RATELIMIT_ENTRIES_MAX) {\n",
             "            if (want > (uint64_t)RATELIMIT_ENTRIES_MAX && 0) { /* MUTATION TS6 */\n")],
    "TS7": [(RL, "    for (size_t n = 0; n < r->n_entries; n++) {\n        ratelimit_entry_t *c = &r->e[(b + n) % r->n_entries];\n",
             "    for (size_t n = 0; n < r->n_entries && n < 1024u; n++) { /* MUTATION TS7 */\n        ratelimit_entry_t *c = &r->e[(b + n) % r->n_entries];\n")],
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
