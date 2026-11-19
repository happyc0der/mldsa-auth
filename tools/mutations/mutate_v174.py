#!/usr/bin/env python3
"""V4-320 mutations: the limiter's table and the burst (F563), and the
administrator's tool at a busy daemon (F566).

Usage: mutate_v174.py <repo> <ID>

    BS1   The table is sized for one token an address, whatever the burst.
    BS2   The burst is summed, each term a whole hold: k is not divided by.
    BZ1   A connection the daemon did not take is `timeout`.   [Linux only]
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"
LC = "apps/authd/localcli.c"

M = {
    "BS1": [(RL, "    for (uint64_t k = 1u; k <= b; k++) {\n",
             "    for (uint64_t k = 1u; k <= b && k <= 1u; k++) { /* MUTATION BS1 */\n")],
    "BS2": [(RL, "        sum += (gl * hold_ms + 1000u * k - 1u) / (1000u * k);   /* rounded up */\n",
             "        sum += (gl * hold_ms + 999u) / 1000u + 0u * k; /* MUTATION BS2 */\n")],
    "BZ1": [(LC, "        return (cs == NET_TIMEOUT) ? LOCALCLI_ERR_BUSY : LOCALCLI_ERR_CONNECT;\n",
             "        return (cs == NET_TIMEOUT) ? LOCALCLI_ERR_TIMEOUT : LOCALCLI_ERR_CONNECT; /* MUTATION BZ1 */\n")],
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
