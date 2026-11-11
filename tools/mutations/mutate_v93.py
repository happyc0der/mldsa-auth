#!/usr/bin/env python3
"""V4-114 mutations: a PROXY v2 source in ::ffff:0:0/96 is the IPv4 client it
names (F202, spec 7.1 erratum 83).

Usage: mutate_v93.py <repo> <ID>

Two-letter IDs: MA = MApped. Every spec line names the check that must catch
it (F90).

    MA1   a mapped source is never recognised: it stays IPv6, keyed on a /64
          that is zero for every IPv4 client.
    MA2   a mapped source becomes IPv4 from its FIRST four bytes, 0.0.0.0.
    MA3   only the ten zero bytes are compared, so ::fffe:... is mapped too.
    MA4   only the ff:ff pair and the bytes before it in the low half are
          compared, so any IPv6 address ending like a mapped one is mapped.
"""
import sys, pathlib
PX = "apps/authd/proxy_v2.c"

M = {
    "MA1": [(PX, "        if (memcmp(src, MAPPED, sizeof MAPPED) == 0) {\n",
                 "        if (memcmp(src, MAPPED, sizeof MAPPED) == 0 && fam == 0x1u) { /* MUTATION MA1 */\n")],
    "MA2": [(PX, "            memcpy(p->addr.addr, src + 12, 4);\n",
                 "            memcpy(p->addr.addr, src, 4); /* MUTATION MA2 */\n")],
    "MA3": [(PX, "        if (memcmp(src, MAPPED, sizeof MAPPED) == 0) {\n",
                 "        if (memcmp(src, MAPPED, sizeof MAPPED - 2u) == 0) { /* MUTATION MA3 */\n")],
    "MA4": [(PX, "        if (memcmp(src, MAPPED, sizeof MAPPED) == 0) {\n",
                 "        if (memcmp(src + 8, MAPPED + 8, 4) == 0) { /* MUTATION MA4 */\n")],
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
