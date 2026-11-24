#!/usr/bin/env python3
"""V4-359 mutations: a refused request behind its PROXY preamble (F766).

Usage: mutate_v197.py <repo> <ID>

    RX1   a connection whose request fails in the read that settled its
          address is closed without the limiter being told.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "RX1": [(EV, "        if (!s->addr_settled && conn_io_proxy_settled(&s->io) && !conn_io_proxy_refused(&s->io)) {\n",
             "        if (0 && !s->addr_settled && conn_io_proxy_settled(&s->io) && !conn_io_proxy_refused(&s->io)) { /* MUTATION RX1 */\n")],
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
