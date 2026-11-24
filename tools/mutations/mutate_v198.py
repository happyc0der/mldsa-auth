#!/usr/bin/env python3
"""V4-361 mutations: what the hundredth review found (F772, F773, F774).

Usage: mutate_v198.py <repo> <ID>

    RY1   a start that failed on a socket another daemon listens on removes
          the store it created.
    RY2   the limiter is asked about a preamble that was refused.
    RY3   the limiter's refusal of a connection whose request failed is not
          acted on.
"""
import sys, pathlib
MA = "apps/authd/authd_main.c"
EV = "apps/authd/evloop.c"

M = {
    "RY1": [(MA, "    if (store_created && socket_in_use) {\n",
             "    if (0 && store_created && socket_in_use) { /* MUTATION RY1 */\n")],
    "RY2": [(EV, "        if (!s->addr_settled && conn_io_proxy_settled(&s->io) && !conn_io_proxy_refused(&s->io)) {\n",
             "        if (!s->addr_settled && conn_io_proxy_settled(&s->io)) { /* MUTATION RY2 */\n")],
    "RY3": [(EV, "            if (ev->on_addr != NULL && ev->on_addr(ev->user, s) == EV_ACTION_CLOSE) {\n                ev->closed_refused_addr++;\n",
             "            if (ev->on_addr != NULL && ev->on_addr(ev->user, s) == EV_ACTION_CLOSE && 0) { /* MUTATION RY3 */\n                ev->closed_refused_addr++;\n")],
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
