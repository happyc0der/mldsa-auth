#!/usr/bin/env python3
"""V4-351 mutations: deadlines acted on when they are due (F728).

Usage: mutate_v192.py <repo> <ID>

    RG1   slots past their deadline are not given back before the accept.
    RG2   the wait the loop is asked for ignores the deadlines.
    RG3   a deadline that has passed still earns a wait.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"

M = {
    "RG1": [(EV, "        if (s->state != SLOT_FREE && s->deadline_ms != 0u && now_ms >= s->deadline_ms &&\n            all[npfd + i].revents == 0) {\n",
             "        if (0 && s->state != SLOT_FREE && s->deadline_ms != 0u && now_ms >= s->deadline_ms && /* MUTATION RG1 */\n            all[npfd + i].revents == 0) {\n")],
    "RG2": [(EV, "            if (left < wait) {\n",
             "            if (0 && left < wait) { /* MUTATION RG2 */\n")],
    "RG3": [(EV, "            const uint64_t left = (s->deadline_ms > now_ms) ? s->deadline_ms - now_ms : 0u;\n",
             "            const uint64_t left = (s->deadline_ms > now_ms) ? s->deadline_ms - now_ms : (uint64_t)cap_ms; /* MUTATION RG3 */\n")],
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
