#!/usr/bin/env python3
"""V4-330 mutations: the loop's deadlines after a handler that blocked (F619).

Usage: mutate_v180.py <repo> <ID>

    LT1   the idle deadline is re-armed from the iteration's time, noted or not.
    LT2   BACKUP does not tell the loop what time it ended at.
    LT3   what a handler noted is kept for later iterations.
    LT4   an earlier time replaces a later one already noted.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
LA = "apps/authd/localapi.c"

M = {
    "LT1": [(EV, "            const uint64_t served_ms = (ev->late_ms > now_ms) ? ev->late_ms : now_ms;\n",
             "            const uint64_t served_ms = now_ms; /* MUTATION LT1 */\n")],
    "LT2": [(LA, "    evloop_note_time(app->ev, app->now_ms);   /* F619: and the loop's deadlines count from now */\n",
             "    /* MUTATION LT2 */\n")],
    "LT3": [(EV, "    ev->late_ms = 0u;                /* F619: a handler's note is for its own iteration */\n",
             "    /* MUTATION LT3 */\n")],
    "LT4": [(EV, "    if (ev != NULL && now_ms > ev->late_ms) {\n        ev->late_ms = now_ms;\n",
             "    if (ev != NULL) { /* MUTATION LT4 */\n        ev->late_ms = now_ms;\n")],
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
