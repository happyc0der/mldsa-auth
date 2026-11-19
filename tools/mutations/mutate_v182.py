#!/usr/bin/env python3
"""V4-335 mutations: how long a login code is said to be good for (F635).

Usage: mutate_v182.py <repo> <ID>

    SL1   the number is not capped.
    SL2   a clock before 1970 is read as a very large time.
    SL3   an expiry in the past is subtracted all the same.

The browser session's queue (F638) is JavaScript, which no campaign
compiles; its controls were run with hand_control.py --interpreted and are
listed in docs/decisions.md under V4-335.
"""
import sys, pathlib
CC = "apps/authd/client_core.c"

M = {
    "SL1": [(CC, "    return (left > CC_SECONDS_LEFT_MAX) ? CC_SECONDS_LEFT_MAX : left;\n",
             "    return left; /* MUTATION SL1 */\n")],
    "SL2": [(CC, "    const uint64_t now = (now_unix > 0) ? (uint64_t)now_unix : 0u;\n",
             "    const uint64_t now = (uint64_t)now_unix; /* MUTATION SL2 */\n")],
    "SL3": [(CC, "    if (expires <= now) {\n        return 0u;\n    }\n    const uint64_t left = expires - now;\n",
             "    /* MUTATION SL3 */\n    const uint64_t left = expires - now;\n")],
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
