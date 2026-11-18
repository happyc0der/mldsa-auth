#!/usr/bin/env python3
"""V4-300 mutations: a failed wall-clock read is not the time (F515).

Usage: mutate_v164.py <repo> <ID>

    WC1   A failed read is used as the time again (-1, before every expiry).
"""
import sys, pathlib
CK = "apps/authd/authd_clock.h"

M = {
    "WC1": [(CK, "    return *last_unix + (int64_t)((now_ms - *last_ms) / 1000u);\n",
             "    return got; /* MUTATION WC1 */\n")],
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
