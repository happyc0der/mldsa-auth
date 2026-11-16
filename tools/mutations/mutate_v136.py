#!/usr/bin/env python3
"""V4-226 mutations: the limiter's refill is exact at every rate (F310).

Usage: mutate_v136.py <repo> <ID>

Two-letter IDs: RF = ReFill. Every spec line names the check that must catch
it (F90).

    RF1   The clock is not advanced by what was credited.
    RF2   A step that has only begun is credited.
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"

M = {
    "RF1": [(RL,
             "    *last_ms += steps * step_ms;\n",
             "    *last_ms += (steps * step_ms) / 4u; /* MUTATION RF1 */\n")],
    "RF2": [(RL,
             "    const uint64_t steps = (now_ms - *last_ms) / step_ms;\n",
             "    const uint64_t steps = (now_ms - *last_ms + step_ms - 1u) / step_ms; /* MUTATION RF2 */\n")],
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
