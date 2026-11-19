#!/usr/bin/env python3
"""V4-318 mutations: what the seventieth review found in the C code
(F552's walk, F556, F558, F561).

Usage: mutate_v173.py <repo> <ID>

    HM1   The hold is 60000 / per_min, rounded up, not the refill's steps.
    RF3   Looking back, the walk compares a flag's value as a flag.
    PL1   A --key whose .ek.next name does not fit exits 1.
    NE1   A full backlog (EAGAIN) is an I/O error at once.   [Linux only]

The browser client (F555's other half, F557) is JavaScript, which no
campaign compiles; its controls were run with hand_control.py --interpreted
and are listed in docs/decisions.md under V4-318.
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"
CL = "apps/authd/client_cli.c"
NI = "apps/net_io.c"

M = {
    "HM1": [(RL, "    return ((1000u + step_tok - 1u) / step_tok) * step_ms;\n",
             "    return (60000u + pm - 1u) / pm + 0u * (step_tok + step_ms); /* MUTATION HM1 */\n")],
    "RF3": [(CL, "            if (j_takes) { j++; }\n",
             "            (void)j_takes; /* MUTATION RF3 */\n")],
    "PL1": [(CL, "        (void)failed(prog, sub, a->key_path, \"path-too-long\");\n        return EX_CONFIG;",
             "        (void)failed(prog, sub, a->key_path, \"path-too-long\");\n        return EX_FAIL; /* MUTATION PL1 */")],
    "NE1": [(NI, "        if (errno == EAGAIN) {\n",
             "        if (errno == EAGAIN && 0) { /* MUTATION NE1 */\n")],
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
