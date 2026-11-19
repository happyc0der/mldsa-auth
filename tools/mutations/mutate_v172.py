#!/usr/bin/env python3
"""V4-317 mutations: what the sixty-ninth review found in the C code
(F548, F550 to F553).

Usage: mutate_v172.py <repo> <ID>

    LB1   The limiter's table leaves out the global bucket's burst.
    RF1   authd_client takes the last of a repeated flag.
    RF2   The value after a flag is compared as if it were a flag.
    ST1   --state lets '%', '+' and '#' through to the daemon.
    SP1   An unusable --server-pub exits 1.
    RW1   rotate calls every unopened session "did not open".

The browser client (F555) is JavaScript, which no campaign compiles; its
control was run with hand_control.py --interpreted and is listed in
docs/decisions.md under V4-317.
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"
CL = "apps/authd/client_cli.c"

M = {
    "LB1": [(RL, "    if (want < held + gl) {\n",
             "    if (want < held + gl && 0) { /* MUTATION LB1 */\n")],
    "RF1": [(CL, "    const char *twice = client_repeated_flag(argc, argv, valued);\n",
             "    const char *twice = (argc < 0) ? client_repeated_flag(argc, argv, valued) : NULL; /* MUTATION RF1 */\n")],
    "RF2": [(CL, "        if (takes) { i++; }\n    }\n    return NULL;\n",
             "        (void)takes; /* MUTATION RF2 */\n    }\n    return NULL;\n")],
    "ST1": [(CL, "            if (ch < 0x21u || ch > 0x7eu || ch == '&' || ch == '%' || ch == '+' || ch == '#') { ok = 0; }\n",
             "            if (ch < 0x21u || ch > 0x7eu || ch == '&') { ok = 0; } /* MUTATION ST1 */\n")],
    "SP1": [(CL, "    return (ps == DEMO_KEYS_ERR_CRYPTO || ps == DEMO_KEYS_ERR_ARG) ? EX_FAIL : EX_CONFIG;\n",
             "    return (ps == DEMO_KEYS_ERR_CRYPTO || ps == DEMO_KEYS_ERR_ARG) ? EX_FAIL : EX_FAIL; /* MUTATION SP1 */\n")],
    "RW1": [(CL, "                    : (g_open_why[0] != '\\0') ? g_open_why\n",
             "                    : (g_open_why[0] == '\\0') ? g_open_why /* MUTATION RW1 */\n")],
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
