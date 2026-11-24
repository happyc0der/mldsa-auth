#!/usr/bin/env python3
"""V4-357 mutations: what the ninety-seventh review found (F754, F759).

Usage: mutate_v195.py <repo> <ID>

    RV1   the daemon's main file writes to descriptor 2 by a parenthesised name.
    RV2   the daemon's main file prints with a compiler builtin.
    RV3   the daemon's main file names standard output (fflush is not poisoned; the name is).
    RV4   a listener index past the table is taken for one.

RV1 to RV3 must not COMPILE: the second poison in authd_main.c is the check
(tools/mutations/compile_kills_allowed.txt).
"""
import sys, pathlib
MA = "apps/authd/authd_main.c"
EV = "apps/authd/evloop.c"
SAY = "        authd_cli_say_valid(&cfg, cfg_path);\n"

M = {
    "RV1": [(MA, SAY, SAY + "        (void)(write)(2, \"x\", 1); /* MUTATION RV1 */\n")],
    "RV2": [(MA, SAY, SAY + "        (void)__builtin_printf(\"x\"); /* MUTATION RV2 */\n")],
    "RV3": [(MA, SAY, SAY + "        (void)fflush(stdout); /* MUTATION RV3 */\n")],
    "RV4": [(EV, "    if (ev == NULL || li >= (size_t)AUTHD_MAX_LISTENERS) {\n",
             "    if (ev == NULL) { /* MUTATION RV4 */\n")],
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
