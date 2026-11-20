#!/usr/bin/env python3
"""V4-348 mutations: what the ninety-first review found (F710 to F716).

Usage: mutate_v189.py <repo> <ID>

    RD1   a stop signal does not give a line that is already waiting its time limit.
    RD2   a start with no store and nowhere to make one says only `io`.
    RD3   the daemon's line timer is left blocked if it was started so.
"""
import sys, pathlib
LG = "apps/authd/authd_log.c"
A = "apps/authd/authd_main.c"

M = {
    "RD1": [(LG, "    if (g_in_line) {\n        line_timer(LOG_STOPPING_LINE_USEC);\n",
             "    if (0 && g_in_line) { /* MUTATION RD1 */\n        line_timer(LOG_STOPPING_LINE_USEC);\n")],
    "RD2": [(A, "                    if (access(dir, W_OK) != 0) {\n",
             "                    if (0 && access(dir, W_OK) != 0) { /* MUTATION RD2 */\n")],
    "RD3": [(LG, "        (void)sigprocmask(SIG_UNBLOCK, &one, NULL);\n",
             "        /* MUTATION RD3 */\n")],
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
