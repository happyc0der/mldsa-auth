#!/usr/bin/env python3
"""V4-349 mutations: what the ninety-second review found (F717 to F724).

Usage: mutate_v190.py <repo> <ID>

    RE1   the warning about RLIMIT_MEMLOCK is a plain write to standard error again.
    RE2   any signal that ends a line while stopping closes the log.
    RE3   SIGTERM is left blocked if the daemon was started so.
"""
import sys, pathlib
LG = "apps/authd/authd_log.c"
A = "apps/authd/authd_main.c"

M = {
    "RE1": [(A, "            authd_log_say(\n                    \"mldsa-authd: RLIMIT_MEMLOCK is %llu bytes but %u slots need %llu \"\n",
             "            fprintf(stderr, /* MUTATION RE1 */\n                    \"mldsa-authd: RLIMIT_MEMLOCK is %llu bytes but %u slots need %llu \"\n")],
    "RE2": [(LG, "        if (why == EINTR && g_timer_fired && g_stop_flag != NULL && *g_stop_flag) {\n",
             "        if (why == EINTR && g_stop_flag != NULL && *g_stop_flag) { /* MUTATION RE2 */\n")],
    "RE3": [(A, "        (void)sigaddset(&ours, SIGTERM);\n",
             "        /* MUTATION RE3 */\n")],
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
