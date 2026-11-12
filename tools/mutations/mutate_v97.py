#!/usr/bin/env python3
"""V4-121 mutations: a SIGHUP is logged and ignored instead of killing the
daemon (F206).

Usage: mutate_v97.py <repo> <ID>

Two-letter IDs: SH = SigHup. Every spec line names the check that must
catch it (F90).

    SH1   no handler is installed for SIGHUP (what F206 reported).
    SH2   SIGHUP is treated like SIGTERM: the daemon drains and exits.
    SH3   the signal is ignored without a log line.
    SH4   sighup-ignored is logged at INFO.
    SH5   the flag is never cleared, so one SIGHUP is logged on every turn
          of the loop.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "SH1": [(MAIN, "    (void)sigaction(SIGHUP, &sa, NULL);\n",
                   "    (void)0; /* MUTATION SH1 */\n")],
    "SH2": [(MAIN, "    if (sig == SIGHUP) {\n",
                   "    if (0 && sig == SIGHUP) { /* MUTATION SH2 */\n")],
    "SH3": [(MAIN, "            authd_log_event(AUTHD_LOG_WARN, \"sighup-ignored\");\n",
                   "            (void)0; /* MUTATION SH3 */\n")],
    "SH4": [(MAIN, "            authd_log_event(AUTHD_LOG_WARN, \"sighup-ignored\");\n",
                   "            authd_log_event(AUTHD_LOG_INFO, \"sighup-ignored\"); /* MUTATION SH4 */\n")],
    "SH5": [(MAIN, "            g_hup = 0;\n",
                   "            (void)0; /* MUTATION SH5 */\n")],
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
