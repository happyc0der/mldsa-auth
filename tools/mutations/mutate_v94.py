#!/usr/bin/env python3
"""V4-115 mutations: a passphrase prompt that is stopped and continued asks
again with echo off (F203, spec 13 erratum 84).

Usage: mutate_v94.py <repo> <ID>

Two-letter IDs: JC = Job Control. Every spec line names the check that must
catch it (F90).

    JC1   the stop signals are never caught: the prompt just resumes its read
          on a terminal the shell has left echoing.
    JC2   the terminal is not restored before the process stops.
    JC3   after the continue the prompt is not armed again: echo stays as the
          shell left it.
    JC4   echo is turned off without discarding what was typed before: after
          a stop the abandoned half-line is read as the start of the
          passphrase. (The same call arms the first prompt, so earlier checks
          that lean on the flush fail too; the named one is the F203 one.)
    JC5   the handler is not put back after the stop: only the first Ctrl-Z
          is handled.
    JC6   an ignored SIGTSTP is caught all the same.
"""
import sys, pathlib
PR = "apps/authd/cli_prompt.c"

M = {
    "JC1": [(PR, "        if (is_stop(k_sigs[i]) && old[i].sa_handler == SIG_IGN) {\n",
                 "        if (is_stop(k_sigs[i])) { /* MUTATION JC1 */\n")],
    "JC2": [(PR, "            (void)tcsetattr(fd, TCSANOW, &saved);\n"
                 "            for (size_t i = 0; i < N_SIGS; i++) {\n",
                 "            /* MUTATION JC2 */\n"
                 "            for (size_t i = 0; i < N_SIGS; i++) {\n")],
    "JC3": [(PR, "            armed = 0;\n",
                 "            /* MUTATION JC3 */\n")],
    "JC4": [(PR, "            if (tcsetattr(fd, TCSAFLUSH, &quiet) != 0) {\n",
                 "            if (tcsetattr(fd, TCSANOW, &quiet) != 0) { /* MUTATION JC4 */\n")],
    "JC5": [(PR, "            (void)sigaction(sig, &sa, NULL);\n",
                 "            /* MUTATION JC5 */\n")],
    "JC6": [(PR, "        if (is_stop(k_sigs[i]) && old[i].sa_handler == SIG_IGN) {\n",
                 "        if (is_stop(k_sigs[i]) && old[i].sa_handler == SIG_ERR) { /* MUTATION JC6 */\n")],
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
