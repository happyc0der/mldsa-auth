#!/usr/bin/env python3
"""V4-181 mutations: what the end-to-end test now checks at shutdown and in
its logs (F256, F257).

Usage: mutate_v121.py <repo> <ID>

Two-letter IDs: EL = End-to-end Leg. Every spec line names the check that
must catch it (F90). (F254 and F255 are the F219 leg's timing and its retry
rule: shell, shown by hand and by v101 DR3.)

    EL1   A daemon that issued logins exits 1 after a clean stop. F256.
    EL2   The daemon prints its key passphrase, as hex, when it starts. F257.

(A socket file left behind at shutdown is not here: the start-up leg's
"left su-s.sock behind" check fails first for the same code, so no mutant
can show the main daemon's own check. Tried by hand, V4-181.)
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "EL1": [(MAIN,
             "    return loop_failed ? 1 : 0;\n",
             "    return (loop_failed || app.logins_issued > 0u) ? 1 : 0; /* MUTATION EL1 */\n")],
    "EL2": [(MAIN,
             "                                                 (const char *)pass, pass_len, &server_kp, kek);\n        authd_secret_free(pass, pass_len);\n",
             "                                                 (const char *)pass, pass_len, &server_kp, kek);\n"
             "        for (size_t mi = 0; mi < pass_len; mi++) { fprintf(stderr, \"%02x\", (unsigned)pass[mi]); } /* MUTATION EL2 */\n"
             "        fprintf(stderr, \"\\n\");\n"
             "        authd_secret_free(pass, pass_len);\n")],
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
