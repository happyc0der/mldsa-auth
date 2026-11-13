#!/usr/bin/env python3
"""V4-146 mutations: with a leftover .ek.next, the client says WHY neither key
logged in -- the files would not open, the daemon was not reached, or the
daemon refused them -- and advises re-enrolment only for the last (F225).

Usage: mutate_v104.py <repo> <ID>

Two-letter IDs: RK = Resolve Key. Every spec line names the check that must
catch it (F90).

    RK1   A failure after ClientAuth is not recorded as the daemon's answer:
          two refused keys are reported as a daemon that could not be asked.
    RK2   A failed connection is recorded as the daemon's answer. Half of
          the defect itself.
    RK3   Two key files that would not open fall through to the daemon's
          verdict. The other half of the defect.
    RK4   The unreachable-daemon report is skipped.
    RK5   The status of an unopenable .ek.next is not printed.
    RK6   A refused key beside an unopenable file is reported as two refused
          keys.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "RK1": [(CL,
             "    g_open_judged = 1;   /* the daemon has the key now; a failure is its answer */\n",
             "    g_open_judged = 0; /* MUTATION RK1 */\n")],
    "RK2": [(CL,
             "        open_failed_before_key(\"cannot connect\", net_status_name(ns));\n",
             "        open_failed_before_key(\"cannot connect\", net_status_name(ns));\n"
             "        g_open_judged = 1; /* MUTATION RK2 */\n")],
    "RK3": [(CL,
             "        if (ks_ek != KEYFILE_OK && ks_next != KEYFILE_OK) {\n",
             "        if (ks_ek != KEYFILE_OK && ks_next != KEYFILE_OK && 0) { /* MUTATION RK3 */\n")],
    "RK4": [(CL,
             "        } else if (unasked) {\n",
             "        } else if (unasked && 0) { /* MUTATION RK4 */\n")],
    "RK5": [(CL,
             "        if (ks_next != KEYFILE_OK) {\n"
             "            fprintf(stderr, \"%s %s: %s: %s\\n\", prog, sub, next_path, keyfile_status_name(ks_next));\n",
             "        if (ks_next != KEYFILE_OK && 0) { /* MUTATION RK5 */\n"
             "            fprintf(stderr, \"%s %s: %s: %s\\n\", prog, sub, next_path, keyfile_status_name(ks_next));\n")],
    "RK6": [(CL,
             "        } else if (ks_ek != KEYFILE_OK || ks_next != KEYFILE_OK) {\n",
             "        } else if (0) { /* MUTATION RK6 */\n")],
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
