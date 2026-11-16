#!/usr/bin/env python3
"""V4-218 mutations: a command that could not print its result has not
succeeded (F295), and a backup destination has a named bound (F296).

Usage: mutate_v133.py <repo> <ID>

Two-letter IDs: SO = Standard Output, BP = Backup Path. Every spec line names
the check that must catch it (F90).

    SO1   The flush's result is not looked at.
    SO2   The device client's status does not pass through the check.
    SO3   The admin tool's status does not pass through the check.
    BP1   The bound is one byte too generous.
"""
import sys, pathlib
CH = "apps/authd/cli_common.h"
CC = "apps/authd/client_cli.c"
AC = "apps/authd/authd_cli.c"

M = {
    "SO1": [(CH,
             "    if (fflush(stdout) != 0 || ferror(stdout)) {\n",
             "    if (fflush(stdout) != 0 && rc != EX_OK) { /* MUTATION SO1 */\n")],
    "SO2": [(CC,
             "    return cli_finish_stdout(prog, client_dispatch(argc, argv, prog));\n",
             "    return client_dispatch(argc, argv, prog); /* MUTATION SO2 */\n")],
    "SO3": [(AC,
             "    return cli_finish_stdout(prog, admin_dispatch(argc, argv, prog));\n",
             "    return admin_dispatch(argc, argv, prog); /* MUTATION SO3 */\n")],
    "BP1": [(AC,
             "    if (plen > AUTHD_BACKUP_PATH_MAX) {\n",
             "    if (plen > AUTHD_BACKUP_PATH_MAX + 1u) { /* MUTATION BP1 */\n")],
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
