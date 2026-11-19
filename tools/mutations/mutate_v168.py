#!/usr/bin/env python3
"""V4-311 mutations: authd_admin's arguments and its wait for BACKUP
(F533, F537, F538, F539).

Usage: mutate_v168.py <repo> <ID>

    AD1   A flag given twice is accepted again: the last value is used.
    AD2   keygen-server takes one path for the key and its public half.
    AD3   pseudonym hashes an --id the daemon could never hold.
    AD4   BACKUP waits ten seconds like every other command.

The reference site's client (F532, F534, F535, F536) is JavaScript, which no
campaign compiles; its six controls were run with hand_control.py
--interpreted and are listed in docs/decisions.md under V4-311.
"""
import sys, pathlib
CL = "apps/authd/authd_cli.c"

M = {
    "AD1": [(CL, "            if (strcmp(argv[i], argv[j]) == 0) {\n                fprintf(stderr, \"%s %s: %s is given more than once\\n\", prog, sub, argv[i]);\n",
             "            if (strcmp(argv[i], argv[j]) == 0 && 0) { /* MUTATION AD1 */\n                fprintf(stderr, \"%s %s: %s is given more than once\\n\", prog, sub, argv[i]);\n")],
    "AD2": [(CL, "    if (strcmp(key, pub) == 0) {\n",
             "    if (strcmp(key, pub) == 0 && 0) { /* MUTATION AD2 */\n")],
    "AD3": [(CL, "    if (!cli_id_in_bounds(who)) {\n",
             "    if (!cli_id_in_bounds(who) && 0) { /* MUTATION AD3 */\n")],
    "AD4": [(CL, "    return (cmd != NULL && strcmp(cmd, \"BACKUP\") == 0) ? (uint64_t)BACKUP_TIMEOUT_MS\n",
             "    return (cmd != NULL && strcmp(cmd, \"BACKUP\") != 0) ? (uint64_t)BACKUP_TIMEOUT_MS /* MUTATION AD4 */\n")],
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
