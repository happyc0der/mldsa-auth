#!/usr/bin/env python3
"""V4-220 mutations: a FIFO where a file is expected is refused, not waited on
(F297); a temp file left by a killed rotation does not stop the next one
(F298); a reply that is not this protocol's is not agreement (F299); the
daemon's bounds on --user and --reason are named by the tool (F300).

Usage: mutate_v134.py <repo> <ID>

Two-letter IDs: FF = FiFo, NP = NewPub, RO = Reply Ok, OB = Online Bounds.
Every spec line names the check that must catch it (F90).

    FF1   The passphrase file is opened without O_NONBLOCK.
    FF2   The sealed key is opened without O_NONBLOCK.
    FF3   The key to promote is opened without O_NONBLOCK.
    FF4   The configuration file is opened without O_NONBLOCK.
    NP1   The stale temp file is not removed before the seal.
    RO1   The reply's first line is not checked.
    RO2   Any line that begins OK is agreement.
    OB1   --user may be one byte longer.
    OB2   --user may hold any byte.
    OB3   --reason may be empty.
    OB4   --reason may be one byte longer.
"""
import sys, pathlib
SE = "apps/authd/authd_secret.c"
KF = "apps/authd/keyfile.c"
CF = "apps/authd/authd_config.c"
CC = "apps/authd/client_cli.c"
AC = "apps/authd/authd_cli.c"
LC = "apps/authd/localcli.c"

M = {
    "FF1": [(SE,
             "    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n",
             "    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FF1 */\n")],
    "FF2": [(KF,
             "    const int fd = open(ek_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n",
             "    const int fd = open(ek_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FF2 */\n")],
    "FF3": [(KF,
             "    const int fd = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);   /* F297 */\n",
             "    const int fd = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FF3 */\n")],
    "FF4": [(CF,
             "    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n",
             "    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FF4 */\n")],
    "NP1": [(CC,
             "     * key directory's lock is held, so whatever has this name is nobody's. */\n"
             "    (void)unlink(pub_tmp);\n",
             "     * key directory's lock is held, so whatever has this name is nobody's. */\n"
             "    /* MUTATION NP1: not removed */\n")],
    "RO1": [(AC,
             "    if (!localcli_reply_ok(resp)) {\n",
             "    if (!localcli_reply_ok(resp) && len == 0u) { /* MUTATION RO1 */\n")],
    "RO2": [(LC,
             "    return resp != NULL && resp[0] == 'O' && resp[1] == 'K' && (resp[2] == ' ' || resp[2] == '\\n');\n",
             "    return resp != NULL && resp[0] == 'O' && resp[1] == 'K'; /* MUTATION RO2 */\n")],
    "OB1": [(AC,
             "            if (vlen < 1u || vlen > AUTHD_CLI_ID_MAX || !printable) {\n",
             "            if (vlen < 1u || vlen > AUTHD_CLI_ID_MAX + 1u || !printable) { /* MUTATION OB1 */\n")],
    "OB2": [(AC,
             "            if (vlen < 1u || vlen > AUTHD_CLI_ID_MAX || !printable) {\n",
             "            if (vlen < 1u || vlen > AUTHD_CLI_ID_MAX || (!printable && vlen > AUTHD_CLI_ID_MAX)) { /* MUTATION OB2 */\n")],
    "OB3": [(AC,
             "            if (vlen < 1u || vlen > AUTHD_CLI_REASON_MAX) {\n",
             "            if (vlen > AUTHD_CLI_REASON_MAX) { /* MUTATION OB3 */\n")],
    "OB4": [(AC,
             "            if (vlen < 1u || vlen > AUTHD_CLI_REASON_MAX) {\n",
             "            if (vlen < 1u || vlen > AUTHD_CLI_REASON_MAX + 1u) { /* MUTATION OB4 */\n")],
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
