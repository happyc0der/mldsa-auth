#!/usr/bin/env python3
"""V4-52 mutations: the local-API client against a misbehaving daemon.

Usage: mutate_v82.py <repo> <ID>

Two-letter IDs: LC = Local Client. localcli_call is the local-API client
authd_admin uses; V4-44's coverage showed none of its refusals had run. Every
spec line names the check that must catch it (F90).

    LC1   the line cap one byte late: a request one byte over spec 8's cap
          is sent instead of refused. (V4-55: this was "no cap at all",
          and that mutant sent 8197 bytes from an 8194-byte buffer, which
          ASan caught on Linux before the named check could -- F128. One
          byte late fits the buffer, so the named check is what decides.)
    LC2   off by one: recv may fill the byte kept for the NUL, which is then
          written one past the caller's buffer.
    LC3   a reply the daemon closes before it is complete is returned as OK.
    LC4   a daemon that never answers is reported as an I/O error, not a
          timeout.
    LC5   a socket with no daemon is reported as a timeout.
    LC6   the line cap one byte early: a request of exactly 8192 bytes,
          which spec 8 allows, is refused (V4-55).
"""
import sys, pathlib
LC = "apps/authd/localcli.c"

M = {
    "LC1": [(LC, "    if ((size_t)rn > AUTHD_LINE_MAX) {\n",
                 "    if ((size_t)rn > AUTHD_LINE_MAX + 1u) { /* MUTATION LC1: the cap one byte late */\n")],
    "LC2": [(LC, "        const ssize_t n = recv(conn.fd, out + got, cap - got - 1u, 0);\n",
                 "        const ssize_t n = recv(conn.fd, out + got, cap - got, 0); /* MUTATION LC2: off by one */\n")],
    "LC3": [(LC, "            result = (got > 0u && response_complete(out, got, is_list)) ? LOCALCLI_OK\n",
                 "            result = (got > 0u) ? LOCALCLI_OK /* MUTATION LC3: a truncation accepted */\n")],
    "LC4": [(LC, "        if (pr == 0) {\n            result = LOCALCLI_ERR_TIMEOUT;\n",
                 "        if (pr == 0) {\n            result = LOCALCLI_ERR_IO; /* MUTATION LC4: a timeout called an I/O error */\n")],
    "LC5": [(LC, "        return (cs == NET_TIMEOUT) ? LOCALCLI_ERR_TIMEOUT : LOCALCLI_ERR_CONNECT;\n",
                 "        return LOCALCLI_ERR_TIMEOUT; /* MUTATION LC5: every connect failure a timeout */\n")],
    "LC6": [(LC, "    if ((size_t)rn > AUTHD_LINE_MAX) {\n",
                 "    if ((size_t)rn >= AUTHD_LINE_MAX) { /* MUTATION LC6: the cap one byte early */\n")],
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
