#!/usr/bin/env python3
"""V4-263 mutations: a signal ends the loop's wait (F399); --check-config and
the start agree about a socket path and a passphrase of one newline (F400);
a login that ran to its deadline is not a refusal (F402).

Usage: mutate_v152.py <repo> <ID>

Two-letter IDs: EI = EIntr, SK = SocKet path, PN = Passphrase Newline, RF =
ReFusal. Every spec line names the check that must catch it (F90).

    EI1   poll() is called again with its whole timeout, as before.
    EI2   A wait ended by a signal is reported as a failed loop.
    SK1   Only a directory at a socket path is refused; a regular file passes.
    SK2   The administrative socket's path is not looked at.
    PN1   A passphrase file of one newline is in range for the probe.
    RF1   A wait that ended exactly at the deadline is a refusal.
    RF2   A failure before ClientAuth was sent is a refusal.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
CF = "apps/authd/authd_config.c"
SE = "apps/authd/authd_secret.c"
CC = "apps/authd/client_core.c"

M = {
    "EI1": [(EV, "        if (rc < 0 && errno == EINTR) {\n            /* F399:",
             "        while (rc < 0 && errno == EINTR) { rc = poll(all, (nfds_t)total, poll_timeout_ms); } /* MUTATION EI1 */\n        if (0) {\n            /* F399:")],
    "EI2": [(EV, "             * from `all`, so there is nothing to serve. */\n            return 0;\n",
             "             * from `all`, so there is nothing to serve. */\n            return -1; /* MUTATION EI2 */\n")],
    "SK1": [(CF, "    if (path[0] != '\\0' && lstat(path, &there) == 0 && !S_ISSOCK(there.st_mode)) {\n",
             "    if (path[0] != '\\0' && lstat(path, &there) == 0 && S_ISDIR(there.st_mode)) { /* MUTATION SK1 */\n")],
    "SK2": [(CF, "        (socks = sock_is_free(K_ADMIN_SOCK, cfg->admin_socket, detail, cap)) != AUTHD_CFG_OK) {\n",
             "        0) { /* MUTATION SK2 */\n")],
    "PN1": [(SE, "        if (pread(probe_fd, &only, 1, 0) == 1 && only == '\\n') {\n",
             "        if (pread(probe_fd, &only, 1, 0) == 1 && only == '\\r') { /* MUTATION PN1 */\n")],
    "RF1": [(CC, "    return client_auth_sent && now_ms < deadline_ms;\n",
             "    return client_auth_sent && now_ms <= deadline_ms; /* MUTATION RF1 */\n")],
    "RF2": [(CC, "    return client_auth_sent && now_ms < deadline_ms;\n",
             "    return (client_auth_sent || 1) && now_ms < deadline_ms; /* MUTATION RF2 */\n")],
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
