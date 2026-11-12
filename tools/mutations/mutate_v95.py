#!/usr/bin/env python3
"""V4-118 mutations: a Unix socket that is being listened on is another
daemon's, and is refused instead of replaced (F204).

Usage: mutate_v95.py <repo> <ID>

Two-letter IDs: LU = Live Unix socket. Every spec line names the check that
must catch it (F90).

    LU1   the look is never taken: a second daemon on a Unix-only
          configuration replaces the running daemon's sockets (what F204
          reported).
    LU2   a socket that refuses a connection is not treated as a leftover,
          so a crash wedges the service.
    LU3   a live socket is refused with the status for a path that is not a
          socket.
    LU4   a socket that ACCEPTS the connection is treated as a leftover.
    LU5   the status is printed under another status's name.
"""
import sys, pathlib
LS = "apps/authd/listener.c"

M = {
    "LU1": [(LS, "        if (unix_socket_in_use(&a)) {\n",
                 "        if (0 && unix_socket_in_use(&a)) { /* MUTATION LU1 */\n")],
    "LU2": [(LS, "    if (rc != 0 && (err == ECONNREFUSED || err == ENOENT)) {\n",
                 "    if (rc != 0 && err == ENOENT) { /* MUTATION LU2 */\n")],
    "LU3": [(LS, "            return LISTENER_ERR_IN_USE;\n",
                 "            return LISTENER_ERR_PATH; /* MUTATION LU3 */\n")],
    "LU4": [(LS, "    if (rc != 0 && (err == ECONNREFUSED || err == ENOENT)) {\n",
                 "    if (rc == 0 || err == ECONNREFUSED || err == ENOENT) { /* MUTATION LU4 */\n")],
    "LU5": [(LS, "    case LISTENER_ERR_IN_USE:  return \"in-use\";\n",
                 "    case LISTENER_ERR_IN_USE:  return \"path\"; /* MUTATION LU5 */\n")],
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
