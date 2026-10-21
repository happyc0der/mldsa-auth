#!/usr/bin/env python3
"""V4-49 mutations: the listener's socket path, and its allowlist bound.

Usage: mutate_v80.py <repo> <ID>

Two-letter IDs: LP = Listener Path. listener_open_unix refuses a path too long
for sun_path and anything at the path that is not a socket, and replaces a
stale socket; listener_accept_ex refuses an allowlist longer than
LISTENER_MAX_ALLOW. V4-44's coverage showed the length refusal and the bound
had never run. Every spec line names the check that must catch it (F90).

    LP1   off by one: a path of exactly sun_path's capacity is accepted, with
          no room for its NUL.
    LP2   anything at the path is removed, not only a socket.
    LP3   stat, not lstat: a planted symlink to a live socket is followed,
          removed and bound over.
    LP4   a stale socket is not removed, so a crash wedges the service.
    LP5   an allowlist of any length is accepted.
"""
import sys, pathlib
L = "apps/authd/listener.c"

M = {
    "LP1": [(L, "    if (n == 0u || n >= sizeof a.sun_path) {\n",
                "    if (n == 0u || n > sizeof a.sun_path) { /* MUTATION LP1: off by one */\n")],
    "LP2": [(L, "        if (!S_ISSOCK(st.st_mode)) {\n            return LISTENER_ERR_PATH;\n",
                "        if (!S_ISSOCK(st.st_mode) && 0) { /* MUTATION LP2: any file removed */\n            return LISTENER_ERR_PATH;\n")],
    "LP3": [(L, "    if (lstat(path, &st) == 0) {\n",
                "    if (stat(path, &st) == 0) { /* MUTATION LP3: symlinks followed */\n")],
    "LP4": [(L, "        if (unlink(path) != 0) {\n            return LISTENER_ERR_PATH;\n        }\n    }\n",
                "        if (1) { /* MUTATION LP4: a stale socket is never removed */\n            return LISTENER_ERR_PATH;\n        }\n    }\n")],
    "LP5": [(L, "    if (out_fd == NULL || listen_fd < 0 || (n_allow > 0u && allow == NULL) ||\n        n_allow > LISTENER_MAX_ALLOW) {\n",
                "    if (out_fd == NULL || listen_fd < 0 || (n_allow > 0u && allow == NULL) ||\n        (n_allow > LISTENER_MAX_ALLOW && 0)) { /* MUTATION LP5: any length */\n")],
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
