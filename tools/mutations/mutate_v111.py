#!/usr/bin/env python3
"""V4-160 mutations: a configuration refused for what it lacks says what
that is, and two sockets on one path are a configuration error (F236).

Usage: mutate_v111.py <repo> <ID>

Two-letter IDs: CD = Config Detail. Every spec line names the check that
must catch it (F90).

    CD1   The detail is never recorded. Half of F236 itself.
    CD2   A parse does not clear the detail the one before it left.
    CD3   The site and admin sockets are not compared.
    CD4   The daemon does not print the detail.
    CD5   authd_admin does not print the detail.
    CD6   The proxy-facing socket is not compared with the site socket.
"""
import sys, pathlib
CF = "apps/authd/authd_config.c"
MN = "apps/authd/authd_main.c"
CL = "apps/authd/authd_cli.c"
M = {
    "CD1": [(CF,
             "    g_detail = what;\n    return st;\n",
             "    (void)what; /* MUTATION CD1 */\n    return st;\n")],
    "CD2": [(CF,
             "    g_detail = \"\";\n    if (err_line != NULL) {\n",
             "    /* MUTATION CD2 */\n    if (err_line != NULL) {\n")],
    "CD3": [(CF,
             "    if (cfg.site_socket[0] != '\\0' && strcmp(cfg.site_socket, cfg.admin_socket) == 0) {\n",
             "    if (cfg.site_socket[0] != '\\0' && strcmp(cfg.site_socket, cfg.admin_socket) == 0 && 0) { /* MUTATION CD3 */\n")],
    "CD4": [(MN,
             "        if (authd_config_error_detail()[0] != '\\0') {\n",
             "        if (authd_config_error_detail()[0] != '\\0' && 0) { /* MUTATION CD4 */\n")],
    "CD5": [(CL,
             "        if (authd_config_error_detail()[0] != '\\0') {\n",
             "        if (authd_config_error_detail()[0] != '\\0' && 0) { /* MUTATION CD5 */\n")],
    "CD6": [(CF,
             "    if (cfg.listen_unix[0] != '\\0' && strcmp(cfg.listen_unix, cfg.site_socket) == 0) {\n",
             "    if (cfg.listen_unix[0] != '\\0' && strcmp(cfg.listen_unix, cfg.site_socket) == 0 && 0) { /* MUTATION CD6 */\n")],
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
