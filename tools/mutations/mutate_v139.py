#!/usr/bin/env python3
"""V4-235 mutations: the connection fuzz target completes a login (F331).

Usage: mutate_v137.py <repo> <ID>

Two-letter IDs: CL = Completed Login. Every spec line names the check that must
catch it (F90).

    CL1   One ClientAuth is counted as two logins.
    CL2   A login is issued and the connection never enters SERVING.
    CL3   Closing a connection that had logged in leaves its session live.

Each needs a ClientAuth the daemon accepts. Before V4-235 no fuzz input
could carry one, and the oracles these three trip could not fire.
"""
import sys, pathlib
CN = "apps/authd/authd_conn.c"

M = {
    "CL1": [(CN,
             "    app->logins_issued++;\n",
             "    app->logins_issued += 2u; /* MUTATION CL1 */\n")],
    "CL2": [(CN,
             "    authd_log_slot_id(AUTHD_LOG_INFO, \"login-code-issued\", slot->index, c->handle, c->handle_len);\n    c->stage = CONN_STAGE_SERVING;\n",
             "    authd_log_slot_id(AUTHD_LOG_INFO, \"login-code-issued\", slot->index, c->handle, c->handle_len);\n    /* MUTATION CL2: the stage is left where it was */\n")],
    "CL3": [(CN,
             "    session_wipe(&c->sess);\n    if (c->hs_live) {\n",
             "    /* MUTATION CL3: the session is not wiped */\n    if (c->hs_live) {\n")],
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
