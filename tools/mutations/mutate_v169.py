#!/usr/bin/env python3
"""V4-312 mutations: a login the daemon could not record, and the client's
exit status for a key it cannot use (F431, F451).

Usage: mutate_v169.py <repo> <ID>

    LR1   A store read that fails at ClientAuth closes with nothing sent.
    LR2   A login code the store will not take closes with nothing sent.
    LR3   The store failure is answered ERROR(0x03), a refusal.
    LR4   A login code that was not stored is not logged.
    CU1   The core reads any ERROR in LOGIN_CODE's place as "could not answer".
    CU2   The core reads ERROR(0x05) there as an unexpected message.
    CL1   The client counts "could not record the login" as the key refused.
    CL2   A --key that cannot be used exits 1.

The browser's flow (web/client/flows.mjs) is JavaScript, which no campaign
compiles; its control was run with hand_control.py --interpreted and is
listed in docs/decisions.md under V4-312.
"""
import sys, pathlib
CN = "apps/authd/authd_conn.c"
CC = "apps/authd/client_core.c"
CL = "apps/authd/client_cli.c"

M = {
    "LR1": [(CN, "            app->handshakes_failed++;\n            return close_with_error(slot, c, AUTHMSG_ERR_INTERNAL);\n",
             "            app->handshakes_failed++;\n            return EV_ACTION_CLOSE; /* MUTATION LR1 */\n")],
    "LR2": [(CN, "        authd_log_slot(AUTHD_LOG_ERROR, \"login-code-failed\", slot->index);\n        return close_with_error(slot, c, AUTHMSG_ERR_INTERNAL);\n",
             "        authd_log_slot(AUTHD_LOG_ERROR, \"login-code-failed\", slot->index);\n        return EV_ACTION_CLOSE; /* MUTATION LR2 */\n")],
    "LR3": [(CN, "            app->handshakes_failed++;\n            return close_with_error(slot, c, AUTHMSG_ERR_INTERNAL);\n",
             "            app->handshakes_failed++;\n            return close_with_error(slot, c, AUTHMSG_ERR_REJECTED); /* MUTATION LR3 */\n")],
    "LR4": [(CN, "        authd_log_slot(AUTHD_LOG_ERROR, \"login-code-failed\", slot->index);\n        return close_with_error(slot, c, AUTHMSG_ERR_INTERNAL);\n",
             "        /* MUTATION LR4 */\n        return close_with_error(slot, c, AUTHMSG_ERR_INTERNAL);\n")],
    "CU1": [(CC, "                            err == AUTHMSG_ERR_INTERNAL);\n",
             "                            err != 0u); /* MUTATION CU1 */\n")],
    "CU2": [(CC, "    if (unanswered) {\n",
             "    if (unanswered && 0) { /* MUTATION CU2 */\n")],
    "CL1": [(CL, "            open_failed_before_key(\"the daemon could not record the login (its store failed) at\", io_stage);\n",
             "            /* MUTATION CL1 */\n")],
    "CL2": [(CL, "    return (ks == KEYFILE_ERR_CRYPTO) ? EX_FAIL : EX_CONFIG;\n}\n\n/* Prints a core failure",
             "    return (ks == KEYFILE_ERR_CRYPTO) ? EX_FAIL : EX_FAIL; /* MUTATION CL2 */\n}\n\n/* Prints a core failure")],
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
