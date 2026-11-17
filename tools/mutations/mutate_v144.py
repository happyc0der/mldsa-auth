#!/usr/bin/env python3
"""V4-242 mutations: a reply before the Close echo; authd_admin's bounds for enroll-operator and backup; REVOKE-DEVICE without a reason (F343, F344, F345, erratum 113).

Usage: mutate_v144.py <repo> <ID>

Two-letter IDs: WQ = Write Queue, CB = Cli Bounds, RR = Revoke Reason.
Every spec line names the check that must catch it (F90).

    WQ1   Control replies always go first: the Close echo before the reply.
    CB1   enroll-operator does not check --user.
    CB2   An empty --user is in bounds.
    CB3   backup --path may carry bytes above 0x7e.
    CB4   backup --path may carry control characters.
    RR1   REVOKE-DEVICE requires reason=.
"""
import sys, pathlib
CIO = "apps/authd/conn_io.c"
CLI = "apps/authd/authd_cli.c"
API = "apps/authd/localapi.c"

M = {
    # (Re-anchored in V4-245: F351 rewrote the rule as ws_reply_turn(). The
    # mutant is the same: the Close echo never waits for the reply.)
    "WQ1": [(CIO, "    if (c->ws.close_queued && c->out_len > c->out_sent && c->ws.reply_sent <= c->ws.close_at) {\n",
                  "    if (c->ws.close_queued && c->out_len > c->out_sent && c->ws.reply_sent <= c->ws.close_at && 0) { /* MUTATION WQ1 */\n")],
    "CB1": [(CLI, "    if (!cli_id_in_bounds(user)) {\n",
                  "    if (!cli_id_in_bounds(user) && 0) { /* MUTATION CB1 */\n")],
    "CB2": [(CLI, "    return n >= 1u && n <= AUTHD_CLI_ID_MAX;\n",
                  "    return n <= AUTHD_CLI_ID_MAX; /* MUTATION CB2 */\n")],
    "CB3": [(CLI, "        if ((unsigned char)path[i] < 0x20u || (unsigned char)path[i] > 0x7eu) {\n",
                  "        if ((unsigned char)path[i] < 0x20u || (unsigned char)path[i] > 0xfeu) { /* MUTATION CB3 */\n")],
    "CB4": [(CLI, "        if ((unsigned char)path[i] < 0x20u || (unsigned char)path[i] > 0x7eu) {\n",
                  "        if ((unsigned char)path[i] < 0x01u || (unsigned char)path[i] > 0x7eu) { /* MUTATION CB4 */\n")],
    "RR1": [(API, "    uint8_t handle[STORE_ID_MAX], reason[256];\n    size_t handle_len = 0, reason_len = 0;\n    if (get_hex(req, \"handle\", handle, sizeof handle, &handle_len, 1u) != 0 ||\n        !id_valid(handle, handle_len)) {\n        return send_err(slot, \"malformed\");\n    }\n    if (kv_get(req, \"reason\") != NULL &&\n",
                  "    uint8_t handle[STORE_ID_MAX], reason[256];\n    size_t handle_len = 0, reason_len = 0;\n    if (get_hex(req, \"handle\", handle, sizeof handle, &handle_len, 1u) != 0 ||\n        !id_valid(handle, handle_len)) {\n        return send_err(slot, \"malformed\");\n    }\n    if ( /* MUTATION RR1 */\n")],
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
