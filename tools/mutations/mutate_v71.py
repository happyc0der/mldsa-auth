#!/usr/bin/env python3
"""V4-29 mutations: a secret printed where an identifier belongs (CLAIMS D13).

Usage: mutate_v71.py <repo> <ID>

Two-letter IDs: EI = Escaped Identifier. With `log_ids = full`,
authd_log_slot_id prints its bytes as an escaped `id=` field -- printable ASCII
as itself, every other byte as '.' -- a form no hex or base64 search sees. Each
mutation hands it a secret instead of the handle or user it logs today, using
the event name already there, so only the field's content changes. Every spec
line names the check that must catch it (F90); each passed V4-28's journal
scans, which looked for hex and base64 only.

    EI1   issue_login_code logs the login code itself, before wiping it.
    EI2   the ClientHello's nonce is logged where its id was.
    EI3   ROTATE logs sig_new where the handle was.
    EI4   EXCHANGE logs the issued token, before wiping it.
    EI5   RECOVERY-USE logs the enrollment ticket where the user was.
"""
import sys, pathlib
CONN = "apps/authd/authd_conn.c"
LA = "apps/authd/localapi.c"

M = {
    "EI1": [(CONN, """    sodium_memzero(&m, sizeof m);          /* the code exists nowhere else now */
""",
                   """    authd_log_slot_id(AUTHD_LOG_INFO, "login-code-issued", slot->index, m.code, sizeof m.code); /* MUTATION EI1 */
    sodium_memzero(&m, sizeof m);          /* the code exists nowhere else now */
""")],
    "EI2": [(CONN, """    authd_log_slot_id(AUTHD_LOG_INFO, "client-hello", slot->index, ch.id, ch.id_len);
""",
                   """    authd_log_slot_id(AUTHD_LOG_INFO, "client-hello", slot->index, ch.nonce, sizeof ch.nonce); /* MUTATION EI2 */
""")],
    "EI3": [(CONN, """    authd_log_slot_id(AUTHD_LOG_INFO, "rotate", slot->index, c->handle, c->handle_len);
""",
                   """    authd_log_slot_id(AUTHD_LOG_INFO, "rotate", slot->index, m.sig_new, m.sig_new_len); /* MUTATION EI3 */
""")],
    "EI4": [(LA, """    sodium_memzero(token, sizeof token);      /* the plaintext lives only in the reply now */
""",
                 """    authd_log_slot_id(AUTHD_LOG_INFO, "exchange", slot->index, token, sizeof token); /* MUTATION EI4 */
    sodium_memzero(token, sizeof token);      /* the plaintext lives only in the reply now */
""")],
    "EI5": [(LA, """    authd_log_slot_id(AUTHD_LOG_WARN, "recovery-use", slot->index, user, user_len);
    authd_log_slot_detail(AUTHD_LOG_WARN, "recovery-use", slot->index, revoke_all ? "ok revoke=all" : "ok");
""",
                 """    authd_log_slot_id(AUTHD_LOG_WARN, "recovery-use", slot->index, ticket, sizeof ticket); /* MUTATION EI5 */
    authd_log_slot_detail(AUTHD_LOG_WARN, "recovery-use", slot->index, revoke_all ? "ok revoke=all" : "ok");
""")],
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
