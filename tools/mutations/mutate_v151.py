#!/usr/bin/env python3
"""V4-262 mutations: the local API against spec 8 and 15 (F392 to F396).

Usage: mutate_v151.py <repo> <ID>

Two-letter IDs: RQ = ReQ 7 before a user refusal, RU = Recovery Use, GN =
Grammar of Numbers, AD = Audit Detail. Every spec line names the check that
must catch it (F90).

    RQ1   A disabled user's own handle with a new key is not looked at.
    RQ2   A signup naming a known user's handle with a new key is not looked at.
    RU1   A disabled user's refused RECOVERY-USE is logged as invalid.
    RU2   RECOVERY-USE: a disabled operator on site.sock is not an operator.
    RU3   RECOVERY-ISSUE: the same.
    GN1   AUDIT-TAIL n= takes a leading zero.
    GN2   RECOVERY-ISSUE count= takes a leading zero.
    GN3   EXCHANGE takes a state of 65 bytes.
    AD1   An '=' in an audit detail is printed as it is.
    AD2   The store writes "issued N" as two words again.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"
ST = "apps/authd/store/store.c"
SITE = "    if (us == STORE_OK && (via_signup || existing != role || strcmp(status, \"active\") != 0)) {\n"

M = {
    "RQ1": [(LA, SITE, "    if (us == STORE_OK && (via_signup || existing != role)) { /* MUTATION RQ1 */\n")],
    "RQ2": [(LA, SITE, "    if (us == STORE_OK && (existing != role || strcmp(status, \"active\") != 0)) { /* MUTATION RQ2 */\n")],
    "RU1": [(LA, "        authd_log_slot_detail(AUTHD_LOG_WARN, \"recovery-use\", slot->index, \"user-disabled\");\n",
             "        authd_log_slot_detail(AUTHD_LOG_WARN, \"recovery-use\", slot->index, \"invalid\"); /* MUTATION RU1 */\n")],
    "RU2": [(LA, "    if (role == STORE_ROLE_OPERATOR && !slot->is_admin) {\n        if (recovery_spend_one(app->recovery_ops, app->recovery_mem) != 0) { return kdf_failed(slot); }\n",
             "    if (role == STORE_ROLE_OPERATOR && !slot->is_admin && strcmp(status, \"active\") == 0) { /* MUTATION RU2 */\n        if (recovery_spend_one(app->recovery_ops, app->recovery_mem) != 0) { return kdf_failed(slot); }\n")],
    "RU3": [(LA, "    if (role == STORE_ROLE_OPERATOR && !slot->is_admin) {\n        /* F474: a site minting an operator's codes is F43's escalation. */\n",
             "    if (role == STORE_ROLE_OPERATOR && !slot->is_admin && strcmp(status, \"active\") == 0) { /* MUTATION RU3 */\n        /* F474: a site minting an operator's codes is F43's escalation. */\n")],
    "GN1": [(LA, "        kv->val[0] == '0') {                /* F395: one spelling per number; 0 is refused below anyway */\n",
             "        0) { /* MUTATION GN1 */\n")],
    "GN2": [(LA, "        kv->val[0] == '0') {                /* F395: `count=07` is not a second spelling of 7 */\n",
             "        0) { /* MUTATION GN2 */\n")],
    "GN3": [(LA, "        state_len > WS_STATE_MAX) {         /* F395: no login code is bound to a longer one (spec 7.1) */\n",
             "        state_len > WS_STATE_MAX + 1u) { /* MUTATION GN3 */\n")],
    "AD1": [(LA, "        word[wn++] = (ch > 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.';\n",
             "        word[wn++] = (ch > 0x20u && ch <= 0x7eu) ? (char)ch : '.'; /* MUTATION AD1 */\n")],
    "AD2": [(ST, "    (void)snprintf(detail, sizeof detail, \"issued-%zu\", n);   /* one word (F396) */\n",
             "    (void)snprintf(detail, sizeof detail, \"issued %zu\", n); /* MUTATION AD2 */\n")],
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
