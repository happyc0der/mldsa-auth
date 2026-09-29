#!/usr/bin/env python3
"""V4-15a mutations: the claim map's daemon gaps, each shown able to fail.

Usage: mutate_v58.py <repo> <ID>

Two-letter IDs: GA = V4-15a's gap checks. Every mutation changes a value and
keeps every use (F79; the runner refuses any other compile kill), and every
spec line names the check that must catch it (F90).

  D5 -- a login code's expiry at EXCHANGE (store.c, authd_conn.c)
    GA1   the store's boundary moves from now >= expires_at to now > expires_at
    GA2   the STORED expiry is an hour late while the wire still says 60 s
  D4 -- no plaintext secret in the store (authd_conn.c, tokens.c)
    GA3   half the login code is parked in the code row's handshake_id column
    GA4   half the token is parked in the token row's handshake_id column
          Both keep every round trip working -- nothing reads those columns
          back (erratum 44) -- so only the store scan can see them.
  D8 -- sig_old decides a rotation on its own (authd_conn.c)
    GA5   sig_old's verdict is ignored unless it is empty, which it never is
  D9 -- revocation, the filter and live sessions (store.c, authd_conn.c, localapi.c)
    GA6   store_lookup_active's device clause becomes d.status=d.status
    GA7   close_matching stops matching sessions by user
    GA8   DISABLE-USER no longer closes the user's live sessions
    GA9   RECOVERY-USE revoke=all no longer closes the user's live sessions
  D7 -- Req 7's log (localapi.c)
    GA10  the pre-check's fp_old is the PRESENTED key's fingerprint
    GA11  the pre-check's key comparison is inverted
    GA12  refuse_conflict's key comparison is inverted
  D11 -- peer credentials at accept, through main's wiring (authd_main.c)
    GA13  site.sock is registered with an empty allowlist
    GA14  admin.sock is registered with an empty allowlist
  D14 -- the new fault points (store.c): each commits what came before it,
         the shape of a transaction split in two
    GA15  revoke   GA16  disable   GA17  enroll (user)   GA18  enroll (device row)
    GA19  enroll via a ticket
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"
CN = "apps/authd/authd_conn.c"
TK = "apps/authd/tokens.c"
LA = "apps/authd/localapi.c"
MN = "apps/authd/authd_main.c"

M = {
 "GA1": (ST, [("    if (now >= expires)    { tx_rollback(s); *verdict = STORE_CODE_EXPIRED; return STORE_OK; }",
               "    if (now > expires)    { tx_rollback(s); *verdict = STORE_CODE_EXPIRED; return STORE_OK; } /* MUTATION GA1 */")]),
 "GA2": (CN, [("                             app->now_unix, (int64_t)m.code_expires) == STORE_OK) {",
               "                             app->now_unix, (int64_t)m.code_expires + 3600) == STORE_OK) { /* MUTATION GA2 */")]),
 "GA3": (CN, [("                             hsid, sizeof hsid,\n                             state_hash,",
               "                             m.code, sizeof hsid, /* MUTATION GA3 */\n                             state_hash,")]),
 "GA4": (TK, [("                                             hsid, hsid_len,",
               "                                             hsid != NULL ? hsid : token_out, hsid != NULL ? hsid_len : TOKEN_BYTES / 2u, /* MUTATION GA4 */")]),
 "GA5": (CN, [("    if (mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, pk_old) != 0) {",
               "    if (mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, pk_old) != 0 && m.sig_old_len == 0u) { /* MUTATION GA5 */")]),
 "GA6": (ST, [("            \"   AND d.status='active' AND u.status='active' LIMIT 1;\",",
               "            \"   AND d.status=d.status AND u.status='active' LIMIT 1;\", /* MUTATION GA6 */")]),
 "GA7": (CN, [("        const uint8_t *have = by_user ? c->user_id : c->handle;",
               "        const uint8_t *have = (by_user == 2) ? c->user_id : c->handle; /* MUTATION GA7 */")]),
 "GA8": (LA, [("    if (disable) {",
               "    if (disable > 1) { /* MUTATION GA8 */")]),
 "GA9": (LA, [("    if (revoke_all) {\n        /* Live sessions close only once the revocations have committed. */",
               "    if (revoke_all > 1) { /* MUTATION GA9 */\n        /* Live sessions close only once the revocations have committed. */")]),
 "GA10": (LA, [("            crypto_hash_sha256(fp_old, cur, STORE_PK_BYTES);",
                "            crypto_hash_sha256(fp_old, pk, STORE_PK_BYTES); (void)cur; /* MUTATION GA10 */")]),
 "GA11": (LA, [("        if (sodium_memcmp(cur, pk, STORE_PK_BYTES) == 0) {",
                "        if (sodium_memcmp(cur, pk, STORE_PK_BYTES) != 0) { /* MUTATION GA11 */")]),
 "GA12": (LA, [("    if (sodium_memcmp(last, pk, STORE_PK_BYTES) != 0) {",
                "    if (sodium_memcmp(last, pk, STORE_PK_BYTES) == 0) { /* MUTATION GA12 */")]),
 "GA13": (MN, [("cfg.site_uids, cfg.n_site_uids, 0) != 0) {",
                "cfg.site_uids, cfg.n_site_uids * 0u, 0) != 0) { /* MUTATION GA13 */")]),
 "GA14": (MN, [("cfg.admin_uids, cfg.n_admin_uids, 1) != 0) {",
                "cfg.admin_uids, cfg.n_admin_uids * 0u, 1) != 0) { /* MUTATION GA14 */")]),
 "GA15": (ST, [("    /* Fault point (V4-15a, CLAIMS D14): all four writes done, none committed.",
                "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION GA15 */\n"
                "    /* Fault point (V4-15a, CLAIMS D14): all four writes done, none committed.")]),
 "GA16": (ST, [("    /* Fault point (V4-15a, CLAIMS D14): the status is written, the tokens and",
                "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION GA16 */\n"
                "    /* Fault point (V4-15a, CLAIMS D14): the status is written, the tokens and")]),
 "GA17": (ST, [("    /* Fault point (V4-15a, CLAIMS D14): a user created for this request, its",
                "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION GA17 */\n"
                "    /* Fault point (V4-15a, CLAIMS D14): a user created for this request, its")]),
 "GA18": (ST, [("    /* Fault point (V4-15a, CLAIMS D14): a device row, no key row yet. Every",
                "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION GA18 */\n"
                "    /* Fault point (V4-15a, CLAIMS D14): a device row, no key row yet. Every")]),
 "GA19": (ST, [("    /* Fault point (V4-15a, CLAIMS D14): the ticket spent, no device yet -- a",
                "    (void)tx_commit(s); (void)tx_begin(s); /* MUTATION GA19 */\n"
                "    /* Fault point (V4-15a, CLAIMS D14): the ticket spent, no device yet -- a")]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
