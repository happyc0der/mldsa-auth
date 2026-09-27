#!/usr/bin/env python3
"""V4-13d mutations: the public-deployment switches.

Usage: mutate_v56.py <repo> <ID>

Two-letter IDs (v54 onward): MB = milestone B. Every mutation changes a
value; none deletes a use (F79). Grouped by commit:

  log privacy (apps/authd/authd_log.c, store.c, authd_main.c)
    MB1   hashed mode is never taken: the identifier is logged in the clear
    MB2   off mode for identifiers is never taken
    MB3   prefix keeps the IPv4 host byte (/32, not /24)
    MB4   prefix keeps the IPv6 /64, not the /48
    MB5   off mode for addresses is never taken
    MB6   key_log is derived under the AUDIT key's label
    MB7   the pseudonym is BLAKE2b with no key at all: anyone can test a guess
    MB8   only the first 64 bytes of an identifier are hashed
    MB9   the daemon applies log_client_ip but ignores log_identities
    MB10  the config word "hashed" parses as off
  the refund (apps/authd/ratelimit.c, authd_conn.c)
    MB11  the refund is not capped at the burst
    MB12  the refund credits two tokens
    MB13  the global bucket is refunded too
    MB14  a RETRYABLE ClientAuth failure -- the decoy's -- is refunded
    MB15  the bucket is not refilled to now before the credit (refilled to a
          time a thousandth of now; first written as `0u`, which left now_ms
          unused and was killed by -Werror, not a test -- F79 again)
  the prompt (apps/authd/cli_prompt.c, client_cli.c, passphrase.c)
    MB16  echo is left on while the passphrase is typed
    MB17  keygen applies the policy only to the prompt, not to a file
    MB18  the repeat is compared by length only
    MB19  the caught signal is not re-raised: Ctrl-C no longer ends the process
    MB20  pp_explain miscounts the characters in "too short (N of 12)"
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LG = "apps/authd/authd_log.c"
ST = "apps/authd/store/store.c"
MA = "apps/authd/authd_main.c"
RL = "apps/authd/ratelimit.c"
CN = "apps/authd/authd_conn.c"
PR = "apps/authd/cli_prompt.c"
CL = "apps/authd/client_cli.c"
PC = "apps/authd/passphrase.c"

M = {
 "MB1":  (LG, [("    if (g_ids == AUTHD_LOG_IDS_HASHED) {",
                "    if (g_ids == (authd_log_ids_t)99) { /* MUTATION MB1 */")]),
 "MB2":  (LG, [("    if (g_ids == AUTHD_LOG_IDS_OFF) {",
                "    if (g_ids == (authd_log_ids_t)99) { /* MUTATION MB2 */")]),
 "MB3":  (LG, [("            memset(a.addr + 3, 0, sizeof a.addr - 3u);",
                "            memset(a.addr + 4, 0, sizeof a.addr - 4u); /* MUTATION MB3 */")]),
 "MB4":  (LG, [("            memset(a.addr + 6, 0, sizeof a.addr - 6u);",
                "            memset(a.addr + 8, 0, sizeof a.addr - 8u); /* MUTATION MB4 */")]),
 "MB5":  (LG, [("    if (g_ip == AUTHD_LOG_IP_OFF) {",
                "    if (g_ip == (authd_log_ip_t)99) { /* MUTATION MB5 */")]),
 "MB6":  (ST, [('#define LOG_LABEL   "mldsa-authd/v1/log-pseudonym"',
                '#define LOG_LABEL   "mldsa-authd/v1/audit-mac" /* MUTATION MB6 */')]),
 "MB7":  (ST, [("    if (crypto_generichash(h, sizeof h, id, id_len, s->key_log, STORE_LOG_KEY_BYTES) != 0) {",
                "    if (crypto_generichash(h, sizeof h, id, id_len, NULL, 0u) != 0) { /* MUTATION MB7 */")]),
 "MB8":  (LG, [("        if (g_pseud == NULL || g_pseud(g_pseud_ctx, id, (id != NULL) ? id_len : 0u, p) != 0) {",
                "        if (g_pseud == NULL || g_pseud(g_pseud_ctx, id, (id != NULL) ? (id_len > 64u ? 64u : id_len) : 0u, p) != 0) { /* MUTATION MB8 */")]),
 "MB9":  (MA, [("    if (authd_log_set_privacy(cfg.log_identities, cfg.log_client_ip, log_pseudonym, store) != 0) {",
                "    if (authd_log_set_privacy(AUTHD_LOG_IDS_FULL, cfg.log_client_ip, log_pseudonym, store) != 0) { /* MUTATION MB9 */")]),
 "MB10": (LG, [('    if (word_is(v, n, "hashed")) { *out = AUTHD_LOG_IDS_HASHED; return 0; }',
                '    if (word_is(v, n, "hashed")) { *out = AUTHD_LOG_IDS_OFF; return 0; } /* MUTATION MB10 */')]),
 "MB11": (RL, [("    e->tokens_milli = (e->tokens_milli + 1000u > cap) ? cap : e->tokens_milli + 1000u;",
                "    e->tokens_milli = (e->tokens_milli + 1000u > cap + 1000000u) ? cap : e->tokens_milli + 1000u; /* MUTATION MB11 */")]),
 "MB12": (RL, [("    e->tokens_milli = (e->tokens_milli + 1000u > cap) ? cap : e->tokens_milli + 1000u;",
                "    e->tokens_milli = (e->tokens_milli + 2000u > cap) ? cap : e->tokens_milli + 2000u; /* MUTATION MB12 */")]),
 "MB13": (RL, [("    r->refunded++;",
                "    r->refunded++; r->global_tokens_milli += 1000u; /* MUTATION MB13 */")]),
 "MB14": (CN, [('            authd_log_slot(AUTHD_LOG_INFO, "client-auth-retryable", slot->index);',
                '            authd_log_slot(AUTHD_LOG_INFO, "client-auth-retryable", slot->index);\n'
                '            if (slot->addr_admitted && app->rl != NULL) { ratelimit_refund(app->rl, conn_io_client_addr(&slot->io), app->now_ms); } /* MUTATION MB14 */')]),
 "MB15": (RL, [("    ratelimit_entry_t *e = &r->e[at];\n    refill_addr(r, e, now_ms);",
                "    ratelimit_entry_t *e = &r->e[at];\n    refill_addr(r, e, now_ms / 1000u); /* MUTATION MB15 */")]),
 "MB16": (PR, [("    quiet.c_lflag &= (tcflag_t)~(ECHO | ECHOE | ECHOK | ECHONL);",
                "    quiet.c_lflag &= (tcflag_t)~(ECHONL); /* MUTATION MB16 */")]),
 "MB17": (CL, [("        if (v != PP_OK) {",
                "        if (v != PP_OK && prompt) { /* MUTATION MB17 */")]),
 "MB18": (PR, [("        const int same = (st == CLI_PROMPT_OK && n1 == n2 && sodium_memcmp(p1, p2, n1) == 0);",
                "        const int same = (st == CLI_PROMPT_OK && n1 == n2 && sodium_memcmp(p1, p2, 0u) == 0); /* MUTATION MB18 */")]),
 "MB19": (PR, [("        (void)raise(sig);                  /* honoured under the old disposition */",
                "        (void)raise(sig * 0); /* MUTATION MB19 */")]),
 "MB20": (PC, [("    case PP_TOO_SHORT: n = snprintf(out, cap, \"too short (%u of %u characters)\",\n                                    (unsigned)cps, (unsigned)PP_MIN_CODE_POINTS); break;",
                "    case PP_TOO_SHORT: n = snprintf(out, cap, \"too short (%u of %u characters)\",\n                                    (unsigned)cps + 1u, (unsigned)PP_MIN_CODE_POINTS); break; /* MUTATION MB20 */")]),
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
