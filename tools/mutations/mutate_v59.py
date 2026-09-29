#!/usr/bin/env python3
"""V4-15b mutations: the protocol's gaps and the constant-time gate.

Usage: mutate_v59.py <repo> <ID>

Two-letter IDs: GB = V4-15b's gap checks. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90).

  P5 -- replay (src/protocol/session.c, src/protocol/handshake.c)
    GB1   the REPLAY check narrowed to the previous record: an older replay
          decrypts, since it was sealed genuinely at its own seq
    GB2   the OUT_OF_ORDER check narrowed to a gap of one
    GB3   record_failure's CONSUMED check disabled: failures would count
          against a spent handshake
    GB4   consume_success's CONSUMED check disabled: a handshake could commit
          twice
  P13 -- padding (session.c)
    GB5   only the first and the last padding byte are checked
  P4 -- what is signed (handshake.c), each changed in BOTH roles, so the
        library stays self-consistent and only a check that brings its own
        bytes can see it
    GB6   TH_server_auth hashes the ClientHello without its nonce
    GB7   TH_client_auth hashes the ServerHello without sig_B
  P3/D3 -- constant time: the swap v49c and v52 declined, because no test
           could observe it and the inventory was not a gate
    GB8   authd_conn_pin_lookup's sodium_memcmp becomes memcmp
    GB9   the login code's state comparison becomes memcmp
    GB10  the audit chain's MAC comparison becomes memcmp
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
SE = "src/protocol/session.c"
HS = "src/protocol/handshake.c"
CN = "apps/authd/authd_conn.c"
ST = "apps/authd/store/store.c"

M = {
 "GB1": (SE, [("    if (seq < s->recv_seq) {\n        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_REPLAY);",
               "    if (seq + 1u == s->recv_seq) { /* MUTATION GB1 */\n        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_REPLAY);")]),
 "GB2": (SE, [("    if (seq > s->recv_seq) {\n        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_OUT_OF_ORDER);",
               "    if (seq == s->recv_seq + 1u) { /* MUTATION GB2 */\n        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_OUT_OF_ORDER);")]),
 "GB3": (HS, [("    if (e->state == PENDING_SLOT_CONSUMED) {\n"
               "        return PENDING_ERR_CONSUMED;\n"
               "    }\n"
               "    if (e->state == PENDING_SLOT_AUTH_LIMITED) {\n"
               "        return PENDING_ERR_AUTH_LIMIT;\n"
               "    }\n"
               "    /* The deadline is deliberately left alone: a failing peer can never",
               "    if (e->state == PENDING_SLOT_CONSUMED && e->failure_count > 99u) { /* MUTATION GB3 */\n"
               "        return PENDING_ERR_CONSUMED;\n"
               "    }\n"
               "    if (e->state == PENDING_SLOT_AUTH_LIMITED) {\n"
               "        return PENDING_ERR_AUTH_LIMIT;\n"
               "    }\n"
               "    /* The deadline is deliberately left alone: a failing peer can never")]),
 "GB4": (HS, [("    if (e->state == PENDING_SLOT_CONSUMED) {\n"
               "        return PENDING_ERR_CONSUMED;\n"
               "    }\n"
               "    if (e->state == PENDING_SLOT_AUTH_LIMITED) {\n"
               "        return PENDING_ERR_AUTH_LIMIT;\n"
               "    }\n"
               "    tombstone(e, PENDING_SLOT_CONSUMED);",
               "    if (e->state == PENDING_SLOT_CONSUMED && e->failure_count > 99u) { /* MUTATION GB4 */\n"
               "        return PENDING_ERR_CONSUMED;\n"
               "    }\n"
               "    if (e->state == PENDING_SLOT_AUTH_LIMITED) {\n"
               "        return PENDING_ERR_AUTH_LIMIT;\n"
               "    }\n"
               "    tombstone(e, PENDING_SLOT_CONSUMED);")]),
 "GB5": (SE, [("        sodium_is_zero(pt_out + SESSION_CONTENT_LEN_BYTES + content_len, pad_len) != 1) {",
               "        (sodium_is_zero(pt_out + SESSION_CONTENT_LEN_BYTES + content_len, 1u) != 1 || /* MUTATION GB5 */\n"
               "         pt_out[SESSION_CONTENT_LEN_BYTES + content_len + pad_len - 1u] != 0)) {")]),
 "GB6": (HS, [("    if (transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len, sh, unsigned_len,",
               "    if (transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len - WIRE_NONCE_LEN, sh, unsigned_len, /* MUTATION GB6 */"),
              ("        transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len, sh_unsigned, unsigned_len,",
               "        transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len - WIRE_NONCE_LEN, sh_unsigned, unsigned_len, /* MUTATION GB6 */")]),
 "GB7": (HS, [("    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh, sh_len,",
               "    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh, unsigned_len, /* MUTATION GB7 */"),
              ("    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh_full, full_len,",
               "    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh_full, unsigned_len, /* MUTATION GB7 */")]),
 "GB8": (CN, [("    if (sodium_memcmp(id, c->handle, id_len) != 0) {",
               "    if (memcmp(id, c->handle, id_len) != 0) { /* MUTATION GB8 */")]),
 "GB9": (ST, [("        sodium_memcmp(stored_state, state_hash, STORE_HASH_BYTES) != 0) {",
               "        memcmp(stored_state, state_hash, STORE_HASH_BYTES) != 0) { /* MUTATION GB9 */")]),
 "GB10": (ST, [("if (sodium_memcmp(want, stored_mac, STORE_AUDIT_MAC_BYTES) != 0) { r = STORE_ERR_CORRUPT; break; }",
                "if (memcmp(want, stored_mac, STORE_AUDIT_MAC_BYTES) != 0) { r = STORE_ERR_CORRUPT; break; } /* MUTATION GB10 */")]),
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
