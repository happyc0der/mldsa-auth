#!/usr/bin/env python3
"""V2-5 mutations: the hybrid handshake. One defect per run; the runner
restores byte-exactly afterwards. Every edit asserts its pattern matched
exactly once, so a stale pattern fails loudly instead of faking a kill."""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1])
WHICH = sys.argv[2]

def edit(rel, old, new):
    p = REPO / rel
    s = p.read_text()
    assert s.count(old) == 1, f"{rel}: pattern found {s.count(old)} times, expected 1"
    p.write_text(s.replace(old, new, 1))

M = {}

# N1: the combiner uses ss_x for BOTH halves -- symmetric, so a real-vs-real
#     handshake still agrees and T1 passes. Only the manual-peer oracles see it.
M["N1"] = lambda: edit("src/protocol/handshake.c",
    "    if (kex_derive_session_key_v2(out + C2S_OFFSET, ss_x, ss_k, session_id, WIRE_SESSION_ID_LEN,",
    "    if (kex_derive_session_key_v2(out + C2S_OFFSET, ss_x, ss_x, session_id, WIRE_SESSION_ID_LEN, /* MUTATION */")

# N2: the responder wipes TH_client_auth before deriving (the v1 memzero,
#     left where it used to be), so it derives from a zeroed digest.
M["N2"] = lambda: edit("src/protocol/handshake.c",
    "    /* `digest` is TH_client_auth and is now a KDF input as well as the\n"
    "     * signed message, so it is wiped after derivation rather than here. */",
    "    sodium_memzero(digest, sizeof(digest)); /* MUTATION */")

# N3: terminal failures leak the responder's retained KEM secret.
M["N3"] = lambda: edit("src/protocol/handshake.c",
    "    mlkem_keypair_free(&ctx->kem);\n"
    "    if (ctx->ss_kem != NULL) {\n"
    "        secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);\n"
    "        ctx->ss_kem = NULL;\n"
    "    }\n"
    "    if (ctx->session_keys != NULL) {\n"
    "        secure_mem_wipe(ctx->session_keys, SESSION_KEYS_LEN);",
    "    mlkem_keypair_free(&ctx->kem);\n"
    "    /* MUTATION: ss_kem not released */\n"
    "    if (ctx->session_keys != NULL) {\n"
    "        secure_mem_wipe(ctx->session_keys, SESSION_KEYS_LEN);")

# N4: finish keeps the decapsulation key.
M["N4"] = lambda: edit("src/protocol/handshake.c",
    "    kex_keypair_free(&ctx->eph);\n"
    "    mlkem_keypair_free(&ctx->kem);\n"
    "    sodium_memzero(ctx->th_client_auth, sizeof(ctx->th_client_auth));\n"
    "    sodium_memzero(ctx->peer_eph_pub, sizeof(ctx->peer_eph_pub));\n"
    "    sodium_memzero(ctx->peer_mlkem_ct, sizeof(ctx->peer_mlkem_ct));\n"
    "    ctx->state = HANDSHAKE_STATE_ESTABLISHED;",
    "    kex_keypair_free(&ctx->eph);\n"
    "    /* MUTATION: dk retained */\n"
    "    sodium_memzero(ctx->th_client_auth, sizeof(ctx->th_client_auth));\n"
    "    sodium_memzero(ctx->peer_eph_pub, sizeof(ctx->peer_eph_pub));\n"
    "    sodium_memzero(ctx->peer_mlkem_ct, sizeof(ctx->peer_mlkem_ct));\n"
    "    ctx->state = HANDSHAKE_STATE_ESTABLISHED;")

# N5: encapsulation status ignored -- a malformed ek is accepted.
M["N5"] = lambda: edit("src/protocol/handshake.c",
    "    if (mlkem_encaps(sh.mlkem_ct, ctx->ss_kem, ch.mlkem_ek) != 0) {\n"
    "        result = HANDSHAKE_ERR_KEX;\n"
    "        goto fail;\n"
    "    }",
    "    (void)mlkem_encaps(sh.mlkem_ct, ctx->ss_kem, ch.mlkem_ek); /* MUTATION */")

# N6: decapsulation result ignored -- the initiator derives from a zero ss_k.
M["N6"] = lambda: edit("src/protocol/handshake.c",
    "    if (mlkem_decaps(ss_kem, ctx->peer_mlkem_ct, &ctx->kem) != 0) {\n"
    "        result = HANDSHAKE_ERR_INTERNAL;\n"
    "        goto fail;\n"
    "    }",
    "    memset(ss_kem, 0, MLKEM_SHARED_SECRET_BYTES); /* MUTATION: decaps skipped */")

# N7: keys enter context state BEFORE the single-use commit.
M["N7"] = lambda: edit("src/protocol/handshake.c",
    "    ps = handshake_pending_consume_success(ctx->pending, ctx->handshake_id);\n"
    "    if (ps != PENDING_OK) {\n"
    "        result = map_pending_failure(ps);\n"
    "        goto fail_no_cancel;\n"
    "    }\n"
    "\n"
    "    /* 9. Only now do keys enter context state. */\n"
    "    memcpy(ctx->session_keys, keys, SESSION_KEYS_LEN);\n"
    "    ctx->keys_committed = true;",
    "    memcpy(ctx->session_keys, keys, SESSION_KEYS_LEN); /* MUTATION */\n"
    "    ctx->keys_committed = true;\n"
    "    ps = handshake_pending_consume_success(ctx->pending, ctx->handshake_id);\n"
    "    if (ps != PENDING_OK) {\n"
    "        result = map_pending_failure(ps);\n"
    "        goto fail_no_cancel;\n"
    "    }")

# N8: a RETRYABLE sig_A failure frees ss_kem, so the genuine retry cannot derive.
M["N8"] = lambda: edit("src/protocol/handshake.c",
    "            /* RETRYABLE: the handshake is still live, so ss_kem is\n"
    "             * deliberately KEPT -- the next ClientAuth needs it. */\n"
    "            return HANDSHAKE_ERR_SIGNATURE;",
    "            if (ctx->ss_kem != NULL) { /* MUTATION */\n"
    "                secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);\n"
    "                ctx->ss_kem = NULL;\n"
    "            }\n"
    "            return HANDSHAKE_ERR_SIGNATURE;")

M[WHICH]()
print(f"applied {WHICH}")
