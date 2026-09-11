/*
 * F2 fuzz_handshake -- the Step 4 state machine under attacker-controlled
 * handshake messages.
 *
 * Input: selector % 3 picks the scenario; the payload is up to 4 messages,
 * each with a 2-byte big-endian length prefix. fuzz_rng_reset() runs first,
 * so every locally generated message equals the canonical transcript.
 *
 *   S0 responder receives ClientHello   OK iff it strictly decodes with id "alice"
 *   S1 initiator receives ServerHello   OK iff it is the genuine ServerHello
 *   S2 responder receives <=4 ClientAuth, after a genuine CH/SH exchange:
 *      exact status per message (MALFORMED / HANDSHAKE_ID_MISMATCH /
 *      SIGNATURE / AUTH_FAILURE_LIMIT / OK), exact state, and the ledger's
 *      failure_count and slot state after every message.
 *
 * "OK iff genuine" (S1, S2) is an assumption-based oracle: accepting other
 * bytes would mean a parser non-canonicality, a verification bypass, or an
 * ML-DSA strong-unforgeability break.
 */

#include "fuzz_common.h"

#include <sodium.h>

#include <string.h>

const char *const fuzz_target_name = "handshake";
const size_t fuzz_target_max_len = 16384;

static handshake_pending_store_t g_store;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fuzz_common_init();
    return 0;
}

int fuzz_target_command(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return -1;
}

static int keys_hidden(const handshake_ctx_t *ctx) {
    static const uint8_t sentinel = 0;
    const uint8_t *a = &sentinel;
    const uint8_t *b = &sentinel;
    return handshake_session_key_c2s(ctx, &a) != HANDSHAKE_OK && handshake_session_key_s2c(ctx, &b) != HANDSHAKE_OK &&
           a == NULL && b == NULL;
}

static void responder_init(handshake_ctx_t *res) {
    const fuzz_identities_t *ids = fuzz_identities();
    FUZZ_ASSERT(handshake_responder_init(res, FUZZ_ID_B, FUZZ_ID_B_LEN, &ids->kp_b, &ids->ks_responder, &g_store) ==
                    HANDSHAKE_OK,
                "fixture: responder init");
}

static void initiator_hello(handshake_ctx_t *ini) {
    const fuzz_identities_t *ids = fuzz_identities();
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t n = 0;
    FUZZ_ASSERT(handshake_initiator_init(ini, FUZZ_ID_A, FUZZ_ID_A_LEN, &ids->kp_a, &ids->ks_initiator, FUZZ_ID_B,
                                         FUZZ_ID_B_LEN) == HANDSHAKE_OK &&
                    handshake_initiator_create_client_hello(ini, ch, sizeof(ch), &n) == HANDSHAKE_OK,
                "fixture: initiator ClientHello");
    FUZZ_ASSERT(n == g->ch_len && memcmp(ch, g->ch, n) == 0,
                "fixture determinism: the ClientHello must equal the canonical one");
}

static void scenario_client_hello(fuzz_chunks_t *chunks) {
    handshake_ctx_t res;
    const uint8_t *c = NULL;
    size_t n = 0;
    responder_init(&res);
    FUZZ_ASSERT(fuzz_chunks_next(chunks, &c, &n), "a payload always yields a first chunk");
    const handshake_status_t st = handshake_responder_accept_client_hello(&res, c, n);

    client_hello_t m;
    size_t used = 0;
    const int dec = decode_client_hello(c, n, &m, &used) == 0;
    const int pinned = dec && m.id_len == FUZZ_ID_A_LEN && memcmp(m.id, FUZZ_ID_A, FUZZ_ID_A_LEN) == 0;
    FUZZ_ASSERT((st == HANDSHAKE_OK) == (pinned != 0), "S0: accepted iff strictly decodable with the pinned id");
    FUZZ_ASSERT(dec || st == HANDSHAKE_ERR_MALFORMED, "S0: undecodable -> MALFORMED");
    FUZZ_ASSERT(!dec || pinned || st == HANDSHAKE_ERR_UNKNOWN_IDENTITY, "S0: unpinned id -> UNKNOWN_IDENTITY");
    FUZZ_ASSERT(handshake_get_state(&res) ==
                    (st == HANDSHAKE_OK ? HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED : HANDSHAKE_STATE_FAILED),
                "S0: resulting state");
    FUZZ_ASSERT(handshake_pending_active_count(&g_store) == 0, "S0: accepting a ClientHello never inserts");
    FUZZ_ASSERT(keys_hidden(&res), "S0: no key is ever exposed");
    handshake_ctx_wipe(&res);
}

static void scenario_server_hello(fuzz_chunks_t *chunks) {
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    handshake_ctx_t ini;
    const uint8_t *c = NULL;
    size_t n = 0;
    initiator_hello(&ini);
    FUZZ_ASSERT(fuzz_chunks_next(chunks, &c, &n), "a payload always yields a first chunk");
    const handshake_status_t st = handshake_initiator_verify_server_hello(&ini, c, n);
    const int genuine = (n == g->sh_len && memcmp(c, g->sh, n) == 0);
    FUZZ_ASSERT((st == HANDSHAKE_OK) == genuine, "S1: ServerHello accepted iff it is the genuine one");
    FUZZ_ASSERT(handshake_get_state(&ini) ==
                    (genuine ? HANDSHAKE_STATE_SERVER_HELLO_VERIFIED : HANDSHAKE_STATE_FAILED),
                "S1: resulting state");
    FUZZ_ASSERT(keys_hidden(&ini), "S1: no traffic key before ESTABLISHED");
    handshake_ctx_wipe(&ini);
}

static void scenario_client_auth(fuzz_chunks_t *chunks) {
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    handshake_ctx_t ini;
    handshake_ctx_t res;
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t shn = 0;
    initiator_hello(&ini);
    responder_init(&res);
    FUZZ_ASSERT(handshake_responder_accept_client_hello(&res, g->ch, g->ch_len) == HANDSHAKE_OK &&
                    handshake_responder_create_server_hello(&res, sh, sizeof(sh), &shn) == HANDSHAKE_OK,
                "fixture: responder ServerHello");
    FUZZ_ASSERT(shn == g->sh_len && memcmp(sh, g->sh, shn) == 0,
                "fixture determinism: the ServerHello must equal the canonical one");

    unsigned sig_failures = 0;
    const uint8_t *c = NULL;
    size_t n = 0;
    while (fuzz_chunks_next(chunks, &c, &n)) {
        const handshake_state_t before = handshake_get_state(&res);
        const handshake_status_t st = handshake_responder_verify_client_auth(&res, c, n);
        if (before != HANDSHAKE_STATE_SERVER_HELLO_CREATED) {
            FUZZ_ASSERT(st == HANDSHAKE_ERR_UNEXPECTED_STATE && handshake_get_state(&res) == before,
                        "S2: after a terminal or successful result, further ClientAuths are refused, state unchanged");
            continue;
        }
        const int genuine = (n == g->ca_len && memcmp(c, g->ca, n) == 0);
        client_auth_t m;
        size_t used = 0;
        const int dec = decode_client_auth(c, n, &m, &used) == 0;
        const int idmatch = dec && sodium_memcmp(m.handshake_id, g->handshake_id, WIRE_HANDSHAKE_ID_LEN) == 0;
        handshake_status_t want;
        if (genuine) {
            want = HANDSHAKE_OK;
        } else if (!dec) {
            want = HANDSHAKE_ERR_MALFORMED;
        } else if (!idmatch) {
            want = HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH;
        } else {
            want = (sig_failures + 1u >= HANDSHAKE_AUTH_FAILURE_LIMIT) ? HANDSHAKE_ERR_AUTH_FAILURE_LIMIT
                                                                        : HANDSHAKE_ERR_SIGNATURE;
        }
        FUZZ_ASSERT(st == want, "S2: ClientAuth status disagrees with the reference model");
        if (want == HANDSHAKE_ERR_SIGNATURE || want == HANDSHAKE_ERR_AUTH_FAILURE_LIMIT) {
            sig_failures++;
        }

        handshake_state_t want_state = HANDSHAKE_STATE_SERVER_HELLO_CREATED;
        pending_status_t want_ps = PENDING_OK;
        pending_slot_state_t want_slot = PENDING_SLOT_ACTIVE;
        if (want == HANDSHAKE_OK) {
            want_state = HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED;
            want_ps = PENDING_ERR_CONSUMED;
            want_slot = PENDING_SLOT_CONSUMED;
        } else if (want == HANDSHAKE_ERR_AUTH_FAILURE_LIMIT) {
            want_state = HANDSHAKE_STATE_FAILED;
            want_ps = PENDING_ERR_AUTH_LIMIT;
            want_slot = PENDING_SLOT_AUTH_LIMITED;
        }
        FUZZ_ASSERT(handshake_get_state(&res) == want_state, "S2: resulting state");
        pending_slot_state_t slot;
        uint8_t fc = 0;
        const pending_status_t ps = handshake_pending_inspect(&g_store, g->handshake_id, &slot, &fc);
        FUZZ_ASSERT(ps == want_ps && slot == want_slot && fc == sig_failures,
                    "S2: ledger slot state and failure_count");

        if (want == HANDSHAKE_OK) {
            const uint8_t *k1 = NULL;
            const uint8_t *k2 = NULL;
            FUZZ_ASSERT(keys_hidden(&res), "S2: keys stay hidden until finish");
            FUZZ_ASSERT(handshake_responder_finish(&res) == HANDSHAKE_OK &&
                            handshake_session_key_c2s(&res, &k1) == HANDSHAKE_OK &&
                            handshake_session_key_s2c(&res, &k2) == HANDSHAKE_OK &&
                            sodium_memcmp(k1, g->c2s, KEX_SESSION_KEY_BYTES) == 0 &&
                            sodium_memcmp(k2, g->s2c, KEX_SESSION_KEY_BYTES) == 0 && handshake_is_peer_confirmed(&res),
                        "S2: after the genuine ClientAuth, finish yields exactly the canonical keys");
        } else {
            FUZZ_ASSERT(keys_hidden(&res), "S2: no key after a rejected ClientAuth");
        }
    }
    handshake_ctx_wipe(&ini);
    handshake_ctx_wipe(&res);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const uint8_t sel = fuzz_selector(data, size, 0);
    const uint8_t *p = NULL;
    size_t n = 0;
    fuzz_payload(data, size, &p, &n);
    fuzz_chunks_t chunks;
    fuzz_chunks_init(&chunks, p, n, 2, 4);

    fuzz_clock_now = FUZZ_CLOCK_T0;
    FUZZ_ASSERT(handshake_pending_store_init(&g_store, 4, HANDSHAKE_PENDING_TTL_MS_DEFAULT, fuzz_clock_fn, NULL) ==
                    PENDING_OK,
                "fixture: pending store");
    fuzz_rng_reset();
    switch (sel % 3u) {
    case 0: scenario_client_hello(&chunks); break;
    case 1: scenario_server_hello(&chunks); break;
    default: scenario_client_auth(&chunks); break;
    }
    handshake_pending_store_wipe(&g_store);
    return 0;
}

/* ---- seeds ------------------------------------------------------------------ */

static void emit_msgs(fuzz_emit_fn emit, void *ctx, const char *name, uint8_t sel, const uint8_t *const *msgs,
                      const size_t *lens, size_t count) {
    uint8_t seed[1 + 4 * (2 + SERVER_HELLO_MAX_ENCODED_LEN)];
    size_t n = 0;
    seed[n++] = sel;
    for (size_t i = 0; i < count; i++) {
        n = fuzz_seed_put_chunk(seed, n, sizeof(seed), 2, msgs[i], lens[i]);
    }
    emit(ctx, name, seed, n);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    uint8_t a[4096];
    uint8_t b[4096];
    size_t an = 0;
    size_t used = 0;
    emit(ctx, "empty", fuzz_empty, 0);

    /* S0 */
    const uint8_t *m1[1] = {g->ch};
    size_t l1[1] = {g->ch_len};
    emit_msgs(emit, ctx, "s0-genuine-client-hello", 0, m1, l1, 1);
    client_hello_t chm;
    if (decode_client_hello(g->ch, g->ch_len, &chm, &used) == 0) {
        memcpy(chm.id, FUZZ_ID_B, FUZZ_ID_B_LEN);
        chm.id_len = FUZZ_ID_B_LEN;
        if (encode_client_hello(&chm, a, sizeof(a), &an) == 0) {
            m1[0] = a;
            l1[0] = an;
            emit_msgs(emit, ctx, "s0-unknown-id", 0, m1, l1, 1);
        }
        memset(chm.id, 'z', sizeof(chm.id));
        chm.id_len = 64;
        if (encode_client_hello(&chm, a, sizeof(a), &an) == 0) {
            m1[0] = a;
            l1[0] = an;
            emit_msgs(emit, ctx, "s0-id64", 0, m1, l1, 1);
        }
    }

    /* S1 */
    m1[0] = g->sh;
    l1[0] = g->sh_len;
    emit_msgs(emit, ctx, "s1-genuine-server-hello", 1, m1, l1, 1);
    memcpy(a, g->sh, g->sh_len);
    a[g->sh_len - 1u] ^= 0x01;
    m1[0] = a;
    emit_msgs(emit, ctx, "s1-flipped-signature", 1, m1, l1, 1);
    server_hello_t shm;
    if (decode_server_hello(g->sh, g->sh_len, &shm, &used) == 0) {
        shm.session_id_echo[0] ^= 0x01;
        if (encode_server_hello(&shm, a, sizeof(a), &an) == 0) {
            m1[0] = a;
            l1[0] = an;
            emit_msgs(emit, ctx, "s1-wrong-echo", 1, m1, l1, 1);
        }
        shm.session_id_echo[0] ^= 0x01;
        memset(shm.ephemeral_pub, 0, sizeof(shm.ephemeral_pub));
        if (encode_server_hello(&shm, a, sizeof(a), &an) == 0) {
            m1[0] = a;
            l1[0] = an;
            emit_msgs(emit, ctx, "s1-zero-ephemeral", 1, m1, l1, 1);
        }
    }

    /* S2 */
    memcpy(a, g->ca, g->ca_len);
    a[g->ca_len - 1u] ^= 0x01; /* forged signature */
    memcpy(b, g->ca, g->ca_len);
    b[1] ^= 0x01; /* wrong handshake_id */
    const uint8_t *m4[4] = {g->ca, NULL, NULL, NULL};
    size_t l4[4] = {g->ca_len, 0, 0, 0};
    emit_msgs(emit, ctx, "s2-genuine", 2, m4, l4, 1);
    m4[0] = a;
    m4[1] = a;
    m4[2] = a;
    l4[0] = l4[1] = l4[2] = g->ca_len;
    emit_msgs(emit, ctx, "s2-three-forgeries", 2, m4, l4, 3);
    m4[3] = g->ca;
    l4[3] = g->ca_len;
    emit_msgs(emit, ctx, "s2-three-forgeries-then-genuine", 2, m4, l4, 4);
    m4[2] = g->ca;
    emit_msgs(emit, ctx, "s2-two-forgeries-then-genuine", 2, m4, l4, 3);
    m4[0] = b;
    m4[1] = g->ca;
    emit_msgs(emit, ctx, "s2-wrong-id-then-genuine", 2, m4, l4, 2);
    m4[0] = g->ca;
    l4[0] = g->ca_len - 1u;
    emit_msgs(emit, ctx, "s2-malformed-then-genuine", 2, m4, l4, 2);
}
