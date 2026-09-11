/*
 * F3 fuzz_session -- session_open() on an initialized, valid session (spec 6.4).
 *
 * Fixture (built once): the canonical deterministic handshake, real sessions
 * from session_init_from_handshake(), and 4 genuine records per direction
 * (plaintexts of 0 / 1 / 64 / 65536 bytes, seq 0-3).
 *
 * Per input, the receiving session is a WHITE-BOX CLONE of the freshly
 * initialized session: the template session_t is copied and its key block
 * re-filled into a harness-owned secure-memory block. That costs ~microseconds
 * instead of a full ML-DSA handshake per input, and start-up verifies that a
 * clone accepts the genuine records exactly like the real session did.
 *
 * Selector bits: 0 receiver (0 = responder receives c2s, 1 = initiator
 * receives s2c); 1 plaintext capacity one byte short; 2 tightened limits
 * (reject after 2 records); 3-4 clock (0 normal, 1 at the hard age limit,
 * 2 unreadable UINT64_MAX, 3 normal). Payload: up to 8 records, each with a
 * 4-byte big-endian length prefix.
 *
 * Oracle: a reference model predicts every status, the resulting state,
 * recv_seq, confirmation and key-block wiping. "OK iff the record is the
 * genuine one at recv_seq" is assumption-based (AEAD integrity).
 */

#include "fuzz_common.h"

#include "secure_mem.h"

#include <sodium.h>

#include <stdlib.h>
#include <string.h>

const char *const fuzz_target_name = "session";
const size_t fuzz_target_max_len = 140000;

#define N_REC 4
enum { RX_RESPONDER = 0, RX_INITIATOR = 1 };

static const size_t PT_LEN[N_REC] = {0, 1, 64, 65536};
static uint8_t *g_pt[N_REC];
static uint8_t *g_rec[2][N_REC]; /* g_rec[rx][i]: genuine record i arriving at receiver rx */
static size_t g_rec_len[2][N_REC];
static session_t g_tpl[2];
static uint8_t g_tpl_keys[2][2 * KEX_SESSION_KEY_BYTES];
static uint8_t *g_keyblock; /* secure_mem, the clone's key block */
static uint8_t *g_out;      /* plaintext output buffer */

int fuzz_target_command(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return -1;
}

static void clone_session(session_t *s, int rx) {
    *s = g_tpl[rx];
    memcpy(g_keyblock, g_tpl_keys[rx], sizeof(g_tpl_keys[rx]));
    s->keys = g_keyblock;
}

static void cleanup(void) {
    for (int i = 0; i < N_REC; i++) {
        free(g_pt[i]);
        free(g_rec[0][i]);
        free(g_rec[1][i]);
    }
    sodium_memzero(g_tpl_keys, sizeof(g_tpl_keys));
    sodium_memzero(g_tpl, sizeof(g_tpl));
    secure_mem_free(g_keyblock, 2 * KEX_SESSION_KEY_BYTES);
    free(g_out);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fuzz_common_init();
    const fuzz_identities_t *ids = fuzz_identities();
    handshake_pending_store_t store;
    handshake_ctx_t ini;
    handshake_ctx_t res;
    session_t si;
    session_t sr;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t chn = 0;
    size_t shn = 0;
    size_t can = 0;
    memset(&si, 0, sizeof(si));
    memset(&sr, 0, sizeof(sr));
    fuzz_clock_now = FUZZ_CLOCK_T0;
    fuzz_rng_reset();
    FUZZ_ASSERT(handshake_pending_store_init(&store, 4, HANDSHAKE_PENDING_TTL_MS_DEFAULT, fuzz_clock_fn, NULL) ==
                        PENDING_OK &&
                    handshake_initiator_init(&ini, FUZZ_ID_A, FUZZ_ID_A_LEN, &ids->kp_a, &ids->ks_initiator,
                                             FUZZ_ID_B, FUZZ_ID_B_LEN) == HANDSHAKE_OK &&
                    handshake_initiator_create_client_hello(&ini, ch, sizeof(ch), &chn) == HANDSHAKE_OK &&
                    handshake_responder_init(&res, FUZZ_ID_B, FUZZ_ID_B_LEN, &ids->kp_b, &ids->ks_responder,
                                             &store) == HANDSHAKE_OK &&
                    handshake_responder_accept_client_hello(&res, ch, chn) == HANDSHAKE_OK &&
                    handshake_responder_create_server_hello(&res, sh, sizeof(sh), &shn) == HANDSHAKE_OK &&
                    handshake_initiator_verify_server_hello(&ini, sh, shn) == HANDSHAKE_OK &&
                    handshake_initiator_create_client_auth(&ini, ca, sizeof(ca), &can) == HANDSHAKE_OK &&
                    handshake_responder_verify_client_auth(&res, ca, can) == HANDSHAKE_OK &&
                    handshake_responder_finish(&res) == HANDSHAKE_OK &&
                    handshake_initiator_finish(&ini) == HANDSHAKE_OK &&
                    session_init_from_handshake(&si, &ini, NULL, fuzz_clock_fn, NULL) == SESSION_OK &&
                    session_init_from_handshake(&sr, &res, NULL, fuzz_clock_fn, NULL) == SESSION_OK,
                "fixture: real handshake and sessions");

    /* Templates: the receiving sessions exactly as initialized. */
    g_tpl[RX_RESPONDER] = sr;
    g_tpl[RX_INITIATOR] = si;
    memcpy(g_tpl_keys[RX_RESPONDER], sr.keys, sizeof(g_tpl_keys[0]));
    memcpy(g_tpl_keys[RX_INITIATOR], si.keys, sizeof(g_tpl_keys[1]));
    g_tpl[RX_RESPONDER].keys = NULL;
    g_tpl[RX_INITIATOR].keys = NULL;

    for (int i = 0; i < N_REC; i++) {
        g_pt[i] = malloc(PT_LEN[i] ? PT_LEN[i] : 1);
        g_rec[0][i] = malloc(PT_LEN[i] + SESSION_OVERHEAD_BYTES);
        g_rec[1][i] = malloc(PT_LEN[i] + SESSION_OVERHEAD_BYTES);
        FUZZ_ASSERT(g_pt[i] && g_rec[0][i] && g_rec[1][i], "fixture: allocation");
        for (size_t j = 0; j < PT_LEN[i]; j++) {
            g_pt[i][j] = (uint8_t)(i * 31 + j);
        }
        /* c2s records (sealed by the initiator) arrive at the responder. */
        FUZZ_ASSERT(session_seal(&si, PT_LEN[i] ? g_pt[i] : NULL, PT_LEN[i], g_rec[RX_RESPONDER][i],
                                 PT_LEN[i] + SESSION_OVERHEAD_BYTES, &g_rec_len[RX_RESPONDER][i]) == SESSION_OK &&
                        session_seal(&sr, PT_LEN[i] ? g_pt[i] : NULL, PT_LEN[i], g_rec[RX_INITIATOR][i],
                                     PT_LEN[i] + SESSION_OVERHEAD_BYTES, &g_rec_len[RX_INITIATOR][i]) == SESSION_OK,
                    "fixture: genuine records");
    }
    session_wipe(&si);
    session_wipe(&sr);
    handshake_ctx_wipe(&ini);
    handshake_ctx_wipe(&res);
    handshake_pending_store_wipe(&store);

    g_keyblock = secure_mem_alloc(2 * KEX_SESSION_KEY_BYTES);
    g_out = malloc(SESSION_MAX_PLAINTEXT_BYTES);
    FUZZ_ASSERT(g_keyblock != NULL && g_out != NULL, "fixture: buffers");
    (void)atexit(cleanup);

    /* Start-up check: a clone accepts the genuine records like the real session. */
    for (int rx = 0; rx < 2; rx++) {
        session_t s;
        clone_session(&s, rx);
        for (int i = 0; i < N_REC; i++) {
            size_t pl = 0;
            FUZZ_ASSERT(session_open(&s, g_rec[rx][i], g_rec_len[rx][i], g_out, SESSION_MAX_PLAINTEXT_BYTES, &pl) ==
                                SESSION_OK &&
                            pl == PT_LEN[i] && (pl == 0 || memcmp(g_out, g_pt[i], pl) == 0),
                        "fixture: a cloned session must accept the genuine records in order");
        }
        sodium_memzero(&s, sizeof(s));
    }
    sodium_memzero(g_keyblock, 2 * KEX_SESSION_KEY_BYTES);
    return 0;
}

static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const uint8_t sel = fuzz_selector(data, size, 0);
    const int rx = (sel & 1u) ? RX_INITIATOR : RX_RESPONDER;
    const int short_cap = (sel >> 1) & 1u;
    const int tight = (sel >> 2) & 1u;
    const unsigned clock_mode = (sel >> 3) & 3u;
    const uint8_t *p = NULL;
    size_t n = 0;
    fuzz_payload(data, size, &p, &n);
    fuzz_chunks_t chunks;
    fuzz_chunks_init(&chunks, p, n, 4, 8);

    session_t s;
    clone_session(&s, rx);
    if (tight) {
        s.limits.rekey_after_messages = 1;
        s.limits.reject_after_messages = 2;
    }
    fuzz_clock_now = (clock_mode == 1u)   ? FUZZ_CLOCK_T0 + s.limits.reject_after_ms
                     : (clock_mode == 2u) ? UINT64_MAX
                                          : FUZZ_CLOCK_T0;
    const int expired = (clock_mode == 1u || clock_mode == 2u);

    session_state_t m_state = SESSION_STATE_ACTIVE;
    uint64_t m_recv = 0;
    int m_confirmed = (rx == RX_RESPONDER);

    const uint8_t *c = NULL;
    size_t len = 0;
    while (fuzz_chunks_next(&chunks, &c, &len)) {
        const size_t body = (len >= SESSION_OVERHEAD_BYTES) ? len - SESSION_OVERHEAD_BYTES : 0;
        const size_t cap = (short_cap && len >= SESSION_OVERHEAD_BYTES && body > 0) ? body - 1u
                                                                                    : SESSION_MAX_PLAINTEXT_BYTES;
        if (body <= SESSION_MAX_PLAINTEXT_BYTES) {
            memset(g_out, 0xA5, body);
        }
        size_t pt_len = 777;
        const session_status_t st = session_open(&s, c, len, g_out, cap, &pt_len);

        /* ---- reference model ---- */
        session_status_t want;
        int genuine = 0;
        if (m_state != SESSION_STATE_ACTIVE) {
            want = SESSION_ERR_UNEXPECTED_STATE;
        } else if (expired) {
            want = SESSION_ERR_EXPIRED;
            m_state = SESSION_STATE_EXPIRED;
        } else if (len < SESSION_OVERHEAD_BYTES || len > SESSION_MAX_RECORD_BYTES || c[0] != SESSION_RECORD_TYPE) {
            want = SESSION_ERR_MALFORMED;
            m_state = SESSION_STATE_FAILED;
        } else if (cap < body) {
            want = SESSION_ERR_INVALID_ARG;
        } else {
            const uint64_t seq = be64(c + 1);
            if (seq < m_recv) {
                want = SESSION_ERR_REPLAY;
                m_state = SESSION_STATE_FAILED;
            } else if (seq > m_recv) {
                want = SESSION_ERR_OUT_OF_ORDER;
                m_state = SESSION_STATE_FAILED;
            } else if (seq >= s.limits.reject_after_messages) {
                want = SESSION_ERR_LIMIT;
                m_state = SESSION_STATE_FAILED;
            } else {
                genuine = m_recv < N_REC && len == g_rec_len[rx][m_recv] && memcmp(c, g_rec[rx][m_recv], len) == 0;
                if (genuine) {
                    want = SESSION_OK;
                } else {
                    want = SESSION_ERR_AUTH;
                    m_state = SESSION_STATE_FAILED;
                }
            }
        }
        FUZZ_ASSERT(st == want, "session_open status disagrees with the reference model");
        if (want == SESSION_OK) {
            FUZZ_ASSERT(pt_len == PT_LEN[m_recv] && (pt_len == 0 || memcmp(g_out, g_pt[m_recv], pt_len) == 0),
                        "OK must yield exactly the genuine plaintext");
            m_recv++;
            m_confirmed = 1;
        }
        if (want == SESSION_ERR_AUTH) {
            FUZZ_ASSERT(sodium_is_zero(g_out, body), "AUTH failure must zero the plaintext region");
        }
        FUZZ_ASSERT(s.state == m_state && s.recv_seq == m_recv, "state and recv_seq (white-box)");
        if (m_state != SESSION_STATE_ACTIVE) {
            FUZZ_ASSERT(sodium_is_zero(g_keyblock, 2 * KEX_SESSION_KEY_BYTES),
                        "keys must be zeroed on every terminal transition");
        }
        FUZZ_ASSERT(session_is_peer_confirmed(&s) == (m_state == SESSION_STATE_ACTIVE && m_confirmed),
                    "confirmation: responder always, initiator only after an authenticated record");
    }
    if (m_state != SESSION_STATE_ACTIVE) {
        size_t pt_len = 0;
        FUZZ_ASSERT(session_open(&s, fuzz_empty, 0, g_out, SESSION_MAX_PLAINTEXT_BYTES, &pt_len) ==
                        SESSION_ERR_UNEXPECTED_STATE,
                    "a dead session refuses every later call");
    }
    sodium_memzero(g_keyblock, 2 * KEX_SESSION_KEY_BYTES);
    sodium_memzero(&s, sizeof(s));
    return 0;
}

/* ---- seeds ------------------------------------------------------------------ */

static void emit_recs(fuzz_emit_fn emit, void *ctx, const char *name, uint8_t sel, const uint8_t *const *recs,
                      const size_t *lens, size_t count) {
    static uint8_t seed[140000];
    size_t n = 0;
    seed[n++] = sel;
    for (size_t i = 0; i < count; i++) {
        n = fuzz_seed_put_chunk(seed, n, sizeof(seed), 4, recs[i], lens[i]);
    }
    emit(ctx, name, seed, n);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    static uint8_t tmp[SESSION_MAX_RECORD_BYTES + 1];
    const uint8_t *r[N_REC];
    size_t l[N_REC];
    emit(ctx, "empty", fuzz_empty, 0);
    for (int rx = 0; rx < 2; rx++) {
        for (int i = 0; i < N_REC; i++) {
            r[i] = g_rec[rx][i];
            l[i] = g_rec_len[rx][i];
        }
        emit_recs(emit, ctx, rx ? "initiator-all-in-order" : "responder-all-in-order", (uint8_t)rx, r, l, N_REC);
        emit_recs(emit, ctx, rx ? "initiator-record0" : "responder-record0", (uint8_t)rx, r, l, 1);
    }
    for (int i = 0; i < N_REC; i++) {
        r[i] = g_rec[RX_RESPONDER][i];
        l[i] = g_rec_len[RX_RESPONDER][i];
    }
    const uint8_t *rr[2] = {r[0], r[0]};
    size_t ll[2] = {l[0], l[0]};
    emit_recs(emit, ctx, "replay", 0, rr, ll, 2);
    emit_recs(emit, ctx, "gap", 0, &r[1], &l[1], 1);
    emit_recs(emit, ctx, "tight-limit", 4, r, l, 3);
    emit_recs(emit, ctx, "short-capacity", 2, &r[2], &l[2], 1);
    emit_recs(emit, ctx, "clock-hard-limit", 8, r, l, 1);
    emit_recs(emit, ctx, "clock-unreadable", 16, r, l, 1);
    emit_recs(emit, ctx, "reflection", 1, r, l, 1); /* a c2s record fed to the initiator */
    emit_recs(emit, ctx, "max-size", 0, r, l, N_REC); /* record 3 has a 65536-byte plaintext */

    memcpy(tmp, r[2], l[2]);
    tmp[l[2] - 1u] ^= 0x01;
    const uint8_t *t1[1] = {tmp};
    emit_recs(emit, ctx, "flipped-tag", 0, t1, &l[2], 1);
    memcpy(tmp, r[0], l[0]);
    tmp[0] = 0x05;
    emit_recs(emit, ctx, "type-0x05", 0, t1, &l[0], 1);
    size_t l24 = 24;
    emit_recs(emit, ctx, "length-24", 0, &r[0], &l24, 1);
    memcpy(tmp, r[0], l[0]);
    memset(tmp + 1, 0, 8);
    tmp[4] = 0x02; /* seq = 2^33 */
    emit_recs(emit, ctx, "seq-2pow33", 0, t1, &l[0], 1);
}
