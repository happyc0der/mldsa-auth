/* V4-8b: the daemon's connection state machine (apps/authd/authd_conn.c).
 *
 * This is the daemon's first attacker-facing protocol surface: every byte it
 * sees before authentication comes from an unauthenticated peer. The harness
 * drives ONE slot in-process, feeding the fuzz input as a sequence of frames
 * exactly as the event loop would after reassembly.
 *
 * THE ORACLE IS THE STATE MACHINE'S INVARIANTS, not a re-implementation.
 * Predicting the exact stage for arbitrary bytes would mean re-implementing
 * decode_client_hello and the whole responder handshake -- two copies of the
 * same code, which proves nothing. What IS checkable independently, and is
 * what actually matters here:
 *
 *   1. The stage only ever moves forward along AWAIT_CH -> AWAIT_CA ->
 *      SERVING -> CLOSING. It never goes backwards and never skips a step, so
 *      no input can talk the daemon into serving records before a handshake.
 *   2. SERVING is unreachable without a real identity: a connection that has
 *      been issued a login code is never a decoy and always has a user id.
 *      This is the property that makes the decoy flow safe rather than merely
 *      uniform -- a decoy that could reach SERVING would hand a login code to
 *      an unauthenticated peer.
 *   3. logins_issued increases ONLY on a transition into SERVING.
 *   4. After a close, the connection record is fully wiped: no stage, no
 *      handle, no user id, no live session.
 *
 * Every one of those is a property a mutation can break, and none of them
 * restates the implementation.
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

#include "authd_conn.h"
#include "authmsg.h"
#include "conn_io.h"
#include "evloop.h"
#include "store.h"
#include "authd_log.h"
#include "handshake.h"
#include "mldsa_wrap.h"

#include <sodium.h>

const char *const fuzz_target_name = "authd_conn";
const size_t fuzz_target_max_len = 16384;

int fuzz_target_command(int argc, char **argv) { (void)argc; (void)argv; return -1; }

static const uint8_t SERVER_ID[] = { 'a','u','t','h','d' };
static const uint8_t USER1[]     = { 'u','1' };
static const uint8_t HANDLE1[]   = { 'd','1','a','a' };
static const uint8_t KEK[32] = { 9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,
                                 9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9 };

static int g_ready;
static store_t *g_store;
static mldsa_keypair_t g_server_kp;
static mldsa_keypair_t g_device_kp;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_common_init();
    /* the daemon's own logging would drown the fuzzer's output */
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    /* Keys come from the deterministic fuzz DRBG, so a crash replays. */
    if (mldsa_keypair_generate(&g_server_kp) != 0) { return 0; }
    if (mldsa_keypair_generate(&g_device_kp) != 0) { return 0; }
    /* An in-memory store: no filesystem, and a fresh one per process. */
    if (store_open(":memory:", KEK, &g_store) != STORE_OK) { return 0; }
    if (store_add_user(g_store, USER1, sizeof USER1, STORE_ROLE_USER) != STORE_OK) { return 0; }
    if (store_enroll_device(g_store, HANDLE1, sizeof HANDLE1, USER1, sizeof USER1,
                            g_device_kp.public_key, "fuzz", "fuzz", NULL, 0) != STORE_OK) { return 0; }
    g_ready = 1;
    return 0;
}

/* The legal order. A stage may stay put or advance, never retreat. */
static int stage_rank(conn_stage_t s)
{
    switch (s) {
    case CONN_STAGE_FREE:     return 0;
    case CONN_STAGE_AWAIT_CH: return 1;
    case CONN_STAGE_AWAIT_CA: return 2;
    case CONN_STAGE_SERVING:  return 3;
    case CONN_STAGE_CLOSING:  return 4;
    default:                  return -1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_ready || size > fuzz_target_max_len) { return 0; }

    static authd_conn_t conn;
    static authd_slot_t slot;
    static authd_app_t app;

    memset(&conn, 0, sizeof conn);
    memset(&slot, 0, sizeof slot);
    memset(&app, 0, sizeof app);

    app.conns = &conn;
    app.n_conns = 1u;
    app.store = g_store;
    app.server_kp = &g_server_kp;
    app.server_id = SERVER_ID;
    app.server_id_len = sizeof SERVER_ID;
    app.pad_bucket = 256u;
    app.code_ttl_s = AUTHD_LOGIN_CODE_TTL_S;
    app.now_ms = FUZZ_CLOCK_T0;
    app.now_unix = 1700000000;

    static handshake_pending_store_t pending;
    if (handshake_pending_store_init(&pending, 8u, 10000u, authd_app_clock, &app) != PENDING_OK) {
        return 0;
    }
    app.pending = &pending;

    slot.index = 0;
    slot.fd = -1;              /* nothing is written: conn_io buffers the reply */
    slot.state = SLOT_ACTIVE;
    conn_io_reset(&slot.io);
    authd_conn_bind(&app, &slot);

    int prev_rank = stage_rank(conn.stage);
    uint64_t prev_logins = app.logins_issued;

    /* The input is a sequence of length-prefixed chunks, each delivered as one
     * reassembled frame -- the same thing evloop hands the callback. */
    fuzz_chunks_t ch;
    fuzz_chunks_init(&ch, data, size, 2u, 8u);
    const uint8_t *chunk = NULL;
    size_t clen = 0;
    while (fuzz_chunks_next(&ch, &chunk, &clen)) {
        if (clen == 0u || clen > AUTHD_FRAME_MAX) { continue; }

        const conn_stage_t before = conn.stage;
        const ev_action_t act = authd_conn_on_frame(&app, &slot, chunk, clen);
        const conn_stage_t after = conn.stage;

        /* 1. never backwards, never a skipped step */
        const int r_before = stage_rank(before), r_after = stage_rank(after);
        FUZZ_ASSERT(r_after >= 0 && r_before >= 0, "unknown connection stage");
        FUZZ_ASSERT(r_after >= r_before, "the connection stage moved BACKWARDS");
        if (r_after > r_before && r_after != stage_rank(CONN_STAGE_CLOSING)) {
            FUZZ_ASSERT(r_after == r_before + 1, "the connection stage SKIPPED a step");
        }
        FUZZ_ASSERT(r_after >= prev_rank, "stage regressed across frames");
        prev_rank = r_after;

        /* 2. SERVING implies a real, identified device -- never the decoy */
        if (after == CONN_STAGE_SERVING) {
            FUZZ_ASSERT(!conn.decoy, "a DECOY connection reached SERVING");
            FUZZ_ASSERT(conn.user_id_len > 0u, "SERVING without a resolved user id");
            FUZZ_ASSERT(conn.handle_len > 0u, "SERVING without a handle");
        }

        /* 3. a login is counted only when the connection becomes SERVING */
        if (app.logins_issued != prev_logins) {
            FUZZ_ASSERT(app.logins_issued == prev_logins + 1u, "more than one login per frame");
            FUZZ_ASSERT(before != CONN_STAGE_SERVING && after == CONN_STAGE_SERVING,
                        "a login was issued without entering SERVING");
            prev_logins = app.logins_issued;
        }

        if (act == EV_ACTION_CLOSE) { break; }
    }

    /* 4. the close path leaves nothing behind */
    authd_conn_on_close(&app, &slot);
    FUZZ_ASSERT(conn.stage == CONN_STAGE_FREE, "a closed connection is not FREE");
    FUZZ_ASSERT(conn.handle_len == 0u && conn.user_id_len == 0u,
                "a closed connection still holds an identity length");
    /* The BYTES, not just the lengths. A wipe that zeroed the length and left
     * the buffer would satisfy the check above -- a non-vacuity probe against
     * exactly that shape passed here before this assertion existed. */
    FUZZ_ASSERT(sodium_is_zero(conn.handle, sizeof conn.handle),
                "a closed connection still holds its handle BYTES");
    FUZZ_ASSERT(sodium_is_zero(conn.user_id, sizeof conn.user_id),
                "a closed connection still holds its user id BYTES");
    FUZZ_ASSERT(session_get_state(&conn.sess) == SESSION_STATE_EMPTY,
                "a closed connection still holds a live session");
    FUZZ_ASSERT(slot.user == NULL, "a closed slot still points at its connection");

    conn_io_reset(&slot.io);
    handshake_pending_store_wipe(&pending);
    return 0;
}

/* Seeds: the shapes that reach each stage, plus the boundaries. A genuine
 * ClientHello is the only way past stage 1, so it is built with the real
 * initiator rather than guessed at. */
static void emit_chunked(fuzz_emit_fn emit, void *ctx, const char *name,
                         const uint8_t *const *parts, const size_t *lens, size_t n)
{
    static uint8_t seed[16384];
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        const size_t w = fuzz_seed_put_chunk(seed, off, sizeof seed, 2u, parts[i], lens[i]);
        if (w == 0u) { return; }
        off = w;
    }
    emit(ctx, name, seed, off);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx)
{
    emit(ctx, "empty", fuzz_empty, 0);

    static uint8_t ch_buf[4096];
    size_t ch_len = 0;
    int have_ch = 0;
    {
        /* A real ClientHello for the enrolled handle. */
        mldsa_keypair_t kp;
        keystore_t pins;
        handshake_ctx_t hs;
        mldsa_keypair_t skp;
        memset(&hs, 0, sizeof hs);
        keystore_init(&pins);
        if (mldsa_keypair_generate(&skp) == 0 && mldsa_keypair_generate(&kp) == 0 &&
            keystore_add(&pins, SERVER_ID, sizeof SERVER_ID, skp.public_key) == KEYSTORE_OK &&
            handshake_initiator_init(&hs, HANDLE1, sizeof HANDLE1, &kp, &pins,
                                     SERVER_ID, sizeof SERVER_ID) == HANDSHAKE_OK &&
            handshake_initiator_create_client_hello(&hs, ch_buf, sizeof ch_buf, &ch_len) == HANDSHAKE_OK) {
            have_ch = 1;
        }
        handshake_ctx_wipe(&hs);
        keystore_wipe(&pins);
        mldsa_keypair_free(&kp);
        mldsa_keypair_free(&skp);
    }

    if (have_ch) {
        const uint8_t *p1[1] = { ch_buf };
        const size_t l1[1] = { ch_len };
        emit_chunked(emit, ctx, "client-hello", p1, l1, 1);

        /* CH followed by junk where the ClientAuth belongs */
        static const uint8_t junk[64] = { 0 };
        const uint8_t *p2[2] = { ch_buf, junk };
        const size_t l2[2] = { ch_len, sizeof junk };
        emit_chunked(emit, ctx, "client-hello-then-junk", p2, l2, 2);

        /* the same ClientHello twice: the second must not be served */
        const uint8_t *p3[2] = { ch_buf, ch_buf };
        const size_t l3[2] = { ch_len, ch_len };
        emit_chunked(emit, ctx, "client-hello-twice", p3, l3, 2);
    }

    /* application ops arriving before any handshake */
    { static uint8_t b[1]; b[0] = AUTHMSG_OP_BYE;
      const uint8_t *p[1] = { b }; const size_t l[1] = { 1 };
      emit_chunked(emit, ctx, "bye-before-handshake", p, l, 1); }
    { static uint8_t r[8]; r[0] = AUTHMSG_OP_ROTATE; memset(r + 1, 0, 7);
      const uint8_t *p[1] = { r }; const size_t l[1] = { sizeof r };
      emit_chunked(emit, ctx, "rotate-before-handshake", p, l, 1); }
    { static uint8_t big[2048]; memset(big, 0xAA, sizeof big);
      const uint8_t *p[1] = { big }; const size_t l[1] = { sizeof big };
      emit_chunked(emit, ctx, "large-garbage", p, l, 1); }
}
