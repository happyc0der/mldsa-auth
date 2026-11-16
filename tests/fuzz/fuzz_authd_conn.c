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
 *
 * A GENUINE LOGIN IS REACHABLE (V4-235, audit F331). Until then it was not:
 * no seed carried a ClientAuth, the one ClientHello seed was made with a key
 * the store does not hold, and the daemon's randomness ran on from wherever
 * the previous input left it, so its ServerHello was different for every
 * input and no fixed ClientAuth could have verified. Oracles 2 and 3 could
 * not fire, and nothing after the handshake -- the login code, a record, a
 * rotation -- was run by any fuzz target.
 *
 * Now: the daemon's randomness restarts for every input on a stream of its
 * own, so the same ClientHello always draws the same ServerHello; the seeds
 * are built by the real initiator with the ENROLLED device's key against
 * that ServerHello, and go on to a sealed BYE, a sealed ROTATE to a new key,
 * and a sealed record of garbage. The seed function itself checks that the
 * login seed logs in, so this cannot quietly stop being true. An input that
 * logged in has changed the store (a login code; after ROTATE, the device's
 * key), so the store is rebuilt after it: every input meets the same store.
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

/* The daemon's own stream, restarted for every input. Distinct from the
 * streams fuzz_common.h names, which the seed builder's client uses. */
#define STREAM_DAEMON 7u
#define STREAM_CLIENT 8u

static int g_ready;
static store_t *g_store;
static mldsa_keypair_t g_server_kp;
static mldsa_keypair_t g_device_kp;

/* An in-memory store holding one user and one device: no filesystem. Made at
 * start, and again after any input that logged in. */
static void fresh_store(void)
{
    if (g_store != NULL) { store_close(g_store); g_store = NULL; }
    FUZZ_ASSERT(store_open(":memory:", KEK, &g_store) == STORE_OK, "fixture: the store did not open");
    FUZZ_ASSERT(store_add_user(g_store, USER1, sizeof USER1, STORE_ROLE_USER) == STORE_OK,
                "fixture: the user could not be added");
    FUZZ_ASSERT(store_enroll_device(g_store, HANDLE1, sizeof HANDLE1, USER1, sizeof USER1,
                                    g_device_kp.public_key, "fuzz", "fuzz", NULL, 0) == STORE_OK,
                "fixture: the device could not be enrolled");
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_common_init();
    /* the daemon's own logging would drown the fuzzer's output */
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    /* Keys come from the deterministic fuzz DRBG, so a crash replays. */
    /* A fixture that cannot be built is fatal (V4-233, F328): each of these
     * returned 0, and with g_ready unset every input then returned at once
     * and was still counted as a run. */
    FUZZ_ASSERT(mldsa_keypair_generate(&g_server_kp) == 0, "fixture: the server key could not be made");
    FUZZ_ASSERT(mldsa_keypair_generate(&g_device_kp) == 0, "fixture: the device key could not be made");
    fresh_store();
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

/* The fixture one input runs in. start_world() builds it and restarts the
 * daemon's randomness; the seed builder uses the same call, so what it sees
 * the daemon answer is what the daemon will answer the seed. */
static authd_conn_t conn;
static authd_slot_t slot;
static authd_app_t app;
static handshake_pending_store_t pending;

static void start_world(void)
{
    fuzz_rng_reset_stream(STREAM_DAEMON);
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

    FUZZ_ASSERT(handshake_pending_store_init(&pending, 8u, 10000u, authd_app_clock, &app) == PENDING_OK,
                "fixture: the pending-handshake table could not be made");
    app.pending = &pending;

    slot.index = 0;
    slot.fd = -1;              /* nothing is written: conn_io buffers the reply */
    slot.state = SLOT_ACTIVE;
    conn_io_reset(&slot.io);
    authd_conn_bind(&app, &slot);
}

/* Runs one input; returns how many logins it was issued. */
static uint64_t run_input(const uint8_t *data, size_t size)
{
    start_world();

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
        /* The peer reads what it was sent. Without this the ServerHello sat
         * in the out buffer for the rest of the input, and the login code
         * that follows a genuine ClientAuth had nowhere to go. */
        conn_io_sent(&slot.io, conn_io_pending(&slot.io));
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
    const uint64_t logins = app.logins_issued;
    if (logins > 0u) {
        fresh_store();          /* a login code was stored; a ROTATE may have changed the key */
    }
    return logins;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FUZZ_ASSERT(g_ready, "fixture: LLVMFuzzerInitialize did not run");
    if (size > fuzz_target_max_len) { return 0; }
    (void)run_input(data, size);
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

/* The real initiator, holding the ENROLLED device's key, against the
 * ServerHello the daemon gives this ClientHello from a freshly restarted
 * stream -- which is the one it will give again when the seed is run. Leaves
 * the client's session ready to seal its first record. */
static void genuine_login(uint8_t *ch_out, size_t *chl, uint8_t *ca_out, size_t *cal,
                          session_t *sess, uint8_t hsid[STORE_HSID_BYTES])
{
    static uint8_t sh[AUTHD_FRAME_MAX];
    size_t shl = 0;
    keystore_t pins;
    handshake_ctx_t hs;
    memset(&hs, 0, sizeof hs);
    memset(sess, 0, sizeof *sess);
    keystore_init(&pins);

    fuzz_rng_reset_stream(STREAM_CLIENT);
    FUZZ_ASSERT(keystore_add(&pins, SERVER_ID, sizeof SERVER_ID, g_server_kp.public_key) == KEYSTORE_OK &&
                handshake_initiator_init(&hs, HANDLE1, sizeof HANDLE1, &g_device_kp, &pins,
                                         SERVER_ID, sizeof SERVER_ID) == HANDSHAKE_OK &&
                handshake_initiator_create_client_hello(&hs, ch_out, CLIENT_HELLO_MAX_ENCODED_LEN, chl) == HANDSHAKE_OK,
                "fixture: the genuine ClientHello could not be made");

    start_world();                      /* a world exactly like an input's */
    (void)authd_conn_on_frame(&app, &slot, ch_out, *chl);
    {
        const size_t pn = conn_io_pending(&slot.io);
        const uint8_t *pp = conn_io_pending_ptr(&slot.io);
        FUZZ_ASSERT(conn.stage == CONN_STAGE_AWAIT_CA && pn > AUTHD_FRAME_HEADER &&
                    pn - AUTHD_FRAME_HEADER <= sizeof sh,
                    "fixture: the daemon did not answer the genuine ClientHello");
        shl = pn - AUTHD_FRAME_HEADER;
        memcpy(sh, pp + AUTHD_FRAME_HEADER, shl);
    }
    authd_conn_on_close(&app, &slot);
    conn_io_reset(&slot.io);
    handshake_pending_store_wipe(&pending);

    fuzz_rng_reset_stream(STREAM_CLIENT);
    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = 256u;
    FUZZ_ASSERT(handshake_initiator_verify_server_hello(&hs, sh, shl) == HANDSHAKE_OK &&
                handshake_initiator_create_client_auth(&hs, ca_out, CLIENT_AUTH_MAX_ENCODED_LEN, cal) == HANDSHAKE_OK &&
                handshake_initiator_finish(&hs) == HANDSHAKE_OK &&
                handshake_get_handshake_id(&hs, hsid) == HANDSHAKE_OK &&
                session_init_from_handshake(sess, &hs, &lim, fuzz_clock_fn, NULL) == SESSION_OK,
                "fixture: the genuine client could not finish the handshake");
    handshake_ctx_wipe(&hs);
    keystore_wipe(&pins);
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

    /* A GENUINE LOGIN, and what an authenticated device can then send. Each
     * record below is the client's FIRST after the handshake, so each comes
     * from a handshake of its own; the streams restart, so the three
     * handshakes are byte for byte the same one. */
    {
        static uint8_t g_ch[CLIENT_HELLO_MAX_ENCODED_LEN], g_ca[CLIENT_AUTH_MAX_ENCODED_LEN];
        static uint8_t rec[AUTHD_MAX_RECORD];
        static uint8_t rot[AUTHMSG_ROTATE_MAX_CONTENT];
        size_t chl = 0, cal = 0, recl = 0, rl = 0;
        session_t sess;
        uint8_t hsid[STORE_HSID_BYTES];

        genuine_login(g_ch, &chl, g_ca, &cal, &sess, hsid);
        const uint8_t *p2[2] = { g_ch, g_ca };
        const size_t l2[2] = { chl, cal };
        emit_chunked(emit, ctx, "login", p2, l2, 2);
        {
            /* The canary: this seed, run as an input, logs in. */
            static uint8_t seed[16384];
            size_t off = fuzz_seed_put_chunk(seed, 0, sizeof seed, 2u, g_ch, chl);
            off = fuzz_seed_put_chunk(seed, off, sizeof seed, 2u, g_ca, cal);
            FUZZ_ASSERT(off > 0u && run_input(seed, off) == 1u,
                        "fixture: the genuine login seed does not log in -- nothing after the handshake is being fuzzed");
        }
        {
            uint8_t bye[AUTHMSG_BYE_CONTENT_LEN];
            FUZZ_ASSERT(authmsg_encode_bye(bye, sizeof bye, &rl) == AUTHMSG_OK &&
                        session_seal(&sess, bye, rl, rec, sizeof rec, &recl) == SESSION_OK,
                        "fixture: BYE could not be sealed");
            const uint8_t *p3[3] = { g_ch, g_ca, rec };
            const size_t l3[3] = { chl, cal, recl };
            emit_chunked(emit, ctx, "login-then-bye", p3, l3, 3);
        }
        session_wipe(&sess);

        genuine_login(g_ch, &chl, g_ca, &cal, &sess, hsid);
        {
            mldsa_keypair_t new_kp;
            uint8_t d_old[32], d_new[32];
            static uint8_t s_old[MLDSA_SIGNATURE_MAX_BYTES], s_new[MLDSA_SIGNATURE_MAX_BYTES];
            size_t sol = 0, snl = 0;
            FUZZ_ASSERT(mldsa_keypair_generate(&new_kp) == 0 &&
                        authmsg_rotate_digest(d_old, AUTHMSG_LABEL_ROTATE_OLD, hsid, 0u, HANDLE1, sizeof HANDLE1,
                                              g_device_kp.public_key, new_kp.public_key) == AUTHMSG_OK &&
                        authmsg_rotate_digest(d_new, AUTHMSG_LABEL_ROTATE_NEW, hsid, 0u, HANDLE1, sizeof HANDLE1,
                                              g_device_kp.public_key, new_kp.public_key) == AUTHMSG_OK &&
                        mldsa_sign(s_old, &sol, d_old, sizeof d_old, &g_device_kp) == 0 &&
                        mldsa_sign(s_new, &snl, d_new, sizeof d_new, &new_kp) == 0 &&
                        authmsg_encode_rotate(rot, sizeof rot, &rl, 0u, HANDLE1, sizeof HANDLE1, new_kp.public_key,
                                              s_old, sol, s_new, snl) == AUTHMSG_OK &&
                        session_seal(&sess, rot, rl, rec, sizeof rec, &recl) == SESSION_OK,
                        "fixture: ROTATE could not be built and sealed");
            mldsa_keypair_free(&new_kp);
            const uint8_t *p3[3] = { g_ch, g_ca, rec };
            const size_t l3[3] = { chl, cal, recl };
            emit_chunked(emit, ctx, "login-then-rotate", p3, l3, 3);
        }
        session_wipe(&sess);

        genuine_login(g_ch, &chl, g_ca, &cal, &sess, hsid);
        {
            static const uint8_t junk[40] = { 0x7Fu, 0x01u, 0x02u };
            FUZZ_ASSERT(session_seal(&sess, junk, sizeof junk, rec, sizeof rec, &recl) == SESSION_OK,
                        "fixture: the junk record could not be sealed");
            const uint8_t *p3[3] = { g_ch, g_ca, rec };
            const size_t l3[3] = { chl, cal, recl };
            emit_chunked(emit, ctx, "login-then-unknown-op", p3, l3, 3);
        }
        session_wipe(&sess);
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
