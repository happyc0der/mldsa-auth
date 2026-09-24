/* V4-13a: the client core (apps/authd/client_core.c), fed what a phishing
 * server or a man in the middle controls -- every frame the daemon sends it.
 *
 * The first input byte selects the moment; the rest is ONE whole frame
 * (`len4 || payload`) handed to the core at that moment:
 *
 *   0  the ServerHello        -> cc_login_on_server_hello
 *   1  the first record       -> cc_login_on_record      (must be LOGIN_CODE)
 *   2  the reply to ROTATE    -> cc_rotate_on_reply      (must be ROTATE_ACK)
 *
 * Each input replays a whole login from a reset deterministic generator
 * (fuzz_common), against a responder built from the same src/ API the daemon
 * uses, with alice as the device and bob as the server. The genuine frame for
 * each moment is therefore the same bytes on every input, and the oracle can
 * be exact:
 *
 *   - the core accepts the input  IFF  it is byte-for-byte the genuine frame;
 *   - on any refusal the core is FAILED, wrote nothing, holds no key, and
 *     refuses every later call (a refused ServerHello leaves no ClientAuth to
 *     send, a refused record no code to print, a refused reply no licence to
 *     replace a key).
 *
 * Only a party holding the session keys can make a record authenticate, so
 * for moments 1 and 2 the refusal is always at the frame or the AEAD; the
 * core's handling of an AUTHENTIC wrong message (BYE first, an ACK naming
 * another key) is test_client_core's, against a server that sends one.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "fuzz_common.h"
#include "authmsg.h"
#include "client_core.h"
#include "frame.h"

const char *const fuzz_target_name = "client";
const size_t fuzz_target_max_len = 8192;

int fuzz_target_command(int argc, char **argv) {
    (void)argc; (void)argv;
    return -1;
}

enum { AT_SERVER_HELLO = 0, AT_FIRST_RECORD = 1, AT_ROTATE_REPLY = 2, AT_COUNT = 3 };

static cc_t g_cc;
static handshake_ctx_t g_res;
static handshake_pending_store_t g_pending;
static session_t g_srv;
static uint8_t g_out[FRAME_BUF_BYTES];
static uint8_t g_genuine[FRAME_BUF_BYTES];
static size_t g_genuine_len;

static void put_len(uint8_t *p, size_t n) {
    p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16); p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}

/* Seals `content` on the server side, framed, into g_genuine. */
static int server_send(const uint8_t *content, size_t n) {
    size_t sealed = 0;
    if (session_seal(&g_srv, content, n, g_genuine + 4, sizeof g_genuine - 4u, &sealed) != SESSION_OK) {
        return -1;
    }
    put_len(g_genuine, sealed);
    g_genuine_len = 4u + sealed;
    return 0;
}

static void teardown(void) {
    cc_wipe(&g_cc);
    handshake_ctx_wipe(&g_res);
    session_wipe(&g_srv);
    handshake_pending_store_wipe(&g_pending);
}

/* Drives a login to moment `at` and leaves the genuine frame for that moment
 * in g_genuine. Deterministic: the generator is reset first. */
static void setup(int at) {
    const fuzz_identities_t *ids = fuzz_identities();
    size_t n = 0, m = 0;
    fuzz_rng_reset();
    fuzz_clock_now = FUZZ_CLOCK_T0;
    cc_init(&g_cc, fuzz_clock_fn, NULL);
    memset(&g_res, 0, sizeof g_res);
    memset(&g_srv, 0, sizeof g_srv);
    if (handshake_pending_store_init(&g_pending, 4u, HANDSHAKE_PENDING_TTL_MS_DEFAULT, fuzz_clock_fn, NULL) !=
            PENDING_OK ||
        cc_pin_server(&g_cc, FUZZ_ID_B, FUZZ_ID_B_LEN, ids->kp_b.public_key) != CC_OK ||
        cc_login_begin(&g_cc, FUZZ_ID_A, FUZZ_ID_A_LEN, &ids->kp_a, CC_KEEP_FOR_ROTATE, g_out, sizeof g_out, &n) !=
            CC_OK ||
        handshake_responder_init(&g_res, FUZZ_ID_B, FUZZ_ID_B_LEN, &ids->kp_b, &ids->ks_responder, &g_pending) !=
            HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&g_res, g_out + 4, n - 4u) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&g_res, g_genuine + 4, sizeof g_genuine - 4u, &m) != HANDSHAKE_OK) {
        FUZZ_ASSERT(0, "fixture: ClientHello / ServerHello");
    }
    put_len(g_genuine, m);
    g_genuine_len = 4u + m;
    if (at == AT_SERVER_HELLO) {
        return;
    }
    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = 256u;
    if (cc_login_on_server_hello(&g_cc, g_genuine, g_genuine_len, g_out, sizeof g_out, &n) != CC_OK ||
        handshake_responder_verify_client_auth(&g_res, g_out + 4, n - 4u) != HANDSHAKE_OK ||
        handshake_responder_finish(&g_res) != HANDSHAKE_OK ||
        session_init_from_handshake(&g_srv, &g_res, &lim, fuzz_clock_fn, NULL) != SESSION_OK) {
        FUZZ_ASSERT(0, "fixture: ClientAuth / session");
    }
    authmsg_login_code_t lc;
    memset(&lc, 0, sizeof lc);
    memset(lc.code, 0x5A, sizeof lc.code);
    lc.code_expires = 1700000060u;
    uint8_t body[AUTHMSG_LOGIN_CODE_CONTENT_LEN];
    if (authmsg_encode_login_code(body, sizeof body, &n, &lc) != AUTHMSG_OK || server_send(body, n) != 0) {
        FUZZ_ASSERT(0, "fixture: LOGIN_CODE");
    }
    if (at == AT_FIRST_RECORD) {
        return;
    }
    authmsg_login_code_t code;
    if (cc_login_on_record(&g_cc, g_genuine, g_genuine_len, &code) != CC_OK ||
        cc_rotate_build(&g_cc, &ids->kp_b, 0u, g_out, sizeof g_out, &n) != CC_OK) {
        FUZZ_ASSERT(0, "fixture: LIVE / ROTATE");
    }
    /* The genuine ACK names alice and the key she asked to rotate to. */
    uint8_t fp[AUTHMSG_FP_BYTES], ack[128];
    crypto_hash_sha256(fp, ids->kp_b.public_key, MLDSA_PUBLIC_KEY_BYTES);
    if (authmsg_encode_rotate_ack(ack, sizeof ack, &n, FUZZ_ID_A, FUZZ_ID_A_LEN, fp, 1700000100u) != AUTHMSG_OK ||
        server_send(ack, n) != 0) {
        FUZZ_ASSERT(0, "fixture: ROTATE_ACK");
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    fuzz_common_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const int at = (int)(fuzz_selector(data, size, 0) % AT_COUNT);
    const uint8_t *msg = NULL;
    size_t len = 0;
    fuzz_payload(data, size, &msg, &len);
    msg = fuzz_ptr(msg, len);

    setup(at);
    const int genuine = (len == g_genuine_len && memcmp(msg, g_genuine, len) == 0);
    cc_status_t st;
    size_t out_len = 12345u;
    authmsg_login_code_t code;
    memset(&code, 0xA5, sizeof code);
    uint8_t ec = 0xEE;
    switch (at) {
    case AT_SERVER_HELLO:
        st = cc_login_on_server_hello(&g_cc, msg, len, g_out, sizeof g_out, &out_len);
        break;
    case AT_FIRST_RECORD:
        st = cc_login_on_record(&g_cc, msg, len, &code);
        break;
    default:
        st = cc_rotate_on_reply(&g_cc, msg, len, &ec);
        break;
    }

    if (genuine) {
        FUZZ_ASSERT(st == CC_OK, "the genuine frame was refused");
    } else {
        FUZZ_ASSERT(st != CC_OK, "a frame other than the genuine one was ACCEPTED");
        FUZZ_ASSERT(st == CC_ERR_FRAME || st == CC_ERR_HANDSHAKE || st == CC_ERR_SESSION,
                    "a forged frame was refused for a reason only an authentic one can have");
        FUZZ_ASSERT(cc_state(&g_cc) == CC_STATE_FAILED, "a refusal left the core usable");
        FUZZ_ASSERT(g_cc.kp == NULL && g_cc.own_kp.secret_key == NULL, "a refusal left a key reachable");
        if (at == AT_SERVER_HELLO) {
            FUZZ_ASSERT(out_len == 0u, "a refused ServerHello still produced a ClientAuth");
        }
        if (at == AT_FIRST_RECORD) {
            FUZZ_ASSERT(sodium_is_zero(code.code, sizeof code.code), "a refused record left a login code behind");
        }
        size_t n = 0;
        FUZZ_ASSERT(cc_login_on_server_hello(&g_cc, g_genuine, g_genuine_len, g_out, sizeof g_out, &n) == CC_ERR_STATE &&
                        cc_login_on_record(&g_cc, g_genuine, g_genuine_len, &code) == CC_ERR_STATE &&
                        cc_rotate_on_reply(&g_cc, g_genuine, g_genuine_len, &ec) == CC_ERR_STATE &&
                        cc_bye(&g_cc, g_out, sizeof g_out, &n) == CC_ERR_STATE,
                    "a failed core accepted a later call");
    }
    teardown();
    return 0;
}

/* Seeds: each moment's genuine frame, and the structural boundaries around it
 * -- header one more and one less than the bytes present, one byte short, a
 * flipped bit in the payload, and an empty frame. */
void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    static uint8_t buf[1u + FRAME_BUF_BYTES];
    static const char *const names[AT_COUNT] = { "server-hello", "first-record", "rotate-reply" };
    emit(ctx, "empty", fuzz_empty, 0);
    for (int at = 0; at < AT_COUNT; at++) {
        char name[64];
        setup(at);
        const size_t gl = g_genuine_len;
        if (1u + gl > fuzz_target_max_len) {
            teardown();
            continue;
        }
        buf[0] = (uint8_t)at;
        memcpy(buf + 1, g_genuine, gl);
        teardown();
        snprintf(name, sizeof name, "%s-genuine", names[at]);
        emit(ctx, name, buf, 1u + gl);
        put_len(buf + 1, gl - 4u + 1u);
        snprintf(name, sizeof name, "%s-hdr-plus-1", names[at]);
        emit(ctx, name, buf, 1u + gl);
        put_len(buf + 1, gl - 4u - 1u);
        snprintf(name, sizeof name, "%s-hdr-minus-1", names[at]);
        emit(ctx, name, buf, 1u + gl);
        put_len(buf + 1, gl - 4u);
        snprintf(name, sizeof name, "%s-short", names[at]);
        emit(ctx, name, buf, gl);
        buf[1u + gl / 2u] ^= 0x01u;
        snprintf(name, sizeof name, "%s-bitflip", names[at]);
        emit(ctx, name, buf, 1u + gl);
        buf[1] = 0; buf[2] = 0; buf[3] = 0; buf[4] = 0;
        snprintf(name, sizeof name, "%s-empty-frame", names[at]);
        emit(ctx, name, buf, 5u);
    }
}
