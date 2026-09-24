#ifndef MLDSA_TESTS_CC_FAKE_SERVER_H
#define MLDSA_TESTS_CC_FAKE_SERVER_H

/*
 * A minimal responder for client-core tests (V4-13a).
 *
 * The real daemon (tests/authd_harness.h) is what the client core is tested
 * AGAINST wherever it can be: login, EXCHANGE, rotation. This exists for the
 * three things the real daemon will never do, which are exactly the things a
 * phishing server or a MITM would -- send a first record that is not
 * LOGIN_CODE, acknowledge a rotation naming a different key or handle -- and
 * for the known-answer test, which needs a server whose every output is a
 * function of the RNG and nothing else (no store, no wall clock).
 *
 * It is built from the same src/ API the daemon uses (responder handshake,
 * pending ledger, session), with an injected clock. Frames in and out are
 * whole `len4 || payload` messages, like the core's.
 *
 * Everything is `static inline`, as in authd_harness.h: one translation unit
 * per test, no library that only tests link.
 */
#include <string.h>

#include <sodium.h>

#include "authmsg.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"

typedef struct {
    mldsa_keypair_t kp;                  /* the server's identity */
    keystore_t ks;                       /* the one client it knows */
    handshake_pending_store_t pending;
    handshake_ctx_t hs;
    session_t sess;
    uint64_t now_ms;                     /* the injected clock */
    uint8_t sid[64];
    size_t sid_len;
} fs_t;

static inline uint64_t fs_clock(void *ctx) { return ((const fs_t *)ctx)->now_ms; }

static inline void fs_put_len(uint8_t *p, size_t n)
{ p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16); p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n; }
static inline size_t fs_get_len(const uint8_t *p)
{ return ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3]; }

/* A server named `sid` with a fresh keypair, knowing one client. */
static inline int fs_init(fs_t *s, const uint8_t *sid, size_t sid_len,
                          const uint8_t *hid, size_t hid_len, const uint8_t client_pk[MLDSA_PUBLIC_KEY_BYTES])
{
    memset(s, 0, sizeof *s);
    s->now_ms = 1000u;
    if (sid_len < 1u || sid_len > sizeof s->sid) { return -1; }
    memcpy(s->sid, sid, sid_len);
    s->sid_len = sid_len;
    keystore_init(&s->ks);
    if (mldsa_keypair_generate(&s->kp) != 0) { return -1; }
    if (keystore_add(&s->ks, hid, hid_len, client_pk) != KEYSTORE_OK) { return -1; }
    if (handshake_pending_store_init(&s->pending, 4u, HANDSHAKE_PENDING_TTL_MS_DEFAULT, fs_clock, s) != PENDING_OK) {
        return -1;
    }
    return 0;
}

static inline void fs_wipe(fs_t *s)
{
    handshake_ctx_wipe(&s->hs);
    session_wipe(&s->sess);
    handshake_pending_store_wipe(&s->pending);
    keystore_wipe(&s->ks);
    mldsa_keypair_free(&s->kp);
}

/* ClientHello frame in, ServerHello frame out. */
static inline int fs_on_client_hello(fs_t *s, const uint8_t *msg, size_t len,
                                     uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    if (len < 4u || fs_get_len(msg) != len - 4u || cap < 4u) { return -1; }
    if (handshake_responder_init(&s->hs, s->sid, s->sid_len, &s->kp, &s->ks, &s->pending) != HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&s->hs, msg + 4, len - 4u) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&s->hs, out + 4, cap - 4u, &n) != HANDSHAKE_OK) {
        return -1;
    }
    fs_put_len(out, n);
    *out_len = 4u + n;
    return 0;
}

/* ClientAuth frame in; on success the session is live, bucket 256 as the
 * daemon's default. */
static inline int fs_on_client_auth(fs_t *s, const uint8_t *msg, size_t len)
{
    if (len < 4u || fs_get_len(msg) != len - 4u) { return -1; }
    if (handshake_responder_verify_client_auth(&s->hs, msg + 4, len - 4u) != HANDSHAKE_OK ||
        handshake_responder_finish(&s->hs) != HANDSHAKE_OK) {
        return -1;
    }
    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = 256u;
    return (session_init_from_handshake(&s->sess, &s->hs, &lim, fs_clock, s) == SESSION_OK) ? 0 : -1;
}

/* Seals `content` as one record, framed. */
static inline int fs_send(fs_t *s, const uint8_t *content, size_t n, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t sealed = 0;
    if (cap < 4u || session_seal(&s->sess, content, n, out + 4, cap - 4u, &sealed) != SESSION_OK) { return -1; }
    fs_put_len(out, sealed);
    *out_len = 4u + sealed;
    return 0;
}

/* Opens one framed record into pt. */
static inline int fs_open(fs_t *s, const uint8_t *msg, size_t len, uint8_t *pt, size_t cap, size_t *pt_len)
{
    if (len < 4u || fs_get_len(msg) != len - 4u) { return -1; }
    return (session_open(&s->sess, msg + 4, len - 4u, pt, cap, pt_len) == SESSION_OK) ? 0 : -1;
}

/* A LOGIN_CODE record with a fixed code and expiry. */
static inline int fs_send_login_code(fs_t *s, uint8_t flags, uint8_t byte, uint64_t expires,
                                     uint8_t *out, size_t cap, size_t *out_len)
{
    authmsg_login_code_t m;
    memset(&m, 0, sizeof m);
    m.flags = flags;
    memset(m.code, byte, sizeof m.code);
    m.code_expires = expires;
    uint8_t body[AUTHMSG_LOGIN_CODE_CONTENT_LEN];
    size_t n = 0;
    if (authmsg_encode_login_code(body, sizeof body, &n, &m) != AUTHMSG_OK) { return -1; }
    return fs_send(s, body, n, out, cap, out_len);
}

/* A ROTATE_ACK naming `handle` and the SHA-256 of `pk` -- whichever the test
 * wants it to name, which is the point. */
static inline int fs_send_rotate_ack(fs_t *s, const uint8_t *handle, size_t handle_len,
                                     const uint8_t pk[MLDSA_PUBLIC_KEY_BYTES], uint64_t at,
                                     uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t fp[AUTHMSG_FP_BYTES];
    crypto_hash_sha256(fp, pk, MLDSA_PUBLIC_KEY_BYTES);
    uint8_t body[128];
    size_t n = 0;
    if (authmsg_encode_rotate_ack(body, sizeof body, &n, handle, handle_len, fp, at) != AUTHMSG_OK) { return -1; }
    return fs_send(s, body, n, out, cap, out_len);
}

#endif /* MLDSA_TESTS_CC_FAKE_SERVER_H */
