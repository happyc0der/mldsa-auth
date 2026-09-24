#include "client_core.h"

#include <string.h>

#include <oqs/oqs.h>
#include <sodium.h>

#include "demo_keys.h"
#include "frame.h"      /* FRAME_* bounds only: nothing here touches a socket */
#include "keyfile.h"
#include "secure_mem.h"

/* The frame header, written and read here rather than through frame.c, whose
 * other half is socket I/O the browser build does not have. */
static void put_len(uint8_t *p, size_t n)
{
    p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16); p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}
static uint32_t get_len(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

const char *cc_status_name(cc_status_t st)
{
    switch (st) {
    case CC_OK:               return "ok";
    case CC_ERR_ARG:          return "invalid-argument";
    case CC_ERR_STATE:        return "unexpected-state";
    case CC_ERR_FRAME:        return "bad-frame";
    case CC_ERR_HANDSHAKE:    return "handshake-refused";
    case CC_ERR_SESSION:      return "record-rejected";
    case CC_ERR_MESSAGE:      return "unexpected-message";
    case CC_ERR_REFUSED:      return "refused-by-daemon";
    case CC_ERR_ACK_MISMATCH: return "ack-mismatch";
    case CC_ERR_KEYFILE:      return "key-envelope";
    case CC_ERR_KEYS:         return "public-key-file";
    case CC_ERR_CRYPTO:       return "crypto-error";
    }
    return "unknown";
}

/* The library exports no handshake_status_name(); spec 13 requires a failure to
 * print a name from the same enum the daemon logs, not an integer an operator
 * would have to look up. */
const char *cc_handshake_status_name(handshake_status_t st)
{
    switch (st) {
    case HANDSHAKE_OK:                        return "ok";
    case HANDSHAKE_ERR_INVALID_ARG:           return "invalid-argument";
    case HANDSHAKE_ERR_UNEXPECTED_STATE:      return "unexpected-state";
    case HANDSHAKE_ERR_MALFORMED:             return "malformed";
    case HANDSHAKE_ERR_UNKNOWN_IDENTITY:      return "unknown-identity";
    case HANDSHAKE_ERR_IDENTITY_KEY_MISMATCH: return "identity-key-mismatch";
    case HANDSHAKE_ERR_PEER_IDENTITY_MISMATCH:return "peer-identity-mismatch";
    case HANDSHAKE_ERR_SESSION_ID_MISMATCH:   return "session-id-mismatch";
    case HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH: return "handshake-id-mismatch";
    case HANDSHAKE_ERR_REPLAY:                return "replay";
    case HANDSHAKE_ERR_EXPIRED:               return "expired";
    case HANDSHAKE_ERR_SIGNATURE:             return "signature";
    case HANDSHAKE_ERR_AUTH_FAILURE_LIMIT:    return "auth-failure-limit";
    case HANDSHAKE_ERR_KEX:                   return "kex";
    case HANDSHAKE_ERR_RESOURCE_EXHAUSTED:    return "resource-exhausted";
    case HANDSHAKE_ERR_INTERNAL:              return "internal";
    }
    return "unknown";
}

static void set_diag(cc_diag_t *d, cc_diag_kind_t kind, const char *stage, const char *detail)
{
    if (d != NULL) {
        d->kind = kind;
        d->stage = stage;
        d->detail = detail;
    }
}

/* ---- identity, no network ------------------------------------------------ */

void cc_new_handle(char out[CC_HANDLE_BUF])
{
    /* Spec 3.1: 16 random bytes, generated with the keypair. No round trip is
     * needed to learn an identity, and 128 bits of unguessability is most of
     * the answer to enumeration -- the wire carries no user name at all. */
    uint8_t raw[16];
    randombytes_buf(raw, sizeof raw);
    out[0] = 'd';
    out[1] = '1';
    (void)sodium_bin2hex(out + 2, CC_HANDLE_BUF - 2u, raw, sizeof raw);
    sodium_memzero(raw, sizeof raw);
}

cc_status_t cc_seal_new_identity(const uint8_t *hid, size_t hid_len, const char *pass, size_t pass_len,
                                 uint32_t opslimit, uint64_t memlimit,
                                 uint8_t *ek_out, size_t ek_cap, size_t *ek_len,
                                 uint8_t *pub_out, size_t pub_cap, size_t *pub_len,
                                 uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES], cc_diag_t *diag)
{
    set_diag(diag, CC_DIAG_NONE, NULL, NULL);
    const size_t img_len = demo_keys_sk2_image_len(hid_len);
    const size_t sealed = keyfile_sealed_len(img_len);
    const size_t pub_need = demo_keys_public_image_len(hid_len);
    if (hid == NULL || pass == NULL || ek_out == NULL || ek_len == NULL || pub_out == NULL ||
        pub_len == NULL || img_len == 0u || ek_cap < sealed || pub_cap < pub_need) {
        return CC_ERR_ARG;
    }
    *ek_len = 0u;
    *pub_len = 0u;
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    if (mldsa_keypair_generate(&kp) != 0) {
        set_diag(diag, CC_DIAG_KEYS, "keygen", "keypair-generation-failed");
        return CC_ERR_CRYPTO;
    }
    /* The plaintext MLDSASK2 image exists only here, in secure memory: spec
     * Req 10 -- no plaintext secret key is ever written anywhere. */
    uint8_t *img = secure_mem_alloc(img_len);
    cc_status_t rc = CC_ERR_CRYPTO;
    if (img == NULL) {
        set_diag(diag, CC_DIAG_KEYS, "envelope", "allocation-failed");
        goto out;
    }
    const demo_keys_status_t bs = demo_keys_build_sk2_image(img, img_len, hid, hid_len, &kp);
    if (bs != DEMO_KEYS_OK) {
        set_diag(diag, CC_DIAG_KEYS, "envelope", demo_keys_status_name(bs));
        rc = CC_ERR_KEYS;
        goto out;
    }
    const keyfile_status_t ks = keyfile_seal_buf(ek_out, ek_cap, img, img_len, pass, pass_len,
                                                 opslimit, memlimit);
    if (ks != KEYFILE_OK) {
        set_diag(diag, CC_DIAG_KEYS, "envelope", keyfile_status_name(ks));
        rc = CC_ERR_KEYFILE;
        goto out;
    }
    const demo_keys_status_t ps = demo_keys_build_public_image(pub_out, pub_cap, hid, hid_len, kp.public_key);
    if (ps != DEMO_KEYS_OK) {
        sodium_memzero(ek_out, sealed);
        set_diag(diag, CC_DIAG_KEYS, "public-key", demo_keys_status_name(ps));
        rc = CC_ERR_KEYS;
        goto out;
    }
    if (pk_out != NULL) {
        memcpy(pk_out, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
    }
    *ek_len = sealed;
    *pub_len = pub_need;
    rc = CC_OK;
out:
    if (img != NULL) {
        secure_mem_free(img, img_len);
    }
    mldsa_keypair_free(&kp);
    return rc;
}

cc_status_t cc_open_sealed(const uint8_t *ek, size_t ek_len, const uint8_t *hid, size_t hid_len,
                           const char *pass, size_t pass_len, mldsa_keypair_t *kp_out, cc_diag_t *diag)
{
    set_diag(diag, CC_DIAG_NONE, NULL, NULL);
    const keyfile_status_t ks = keyfile_open_buf(ek, ek_len, hid, hid_len, pass, pass_len, kp_out, NULL);
    if (ks == KEYFILE_ERR_ARG) {
        return CC_ERR_ARG;
    }
    if (ks != KEYFILE_OK) {
        set_diag(diag, CC_DIAG_KEYS, "envelope", keyfile_status_name(ks));
        return CC_ERR_KEYFILE;
    }
    return CC_OK;
}

cc_status_t cc_parse_server_pub(const uint8_t *pub, size_t pub_len, const uint8_t *sid, size_t sid_len,
                                uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES], cc_diag_t *diag)
{
    set_diag(diag, CC_DIAG_NONE, NULL, NULL);
    const demo_keys_status_t ps = demo_keys_parse_public(pub, pub_len, sid, sid_len, pk_out);
    if (ps == DEMO_KEYS_ERR_ARG) {
        return CC_ERR_ARG;
    }
    if (ps != DEMO_KEYS_OK) {
        set_diag(diag, CC_DIAG_KEYS, "server-key", demo_keys_status_name(ps));
        return CC_ERR_KEYS;
    }
    return CC_OK;
}

/* ---- the state machine --------------------------------------------------- */

/* The key signing ClientAuth stops being reachable: freed if the core opened
 * it, forgotten if it was lent. The handshake context keeps a stale pointer
 * to it, which nothing after create_client_auth dereferences -- the only two
 * readers of local_keypair are the two sign calls (handshake.c). */
static void release_key(cc_t *cc)
{
    cc->kp = NULL;
    mldsa_keypair_free(&cc->own_kp);   /* no-op when the key was lent */
}

static void wipe_secrets(cc_t *cc)
{
    release_key(cc);
    handshake_ctx_wipe(&cc->hs);
    session_wipe(&cc->sess);
    sodium_memzero(cc->hsid, sizeof cc->hsid);
    sodium_memzero(cc->want_fp, sizeof cc->want_fp);
    sodium_memzero(cc->body, sizeof cc->body);
    sodium_memzero(cc->pt, sizeof cc->pt);
}

/* Every failure goes through here: terminal, secrets gone, reason recorded. */
static cc_status_t fail(cc_t *cc, cc_status_t st, cc_diag_kind_t kind, const char *stage, const char *detail)
{
    wipe_secrets(cc);
    set_diag(&cc->diag, kind, stage, detail);
    cc->state = CC_STATE_FAILED;
    return st;
}

/* The one place an inbound frame is taken apart. The header must equal the
 * bytes actually present AND lie within the state's bounds; the payload is
 * then msg+4 for msg_len-4 -- the claim in the header is never used to index
 * anything. */
static int take_frame(const uint8_t *msg, size_t msg_len, size_t min_len, size_t max_len, size_t *plen)
{
    if (msg == NULL || msg_len < FRAME_HEADER_BYTES) {
        return -1;
    }
    const size_t claimed = get_len(msg);
    if (claimed != msg_len - FRAME_HEADER_BYTES || claimed < min_len || claimed > max_len) {
        return -1;
    }
    *plen = claimed;
    return 0;
}

void cc_init(cc_t *cc, handshake_clock_fn clock_fn, void *clock_ctx)
{
    if (cc == NULL) {
        return;
    }
    memset(cc, 0, sizeof *cc);
    keystore_init(&cc->pins);
    cc->clock_fn = clock_fn;
    cc->clock_ctx = clock_ctx;
    cc->state = CC_STATE_NEW;
}

cc_status_t cc_pin_server(cc_t *cc, const uint8_t *sid, size_t sid_len, const uint8_t pk[MLDSA_PUBLIC_KEY_BYTES])
{
    if (cc == NULL || sid == NULL || pk == NULL || sid_len < 1u || sid_len > sizeof cc->sid) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_NEW) {
        return CC_ERR_STATE;
    }
    if (keystore_add(&cc->pins, sid, sid_len, pk) != KEYSTORE_OK) {
        return CC_ERR_ARG;
    }
    memcpy(cc->sid, sid, sid_len);
    cc->sid_len = sid_len;
    cc->state = CC_STATE_PINNED;
    return CC_OK;
}

/* PINNED, with cc->kp set -> WAIT_SERVER_HELLO. */
static cc_status_t begin(cc_t *cc, uint8_t *out, size_t out_cap, size_t *out_len)
{
    handshake_status_t hst = handshake_initiator_init(&cc->hs, cc->hid, cc->hid_len, cc->kp, &cc->pins,
                                                      cc->sid, cc->sid_len);
    if (hst != HANDSHAKE_OK) {
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_HANDSHAKE, "init", cc_handshake_status_name(hst));
    }
    size_t n = 0;
    hst = handshake_initiator_create_client_hello(&cc->hs, out + FRAME_HEADER_BYTES,
                                                  out_cap - FRAME_HEADER_BYTES, &n);
    if (hst != HANDSHAKE_OK) {
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_HANDSHAKE, "client-hello", cc_handshake_status_name(hst));
    }
    put_len(out, n);
    *out_len = FRAME_HEADER_BYTES + n;
    cc->state = CC_STATE_WAIT_SERVER_HELLO;
    return CC_OK;
}

static cc_status_t begin_args(cc_t *cc, const uint8_t *hid, size_t hid_len, uint8_t *out, size_t out_cap,
                              size_t *out_len)
{
    if (cc == NULL || hid == NULL || out == NULL || out_len == NULL || hid_len < 1u ||
        hid_len > sizeof cc->hid || out_cap < FRAME_HEADER_BYTES + FRAME_MAX_CLIENT_HELLO) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_PINNED) {
        return CC_ERR_STATE;
    }
    *out_len = 0u;
    memcpy(cc->hid, hid, hid_len);
    cc->hid_len = hid_len;
    return CC_OK;
}

cc_status_t cc_login_begin(cc_t *cc, const uint8_t *hid, size_t hid_len, const mldsa_keypair_t *kp,
                           unsigned flags, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (kp == NULL || kp->secret_key == NULL) {
        return CC_ERR_ARG;
    }
    const cc_status_t a = begin_args(cc, hid, hid_len, out, out_cap, out_len);
    if (a != CC_OK) {
        return a;
    }
    cc->flags = flags;
    cc->kp = kp;
    return begin(cc, out, out_cap, out_len);
}

cc_status_t cc_login_begin_sealed(cc_t *cc, const uint8_t *hid, size_t hid_len,
                                  const uint8_t *ek, size_t ek_len, const char *pass, size_t pass_len,
                                  unsigned flags, uint8_t *out, size_t out_cap, size_t *out_len)
{
    const cc_status_t a = begin_args(cc, hid, hid_len, out, out_cap, out_len);
    if (a != CC_OK) {
        return a;
    }
    /* A wrong passphrase is not a protocol failure: the core stays PINNED
     * and nothing has been sent, so the caller may simply ask again. */
    const cc_status_t os = cc_open_sealed(ek, ek_len, hid, hid_len, pass, pass_len, &cc->own_kp, &cc->diag);
    if (os != CC_OK) {
        return os;
    }
    cc->flags = flags;
    cc->kp = &cc->own_kp;
    return begin(cc, out, out_cap, out_len);
}

cc_status_t cc_login_on_server_hello(cc_t *cc, const uint8_t *msg, size_t msg_len,
                                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (cc == NULL || out == NULL || out_len == NULL || out_cap < FRAME_HEADER_BYTES + FRAME_MAX_CLIENT_AUTH) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_WAIT_SERVER_HELLO) {
        return CC_ERR_STATE;
    }
    *out_len = 0u;
    size_t plen = 0;
    if (take_frame(msg, msg_len, 1u, FRAME_MAX_SERVER_HELLO, &plen) != 0) {
        return fail(cc, CC_ERR_FRAME, CC_DIAG_IO, "server-hello", NULL);
    }
    /* Spec 4: a ServerHello not signed by the PINNED key ends here, before a
     * ClientAuth exists -- this device authenticates to nobody else. */
    handshake_status_t hst = handshake_initiator_verify_server_hello(&cc->hs, msg + FRAME_HEADER_BYTES, plen);
    if (hst != HANDSHAKE_OK) {
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_HANDSHAKE, "server-hello", cc_handshake_status_name(hst));
    }
    size_t n = 0;
    hst = handshake_initiator_create_client_auth(&cc->hs, out + FRAME_HEADER_BYTES,
                                                 out_cap - FRAME_HEADER_BYTES, &n);
    if (hst != HANDSHAKE_OK) {
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_HANDSHAKE, "client-auth", cc_handshake_status_name(hst));
    }
    /* ClientAuth is signed: the identity key has done its job for a login. */
    if ((cc->flags & CC_KEEP_FOR_ROTATE) == 0u) {
        release_key(cc);
    }
    hst = handshake_initiator_finish(&cc->hs);
    if (hst != HANDSHAKE_OK) {
        sodium_memzero(out, FRAME_HEADER_BYTES + n);
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_HANDSHAKE, "client-auth", cc_handshake_status_name(hst));
    }
    /* Captured BEFORE session_init consumes the context: ROTATE's digest binds
     * to it and nothing else can hand it back. */
    if (handshake_get_handshake_id(&cc->hs, cc->hsid) != HANDSHAKE_OK) {
        sodium_memzero(out, FRAME_HEADER_BYTES + n);
        return fail(cc, CC_ERR_HANDSHAKE, CC_DIAG_IO, "client-auth", NULL);
    }
    session_limits_t lim;
    session_default_limits(&lim);
    if (session_init_from_handshake(&cc->sess, &cc->hs, &lim, cc->clock_fn, cc->clock_ctx) != SESSION_OK) {
        sodium_memzero(out, FRAME_HEADER_BYTES + n);
        return fail(cc, CC_ERR_SESSION, CC_DIAG_IO, "session-init", NULL);
    }
    put_len(out, n);
    *out_len = FRAME_HEADER_BYTES + n;
    cc->state = CC_STATE_WAIT_LOGIN_CODE;
    return CC_OK;
}

cc_status_t cc_login_on_record(cc_t *cc, const uint8_t *msg, size_t msg_len, authmsg_login_code_t *code_out)
{
    if (cc == NULL || code_out == NULL) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_WAIT_LOGIN_CODE) {
        return CC_ERR_STATE;
    }
    memset(code_out, 0, sizeof *code_out);
    size_t plen = 0, pt_len = 0;
    if (take_frame(msg, msg_len, FRAME_CONFIRM_MIN, FRAME_CONFIRM_MAX, &plen) != 0) {
        return fail(cc, CC_ERR_FRAME, CC_DIAG_IO, "login-code", NULL);
    }
    if (session_open(&cc->sess, msg + FRAME_HEADER_BYTES, plen, cc->pt,
                     SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX), &pt_len) != SESSION_OK) {
        return fail(cc, CC_ERR_SESSION, CC_DIAG_IO, "login-code", NULL);
    }
    /* The daemon's first record is LOGIN_CODE and nothing else: anything that
     * authenticates but is not one is refused, not skipped. */
    const authmsg_status_t as = authmsg_decode_login_code(cc->pt, pt_len, code_out);
    sodium_memzero(cc->pt, pt_len);
    if (as != AUTHMSG_OK) {
        memset(code_out, 0, sizeof *code_out);
        return fail(cc, CC_ERR_MESSAGE, CC_DIAG_MESSAGE, "login-code", authmsg_status_name(as));
    }
    cc->state = CC_STATE_LIVE;
    return CC_OK;
}

cc_status_t cc_bye(cc_t *cc, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (cc == NULL || out == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_LIVE) {
        return CC_ERR_STATE;
    }
    *out_len = 0u;
    uint8_t body[AUTHMSG_BYE_CONTENT_LEN];
    size_t n = 0, sealed = 0;
    if (authmsg_encode_bye(body, sizeof body, &n) != AUTHMSG_OK) {
        return fail(cc, CC_ERR_MESSAGE, CC_DIAG_IO, "bye", NULL);
    }
    const size_t need = session_sealed_len(&cc->sess, n);
    if (need == 0u || out_cap < FRAME_HEADER_BYTES + need) {
        return CC_ERR_ARG;
    }
    if (session_seal(&cc->sess, body, n, out + FRAME_HEADER_BYTES, out_cap - FRAME_HEADER_BYTES,
                     &sealed) != SESSION_OK) {
        return fail(cc, CC_ERR_SESSION, CC_DIAG_IO, "bye", NULL);
    }
    put_len(out, sealed);
    *out_len = FRAME_HEADER_BYTES + sealed;
    wipe_secrets(cc);
    cc->state = CC_STATE_CLOSED;
    return CC_OK;
}

/* ---- rotation ------------------------------------------------------------ */

cc_status_t cc_rotate_build(cc_t *cc, const mldsa_keypair_t *new_kp, uint8_t rotate_flags,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (cc == NULL || new_kp == NULL || new_kp->secret_key == NULL || out == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_LIVE || (cc->flags & CC_KEEP_FOR_ROTATE) == 0u || cc->kp == NULL) {
        return CC_ERR_STATE;
    }
    const size_t need = session_sealed_len(&cc->sess, AUTHMSG_ROTATE_MAX_CONTENT);
    if (need == 0u || out_cap < FRAME_HEADER_BYTES + need) {
        return CC_ERR_ARG;
    }
    *out_len = 0u;
    uint8_t dig[crypto_hash_sha256_BYTES];
    uint8_t sig_old[MLDSA_SIGNATURE_MAX_BYTES], sig_new[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sol = 0, snl = 0, n = 0, sealed = 0;
    const int built =
        authmsg_rotate_digest(dig, AUTHMSG_LABEL_ROTATE_OLD, cc->hsid, rotate_flags, cc->hid, cc->hid_len,
                              cc->kp->public_key, new_kp->public_key) == AUTHMSG_OK &&
        mldsa_sign(sig_old, &sol, dig, sizeof dig, cc->kp) == 0 &&
        authmsg_rotate_digest(dig, AUTHMSG_LABEL_ROTATE_NEW, cc->hsid, rotate_flags, cc->hid, cc->hid_len,
                              cc->kp->public_key, new_kp->public_key) == AUTHMSG_OK &&
        mldsa_sign(sig_new, &snl, dig, sizeof dig, new_kp) == 0 &&
        authmsg_encode_rotate(cc->body, sizeof cc->body, &n, rotate_flags, cc->hid, cc->hid_len,
                              new_kp->public_key, sig_old, sol, sig_new, snl) == AUTHMSG_OK;
    sodium_memzero(dig, sizeof dig);
    /* Both signatures are made: the old key has nothing left to do. */
    release_key(cc);
    if (!built) {
        return fail(cc, CC_ERR_CRYPTO, CC_DIAG_IO, "rotate", NULL);
    }
    if (session_seal(&cc->sess, cc->body, n, out + FRAME_HEADER_BYTES, out_cap - FRAME_HEADER_BYTES,
                     &sealed) != SESSION_OK) {
        return fail(cc, CC_ERR_SESSION, CC_DIAG_IO, "rotate", NULL);
    }
    sodium_memzero(cc->body, n);
    crypto_hash_sha256(cc->want_fp, new_kp->public_key, MLDSA_PUBLIC_KEY_BYTES);
    put_len(out, sealed);
    *out_len = FRAME_HEADER_BYTES + sealed;
    cc->state = CC_STATE_WAIT_ROTATE_REPLY;
    return CC_OK;
}

cc_status_t cc_rotate_on_reply(cc_t *cc, const uint8_t *msg, size_t msg_len, uint8_t *err_code)
{
    if (cc == NULL) {
        return CC_ERR_ARG;
    }
    if (cc->state != CC_STATE_WAIT_ROTATE_REPLY) {
        return CC_ERR_STATE;
    }
    if (err_code != NULL) {
        *err_code = 0u;
    }
    size_t plen = 0, pl = 0;
    if (take_frame(msg, msg_len, FRAME_MIN_RECORD, FRAME_MAX_RECORD, &plen) != 0) {
        return fail(cc, CC_ERR_FRAME, CC_DIAG_IO, "rotate-reply", NULL);
    }
    if (session_open(&cc->sess, msg + FRAME_HEADER_BYTES, plen, cc->pt, sizeof cc->pt, &pl) != SESSION_OK) {
        return fail(cc, CC_ERR_SESSION, CC_DIAG_IO, "rotate-reply", NULL);
    }
    /* From here the record authenticated, so the session is intact and the
     * core returns to LIVE whatever it said -- a BYE can still be sent. Only
     * CC_OK licenses replacing the old key. */
    cc_status_t rc;
    authmsg_rotate_ack_t ack;
    uint8_t code = 0;
    if (authmsg_decode_rotate_ack(cc->pt, pl, &ack) == AUTHMSG_OK) {
        /* The ACK must name THIS handle and the key actually sealed.
         * Constant-time, because Req 3 says every digest comparison is. */
        if (ack.handle_len == cc->hid_len && sodium_memcmp(ack.handle, cc->hid, cc->hid_len) == 0 &&
            sodium_memcmp(ack.fp_new, cc->want_fp, sizeof cc->want_fp) == 0) {
            rc = CC_OK;
            set_diag(&cc->diag, CC_DIAG_NONE, NULL, NULL);
        } else {
            rc = CC_ERR_ACK_MISMATCH;
            set_diag(&cc->diag, CC_DIAG_IO, "rotate-reply", NULL);
        }
    } else if (authmsg_decode_error(cc->pt, pl, &code) == AUTHMSG_OK) {
        rc = CC_ERR_REFUSED;
        if (err_code != NULL) {
            *err_code = code;
        }
        set_diag(&cc->diag, CC_DIAG_IO, "rotate-reply", NULL);
    } else {
        rc = CC_ERR_MESSAGE;
        set_diag(&cc->diag, CC_DIAG_IO, "rotate-reply", NULL);
    }
    sodium_memzero(cc->pt, pl);
    sodium_memzero(cc->want_fp, sizeof cc->want_fp);
    cc->state = CC_STATE_LIVE;
    return rc;
}

/* ---- state -------------------------------------------------------------- */

cc_state_t cc_state(const cc_t *cc)
{
    return (cc != NULL) ? cc->state : CC_STATE_FAILED;
}

const cc_diag_t *cc_diag(const cc_t *cc)
{
    return (cc != NULL) ? &cc->diag : NULL;
}

void cc_recv_bounds(const cc_t *cc, size_t *min_payload, size_t *max_payload)
{
    size_t lo = 0u, hi = 0u;
    switch (cc_state(cc)) {
    case CC_STATE_WAIT_SERVER_HELLO: lo = 1u;                hi = FRAME_MAX_SERVER_HELLO; break;
    case CC_STATE_WAIT_LOGIN_CODE:   lo = FRAME_CONFIRM_MIN; hi = FRAME_CONFIRM_MAX;      break;
    case CC_STATE_WAIT_ROTATE_REPLY: lo = FRAME_MIN_RECORD;  hi = FRAME_MAX_RECORD;       break;
    default: break;
    }
    if (min_payload != NULL) { *min_payload = lo; }
    if (max_payload != NULL) { *max_payload = hi; }
}

void cc_wipe(cc_t *cc)
{
    if (cc == NULL) {
        return;
    }
    wipe_secrets(cc);
    keystore_wipe(&cc->pins);
    sodium_memzero(cc, sizeof *cc);
    cc->state = CC_STATE_FAILED;
}

/* ---- the .ek.next decision (spec 10.2) ----------------------------------- */

/* What to do about a leftover <handle>.ek.next.
 *
 * Spec 10.2 once said: "if it is unknown, the server never committed". That
 * rule CANNOT BE IMPLEMENTED, and implementing it as written would be
 * dangerous. Req 6 and 7.3 guarantee a client cannot distinguish an unknown
 * key from a revoked one from a wrong signature -- every one of them pins the
 * decoy and fails at the same point. "Unknown" is not observable, so "unknown
 * therefore the server never committed" is an inference from something the
 * client never learns.
 *
 * The sound rule is the contrapositive on the OTHER file, and it is stronger:
 *
 *     .ek authenticating PROVES the server did not commit -- there is exactly
 *     one active key per handle (the one_active_key index, spec 9.1) -- and
 *     only then may .ek.next be discarded. .ek.next failing proves nothing.
 *
 * So this never deletes on ambiguity. A stale file costs one confusing entry
 * in a directory; a wrong delete costs the only copy of a live key, and there
 * is no recovery path from that but re-enrolment by an administrator.
 *
 * Recorded as errata against 10.2 rather than silently deviated from.
 * Moved here from authd_cli.c (V4-13a) so the browser's storage follows the
 * same rule through the same function. */
/* `ek_ok` / `next_ok` are "this file opened AND the daemon accepted it".
 * `next_present` distinguishes "no .ek.next" from "one that did not work". */
key_plan_t client_key_plan(int ek_ok, int next_present, int next_ok)
{
    if (ek_ok) {
        return KEY_PLAN_USE_EK;
    }
    if (next_present && next_ok) {
        return KEY_PLAN_PROMOTE_NEXT;
    }
    return KEY_PLAN_REFUSE;
}

/* ---- randomness --------------------------------------------------------- */

static void cc_oqs_rng(uint8_t *buf, size_t n)
{
    randombytes_buf(buf, n);
}

void cc_use_sodium_rng_for_oqs(void)
{
    OQS_randombytes_custom_algorithm(cc_oqs_rng);
}
