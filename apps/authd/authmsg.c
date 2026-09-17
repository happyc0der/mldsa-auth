#include "authmsg.h"

#include <string.h>

#include <sodium.h>

#include "mldsa_wrap.h"
#include "session.h"
#include "store.h"   /* STORE_ID_MAX: the handle bound both layers share */

/* The spec's numbers, pinned to the arithmetic rather than retyped.
 * §6.2: content 43 -> a 281-byte record at the default bucket 256.
 * §6.1: AUTHD_MAX_CONTENT 9216 -> AUTHD_MAX_RECORD 12313 at bucket 4096. */
_Static_assert(AUTHMSG_LOGIN_CODE_CONTENT_LEN == 1u + 1u + 1u + AUTHMSG_CODE_BYTES + 8u,
               "LOGIN_CODE content is op+version+flags+code+expires");
_Static_assert(AUTHMSG_LOGIN_CODE_CONTENT_LEN == 43u, "spec 6.2: 43 bytes of content");
_Static_assert(SESSION_RECORD_LEN(AUTHMSG_LOGIN_CODE_CONTENT_LEN, 256u) == 281u,
               "spec 6.2: a 281-byte record at the default bucket");
_Static_assert(AUTHMSG_ERROR_CONTENT_LEN == 3u, "spec 6.5: ERROR is version+code");
_Static_assert(AUTHMSG_BYE_CONTENT_LEN == 1u, "spec 6.5: BYE has an empty body");
_Static_assert(AUTHD_MAX_CONTENT == 9216u, "spec 6.1");
_Static_assert(AUTHD_MAX_RECORD == 12313u, "spec 6.1: the tightened record maximum");
_Static_assert(AUTHMSG_LOGIN_CODE_CONTENT_LEN <= AUTHD_MAX_CONTENT, "must fit the content cap");

const char *authmsg_status_name(authmsg_status_t st)
{
    switch (st) {
    case AUTHMSG_OK:              return "ok";
    case AUTHMSG_ERR_ARG:         return "bad-argument";
    case AUTHMSG_ERR_EMPTY:       return "empty-content";
    case AUTHMSG_ERR_BAD_LENGTH:  return "bad-length";
    case AUTHMSG_ERR_BAD_VERSION: return "bad-version";
    case AUTHMSG_ERR_BAD_FIELD:   return "bad-field";
    case AUTHMSG_ERR_UNKNOWN_OP:  return "unknown-op";
    default:                      return "unknown";
    }
}

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

authmsg_status_t authmsg_peek_op(const uint8_t *in, size_t len, uint8_t *op_out)
{
    if (in == NULL || op_out == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    if (len == 0u) {
        return AUTHMSG_ERR_EMPTY;
    }
    *op_out = in[0];
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_encode_login_code(uint8_t *out, size_t out_cap, size_t *out_len,
                                           const authmsg_login_code_t *m)
{
    if (out == NULL || out_len == NULL || m == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    if (out_cap < AUTHMSG_LOGIN_CODE_CONTENT_LEN) {
        return AUTHMSG_ERR_ARG;
    }
    /* Reserved bits are refused on the way OUT as well as in: a caller that
     * invents a flag should find out here, not on a peer's strict decoder. */
    if ((m->flags & (uint8_t)~AUTHMSG_FLAG_ROTATION_DUE) != 0u) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    out[0] = AUTHMSG_OP_LOGIN_CODE;
    out[1] = AUTHMSG_VERSION;
    out[2] = m->flags;
    memcpy(out + 3, m->code, AUTHMSG_CODE_BYTES);
    put_be64(out + 3 + AUTHMSG_CODE_BYTES, m->code_expires);
    *out_len = AUTHMSG_LOGIN_CODE_CONTENT_LEN;
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_decode_login_code(const uint8_t *in, size_t len, authmsg_login_code_t *out)
{
    if (in == NULL || out == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    if (len == 0u) {
        return AUTHMSG_ERR_EMPTY;
    }
    if (in[0] != AUTHMSG_OP_LOGIN_CODE) {
        return AUTHMSG_ERR_UNKNOWN_OP;
    }
    if (len != AUTHMSG_LOGIN_CODE_CONTENT_LEN) {
        return AUTHMSG_ERR_BAD_LENGTH;   /* exact, and fully consumed */
    }
    if (in[1] != AUTHMSG_VERSION) {
        return AUTHMSG_ERR_BAD_VERSION;
    }
    if ((in[2] & (uint8_t)~AUTHMSG_FLAG_ROTATION_DUE) != 0u) {
        return AUTHMSG_ERR_BAD_FIELD;    /* reserved bits MUST be zero */
    }
    out->flags = in[2];
    memcpy(out->code, in + 3, AUTHMSG_CODE_BYTES);
    out->code_expires = get_be64(in + 3 + AUTHMSG_CODE_BYTES);
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_encode_error(uint8_t *out, size_t out_cap, size_t *out_len, uint8_t code)
{
    if (out == NULL || out_len == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    if (out_cap < AUTHMSG_ERROR_CONTENT_LEN) {
        return AUTHMSG_ERR_ARG;
    }
    if (code < AUTHMSG_ERR_MALFORMED || code > AUTHMSG_ERR_INTERNAL) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    out[0] = AUTHMSG_OP_ERROR;
    out[1] = AUTHMSG_VERSION;
    out[2] = code;
    *out_len = AUTHMSG_ERROR_CONTENT_LEN;
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_decode_error(const uint8_t *in, size_t len, uint8_t *code_out)
{
    if (in == NULL || code_out == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    *code_out = 0;
    if (len == 0u) {
        return AUTHMSG_ERR_EMPTY;
    }
    if (in[0] != AUTHMSG_OP_ERROR) {
        return AUTHMSG_ERR_UNKNOWN_OP;
    }
    if (len != AUTHMSG_ERROR_CONTENT_LEN) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    if (in[1] != AUTHMSG_VERSION) {
        return AUTHMSG_ERR_BAD_VERSION;
    }
    if (in[2] < AUTHMSG_ERR_MALFORMED || in[2] > AUTHMSG_ERR_INTERNAL) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    *code_out = in[2];
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_encode_bye(uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    if (out_cap < AUTHMSG_BYE_CONTENT_LEN) {
        return AUTHMSG_ERR_ARG;
    }
    out[0] = AUTHMSG_OP_BYE;
    *out_len = AUTHMSG_BYE_CONTENT_LEN;
    return AUTHMSG_OK;
}

/* ---- ROTATE (0x11) and ROTATE_ACK (0x12), spec 6.3 / 6.4 ---------------- */

/* Both size constants pinned: the spec's quoted figure AND the real maximum.
 * check_spec_constants.sh derives the first from the headers independently. */
_Static_assert(AUTHMSG_ROTATE_CONTENT_H34 ==
                   1u + 1u + 1u + 1u + 34u + MLDSA_PUBLIC_KEY_BYTES +
                   2u + MLDSA_SIGNATURE_MAX_BYTES + 2u + MLDSA_SIGNATURE_MAX_BYTES,
               "spec 6.3: 8612 with a 34-byte handle");
_Static_assert(AUTHMSG_ROTATE_CONTENT_H34 == 8612u, "spec 6.3 quotes 8612");
_Static_assert(AUTHMSG_ROTATE_MAX_CONTENT ==
                   AUTHMSG_ROTATE_CONTENT_H34 + (STORE_ID_MAX - 34u),
               "the largest legal handle is 64, not 34");
_Static_assert(AUTHMSG_ROTATE_MAX_CONTENT <= AUTHD_MAX_CONTENT,
               "spec 6.1: ROTATE must fit the content cap");
_Static_assert(AUTHMSG_ROTATE_ACK_CONTENT_LEN(34u) == 77u,
               "spec 6.4: op+version+handle_len+handle+fp+rotated_at");

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xffu);
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

authmsg_status_t authmsg_rotate_digest(uint8_t out[32], const char *label,
                                       const uint8_t handshake_id[AUTHMSG_HANDSHAKE_ID_BYTES],
                                       uint8_t flags,
                                       const uint8_t *handle, size_t handle_len,
                                       const uint8_t *pk_old, const uint8_t *pk_new)
{
    static const uint8_t separator = 0x00;
    if (out == NULL || label == NULL || handshake_id == NULL || handle == NULL ||
        pk_old == NULL || pk_new == NULL ||
        handle_len == 0u || handle_len > STORE_ID_MAX) {
        return AUTHMSG_ERR_ARG;
    }
    const uint8_t hl = (uint8_t)handle_len;
    crypto_hash_sha256_state st;
    if (crypto_hash_sha256_init(&st) != 0) {
        return AUTHMSG_ERR_ARG;
    }
    /* label || 0x00 || M, incrementally. The field order IS the spec's. */
    (void)crypto_hash_sha256_update(&st, (const unsigned char *)label, strlen(label));
    (void)crypto_hash_sha256_update(&st, &separator, 1u);
    (void)crypto_hash_sha256_update(&st, handshake_id, AUTHMSG_HANDSHAKE_ID_BYTES);
    (void)crypto_hash_sha256_update(&st, &flags, 1u);
    (void)crypto_hash_sha256_update(&st, &hl, 1u);
    (void)crypto_hash_sha256_update(&st, handle, handle_len);
    (void)crypto_hash_sha256_update(&st, pk_old, MLDSA_PUBLIC_KEY_BYTES);
    (void)crypto_hash_sha256_update(&st, pk_new, MLDSA_PUBLIC_KEY_BYTES);
    (void)crypto_hash_sha256_final(&st, out);
    sodium_memzero(&st, sizeof st);
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_encode_rotate(uint8_t *out, size_t out_cap, size_t *out_len,
                                       uint8_t flags,
                                       const uint8_t *handle, size_t handle_len,
                                       const uint8_t *pk_new,
                                       const uint8_t *sig_old, size_t sig_old_len,
                                       const uint8_t *sig_new, size_t sig_new_len)
{
    if (out == NULL || out_len == NULL || handle == NULL || pk_new == NULL ||
        sig_old == NULL || sig_new == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    *out_len = 0;
    if (handle_len == 0u || handle_len > STORE_ID_MAX ||
        sig_old_len == 0u || sig_old_len > MLDSA_SIGNATURE_MAX_BYTES ||
        sig_new_len == 0u || sig_new_len > MLDSA_SIGNATURE_MAX_BYTES) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    /* Reserved bits refused on the way OUT as well as in: an encoder that can
     * emit something the decoder must reject is a bug waiting for a peer. */
    if ((flags & (uint8_t)~AUTHMSG_FLAG_ROTATE_DROP_TOKENS) != 0u) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    const size_t need = 1u + 1u + 1u + 1u + handle_len + MLDSA_PUBLIC_KEY_BYTES +
                        2u + sig_old_len + 2u + sig_new_len;
    if (out_cap < need) {
        return AUTHMSG_ERR_ARG;
    }
    size_t o = 0;
    out[o++] = AUTHMSG_OP_ROTATE;
    out[o++] = AUTHMSG_VERSION;
    out[o++] = flags;
    out[o++] = (uint8_t)handle_len;
    memcpy(out + o, handle, handle_len);            o += handle_len;
    memcpy(out + o, pk_new, MLDSA_PUBLIC_KEY_BYTES); o += MLDSA_PUBLIC_KEY_BYTES;
    put_be16(out + o, (uint16_t)sig_old_len);        o += 2u;
    memcpy(out + o, sig_old, sig_old_len);           o += sig_old_len;
    put_be16(out + o, (uint16_t)sig_new_len);        o += 2u;
    memcpy(out + o, sig_new, sig_new_len);           o += sig_new_len;
    *out_len = o;
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_decode_rotate(const uint8_t *in, size_t len, authmsg_rotate_t *out)
{
    if (in == NULL || out == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    if (len == 0u) {
        return AUTHMSG_ERR_EMPTY;
    }
    if (in[0] != AUTHMSG_OP_ROTATE) {
        return AUTHMSG_ERR_UNKNOWN_OP;
    }
    /* The fixed prefix must be present before any length byte is believed. */
    if (len < 4u) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    if (in[1] != AUTHMSG_VERSION) {
        return AUTHMSG_ERR_BAD_VERSION;
    }
    const uint8_t flags = in[2];
    if ((flags & (uint8_t)~AUTHMSG_FLAG_ROTATE_DROP_TOKENS) != 0u) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    const size_t hl = (size_t)in[3];
    if (hl == 0u || hl > STORE_ID_MAX) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    /* Each step checks there is room for the NEXT field before reading it, so
     * no declared length is ever trusted past the end of the buffer. */
    size_t o = 4u;
    if (len < o + hl + MLDSA_PUBLIC_KEY_BYTES + 2u) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    const uint8_t *handle = in + o;                  o += hl;
    const uint8_t *pk_new = in + o;                  o += MLDSA_PUBLIC_KEY_BYTES;
    const size_t sol = (size_t)get_be16(in + o);     o += 2u;
    if (sol == 0u || sol > MLDSA_SIGNATURE_MAX_BYTES) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    if (len < o + sol + 2u) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    const uint8_t *sig_old = in + o;                 o += sol;
    const size_t snl = (size_t)get_be16(in + o);     o += 2u;
    if (snl == 0u || snl > MLDSA_SIGNATURE_MAX_BYTES) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    if (len < o + snl) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    const uint8_t *sig_new = in + o;                 o += snl;
    /* FULL consumption: a trailing byte is a decode failure, not a courtesy. */
    if (o != len) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    out->flags = flags;
    out->handle = handle;
    out->handle_len = hl;
    out->pk_new = pk_new;
    out->sig_old = sig_old;
    out->sig_old_len = sol;
    out->sig_new = sig_new;
    out->sig_new_len = snl;
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_encode_rotate_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                           const uint8_t *handle, size_t handle_len,
                                           const uint8_t fp_new[AUTHMSG_FP_BYTES],
                                           uint64_t rotated_at)
{
    if (out == NULL || out_len == NULL || handle == NULL || fp_new == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    *out_len = 0;
    if (handle_len == 0u || handle_len > STORE_ID_MAX) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    const size_t need = AUTHMSG_ROTATE_ACK_CONTENT_LEN(handle_len);
    if (out_cap < need) {
        return AUTHMSG_ERR_ARG;
    }
    size_t o = 0;
    out[o++] = AUTHMSG_OP_ROTATE_ACK;
    out[o++] = AUTHMSG_VERSION;
    out[o++] = (uint8_t)handle_len;
    memcpy(out + o, handle, handle_len);       o += handle_len;
    memcpy(out + o, fp_new, AUTHMSG_FP_BYTES); o += AUTHMSG_FP_BYTES;
    put_be64(out + o, rotated_at);             o += 8u;
    *out_len = o;
    return AUTHMSG_OK;
}

authmsg_status_t authmsg_decode_rotate_ack(const uint8_t *in, size_t len,
                                           authmsg_rotate_ack_t *out)
{
    if (in == NULL || out == NULL) {
        return AUTHMSG_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    if (len == 0u) {
        return AUTHMSG_ERR_EMPTY;
    }
    if (in[0] != AUTHMSG_OP_ROTATE_ACK) {
        return AUTHMSG_ERR_UNKNOWN_OP;
    }
    if (len < 3u) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    if (in[1] != AUTHMSG_VERSION) {
        return AUTHMSG_ERR_BAD_VERSION;
    }
    const size_t hl = (size_t)in[2];
    if (hl == 0u || hl > STORE_ID_MAX) {
        return AUTHMSG_ERR_BAD_FIELD;
    }
    if (len != AUTHMSG_ROTATE_ACK_CONTENT_LEN(hl)) {
        return AUTHMSG_ERR_BAD_LENGTH;
    }
    out->handle = in + 3u;
    out->handle_len = hl;
    memcpy(out->fp_new, in + 3u + hl, AUTHMSG_FP_BYTES);
    out->rotated_at = get_be64(in + 3u + hl + AUTHMSG_FP_BYTES);
    return AUTHMSG_OK;
}
