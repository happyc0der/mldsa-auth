#include "authmsg.h"

#include <string.h>

#include <sodium.h>

#include "session.h"

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
