#ifndef MLDSA_AUTHD_AUTHMSG_H
#define MLDSA_AUTHD_AUTHMSG_H

#include <stddef.h>
#include <stdint.h>

#include "conn_io.h"   /* AUTHD_MAX_CONTENT */

/*
 * The daemon's application messages (V4-8b), spec mldsa-authd §6.
 *
 * These travel as the CONTENT of spec-v2 records: the record layer already
 * supplies confidentiality, integrity, ordering and replay protection, and
 * nothing here repeats that work. One op per record.
 *
 *   content = op (1 byte) || body
 *
 * Decoding is STRICT in exactly the sense spec-v2 §6.3.4 established for the
 * handshake wire: the length must be exact for the op, the content must be
 * fully consumed, and there are no trailing bytes. A violation is terminal.
 * There is no "tolerant" mode and no version negotiation -- a version byte
 * that is not 0x01 is a decode failure, not a downgrade.
 *
 * V4-9c completes the set: LOGIN_CODE, ROTATE, ROTATE_ACK, ERROR and BYE.
 *
 * ROTATE is the only message here with a variable-length body, and the only
 * one whose decoder BORROWS rather than copies: `pk_new`, `sig_old` and
 * `sig_new` are pointers into the caller's buffer, bounds-checked against it.
 * Copying them by value would put ~8.6 KB on top of the 12 KB record buffer in
 * one event-loop callback frame, for no benefit -- the caller already owns the
 * decrypted content and wipes it.
 */

#define AUTHMSG_VERSION 0x01u

/* Ops (§6). */
#define AUTHMSG_OP_LOGIN_CODE 0x10u
#define AUTHMSG_OP_ROTATE     0x11u  /* V4-9 */
#define AUTHMSG_OP_ROTATE_ACK 0x12u  /* V4-9 */
#define AUTHMSG_OP_ERROR      0x1Fu
#define AUTHMSG_OP_BYE        0x20u

/* ERROR codes (§6.5). Coarse by design: a remote peer learns THAT it failed,
 * not why. Anything finer is an oracle. */
#define AUTHMSG_ERR_MALFORMED     0x01u
#define AUTHMSG_ERR_NOT_PERMITTED 0x02u
#define AUTHMSG_ERR_REJECTED      0x03u
#define AUTHMSG_ERR_RATE_LIMITED  0x04u
#define AUTHMSG_ERR_INTERNAL      0x05u

#define AUTHMSG_CODE_BYTES 32u

/* Exact content lengths. Pinned against the spec by _Static_assert in the .c. */
#define AUTHMSG_LOGIN_CODE_CONTENT_LEN 43u  /* op + version + flags + code(32) + expires(8) */
#define AUTHMSG_ERROR_CONTENT_LEN       3u  /* op + version + code */
#define AUTHMSG_BYE_CONTENT_LEN         1u  /* op */

/* LOGIN_CODE flags. */
#define AUTHMSG_FLAG_ROTATION_DUE 0x01u

typedef enum {
    AUTHMSG_OK = 0,
    AUTHMSG_ERR_ARG,        /* NULL, or an output buffer too small */
    AUTHMSG_ERR_EMPTY,      /* zero-length content: no op byte at all */
    AUTHMSG_ERR_BAD_LENGTH, /* length does not match the op exactly */
    AUTHMSG_ERR_BAD_VERSION,
    AUTHMSG_ERR_BAD_FIELD,  /* a reserved bit set, or a value out of range */
    AUTHMSG_ERR_UNKNOWN_OP
} authmsg_status_t;

const char *authmsg_status_name(authmsg_status_t st);

typedef struct {
    uint8_t  flags;
    uint8_t  code[AUTHMSG_CODE_BYTES];
    uint64_t code_expires;   /* unix seconds */
} authmsg_login_code_t;

/* Encodes LOGIN_CODE content into out (needs AUTHMSG_LOGIN_CODE_CONTENT_LEN). */
authmsg_status_t authmsg_encode_login_code(uint8_t *out, size_t out_cap, size_t *out_len,
                                           const authmsg_login_code_t *m);

/* Decodes LOGIN_CODE content. Strict: exact length, version 0x01, no reserved
 * flag bits. (The daemon does not receive this message; the decoder exists so
 * the client side and the tests share one definition of the format rather
 * than two that can drift.) */
authmsg_status_t authmsg_decode_login_code(const uint8_t *in, size_t len, authmsg_login_code_t *out);

authmsg_status_t authmsg_encode_error(uint8_t *out, size_t out_cap, size_t *out_len, uint8_t code);
authmsg_status_t authmsg_decode_error(const uint8_t *in, size_t len, uint8_t *code_out);

authmsg_status_t authmsg_encode_bye(uint8_t *out, size_t out_cap, size_t *out_len);

/* Returns the op byte of a content buffer without decoding the body, so the
 * connection layer can decide "is this permitted in this state?" before
 * spending anything on the body. AUTHMSG_ERR_EMPTY for zero length. */
authmsg_status_t authmsg_peek_op(const uint8_t *in, size_t len, uint8_t *op_out);

/* ---- ROTATE (0x11) and ROTATE_ACK (0x12), spec 6.3 / 6.4 ---------------- */

/* ROTATE flags. Bit 0 asks the daemon to delete this handle's other tokens on
 * commit -- the "I think this key leaked" path (spec 10.2). */
#define AUTHMSG_FLAG_ROTATE_DROP_TOKENS 0x01u

/* The two digest labels (spec 6.3). Different labels are what stop a signature
 * by either key from being replayed as the other's. */
#define AUTHMSG_LABEL_ROTATE_OLD "mldsa-authd/v1/rotate-old"
#define AUTHMSG_LABEL_ROTATE_NEW "mldsa-authd/v1/rotate-new"

#define AUTHMSG_HANDSHAKE_ID_BYTES 16u
#define AUTHMSG_FP_BYTES           32u   /* SHA-256 of a public key */

/* TWO size constants, and the difference matters.
 *
 * The spec quotes 8612 "with a 34-byte handle" -- that is the figure
 * tools/audit/check_spec_constants.sh derives independently, so it is pinned
 * here under the name that says what it is. But `handle_len` is one byte and a
 * handle is 1..64, so the largest SPEC-LEGAL ROTATE is 30 bytes bigger. A
 * buffer sized from the quoted figure overflows on a 64-byte handle. Allocate
 * from _MAX_CONTENT; compare against the spec with _H34. */
#define AUTHMSG_ROTATE_CONTENT_H34 8612u
#define AUTHMSG_ROTATE_MAX_CONTENT 8642u
#define AUTHMSG_ROTATE_ACK_CONTENT_LEN(handle_len) (43u + (size_t)(handle_len))

/* Decoded ROTATE. pk_new/sig_old/sig_new point INTO the buffer passed to
 * authmsg_decode_rotate and are valid only while that buffer is. */
typedef struct {
    uint8_t        flags;
    const uint8_t *handle;
    size_t         handle_len;
    const uint8_t *pk_new;      /* MLDSA_PUBLIC_KEY_BYTES */
    const uint8_t *sig_old;
    size_t         sig_old_len;
    const uint8_t *sig_new;
    size_t         sig_new_len;
} authmsg_rotate_t;

typedef struct {
    const uint8_t *handle;
    size_t         handle_len;
    uint8_t        fp_new[AUTHMSG_FP_BYTES];
    uint64_t       rotated_at;
} authmsg_rotate_ack_t;

/* SHA-256(label || 0x00 || M) where, per spec 6.3,
 *
 *   M = handshake_id(16) || flags(1) || handle_len(1) || handle
 *       || pk_old(1952) || pk_new(1952)
 *
 * ONE implementation, shared by the client that signs and the daemon that
 * verifies. Two implementations that agree with each other but not with the
 * spec would pass every round-trip test ever written, which is why the tests
 * compare this against a hand-built literal vector rather than against itself.
 *
 * Hashed incrementally -- never concatenated into one buffer first, the rule
 * src/protocol/transcript.c states for every transcript hash in this project. */
authmsg_status_t authmsg_rotate_digest(uint8_t out[32], const char *label,
                                       const uint8_t handshake_id[AUTHMSG_HANDSHAKE_ID_BYTES],
                                       uint8_t flags,
                                       const uint8_t *handle, size_t handle_len,
                                       const uint8_t *pk_old, const uint8_t *pk_new);

/* Encodes ROTATE content. `out_cap` should be AUTHMSG_ROTATE_MAX_CONTENT. */
authmsg_status_t authmsg_encode_rotate(uint8_t *out, size_t out_cap, size_t *out_len,
                                       uint8_t flags,
                                       const uint8_t *handle, size_t handle_len,
                                       const uint8_t *pk_new,
                                       const uint8_t *sig_old, size_t sig_old_len,
                                       const uint8_t *sig_new, size_t sig_new_len);

/* Strict decode: exact field arithmetic, full consumption, no trailing bytes.
 * Every pointer in *out lies inside [in, in+len). */
authmsg_status_t authmsg_decode_rotate(const uint8_t *in, size_t len, authmsg_rotate_t *out);

authmsg_status_t authmsg_encode_rotate_ack(uint8_t *out, size_t out_cap, size_t *out_len,
                                           const uint8_t *handle, size_t handle_len,
                                           const uint8_t fp_new[AUTHMSG_FP_BYTES],
                                           uint64_t rotated_at);

authmsg_status_t authmsg_decode_rotate_ack(const uint8_t *in, size_t len,
                                           authmsg_rotate_ack_t *out);

#endif /* MLDSA_AUTHD_AUTHMSG_H */
