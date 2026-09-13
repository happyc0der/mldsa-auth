#ifndef MLDSA_AUTH_PROTOCOL_SESSION_H
#define MLDSA_AUTH_PROTOCOL_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "handshake.h"

/*
 * Session record layer (spec-v2 §6.4): ChaCha20-Poly1305 IETF records over
 * the per-direction keys of an ESTABLISHED handshake.
 *
 * ============================================================================
 * CONCURRENCY (v2) -- see spec-v2 §6.3.6. session_t is NOT thread-safe; every
 * call on a given session must be serialized by the caller.
 * ============================================================================
 *
 * RECORD FORMAT (normative, spec-v2 §6.4.1)
 *   inner  = content_len (2, big-endian; 0..65534) || content || 0x00 padding
 *   record = record_type (1, 0x04) || seq (8, big-endian) || AEAD(inner) || tag (16)
 *   nonce  = 0x00 0x00 0x00 0x00 || seq (8, big-endian)
 *   ad     = "mldsa-auth/v2/record" || 0x00 || handshake_id (16)
 *            || direction (1) || record_type (1) || seq (8, big-endian)
 *   direction is 0x43 for initiator->responder records, 0x53 for
 *   responder->initiator records.
 *
 * PADDING (spec-v2 §6.4.1). The AEAD plaintext is `inner`, not the content:
 *   padding sits inside the authenticated, encrypted region. The SENDER
 *   rounds the inner up to a bucket chosen at session creation
 *   (session_limits_t.pad_bucket, one of {1, 16, 64, 256, 1024, 4096};
 *   default 256; 1 means no padding), so 2 <= inner_len <= 65536 and a
 *   record is 27..65561 bytes. The RECEIVER knows nothing about the sender's
 *   bucket and requires nothing of inner_len beyond the bounds; after
 *   successful decryption it MUST reject, terminally, an inner shorter than
 *   2 bytes, a content_len larger than inner_len - 2, or ANY nonzero padding
 *   byte (Security Req 4.13).
 *   What padding hides: an observer sees content length only to within the
 *   bucket. What it does not hide: timing, message counts, direction, or the
 *   session's total volume. It is a mitigation for traffic analysis, not a
 *   solution.
 *
 * SEQUENCE POLICY: each direction counts from 0. A received record must carry
 *   EXACTLY the next expected seq -- lower is a replay, higher is a gap -- and
 *   every receive failure is TERMINAL for the whole session.
 *
 * LIFECYCLE AND OWNERSHIP
 *   - A session_t MUST be zero-initialized before first use; all-zero is
 *     SESSION_STATE_EMPTY with no key block.
 *   - session_init_from_handshake() is valid ONLY on an EMPTY session (zero-
 *     initialized, or passed to session_wipe()). Otherwise it returns
 *     SESSION_ERR_UNEXPECTED_STATE and touches neither the session nor the
 *     handshake context, so a live key block is never overwritten or leaked.
 *   - On success it CONSUMES the handshake context (handshake_ctx_wipe), so
 *     one handshake can never feed two sessions (which would reuse nonces).
 *   - FAILED/EXPIRED sessions keep their already-zeroed key block until
 *     session_wipe(). session_wipe() is idempotent and returns the session
 *     to EMPTY.
 *
 * INITIATOR CONFIRMATION: the initiator's session starts unconfirmed and
 *   becomes confirmed on its first successful session_open() -- a valid
 *   record under the responder->initiator key proves the responder verified
 *   ClientAuth and committed its keys. The responder is confirmed from init.
 *   The responder SHOULD send a record (it may be empty) immediately after
 *   init so the initiator is confirmed without waiting for application data.
 *
 * ZERO ALLOCATION: the only session-owned memory is one 64-byte secure_mem key
 *   block, allocated in session_init_from_handshake() and freed in
 *   session_wipe(). seal/open/rekey_due/is_peer_confirmed never allocate,
 *   padding included: nonce and AD are stack buffers, the padded inner is
 *   assembled directly in the caller's output buffer and encrypted in place,
 *   and all record buffers are caller-owned.
 */

#define SESSION_RECORD_TYPE 0x04u
#define SESSION_HEADER_BYTES 9u    /* record_type + seq */
#define SESSION_OVERHEAD_BYTES 25u /* header + AEAD tag */

/* The AEAD plaintext is the padded INNER, so this is the inner's bound. */
#define SESSION_MAX_PLAINTEXT_BYTES 65536u
#define SESSION_CONTENT_LEN_BYTES 2u
/* The largest content whose 2-byte prefix still fits the inner bound. */
#define SESSION_MAX_CONTENT_BYTES (SESSION_MAX_PLAINTEXT_BYTES - SESSION_CONTENT_LEN_BYTES) /* 65534 */
#define SESSION_MAX_RECORD_BYTES (SESSION_MAX_PLAINTEXT_BYTES + SESSION_OVERHEAD_BYTES)     /* 65561 */
/* Smallest possible record: a 2-byte inner (empty content, bucket 1). */
#define SESSION_MIN_RECORD_BYTES (SESSION_CONTENT_LEN_BYTES + SESSION_OVERHEAD_BYTES) /* 27 */

/* Sender-side padding policy. Every allowed bucket is a power of two that
 * divides the inner bound, so rounding up can never exceed it. */
#define SESSION_PAD_BUCKET_MIN 1u /* no padding */
#define SESSION_PAD_BUCKET_DEFAULT 256u
#define SESSION_PAD_BUCKET_MAX 4096u

/* Exact sizes a given (content_len, bucket) produces. Both are pure
 * arithmetic on constants, so callers can size buffers and CTest checks can
 * pin the spec's numbers without calling into the session. */
#define SESSION_INNER_LEN(content_len, bucket) \
    ((((content_len) + SESSION_CONTENT_LEN_BYTES + (bucket) - 1u) / (bucket)) * (bucket))
#define SESSION_RECORD_LEN(content_len, bucket) \
    (SESSION_INNER_LEN((content_len), (bucket)) + SESSION_OVERHEAD_BYTES)

/* The receive-buffer capacity session_open() needs for a record of at most
 * max_record_len bytes. The SENDER picks the pad bucket, so this is the only
 * safe way to size pt_cap -- see the contract on session_open() below. The
 * two standard uses:
 *
 *   session phase:      SESSION_OPEN_CAP_FOR(SESSION_MAX_RECORD_BYTES)  65536
 *   confirmation phase: SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX)          4096
 */
#define SESSION_OPEN_CAP_FOR(max_record_len) ((max_record_len) - SESSION_OVERHEAD_BYTES)

#define SESSION_AD_LABEL "mldsa-auth/v2/record"
#define SESSION_AD_BYTES 47u /* 20 + 1 + 16 + 1 + 1 + 8 */

/* v1 policy limits (spec §6.4). Soft = rekey due; hard = refuse and expire.
 * Conservative policy values, not a derived AEAD bound -- they must be
 * revisited if the maximum plaintext size, AEAD, transport or rekey policy
 * changes. Records are counted per direction. */
#define SESSION_REKEY_AFTER_MESSAGES (UINT64_C(1) << 32)
#define SESSION_REJECT_AFTER_MESSAGES (UINT64_C(1) << 33)
#define SESSION_REKEY_AFTER_MS UINT64_C(3600000)
#define SESSION_REJECT_AFTER_MS UINT64_C(3900000)

typedef enum {
    SESSION_STATE_EMPTY = 0, /* zero-initialized or wiped; owns nothing */
    SESSION_STATE_ACTIVE,
    SESSION_STATE_EXPIRED, /* hard limit reached: a new handshake is required */
    SESSION_STATE_FAILED   /* attack, corruption or bug: terminal */
} session_state_t;

typedef enum {
    SESSION_OK = 0,
    SESSION_ERR_INVALID_ARG,      /* misuse: no state change, no seq consumed */
    SESSION_ERR_UNEXPECTED_STATE, /* not ACTIVE (or, for init, not EMPTY) */
    SESSION_ERR_MALFORMED,        /* terminal */
    SESSION_ERR_REPLAY,           /* seq < expected; terminal */
    SESSION_ERR_OUT_OF_ORDER,     /* seq > expected; terminal */
    SESSION_ERR_AUTH,             /* AEAD verification failed; terminal */
    SESSION_ERR_LIMIT,            /* peer exceeded the hard record limit; terminal */
    SESSION_ERR_EXPIRED,          /* local hard limit reached -> EXPIRED */
    SESSION_ERR_RESOURCE_EXHAUSTED,
    SESSION_ERR_INTERNAL
} session_status_t;

/* Limits can only be TIGHTENED: every value must be >= 1 and <= its default,
 * and each soft value <= its hard value.
 *
 * pad_bucket is the exception in kind, not in strictness: it is a
 * SENDER-SIDE policy, never negotiated, fixed for the life of the session
 * (spec-v2 §6.4.6), and it must be exactly one of {1, 16, 64, 256, 1024,
 * 4096}. Any other value -- including 0 -- is rejected rather than silently
 * replaced by a default. */
typedef struct {
    uint64_t rekey_after_messages;
    uint64_t reject_after_messages;
    uint64_t rekey_after_ms;
    uint64_t reject_after_ms;
    uint32_t pad_bucket;
} session_limits_t;

/* Storage is caller-provided, so the struct is visible -- but EVERY FIELD IS
 * PRIVATE to session.c. */
typedef struct {
    session_state_t state;
    handshake_role_t role;
    bool peer_confirmed;
    uint8_t *keys; /* secure_mem, 64 bytes: [send | recv] */
    uint8_t send_dir;
    uint8_t recv_dir;
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    uint64_t send_seq; /* next seq to send */
    uint64_t recv_seq; /* next seq expected */
    uint64_t start_ms;
    session_limits_t limits;
    handshake_clock_fn clock_fn;
    void *clock_ctx;
} session_t;

void session_default_limits(session_limits_t *out);

/* EMPTY -> ACTIVE. Requires hs in ESTABLISHED (a responder must also be
 * peer-confirmed). limits NULL = defaults; clock_fn NULL = the default
 * monotonic clock. On success hs is consumed (wiped). On ANY failure both s
 * and hs are left exactly as they were. */
session_status_t session_init_from_handshake(session_t *s, handshake_ctx_t *hs,
                                             const session_limits_t *limits,
                                             handshake_clock_fn clock_fn, void *clock_ctx);

/* Frees the key block (if any) and zeroes the whole struct -> EMPTY.
 * Idempotent; safe on an EMPTY session. */
void session_wipe(session_t *s);

/* SESSION_STATE_EMPTY for a NULL session. */
session_state_t session_get_state(const session_t *s);

/* Exact length of the record session_seal() will produce for content_len
 * bytes of content, given this session's pad bucket. Returns 0 if s is NULL
 * or content_len > SESSION_MAX_CONTENT_BYTES, so 0 is an unambiguous
 * "cannot be sealed" (every real record is at least 27 bytes). */
size_t session_sealed_len(const session_t *s, size_t content_len);

/* Encrypts pt (the CONTENT, 0..65534 bytes) into one padded record in out.
 * out_cap must be at least session_sealed_len(s, pt_len), which is larger
 * than pt_len + 25 whenever the bucket pads. pt may be NULL only when
 * pt_len == 0. pt and out must not overlap. Misuse -> INVALID_ARG with no
 * seq consumed. Hard limit reached -> EXPIRED. */
session_status_t session_seal(session_t *s, const uint8_t *pt, size_t pt_len, uint8_t *out,
                              size_t out_cap, size_t *out_len);

/* Authenticates and decrypts one record, then validates the inner plaintext
 * and writes the CONTENT to pt_out, setting *pt_len to the content length.
 *
 * pt_cap must be at least rec_len - 25 (the inner length), because the inner
 * is decrypted into pt_out before it can be parsed; the content is then
 * moved to offset 0 and everything after it is zeroed, so no padding or
 * length prefix is left in the caller's buffer.
 *
 * rec and pt_out must not overlap. Every failure except INVALID_ARG and
 * UNEXPECTED_STATE is terminal -- including an inner whose content_len
 * exceeds the inner, or whose padding is not all zero. On AUTH failure, and
 * on either malformed-inner failure, the plaintext region of pt_out is
 * zeroed.
 *
 * ======================================================================
 * SIZING pt_cap -- THE ONE WAY TO GET THIS WRONG
 *
 *   Size pt_cap from the largest RECORD you are willing to accept:
 *       SESSION_OPEN_CAP_FOR(<that record bound>)
 *   NEVER from the content length you expect.
 *
 *     session phase:      SESSION_OPEN_CAP_FOR(SESSION_MAX_RECORD_BYTES)
 *     confirmation phase: SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX)
 *
 * The pad bucket is the SENDER's policy. The receiver neither controls it
 * nor learns it in advance, so an "empty" message is not a small record: at
 * bucket 4096 an empty content arrives as a 4121-byte record with a
 * 4096-byte inner. A 1-byte buffer for an "empty" message is WRONG, and
 * session_open() will return INVALID_ARG for a record it could otherwise
 * have opened.
 *
 * This is not hypothetical. In V2-6 tests/test_net.c opened the (empty)
 * confirmation record into `uint8_t pt[1]` -- correct under v1, where the
 * confirmation was always 25 bytes, and wrong the moment records could be
 * padded. All three of that file's failures traced to those two buffers.
 * ====================================================================== */
session_status_t session_open(session_t *s, const uint8_t *rec, size_t rec_len, uint8_t *pt_out,
                              size_t pt_cap, size_t *pt_len);

/* Initiator: false until the first successful session_open(). Responder: true
 * while ACTIVE. False in every non-ACTIVE state. */
bool session_is_peer_confirmed(const session_t *s);

/* True when a new handshake should be run: a soft limit has been reached in
 * either direction or by age, or the session is not ACTIVE. */
bool session_rekey_due(const session_t *s);

#endif /* MLDSA_AUTH_PROTOCOL_SESSION_H */
