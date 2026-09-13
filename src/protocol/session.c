#include "session.h"

#include "aead.h"
#include "secure_mem.h"

#include <sodium.h>
#include <string.h>

#define AD_LABEL_LEN (sizeof(SESSION_AD_LABEL) - 1u) /* no NUL */
#define KEY_BLOCK_LEN (2u * AEAD_KEY_BYTES)
#define SEND_KEY_OFFSET 0u
#define RECV_KEY_OFFSET AEAD_KEY_BYTES

_Static_assert(SESSION_RECORD_TYPE != MSG_TYPE_CLIENT_HELLO &&
                   SESSION_RECORD_TYPE != MSG_TYPE_SERVER_HELLO &&
                   SESSION_RECORD_TYPE != MSG_TYPE_CLIENT_AUTH,
               "records share the message-type namespace with the handshake");
_Static_assert(AD_LABEL_LEN == 20u, "record AD label is 20 bytes");
_Static_assert(SESSION_AD_BYTES == AD_LABEL_LEN + 1u + WIRE_HANDSHAKE_ID_LEN + 1u + SESSION_HEADER_BYTES,
               "AD layout: label || 0x00 || handshake_id || direction || type || seq");
_Static_assert(SESSION_HEADER_BYTES == 1u + 8u, "header is record_type || seq");
_Static_assert(SESSION_OVERHEAD_BYTES == SESSION_HEADER_BYTES + AEAD_TAG_BYTES, "overhead");
_Static_assert(AEAD_NONCE_BYTES == 12u, "IETF ChaCha20-Poly1305 nonce");
_Static_assert(AEAD_KEY_BYTES == KEX_SESSION_KEY_BYTES, "traffic keys are AEAD keys");
_Static_assert(SESSION_REKEY_AFTER_MESSAGES <= SESSION_REJECT_AFTER_MESSAGES &&
                   SESSION_REKEY_AFTER_MS <= SESSION_REJECT_AFTER_MS,
               "soft limits must not exceed hard limits");
_Static_assert(SESSION_REJECT_AFTER_MESSAGES < UINT64_MAX, "seq + 1 can never wrap");

/* The padded record bounds of spec-v2 6.4.1 and the frame table of 6.5.1,
 * pinned to the sizing macros rather than restated as literals elsewhere. */
_Static_assert(SESSION_RECORD_LEN(0, SESSION_PAD_BUCKET_MIN) == 27u, "smallest record: empty, bucket 1");
_Static_assert(SESSION_RECORD_LEN(0, SESSION_PAD_BUCKET_MIN) == SESSION_MIN_RECORD_BYTES, "min record");
_Static_assert(SESSION_RECORD_LEN(0, SESSION_PAD_BUCKET_MAX) == 4121u,
               "largest confirmation record: empty content, bucket 4096 (spec-v2 6.5.1)");
_Static_assert(SESSION_RECORD_LEN(SESSION_MAX_CONTENT_BYTES, SESSION_PAD_BUCKET_MIN) ==
                   SESSION_MAX_RECORD_BYTES,
               "largest content fills the record bound exactly");
_Static_assert(SESSION_RECORD_LEN(SESSION_MAX_CONTENT_BYTES, SESSION_PAD_BUCKET_MAX) ==
                   SESSION_MAX_RECORD_BYTES,
               "...at every bucket: rounding never exceeds the inner bound");
_Static_assert(SESSION_MAX_PLAINTEXT_BYTES % SESSION_PAD_BUCKET_MAX == 0u &&
                   SESSION_MAX_PLAINTEXT_BYTES % 1024u == 0u && SESSION_MAX_PLAINTEXT_BYTES % 256u == 0u &&
                   SESSION_MAX_PLAINTEXT_BYTES % 64u == 0u && SESSION_MAX_PLAINTEXT_BYTES % 16u == 0u,
               "every allowed bucket divides the inner bound");
_Static_assert(SESSION_MAX_CONTENT_BYTES <= UINT16_MAX, "content_len is a 2-byte field");

/* ============================================================================
 * Setup and teardown -- the ONLY place the session allocates or frees.
 * ========================================================================= */

void session_default_limits(session_limits_t *out) {
    if (out == NULL) {
        return;
    }
    out->rekey_after_messages = SESSION_REKEY_AFTER_MESSAGES;
    out->reject_after_messages = SESSION_REJECT_AFTER_MESSAGES;
    out->rekey_after_ms = SESSION_REKEY_AFTER_MS;
    out->reject_after_ms = SESSION_REJECT_AFTER_MS;
    out->pad_bucket = SESSION_PAD_BUCKET_DEFAULT;
}

/* Exactly the set spec-v2 6.4.1 permits: no other value, 0 included, is
 * treated as "use the default". */
static bool pad_bucket_valid(uint32_t bucket) {
    return bucket == 1u || bucket == 16u || bucket == 64u || bucket == 256u || bucket == 1024u ||
           bucket == 4096u;
}

/* Tighten-only: 1 <= soft <= hard <= default, for both counters. The pad
 * bucket is not an ordered limit -- it is validated against its set. */
static bool limits_valid(const session_limits_t *l) {
    return l->rekey_after_messages >= 1u && l->rekey_after_messages <= l->reject_after_messages &&
           l->reject_after_messages <= SESSION_REJECT_AFTER_MESSAGES &&
           l->rekey_after_messages <= SESSION_REKEY_AFTER_MESSAGES && l->rekey_after_ms >= 1u &&
           l->rekey_after_ms <= l->reject_after_ms && l->reject_after_ms <= SESSION_REJECT_AFTER_MS &&
           l->rekey_after_ms <= SESSION_REKEY_AFTER_MS && pad_bucket_valid(l->pad_bucket);
}

session_status_t session_init_from_handshake(session_t *s, handshake_ctx_t *hs,
                                             const session_limits_t *limits,
                                             handshake_clock_fn clock_fn, void *clock_ctx) {
    if (s == NULL || hs == NULL) {
        return SESSION_ERR_INVALID_ARG;
    }
    /* Checked before anything else is read: a session that owns (or may own)
     * a key block is never overwritten. */
    if (s->state != SESSION_STATE_EMPTY || s->keys != NULL) {
        return SESSION_ERR_UNEXPECTED_STATE;
    }

    session_limits_t eff;
    session_default_limits(&eff);
    if (limits != NULL) {
        if (!limits_valid(limits)) {
            return SESSION_ERR_INVALID_ARG;
        }
        eff = *limits;
    }

    /* Everything is read through the handshake's public accessors. */
    handshake_role_t role;
    const uint8_t *c2s = NULL;
    const uint8_t *s2c = NULL;
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    if (handshake_get_state(hs) != HANDSHAKE_STATE_ESTABLISHED ||
        handshake_get_role(hs, &role) != HANDSHAKE_OK ||
        handshake_session_key_c2s(hs, &c2s) != HANDSHAKE_OK ||
        handshake_session_key_s2c(hs, &s2c) != HANDSHAKE_OK ||
        handshake_get_handshake_id(hs, handshake_id) != HANDSHAKE_OK) {
        return SESSION_ERR_UNEXPECTED_STATE;
    }
    if (role == HANDSHAKE_ROLE_RESPONDER && !handshake_is_peer_confirmed(hs)) {
        return SESSION_ERR_UNEXPECTED_STATE; /* defensive: a responder is always confirmed */
    }

    const handshake_clock_fn fn = (clock_fn != NULL) ? clock_fn : handshake_default_clock_ms;
    const uint64_t now = fn(clock_ctx);
    if (now == UINT64_MAX) {
        return SESSION_ERR_EXPIRED; /* unreadable clock: fail closed */
    }

    uint8_t *keys = secure_mem_alloc(KEY_BLOCK_LEN);
    if (keys == NULL) {
        return SESSION_ERR_RESOURCE_EXHAUSTED;
    }

    /* Nothing below can fail: s is written, then hs is consumed. */
    const bool initiator = (role == HANDSHAKE_ROLE_INITIATOR);
    memcpy(keys + SEND_KEY_OFFSET, initiator ? c2s : s2c, AEAD_KEY_BYTES);
    memcpy(keys + RECV_KEY_OFFSET, initiator ? s2c : c2s, AEAD_KEY_BYTES);

    s->role = role;
    s->peer_confirmed = !initiator;
    s->keys = keys;
    s->send_dir = (uint8_t)(initiator ? KEX_DIR_C2S : KEX_DIR_S2C);
    s->recv_dir = (uint8_t)(initiator ? KEX_DIR_S2C : KEX_DIR_C2S);
    memcpy(s->handshake_id, handshake_id, WIRE_HANDSHAKE_ID_LEN);
    s->send_seq = 0;
    s->recv_seq = 0;
    s->start_ms = now;
    s->limits = eff;
    s->clock_fn = fn;
    s->clock_ctx = clock_ctx;
    s->state = SESSION_STATE_ACTIVE;

    /* Exactly-once handoff: the only other copy of the keys goes away, so one
     * handshake can never feed two sessions (nonce reuse). */
    handshake_ctx_wipe(hs);
    return SESSION_OK;
}

void session_wipe(session_t *s) {
    if (s == NULL) {
        return;
    }
    if (s->keys != NULL) {
        secure_mem_free(s->keys, KEY_BLOCK_LEN);
    }
    sodium_memzero(s, sizeof(*s)); /* keys = NULL, state = EMPTY */
}

session_state_t session_get_state(const session_t *s) {
    return (s != NULL) ? s->state : SESSION_STATE_EMPTY;
}

/* BEGIN STEADY-STATE: NO ALLOCATION */

/* Fails closed: an unreadable clock (UINT64_MAX) or one that went backwards
 * reports the maximum age. */
static uint64_t session_age_ms(const session_t *s) {
    const uint64_t now = s->clock_fn(s->clock_ctx);
    if (now == UINT64_MAX || now < s->start_ms) {
        return UINT64_MAX;
    }
    return now - s->start_ms;
}

/* Terminal transition: keys are zeroed now; the block is freed by
 * session_wipe(), so failure paths perform no heap operation either. */
static session_status_t terminate(session_t *s, session_state_t state, session_status_t why) {
    sodium_memzero(s->keys, KEY_BLOCK_LEN);
    s->peer_confirmed = false;
    s->state = state;
    return why;
}

static void store_be64(uint8_t out[8], uint64_t v) {
    for (size_t i = 0; i < 8u; i++) {
        out[i] = (uint8_t)(v >> (56u - 8u * i));
    }
}

static uint64_t load_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8u; i++) {
        v = (v << 8) | in[i];
    }
    return v;
}

static void build_nonce(uint8_t nonce[AEAD_NONCE_BYTES], uint64_t seq) {
    memset(nonce, 0, 4u);
    store_be64(nonce + 4u, seq);
}

static void build_ad(uint8_t ad[SESSION_AD_BYTES], const session_t *s, uint8_t direction,
                     uint64_t seq) {
    size_t off = 0;
    memcpy(ad + off, SESSION_AD_LABEL, AD_LABEL_LEN);
    off += AD_LABEL_LEN;
    ad[off++] = 0x00u;
    memcpy(ad + off, s->handshake_id, WIRE_HANDSHAKE_ID_LEN);
    off += WIRE_HANDSHAKE_ID_LEN;
    ad[off++] = direction;
    ad[off++] = (uint8_t)SESSION_RECORD_TYPE;
    store_be64(ad + off, seq);
}

static void store_be16(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

static uint16_t load_be16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

/* Padded inner length for a content length under a given bucket. */
static size_t inner_len_for(size_t content_len, uint32_t bucket) {
    const size_t b = (size_t)bucket;
    return ((content_len + SESSION_CONTENT_LEN_BYTES + b - 1u) / b) * b;
}

size_t session_sealed_len(const session_t *s, size_t content_len) {
    if (s == NULL || content_len > SESSION_MAX_CONTENT_BYTES || !pad_bucket_valid(s->limits.pad_bucket)) {
        return 0;
    }
    return inner_len_for(content_len, s->limits.pad_bucket) + SESSION_OVERHEAD_BYTES;
}

static bool ranges_overlap(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    if (a_len == 0 || b_len == 0) {
        return false;
    }
    const uintptr_t a0 = (uintptr_t)a;
    const uintptr_t b0 = (uintptr_t)b;
    return a0 < b0 + b_len && b0 < a0 + a_len;
}

session_status_t session_seal(session_t *s, const uint8_t *pt, size_t pt_len, uint8_t *out,
                              size_t out_cap, size_t *out_len) {
    if (s == NULL || out == NULL || out_len == NULL || (pt == NULL && pt_len != 0) ||
        pt_len > SESSION_MAX_CONTENT_BYTES) {
        return SESSION_ERR_INVALID_ARG;
    }
    /* State is checked BEFORE the capacity, because the required capacity now
     * depends on the pad bucket, and a non-ACTIVE session has no meaningful
     * one (an EMPTY session's limits are all zero). "Not ACTIVE" is the
     * honest answer there, not "bad argument". */
    if (s->state != SESSION_STATE_ACTIVE) {
        return SESSION_ERR_UNEXPECTED_STATE;
    }
    if (!pad_bucket_valid(s->limits.pad_bucket)) {
        return SESSION_ERR_INTERNAL; /* unreachable: limits_valid ran at init */
    }
    const size_t inner_len = inner_len_for(pt_len, s->limits.pad_bucket);
    const size_t need = inner_len + SESSION_OVERHEAD_BYTES;
    /* Still before the expiry check and the seq reservation: misuse never
     * terminates a session and never consumes a sequence number. */
    if (out_cap < need || ranges_overlap(pt, pt_len, out, need)) {
        return SESSION_ERR_INVALID_ARG;
    }
    if (session_age_ms(s) >= s->limits.reject_after_ms ||
        s->send_seq >= s->limits.reject_after_messages) {
        return terminate(s, SESSION_STATE_EXPIRED, SESSION_ERR_EXPIRED);
    }

    /* Reserve the seq BEFORE encrypting: no path can ever reuse a nonce. */
    const uint64_t seq = s->send_seq;
    s->send_seq = seq + 1u;

    uint8_t nonce[AEAD_NONCE_BYTES];
    uint8_t ad[SESSION_AD_BYTES];
    build_nonce(nonce, seq);
    build_ad(ad, s, s->send_dir, seq);

    out[0] = (uint8_t)SESSION_RECORD_TYPE;
    store_be64(out + 1u, seq);

    /* The padded inner is assembled IN PLACE, in the caller's buffer, and
     * encrypted from there -- no scratch buffer, so no allocation. This is
     * sound because libsodium's IETF ChaCha20-Poly1305 encrypts with
     * crypto_stream_chacha20_ietf_xor_ic(c, m, ...), a same-index keystream
     * XOR, and writes the tag only after the message: c == m is safe. */
    uint8_t *inner = out + SESSION_HEADER_BYTES;
    store_be16(inner, (uint16_t)pt_len);
    if (pt_len != 0) {
        memcpy(inner + SESSION_CONTENT_LEN_BYTES, pt, pt_len);
    }
    const size_t used = SESSION_CONTENT_LEN_BYTES + pt_len;
    memset(inner + used, 0, inner_len - used); /* padding: zero by definition */

    size_t ct_len = 0;
    if (aead_encrypt(inner, &ct_len, inner, inner_len, ad, sizeof(ad), nonce,
                     s->keys + SEND_KEY_OFFSET) != 0 ||
        ct_len != inner_len + AEAD_TAG_BYTES) {
        sodium_memzero(out, need);
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_INTERNAL);
    }
    *out_len = need;
    return SESSION_OK;
}

session_status_t session_open(session_t *s, const uint8_t *rec, size_t rec_len, uint8_t *pt_out,
                              size_t pt_cap, size_t *pt_len) {
    if (s == NULL || rec == NULL || pt_out == NULL || pt_len == NULL) {
        return SESSION_ERR_INVALID_ARG;
    }
    /* Never writes more than SESSION_MAX_PLAINTEXT_BYTES into pt_out. */
    const size_t writable = (pt_cap < SESSION_MAX_PLAINTEXT_BYTES) ? pt_cap
                                                                   : SESSION_MAX_PLAINTEXT_BYTES;
    if (ranges_overlap(rec, rec_len, pt_out, writable)) {
        return SESSION_ERR_INVALID_ARG;
    }
    if (s->state != SESSION_STATE_ACTIVE) {
        return SESSION_ERR_UNEXPECTED_STATE;
    }
    if (session_age_ms(s) >= s->limits.reject_after_ms) {
        return terminate(s, SESSION_STATE_EXPIRED, SESSION_ERR_EXPIRED);
    }
    /* The minimum is now 27: a record too short to hold even a 2-byte inner
     * is malformed before any AEAD work. */
    if (rec_len < SESSION_MIN_RECORD_BYTES || rec_len > SESSION_MAX_RECORD_BYTES ||
        rec[0] != SESSION_RECORD_TYPE) {
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);
    }
    const size_t body = rec_len - SESSION_OVERHEAD_BYTES; /* the inner length */
    if (pt_cap < body) {
        return SESSION_ERR_INVALID_ARG; /* nothing consumed: retry with a bigger buffer */
    }

    /* Ordering is checked on the (unauthenticated) header BEFORE any AEAD
     * work; a forged header also fails the AEAD, since seq is in both the
     * nonce and the AD. */
    const uint64_t seq = load_be64(rec + 1u);
    if (seq < s->recv_seq) {
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_REPLAY);
    }
    if (seq > s->recv_seq) {
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_OUT_OF_ORDER);
    }
    if (seq >= s->limits.reject_after_messages) {
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_LIMIT);
    }

    uint8_t nonce[AEAD_NONCE_BYTES];
    uint8_t ad[SESSION_AD_BYTES];
    build_nonce(nonce, seq);
    build_ad(ad, s, s->recv_dir, seq);

    size_t got = 0;
    if (aead_decrypt(pt_out, &got, rec + SESSION_HEADER_BYTES, rec_len - SESSION_HEADER_BYTES, ad,
                     sizeof(ad), nonce, s->keys + RECV_KEY_OFFSET) != 0 ||
        got != body) {
        sodium_memzero(pt_out, body);
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_AUTH);
    }

    /* The inner is authentic; now it must be well formed (spec-v2 6.4.1).
     * The receiver requires NOTHING of the inner length beyond its bounds --
     * it does not know, and must not assume, the sender's bucket. */
    const size_t content_len = load_be16(pt_out);
    if (content_len > body - SESSION_CONTENT_LEN_BYTES) {
        sodium_memzero(pt_out, body);
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);
    }
    const size_t pad_len = body - SESSION_CONTENT_LEN_BYTES - content_len;
    if (pad_len != 0 &&
        sodium_is_zero(pt_out + SESSION_CONTENT_LEN_BYTES + content_len, pad_len) != 1) {
        sodium_memzero(pt_out, body);
        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);
    }

    /* Hand back the content at offset 0 and leave nothing behind it: the
     * length prefix and the padding must not linger in the caller's buffer. */
    if (content_len != 0) {
        memmove(pt_out, pt_out + SESSION_CONTENT_LEN_BYTES, content_len);
    }
    sodium_memzero(pt_out + content_len, body - content_len);

    s->recv_seq = seq + 1u;
    if (s->role == HANDSHAKE_ROLE_INITIATOR) {
        /* A valid responder->initiator record: the responder verified
         * ClientAuth and committed its keys. */
        s->peer_confirmed = true;
    }
    *pt_len = content_len;
    return SESSION_OK;
}

bool session_is_peer_confirmed(const session_t *s) {
    return s != NULL && s->state == SESSION_STATE_ACTIVE && s->peer_confirmed;
}

bool session_rekey_due(const session_t *s) {
    if (s == NULL || s->state != SESSION_STATE_ACTIVE) {
        return true;
    }
    return s->send_seq >= s->limits.rekey_after_messages ||
           s->recv_seq >= s->limits.rekey_after_messages ||
           session_age_ms(s) >= s->limits.rekey_after_ms;
}

/* END STEADY-STATE */
