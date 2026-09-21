#include "handshake.h"

#include "secure_mem.h"

#include <sodium.h>
#include <string.h>
#include <time.h>

/* The crypto layer restates the wire-format bounds rather than depending on
 * the protocol layer; these asserts make sure the two can never drift. */
_Static_assert(KEX_ID_MIN_LEN == WIRE_ID_MIN_LEN, "KDF/wire id minimum must match");
_Static_assert(KEX_ID_MAX_LEN == WIRE_ID_MAX_LEN, "KDF/wire id maximum must match");
_Static_assert(KEX_SESSION_ID_LEN == WIRE_SESSION_ID_LEN, "KDF salt must be the session_id");
_Static_assert(KEX_PUBLIC_KEY_BYTES == WIRE_X25519_PUB_LEN, "X25519 key size mismatch");
_Static_assert(HANDSHAKE_TRANSCRIPT_HASH_BYTES == crypto_hash_sha256_BYTES,
               "transcript digests are SHA-256");
_Static_assert(HANDSHAKE_AUTH_FAILURE_LIMIT >= 1u && HANDSHAKE_AUTH_FAILURE_LIMIT <= 255u,
               "failure_count is a uint8_t");
/* The hybrid halves must agree with the wire format and with each other:
 * the KDF binds a 32-byte transcript digest, and both shared secrets are
 * the same length because HKDF's IKM is their concatenation. */
_Static_assert(KEX_TRANSCRIPT_HASH_BYTES == HANDSHAKE_TRANSCRIPT_HASH_BYTES,
               "the KDF binds the transcript digest this module computes");
_Static_assert(MLKEM_PUBLIC_KEY_BYTES == WIRE_MLKEM_EK_LEN, "ML-KEM ek size vs the wire");
_Static_assert(MLKEM_CIPHERTEXT_BYTES == WIRE_MLKEM_CT_LEN, "ML-KEM ciphertext size vs the wire");
_Static_assert(MLKEM_SHARED_SECRET_BYTES == KEX_SHARED_SECRET_BYTES,
               "both hybrid secrets are the same length");

#define SESSION_KEYS_LEN (2u * KEX_SESSION_KEY_BYTES)
#define C2S_OFFSET 0u
#define S2C_OFFSET KEX_SESSION_KEY_BYTES

/* ============================================================================
 * Pending-handshake ledger
 * ========================================================================= */

/* Fails CLOSED: an unreadable clock reports "the end of time", so every
 * entry reads as expired rather than living forever. */
static uint64_t default_monotonic_ms(void *unused) {
    (void)unused;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return UINT64_MAX;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t handshake_default_clock_ms(void *clock_ctx) {
    return default_monotonic_ms(clock_ctx);
}

/* WHICH capacity limit applies is DERIVED from where the slots are, never
 * stored: a separate "this one is external" flag could disagree with the
 * pointer, and then one of the two would be a lie. */
static size_t cap_limit_for(const handshake_pending_store_t *s,
                            const handshake_pending_entry_t *slots) {
    return (slots == s->entries) ? HANDSHAKE_PENDING_MAX : HANDSHAKE_PENDING_EXT_MAX;
}

/* s->slots != NULL is load-bearing, not tidiness: every accessor dereferences
 * it. It is also what makes a WIPED store fail closed, which the old code got
 * only as a side effect of capacity becoming 0. A zeroed store has
 * slots == NULL != entries, so cap_limit_for would answer the external limit
 * -- which costs nothing, because slots != NULL and capacity >= 1 have already
 * rejected it. */
static bool store_usable(const handshake_pending_store_t *s) {
    return s != NULL && s->slots != NULL && s->clock_fn != NULL && s->capacity >= 1u &&
           s->capacity <= cap_limit_for(s, s->slots) && s->ttl_ms > 0;
}

static uint64_t store_now(const handshake_pending_store_t *s) {
    return s->clock_fn(s->clock_ctx);
}

static bool entry_expired(const handshake_pending_entry_t *e, uint64_t now) {
    return now >= e->deadline_ms;
}

static void free_slot(handshake_pending_entry_t *e) {
    sodium_memzero(e, sizeof(*e)); /* PENDING_SLOT_FREE == 0 */
}

static void tombstone(handshake_pending_entry_t *e, pending_slot_state_t state) {
    e->state = state;
    sodium_memzero(e->th_client_auth, sizeof(e->th_client_auth));
}

/* Scans every in-use slot with sodium_memcmp and no early exit. */
static bool find_slot(const handshake_pending_store_t *s,
                      const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN], size_t *index_out) {
    bool found = false;
    size_t index = 0;
    for (size_t i = 0; i < s->capacity; i++) {
        const handshake_pending_entry_t *e = &s->slots[i];
        const bool in_use = (e->state != PENDING_SLOT_FREE);
        const bool equal = (sodium_memcmp(e->handshake_id, handshake_id, WIRE_HANDSHAKE_ID_LEN) == 0);
        if (in_use && equal && !found) {
            found = true;
            index = i;
        }
    }
    *index_out = index;
    return found;
}

/* One implementation behind both public inits, so their validation cannot
 * drift apart. `slots` selects which limit applies, via cap_limit_for. */
static pending_status_t store_init_common(handshake_pending_store_t *s,
                                          handshake_pending_entry_t *slots,
                                          size_t capacity, uint64_t ttl_ms,
                                          handshake_clock_fn clock_fn, void *clock_ctx) {
    if (s == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    memset(s, 0, sizeof(*s)); /* a rejected init leaves the store unusable */
    /* cap_limit_for reads only the ADDRESS of s->entries, never its contents,
     * so calling it after the memset above is intentional and safe. */
    if (slots == NULL || capacity < 1u || capacity > cap_limit_for(s, slots) || ttl_ms == 0) {
        return PENDING_ERR_INVALID_ARG;
    }
    /* The caller's array may be a REUSED static: stale bytes would read as
     * occupied slots that nothing ever frees. The inline array is zeroed twice,
     * which costs one memset and removes a special case. */
    memset(slots, 0, capacity * sizeof(*slots));
    s->slots = slots;
    s->capacity = capacity;
    s->ttl_ms = ttl_ms;
    s->clock_fn = (clock_fn != NULL) ? clock_fn : default_monotonic_ms;
    s->clock_ctx = clock_ctx;
    return PENDING_OK;
}

pending_status_t handshake_pending_store_init(handshake_pending_store_t *s, size_t capacity,
                                              uint64_t ttl_ms, handshake_clock_fn clock_fn,
                                              void *clock_ctx) {
    if (s == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    return store_init_common(s, s->entries, capacity, ttl_ms, clock_fn, clock_ctx);
}

pending_status_t handshake_pending_store_init_ext(handshake_pending_store_t *s,
                                                  handshake_pending_entry_t *slots,
                                                  size_t capacity, uint64_t ttl_ms,
                                                  handshake_clock_fn clock_fn,
                                                  void *clock_ctx) {
    return store_init_common(s, slots, capacity, ttl_ms, clock_fn, clock_ctx);
}

void handshake_pending_store_wipe(handshake_pending_store_t *s) {
    if (s == NULL) {
        return;
    }
    /* The EXTERNAL array FIRST, through the pointer that is about to be
     * zeroed. Reversing these two statements leaves a caller's ledger full of
     * handshake_ids and transcript digests with nothing pointing at it --
     * sizeof(*s) cannot reach an array this store does not contain. The array
     * is BORROWED, so it is zeroed and never freed. */
    if (s->slots != NULL && s->slots != s->entries) {
        sodium_memzero(s->slots, s->capacity * sizeof(*s->slots));
    }
    sodium_memzero(s, sizeof(*s));
}

void handshake_pending_sweep(handshake_pending_store_t *s) {
    if (!store_usable(s)) {
        return;
    }
    const uint64_t now = store_now(s);
    for (size_t i = 0; i < s->capacity; i++) {
        handshake_pending_entry_t *e = &s->slots[i];
        if (e->state != PENDING_SLOT_FREE && entry_expired(e, now)) {
            free_slot(e);
        }
    }
}

pending_status_t handshake_pending_insert(handshake_pending_store_t *s,
                                          const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                          const uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES]) {
    if (!store_usable(s) || handshake_id == NULL || th_client_auth == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    handshake_pending_sweep(s);

    size_t index;
    if (find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_INVALID_ARG; /* duplicate handshake_id: fail closed */
    }

    const uint64_t now = store_now(s);
    /* Saturating add: an overflowed deadline would otherwise wrap to a small
     * value and the entry would never expire (fail open). */
    const uint64_t deadline = (now > UINT64_MAX - s->ttl_ms) ? UINT64_MAX : now + s->ttl_ms;

    for (size_t i = 0; i < s->capacity; i++) {
        handshake_pending_entry_t *e = &s->slots[i];
        if (e->state == PENDING_SLOT_FREE) {
            e->state = PENDING_SLOT_ACTIVE;
            memcpy(e->handshake_id, handshake_id, WIRE_HANDSHAKE_ID_LEN);
            memcpy(e->th_client_auth, th_client_auth, HANDSHAKE_TRANSCRIPT_HASH_BYTES);
            e->deadline_ms = deadline;
            e->failure_count = 0;
            return PENDING_OK;
        }
    }
    /* Only expired entries were swept; live ones are never evicted. */
    return PENDING_ERR_FULL;
}

pending_status_t handshake_pending_get_digest(handshake_pending_store_t *s,
                                              const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                              uint8_t th_client_auth_out[HANDSHAKE_TRANSCRIPT_HASH_BYTES]) {
    if (th_client_auth_out == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    sodium_memzero(th_client_auth_out, HANDSHAKE_TRANSCRIPT_HASH_BYTES);
    if (!store_usable(s) || handshake_id == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }

    size_t index;
    if (!find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_NOT_FOUND;
    }
    handshake_pending_entry_t *e = &s->slots[index];
    if (entry_expired(e, store_now(s))) { /* expiry before state, always */
        free_slot(e);
        return PENDING_ERR_EXPIRED;
    }
    if (e->state == PENDING_SLOT_CONSUMED) {
        return PENDING_ERR_CONSUMED;
    }
    if (e->state == PENDING_SLOT_AUTH_LIMITED) {
        return PENDING_ERR_AUTH_LIMIT;
    }
    memcpy(th_client_auth_out, e->th_client_auth, HANDSHAKE_TRANSCRIPT_HASH_BYTES);
    return PENDING_OK;
}

pending_status_t handshake_pending_inspect(const handshake_pending_store_t *s,
                                           const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                           pending_slot_state_t *state_out,
                                           uint8_t *failure_count_out) {
    if (state_out == NULL || failure_count_out == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    *state_out = PENDING_SLOT_FREE;
    *failure_count_out = 0;
    if (!store_usable(s) || handshake_id == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }

    size_t index;
    if (!find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_NOT_FOUND;
    }
    const handshake_pending_entry_t *e = &s->slots[index];
    *failure_count_out = e->failure_count;
    /* Report LOGICAL expiry without evicting: never describe an expired
     * entry as live, and never mutate anything. */
    if (entry_expired(e, store_now(s))) {
        *state_out = PENDING_SLOT_EXPIRED;
        return PENDING_ERR_EXPIRED;
    }
    *state_out = e->state;
    if (e->state == PENDING_SLOT_CONSUMED) {
        return PENDING_ERR_CONSUMED;
    }
    if (e->state == PENDING_SLOT_AUTH_LIMITED) {
        return PENDING_ERR_AUTH_LIMIT;
    }
    return PENDING_OK;
}

pending_status_t handshake_pending_record_failure(handshake_pending_store_t *s,
                                                  const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]) {
    if (!store_usable(s) || handshake_id == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    size_t index;
    if (!find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_NOT_FOUND;
    }
    handshake_pending_entry_t *e = &s->slots[index];
    if (entry_expired(e, store_now(s))) {
        free_slot(e);
        return PENDING_ERR_EXPIRED;
    }
    if (e->state == PENDING_SLOT_CONSUMED) {
        return PENDING_ERR_CONSUMED;
    }
    if (e->state == PENDING_SLOT_AUTH_LIMITED) {
        return PENDING_ERR_AUTH_LIMIT;
    }
    /* The deadline is deliberately left alone: a failing peer can never
     * keep an entry alive. */
    e->failure_count++;
    if ((unsigned)e->failure_count >= HANDSHAKE_AUTH_FAILURE_LIMIT) {
        tombstone(e, PENDING_SLOT_AUTH_LIMITED);
        return PENDING_ERR_AUTH_LIMIT;
    }
    return PENDING_OK;
}

pending_status_t handshake_pending_consume_success(handshake_pending_store_t *s,
                                                   const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]) {
    if (!store_usable(s) || handshake_id == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    size_t index;
    if (!find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_NOT_FOUND;
    }
    handshake_pending_entry_t *e = &s->slots[index];
    if (entry_expired(e, store_now(s))) { /* re-checked: may have expired since get_digest */
        free_slot(e);
        return PENDING_ERR_EXPIRED;
    }
    if (e->state == PENDING_SLOT_CONSUMED) {
        return PENDING_ERR_CONSUMED;
    }
    if (e->state == PENDING_SLOT_AUTH_LIMITED) {
        return PENDING_ERR_AUTH_LIMIT;
    }
    tombstone(e, PENDING_SLOT_CONSUMED);
    return PENDING_OK;
}

pending_status_t handshake_pending_cancel(handshake_pending_store_t *s,
                                          const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]) {
    if (!store_usable(s) || handshake_id == NULL) {
        return PENDING_ERR_INVALID_ARG;
    }
    size_t index;
    if (!find_slot(s, handshake_id, &index)) {
        return PENDING_ERR_NOT_FOUND;
    }
    handshake_pending_entry_t *e = &s->slots[index];
    /* Uniform expiry rule first: an expired entry of ANY state is evicted
     * now, so it never lingers occupying capacity until a later sweep. */
    if (entry_expired(e, store_now(s))) {
        free_slot(e);
        return PENDING_ERR_EXPIRED;
    }
    /* An unexpired tombstone is never erased by cancel. */
    if (e->state == PENDING_SLOT_CONSUMED) {
        return PENDING_ERR_CONSUMED;
    }
    if (e->state == PENDING_SLOT_AUTH_LIMITED) {
        return PENDING_ERR_AUTH_LIMIT;
    }
    free_slot(e);
    return PENDING_OK;
}

size_t handshake_pending_active_count(const handshake_pending_store_t *s) {
    if (!store_usable(s)) {
        return 0;
    }
    const uint64_t now = store_now(s);
    size_t n = 0;
    for (size_t i = 0; i < s->capacity; i++) {
        const handshake_pending_entry_t *e = &s->slots[i];
        if (e->state == PENDING_SLOT_ACTIVE && !entry_expired(e, now)) {
            n++;
        }
    }
    return n;
}

/* ============================================================================
 * Context helpers
 * ========================================================================= */

static bool id_len_valid(size_t id_len) {
    return id_len >= WIRE_ID_MIN_LEN && id_len <= WIRE_ID_MAX_LEN;
}

/* ctx NULL -> INVALID_ARG; wrong role or state -> UNEXPECTED_STATE. Checked
 * before any other argument so a wrong-state call is always reported as
 * such, and always leaves the state unchanged. */
static handshake_status_t check_call(const handshake_ctx_t *ctx, handshake_role_t role,
                                     handshake_state_t state) {
    if (ctx == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    if (ctx->role != role || ctx->state != state) {
        return HANDSHAKE_ERR_UNEXPECTED_STATE;
    }
    return HANDSHAKE_OK;
}

/* Terminal transition. Wipes every secret and all transcript material
 * before returning. Does NOT touch the ledger: cancellation is explicit
 * at the specific call sites that require it (spec §6.3.5 / ledger
 * consequences), and must happen before this wipes handshake_id. */
static handshake_status_t fail_ctx(handshake_ctx_t *ctx, handshake_status_t why) {
    kex_keypair_free(&ctx->eph);
    /* Both hybrid secrets go here too: the initiator's decapsulation key
     * and the responder's retained KEM secret (Security Req 4.12). */
    mlkem_keypair_free(&ctx->kem);
    if (ctx->ss_kem != NULL) {
        secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);
        ctx->ss_kem = NULL;
    }
    if (ctx->session_keys != NULL) {
        secure_mem_wipe(ctx->session_keys, SESSION_KEYS_LEN);
    }
    ctx->keys_committed = false;
    sodium_memzero(ctx->ch_bytes, sizeof(ctx->ch_bytes));
    ctx->ch_len = 0;
    sodium_memzero(ctx->th_client_auth, sizeof(ctx->th_client_auth));
    sodium_memzero(ctx->handshake_id, sizeof(ctx->handshake_id));
    sodium_memzero(ctx->peer_eph_pub, sizeof(ctx->peer_eph_pub));
    sodium_memzero(ctx->peer_mlkem_ct, sizeof(ctx->peer_mlkem_ct));
    ctx->state = HANDSHAKE_STATE_FAILED;
    return why;
}

static handshake_status_t map_pending_failure(pending_status_t p) {
    switch (p) {
    case PENDING_ERR_EXPIRED:
    case PENDING_ERR_NOT_FOUND:
        /* This context inserted its own entry, and every cancel path fails
         * or wipes the context -- so an absent entry means an expiry sweep
         * evicted it. */
        return HANDSHAKE_ERR_EXPIRED;
    case PENDING_ERR_CONSUMED:
        return HANDSHAKE_ERR_REPLAY;
    case PENDING_ERR_AUTH_LIMIT:
        return HANDSHAKE_ERR_AUTH_FAILURE_LIMIT;
    default:
        return HANDSHAKE_ERR_INTERNAL;
    }
}

/* c2s then s2c, from BOTH hybrid secrets and the transcript digest
 * (spec-v2 §6.3.7). a_id is ALWAYS the initiator, b_id ALWAYS the
 * responder, so both peers build byte-identical KDF info. */
static int derive_traffic_keys(uint8_t out[SESSION_KEYS_LEN],
                               const uint8_t ss_x[KEX_SHARED_SECRET_BYTES],
                               const uint8_t ss_k[KEX_SHARED_SECRET_BYTES],
                               const uint8_t session_id[WIRE_SESSION_ID_LEN],
                               const uint8_t *initiator_id, size_t initiator_id_len,
                               const uint8_t *responder_id, size_t responder_id_len,
                               const uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES]) {
    if (kex_derive_session_key_v2(out + C2S_OFFSET, ss_x, ss_k, session_id, WIRE_SESSION_ID_LEN,
                                  initiator_id, initiator_id_len, responder_id, responder_id_len,
                                  th_client_auth, HANDSHAKE_DIR_C2S) != 0) {
        return -1;
    }
    if (kex_derive_session_key_v2(out + S2C_OFFSET, ss_x, ss_k, session_id, WIRE_SESSION_ID_LEN,
                                  initiator_id, initiator_id_len, responder_id, responder_id_len,
                                  th_client_auth, HANDSHAKE_DIR_S2C) != 0) {
        return -1;
    }
    return 0;
}

/* The ONE place a peer's pinned key is resolved, for both roles and both
 * initialization forms.
 *
 * The keystore path is bit-identical to the code this replaced:
 * keystore_lookup() sets *out = NULL on EVERY non-KEYSTORE_OK status, so
 * "NULL" and "!= KEYSTORE_OK" are the same condition, not an approximation.
 *
 * The ctx->keystore == NULL guard is not decorative. Without it a context
 * carrying neither resolver would dereference NULL inside keystore_lookup,
 * turning a mutation that forgets to set lookup_fn into a segfault instead of
 * a named check failure. */
static const uint8_t *resolve_peer_pk(const handshake_ctx_t *ctx,
                                      const uint8_t *id, size_t id_len) {
    if (ctx->lookup_fn != NULL) {
        return ctx->lookup_fn(ctx->lookup_ctx, id, id_len);
    }
    if (ctx->keystore == NULL) {
        return NULL;
    }
    const uint8_t *pk = NULL;
    if (keystore_lookup(ctx->keystore, id, id_len, &pk) != KEYSTORE_OK) {
        return NULL;
    }
    return pk;
}

static handshake_status_t init_common(handshake_ctx_t *ctx, handshake_role_t role,
                                      const uint8_t *local_id, size_t local_id_len,
                                      const mldsa_keypair_t *local_keypair,
                                      const keystore_t *keystore,
                                      handshake_lookup_fn lookup_fn, void *lookup_ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = HANDSHAKE_STATE_FAILED; /* unusable until fully initialized */

    uint8_t *keys = secure_mem_alloc(SESSION_KEYS_LEN);
    if (keys == NULL) {
        return HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
    }
    secure_mem_wipe(keys, SESSION_KEYS_LEN); /* sodium_malloc does not zero */

    ctx->session_keys = keys;
    ctx->role = role;
    memcpy(ctx->local_id, local_id, local_id_len);
    ctx->local_id_len = (uint8_t)local_id_len;
    ctx->local_keypair = local_keypair;
    ctx->keystore = keystore;
    ctx->lookup_fn = lookup_fn;
    ctx->lookup_ctx = lookup_ctx;
    ctx->state = HANDSHAKE_STATE_NEW;
    return HANDSHAKE_OK;
}

/* ============================================================================
 * Initialization and teardown
 * ========================================================================= */

handshake_status_t handshake_initiator_init(handshake_ctx_t *ctx,
                                            const uint8_t *local_id, size_t local_id_len,
                                            const mldsa_keypair_t *local_keypair,
                                            const keystore_t *keystore,
                                            const uint8_t *peer_id, size_t peer_id_len) {
    if (ctx == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    if (local_id == NULL || !id_len_valid(local_id_len) || local_keypair == NULL ||
        local_keypair->secret_key == NULL || keystore == NULL || peer_id == NULL ||
        !id_len_valid(peer_id_len)) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->state = HANDSHAKE_STATE_FAILED;
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    handshake_status_t st = init_common(ctx, HANDSHAKE_ROLE_INITIATOR, local_id, local_id_len,
                                        local_keypair, keystore, NULL, NULL);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    memcpy(ctx->peer_id, peer_id, peer_id_len);
    ctx->peer_id_len = (uint8_t)peer_id_len;
    return HANDSHAKE_OK;
}

/* Both responder entry points go through here so their validation cannot
 * drift apart -- the shape V4-9b's authd_config_check_paths() established:
 * one validator, two entry points. */
static handshake_status_t responder_init_impl(handshake_ctx_t *ctx,
                                              const uint8_t *local_id, size_t local_id_len,
                                              const mldsa_keypair_t *local_keypair,
                                              const keystore_t *keystore,
                                              handshake_lookup_fn lookup_fn, void *lookup_ctx,
                                              handshake_pending_store_t *pending) {
    if (ctx == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    /* EXACTLY one resolver. Neither is API misuse, and so is both: a context
     * carrying two answers has no defined precedence, and inventing one here
     * would make which resolver wins a property nobody stated. */
    const bool one_resolver = ((keystore != NULL) != (lookup_fn != NULL));
    if (local_id == NULL || !id_len_valid(local_id_len) || local_keypair == NULL ||
        local_keypair->secret_key == NULL || !one_resolver || !store_usable(pending)) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->state = HANDSHAKE_STATE_FAILED;
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    handshake_status_t st = init_common(ctx, HANDSHAKE_ROLE_RESPONDER, local_id, local_id_len,
                                        local_keypair, keystore, lookup_fn, lookup_ctx);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    ctx->pending = pending;
    return HANDSHAKE_OK;
}

handshake_status_t handshake_responder_init(handshake_ctx_t *ctx,
                                            const uint8_t *local_id, size_t local_id_len,
                                            const mldsa_keypair_t *local_keypair,
                                            const keystore_t *keystore,
                                            handshake_pending_store_t *pending) {
    return responder_init_impl(ctx, local_id, local_id_len, local_keypair, keystore,
                               NULL, NULL, pending);
}

handshake_status_t handshake_responder_init_ext(handshake_ctx_t *ctx,
                                                const uint8_t *local_id, size_t local_id_len,
                                                const mldsa_keypair_t *local_keypair,
                                                handshake_lookup_fn lookup_fn, void *lookup_ctx,
                                                handshake_pending_store_t *pending) {
    return responder_init_impl(ctx, local_id, local_id_len, local_keypair, NULL,
                               lookup_fn, lookup_ctx, pending);
}

void handshake_ctx_wipe(handshake_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    /* Explicit cancellation: an abandoned responder handshake stops holding
     * ledger capacity now. In any other state there is no live entry this
     * context owns (none yet, or already consumed/tombstoned). */
    if (ctx->role == HANDSHAKE_ROLE_RESPONDER && ctx->state == HANDSHAKE_STATE_SERVER_HELLO_CREATED &&
        ctx->pending != NULL) {
        (void)handshake_pending_cancel(ctx->pending, ctx->handshake_id);
    }
    kex_keypair_free(&ctx->eph);
    mlkem_keypair_free(&ctx->kem);
    if (ctx->ss_kem != NULL) {
        secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);
        ctx->ss_kem = NULL;
    }
    if (ctx->session_keys != NULL) {
        secure_mem_free(ctx->session_keys, SESSION_KEYS_LEN);
    }
    sodium_memzero(ctx, sizeof(*ctx));
    ctx->state = HANDSHAKE_STATE_FAILED; /* role is 0: every call is rejected */
}

handshake_state_t handshake_get_state(const handshake_ctx_t *ctx) {
    return (ctx != NULL) ? ctx->state : HANDSHAKE_STATE_FAILED;
}

handshake_status_t handshake_get_role(const handshake_ctx_t *ctx, handshake_role_t *role_out) {
    if (ctx == NULL || role_out == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    if (ctx->role != HANDSHAKE_ROLE_INITIATOR && ctx->role != HANDSHAKE_ROLE_RESPONDER) {
        return HANDSHAKE_ERR_UNEXPECTED_STATE; /* failed init, or wiped */
    }
    *role_out = ctx->role;
    return HANDSHAKE_OK;
}

handshake_status_t handshake_get_handshake_id(const handshake_ctx_t *ctx,
                                              uint8_t handshake_id_out[WIRE_HANDSHAKE_ID_LEN]) {
    if (handshake_id_out == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    memset(handshake_id_out, 0, WIRE_HANDSHAKE_ID_LEN);
    if (ctx == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    if (ctx->state != HANDSHAKE_STATE_ESTABLISHED || !ctx->keys_committed) {
        return HANDSHAKE_ERR_UNEXPECTED_STATE;
    }
    memcpy(handshake_id_out, ctx->handshake_id, WIRE_HANDSHAKE_ID_LEN);
    return HANDSHAKE_OK;
}

/* ============================================================================
 * Initiator
 * ========================================================================= */

handshake_status_t handshake_initiator_create_client_hello(handshake_ctx_t *ctx, uint8_t *out,
                                                           size_t out_cap, size_t *out_len) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_INITIATOR, HANDSHAKE_STATE_NEW);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (out == NULL || out_len == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    client_hello_t ch;
    size_t ch_len = 0;
    memset(&ch, 0, sizeof(ch));

    if (kex_keypair_generate(&ctx->eph) != 0) {
        return fail_ctx(ctx, HANDSHAKE_ERR_INTERNAL);
    }
    /* The post-quantum half: a fresh ML-KEM-768 keypair per handshake. The
     * decapsulation key stays in secure_mem until finish(). */
    if (mlkem_keypair_generate(&ctx->kem) != 0) {
        return fail_ctx(ctx, HANDSHAKE_ERR_INTERNAL);
    }

    memcpy(ch.id, ctx->local_id, ctx->local_id_len);
    ch.id_len = ctx->local_id_len;
    memcpy(ch.ephemeral_pub, ctx->eph.public_key, KEX_PUBLIC_KEY_BYTES);
    memcpy(ch.mlkem_ek, ctx->kem.public_key, WIRE_MLKEM_EK_LEN);
    randombytes_buf(ch.session_id, WIRE_SESSION_ID_LEN);
    randombytes_buf(ch.nonce, WIRE_NONCE_LEN);

    /* Encoded straight into the context: these exact bytes are what the
     * transcripts will later hash. */
    if (encode_client_hello(&ch, ctx->ch_bytes, sizeof(ctx->ch_bytes), &ch_len) != 0) {
        sodium_memzero(&ch, sizeof(ch));
        return fail_ctx(ctx, HANDSHAKE_ERR_INTERNAL);
    }
    if (out_cap < ch_len) {
        /* API misuse: roll back every side effect, BOTH keypairs included;
         * state stays NEW and the call can be retried. */
        kex_keypair_free(&ctx->eph);
        mlkem_keypair_free(&ctx->kem);
        sodium_memzero(ctx->ch_bytes, sizeof(ctx->ch_bytes));
        sodium_memzero(&ch, sizeof(ch));
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    memcpy(ctx->session_id, ch.session_id, WIRE_SESSION_ID_LEN);
    ctx->ch_len = ch_len;
    memcpy(out, ctx->ch_bytes, ch_len);
    *out_len = ch_len;
    sodium_memzero(&ch, sizeof(ch));
    ctx->state = HANDSHAKE_STATE_CLIENT_HELLO_CREATED;
    return HANDSHAKE_OK;
}

handshake_status_t handshake_initiator_verify_server_hello(handshake_ctx_t *ctx,
                                                           const uint8_t *sh, size_t sh_len) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_INITIATOR,
                                       HANDSHAKE_STATE_CLIENT_HELLO_CREATED);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (sh == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    server_hello_t msg;
    size_t consumed = 0;
    size_t unsigned_len = 0;
    uint8_t th_server_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES];
    uint8_t *probe = NULL;
    int kex_rc = -1;
    handshake_status_t result = HANDSHAKE_ERR_INTERNAL;
    memset(&msg, 0, sizeof(msg));
    memset(th_server_auth, 0, sizeof(th_server_auth));

    /* 2. Strict decode: exact type 0x02, length bounds, full consumption. */
    if (decode_server_hello(sh, sh_len, &msg, &consumed) != 0) {
        result = HANDSHAKE_ERR_MALFORMED;
        goto fail;
    }

    /* 3. The responder must be the peer we dialed (identity binding). */
    if (msg.id_len != ctx->peer_id_len ||
        sodium_memcmp(msg.id, ctx->peer_id, ctx->peer_id_len) != 0) {
        result = HANDSHAKE_ERR_PEER_IDENTITY_MISMATCH;
        goto fail;
    }

    /* 4. Pinned key for that identity. */
    ctx->peer_pk = resolve_peer_pk(ctx, msg.id, msg.id_len);
    if (ctx->peer_pk == NULL) {
        result = HANDSHAKE_ERR_UNKNOWN_IDENTITY;
        goto fail;
    }

    /* 5. Session-ID echo, BEFORE any ML-DSA work. */
    if (sodium_memcmp(msg.session_id_echo, ctx->session_id, WIRE_SESSION_ID_LEN) != 0) {
        result = HANDSHAKE_ERR_SESSION_ID_MISMATCH;
        goto fail;
    }

    /* 6. TH_server_auth over the ORIGINAL received bytes: SH_unsigned is
     *    sliced out of `sh`, never re-encoded from the decoded struct. */
    unsigned_len = transcript_server_hello_unsigned_len(msg.id_len);
    if (unsigned_len == 0 || unsigned_len >= sh_len) {
        goto fail; /* unreachable after a strict decode */
    }
    if (transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len, sh, unsigned_len,
                                    th_server_auth) != 0) {
        goto fail;
    }

    /* 7. sig_B. */
    if (mldsa_verify(th_server_auth, sizeof(th_server_auth), msg.sig, msg.sig_len,
                     ctx->peer_pk) != 0) {
        result = HANDSHAKE_ERR_SIGNATURE;
        goto fail;
    }

    /* 8. VALIDATION PROBE ONLY -- not key setup. Rejects an invalid or
     *    low-order peer key before we sign a ClientAuth over a transcript
     *    containing it. The result is wiped and freed immediately; nothing
     *    derived from it is kept, and no traffic key exists yet. */
    probe = secure_mem_alloc(KEX_SHARED_SECRET_BYTES);
    if (probe == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto fail;
    }
    kex_rc = kex_shared_secret(probe, &ctx->eph, msg.ephemeral_pub);
    secure_mem_free(probe, KEX_SHARED_SECRET_BYTES);
    probe = NULL;
    if (kex_rc != 0) {
        result = HANDSHAKE_ERR_KEX;
        goto fail;
    }

    /* 9. Retain the authenticated peer PUBLIC values and the transcript
     *    digests; all computed from the exact wire bytes. The KEM
     *    ciphertext is public and is decapsulated at finish (spec-v2
     *    §6.3): decapsulation cannot validate it, so doing it earlier
     *    would prove nothing. */
    memcpy(ctx->peer_eph_pub, msg.ephemeral_pub, KEX_PUBLIC_KEY_BYTES);
    memcpy(ctx->peer_mlkem_ct, msg.mlkem_ct, WIRE_MLKEM_CT_LEN);
    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh, sh_len,
                                    ctx->th_client_auth) != 0 ||
        transcript_handshake_id(ctx->ch_bytes, ctx->ch_len, sh, sh_len, ctx->handshake_id) != 0) {
        goto fail;
    }

    /* 10. The ClientHello bytes are no longer needed. No traffic keys. */
    sodium_memzero(ctx->ch_bytes, sizeof(ctx->ch_bytes));
    ctx->ch_len = 0;
    sodium_memzero(th_server_auth, sizeof(th_server_auth));
    sodium_memzero(&msg, sizeof(msg));
    ctx->state = HANDSHAKE_STATE_SERVER_HELLO_VERIFIED;
    return HANDSHAKE_OK;

fail:
    if (probe != NULL) {
        secure_mem_free(probe, KEX_SHARED_SECRET_BYTES);
    }
    sodium_memzero(th_server_auth, sizeof(th_server_auth));
    sodium_memzero(&msg, sizeof(msg));
    return fail_ctx(ctx, result);
}

handshake_status_t handshake_initiator_create_client_auth(handshake_ctx_t *ctx, uint8_t *out,
                                                          size_t out_cap, size_t *out_len) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_INITIATOR,
                                       HANDSHAKE_STATE_SERVER_HELLO_VERIFIED);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (out == NULL || out_len == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    client_auth_t ca;
    uint8_t buf[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t sig_len = 0;
    size_t len = 0;
    memset(&ca, 0, sizeof(ca));

    memcpy(ca.handshake_id, ctx->handshake_id, WIRE_HANDSHAKE_ID_LEN);
    if (mldsa_sign(ca.sig, &sig_len, ctx->th_client_auth, sizeof(ctx->th_client_auth),
                   ctx->local_keypair) != 0 ||
        sig_len == 0 || sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        sodium_memzero(&ca, sizeof(ca));
        return fail_ctx(ctx, HANDSHAKE_ERR_INTERNAL);
    }
    ca.sig_len = (uint16_t)sig_len;

    if (encode_client_auth(&ca, buf, sizeof(buf), &len) != 0) {
        sodium_memzero(&ca, sizeof(ca));
        return fail_ctx(ctx, HANDSHAKE_ERR_INTERNAL);
    }
    if (out_cap < len) {
        /* API misuse: nothing in the context changed; state unchanged. */
        sodium_memzero(&ca, sizeof(ca));
        sodium_memzero(buf, sizeof(buf));
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    memcpy(out, buf, len);
    *out_len = len;
    sodium_memzero(&ca, sizeof(ca));
    sodium_memzero(buf, sizeof(buf));
    ctx->state = HANDSHAKE_STATE_CLIENT_AUTH_CREATED;
    return HANDSHAKE_OK;
}

handshake_status_t handshake_initiator_finish(handshake_ctx_t *ctx) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_INITIATOR,
                                       HANDSHAKE_STATE_CLIENT_AUTH_CREATED);
    if (st != HANDSHAKE_OK) {
        return st;
    }

    uint8_t *shared = NULL;
    uint8_t *ss_kem = NULL;
    uint8_t *keys = NULL;
    handshake_status_t result = HANDSHAKE_ERR_INTERNAL;

    /* 1. RECOMPUTE the X25519 shared secret: nothing was carried over from
     *    the validation probe in verify_server_hello. */
    shared = secure_mem_alloc(KEX_SHARED_SECRET_BYTES);
    if (shared == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto fail;
    }
    if (kex_shared_secret(shared, &ctx->eph, ctx->peer_eph_pub) != 0) {
        result = HANDSHAKE_ERR_KEX; /* defensive: the key was validated earlier */
        goto fail;
    }

    /* 2. Decapsulate for the post-quantum secret. This CANNOT detect a
     *    tampered ciphertext -- that is implicit rejection, which returns
     *    success and a different secret (Security Req 4.11) -- so a
     *    nonzero return here means only a missing or corrupt
     *    decapsulation key, which is a local defect. */
    ss_kem = secure_mem_alloc(MLKEM_SHARED_SECRET_BYTES);
    if (ss_kem == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto fail;
    }
    if (mlkem_decaps(ss_kem, ctx->peer_mlkem_ct, &ctx->kem) != 0) {
        result = HANDSHAKE_ERR_INTERNAL;
        goto fail;
    }

    /* 3. Derive c2s/s2c into temporaries (initiator = A, responder = B),
     *    binding both secrets and the transcript digest. */
    keys = secure_mem_alloc(SESSION_KEYS_LEN);
    if (keys == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto fail;
    }
    if (derive_traffic_keys(keys, shared, ss_kem, ctx->session_id, ctx->local_id, ctx->local_id_len,
                            ctx->peer_id, ctx->peer_id_len, ctx->th_client_auth) != 0) {
        goto fail;
    }

    /* Commit (OPTIMISTIC -- see handshake.h). */
    memcpy(ctx->session_keys, keys, SESSION_KEYS_LEN);
    ctx->keys_committed = true;

    /* 4. Wipe the temporary secrets, both ephemeral keys and
     *    TH_client_auth. handshake_id is KEPT: it is public (ClientAuth
     *    carries it in the clear) and the session layer binds it into
     *    every record's AD. */
    secure_mem_free(shared, KEX_SHARED_SECRET_BYTES);
    secure_mem_free(ss_kem, MLKEM_SHARED_SECRET_BYTES);
    secure_mem_free(keys, SESSION_KEYS_LEN);
    kex_keypair_free(&ctx->eph);
    mlkem_keypair_free(&ctx->kem);
    sodium_memzero(ctx->th_client_auth, sizeof(ctx->th_client_auth));
    sodium_memzero(ctx->peer_eph_pub, sizeof(ctx->peer_eph_pub));
    sodium_memzero(ctx->peer_mlkem_ct, sizeof(ctx->peer_mlkem_ct));
    ctx->state = HANDSHAKE_STATE_ESTABLISHED;
    return HANDSHAKE_OK;

fail:
    if (shared != NULL) {
        secure_mem_free(shared, KEX_SHARED_SECRET_BYTES);
    }
    if (ss_kem != NULL) {
        secure_mem_free(ss_kem, MLKEM_SHARED_SECRET_BYTES);
    }
    if (keys != NULL) {
        secure_mem_free(keys, SESSION_KEYS_LEN);
    }
    return fail_ctx(ctx, result);
}

/* ============================================================================
 * Responder
 * ========================================================================= */

handshake_status_t handshake_responder_accept_client_hello(handshake_ctx_t *ctx,
                                                           const uint8_t *ch, size_t ch_len) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_RESPONDER, HANDSHAKE_STATE_NEW);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (ch == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    client_hello_t msg;
    size_t consumed = 0;
    handshake_status_t result = HANDSHAKE_ERR_INTERNAL;
    memset(&msg, 0, sizeof(msg));

    if (decode_client_hello(ch, ch_len, &msg, &consumed) != 0 || ch_len > sizeof(ctx->ch_bytes)) {
        result = HANDSHAKE_ERR_MALFORMED;
        goto fail;
    }

    /* Unknown initiator: fail closed WITHOUT creating any pending entry. */
    ctx->peer_pk = resolve_peer_pk(ctx, msg.id, msg.id_len);
    if (ctx->peer_pk == NULL) {
        result = HANDSHAKE_ERR_UNKNOWN_IDENTITY;
        goto fail;
    }

    memcpy(ctx->peer_id, msg.id, msg.id_len);
    ctx->peer_id_len = msg.id_len;
    memcpy(ctx->session_id, msg.session_id, WIRE_SESSION_ID_LEN);
    /* Unauthenticated until sig_A verifies; not used before then. */
    memcpy(ctx->peer_eph_pub, msg.ephemeral_pub, KEX_PUBLIC_KEY_BYTES);
    memcpy(ctx->ch_bytes, ch, ch_len); /* exact wire bytes, held until ServerHello */
    ctx->ch_len = ch_len;

    sodium_memzero(&msg, sizeof(msg));
    ctx->state = HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED;
    return HANDSHAKE_OK;

fail:
    sodium_memzero(&msg, sizeof(msg));
    return fail_ctx(ctx, result);
}

handshake_status_t handshake_responder_create_server_hello(handshake_ctx_t *ctx, uint8_t *out,
                                                           size_t out_cap, size_t *out_len) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_RESPONDER,
                                       HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (out == NULL || out_len == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    server_hello_t sh;
    client_hello_t ch;
    uint8_t sh_unsigned[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
    uint8_t sh_full[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t th_server_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES];
    uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES];
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    size_t consumed = 0;
    size_t unsigned_len = 0;
    size_t full_len = 0;
    size_t sig_len = 0;
    pending_status_t ps = PENDING_OK;
    handshake_status_t result = HANDSHAKE_ERR_INTERNAL;
    memset(&sh, 0, sizeof(sh));
    memset(&ch, 0, sizeof(ch));
    memset(th_server_auth, 0, sizeof(th_server_auth));
    memset(th_client_auth, 0, sizeof(th_client_auth));
    memset(handshake_id, 0, sizeof(handshake_id));

    if (kex_keypair_generate(&ctx->eph) != 0) {
        goto fail;
    }

    memcpy(sh.id, ctx->local_id, ctx->local_id_len);
    sh.id_len = ctx->local_id_len;
    memcpy(sh.ephemeral_pub, ctx->eph.public_key, KEX_PUBLIC_KEY_BYTES);
    randombytes_buf(sh.nonce, WIRE_NONCE_LEN);
    memcpy(sh.session_id_echo, ctx->session_id, WIRE_SESSION_ID_LEN);

    /* Encapsulate to the initiator's key, taken from the EXACT ClientHello
     * bytes this context accepted rather than from a second copy kept in
     * the context. Those bytes already passed a strict decode, so a
     * failure here is a local defect, not peer input. */
    if (decode_client_hello(ctx->ch_bytes, ctx->ch_len, &ch, &consumed) != 0) {
        goto fail;
    }
    ctx->ss_kem = secure_mem_alloc(MLKEM_SHARED_SECRET_BYTES);
    if (ctx->ss_kem == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto fail;
    }
    /* BEFORE sig_B, so a malformed encapsulation key (FIPS 203 7.2) costs
     * no ML-DSA signature. This is the first point at which such a key can
     * be detected: the wire decoder validates length only. */
    if (mlkem_encaps(sh.mlkem_ct, ctx->ss_kem, ch.mlkem_ek) != 0) {
        result = HANDSHAKE_ERR_KEX;
        goto fail;
    }

    /* sig_B covers the ClientHello AND this ServerHello's own unsigned
     * fields (spec §6.3.2). */
    if (encode_server_hello_unsigned(&sh, sh_unsigned, sizeof(sh_unsigned), &unsigned_len) != 0 ||
        transcript_hash_server_auth(ctx->ch_bytes, ctx->ch_len, sh_unsigned, unsigned_len,
                                    th_server_auth) != 0) {
        goto fail;
    }
    if (mldsa_sign(sh.sig, &sig_len, th_server_auth, sizeof(th_server_auth),
                   ctx->local_keypair) != 0 ||
        sig_len == 0 || sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        goto fail;
    }
    sh.sig_len = (uint16_t)sig_len;
    if (encode_server_hello(&sh, sh_full, sizeof(sh_full), &full_len) != 0) {
        goto fail;
    }
    /* SH_unsigned must be a literal prefix of the full message. */
    if (full_len <= unsigned_len || sodium_memcmp(sh_full, sh_unsigned, unsigned_len) != 0) {
        goto fail;
    }

    if (out_cap < full_len) {
        /* API misuse: roll back; state stays CLIENT_HELLO_ACCEPTED and
         * nothing has been inserted into the ledger. The retained KEM
         * secret is discarded too -- a retry encapsulates afresh. */
        kex_keypair_free(&ctx->eph);
        if (ctx->ss_kem != NULL) {
            secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);
            ctx->ss_kem = NULL;
        }
        sodium_memzero(&sh, sizeof(sh));
        sodium_memzero(&ch, sizeof(ch));
        sodium_memzero(sh_unsigned, sizeof(sh_unsigned));
        sodium_memzero(sh_full, sizeof(sh_full));
        sodium_memzero(th_server_auth, sizeof(th_server_auth));
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    /* Both digests from the exact CH and full SH wire bytes, computed once
     * now; the ledger stores digests, never message bytes. */
    if (transcript_hash_client_auth(ctx->ch_bytes, ctx->ch_len, sh_full, full_len,
                                    th_client_auth) != 0 ||
        transcript_handshake_id(ctx->ch_bytes, ctx->ch_len, sh_full, full_len, handshake_id) != 0) {
        goto fail;
    }

    /* Last fallible step. */
    ps = handshake_pending_insert(ctx->pending, handshake_id, th_client_auth);
    if (ps != PENDING_OK) {
        result = (ps == PENDING_ERR_FULL) ? HANDSHAKE_ERR_RESOURCE_EXHAUSTED : HANDSHAKE_ERR_INTERNAL;
        goto fail;
    }

    memcpy(ctx->handshake_id, handshake_id, WIRE_HANDSHAKE_ID_LEN);
    memcpy(out, sh_full, full_len);
    *out_len = full_len;

    sodium_memzero(ctx->ch_bytes, sizeof(ctx->ch_bytes)); /* no longer needed */
    ctx->ch_len = 0;
    sodium_memzero(&sh, sizeof(sh));
    sodium_memzero(&ch, sizeof(ch));
    sodium_memzero(sh_unsigned, sizeof(sh_unsigned));
    sodium_memzero(sh_full, sizeof(sh_full));
    sodium_memzero(th_server_auth, sizeof(th_server_auth));
    sodium_memzero(th_client_auth, sizeof(th_client_auth));
    sodium_memzero(handshake_id, sizeof(handshake_id));
    ctx->state = HANDSHAKE_STATE_SERVER_HELLO_CREATED;
    return HANDSHAKE_OK;

fail:
    sodium_memzero(&sh, sizeof(sh));
    sodium_memzero(&ch, sizeof(ch));
    sodium_memzero(sh_unsigned, sizeof(sh_unsigned));
    sodium_memzero(sh_full, sizeof(sh_full));
    sodium_memzero(th_server_auth, sizeof(th_server_auth));
    sodium_memzero(th_client_auth, sizeof(th_client_auth));
    sodium_memzero(handshake_id, sizeof(handshake_id));
    return fail_ctx(ctx, result);
}

handshake_status_t handshake_responder_verify_client_auth(handshake_ctx_t *ctx,
                                                          const uint8_t *ca, size_t ca_len) {
    /* 1. */
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_RESPONDER,
                                       HANDSHAKE_STATE_SERVER_HELLO_CREATED);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    if (ca == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }

    client_auth_t msg;
    size_t consumed = 0;
    uint8_t digest[HANDSHAKE_TRANSCRIPT_HASH_BYTES];
    uint8_t *shared = NULL;
    uint8_t *keys = NULL;
    pending_status_t ps = PENDING_OK;
    handshake_status_t result = HANDSHAKE_ERR_INTERNAL;
    memset(&msg, 0, sizeof(msg));
    memset(digest, 0, sizeof(digest));

    /* 2. Strict decode. RETRYABLE: no entry touched, state unchanged. */
    if (decode_client_auth(ca, ca_len, &msg, &consumed) != 0) {
        sodium_memzero(&msg, sizeof(msg));
        return HANDSHAKE_ERR_MALFORMED;
    }

    /* 3. handshake_id must be THIS context's. RETRYABLE, and checked
     *    before the ledger is consulted, so a misrouted or forged id can
     *    neither consume nor damage the genuine entry. */
    if (sodium_memcmp(msg.handshake_id, ctx->handshake_id, WIRE_HANDSHAKE_ID_LEN) != 0) {
        sodium_memzero(&msg, sizeof(msg));
        return HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH;
    }

    /* 4. Ledger: expiry/state check + digest copy-out. Terminal on
     *    failure; the store has already decided the ledger state. */
    ps = handshake_pending_get_digest(ctx->pending, ctx->handshake_id, digest);
    if (ps != PENDING_OK) {
        sodium_memzero(&msg, sizeof(msg));
        return fail_ctx(ctx, map_pending_failure(ps));
    }

    /* 5. sig_A. Below the limit a failure is RETRYABLE (entry preserved,
     *    counted); reaching the limit is terminal, and record_failure has
     *    already tombstoned the entry -- no additional cancel. */
    if (mldsa_verify(digest, sizeof(digest), msg.sig, msg.sig_len, ctx->peer_pk) != 0) {
        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(&msg, sizeof(msg));
        ps = handshake_pending_record_failure(ctx->pending, ctx->handshake_id);
        if (ps == PENDING_OK) {
            /* RETRYABLE: the handshake is still live, so ss_kem is
             * deliberately KEPT -- the next ClientAuth needs it. */
            return HANDSHAKE_ERR_SIGNATURE;
        }
        return fail_ctx(ctx, map_pending_failure(ps));
    }
    /* `digest` is TH_client_auth and is now a KDF input as well as the
     * signed message, so it is wiped after derivation rather than here. */

    /* 6. X25519 into a TEMPORARY buffer -- A's ephemeral key is only used
     *    now that sig_A has authenticated it. */
    shared = secure_mem_alloc(KEX_SHARED_SECRET_BYTES);
    if (shared == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto cancel_and_fail;
    }
    if (kex_shared_secret(shared, &ctx->eph, ctx->peer_eph_pub) != 0) {
        result = HANDSHAKE_ERR_KEX;
        goto cancel_and_fail;
    }

    /* 7. Traffic keys into TEMPORARY buffers (initiator = A, responder =
     *    B), from both hybrid secrets and this handshake's transcript
     *    digest. ss_kem was produced when this context encapsulated. */
    if (ctx->ss_kem == NULL) {
        result = HANDSHAKE_ERR_INTERNAL; /* unreachable: set at ServerHello */
        goto cancel_and_fail;
    }
    keys = secure_mem_alloc(SESSION_KEYS_LEN);
    if (keys == NULL) {
        result = HANDSHAKE_ERR_RESOURCE_EXHAUSTED;
        goto cancel_and_fail;
    }
    if (derive_traffic_keys(keys, shared, ctx->ss_kem, ctx->session_id, ctx->peer_id,
                            ctx->peer_id_len, ctx->local_id, ctx->local_id_len, digest) != 0) {
        result = HANDSHAKE_ERR_INTERNAL;
        goto cancel_and_fail;
    }

    /* 8. COMMIT POINT: the last fallible step. On failure the store's own
     *    semantics determine the ledger state -- no second transition. */
    ps = handshake_pending_consume_success(ctx->pending, ctx->handshake_id);
    if (ps != PENDING_OK) {
        result = map_pending_failure(ps);
        goto fail_no_cancel;
    }

    /* 9. Only now do keys enter context state. */
    memcpy(ctx->session_keys, keys, SESSION_KEYS_LEN);
    ctx->keys_committed = true;

    /* 10. The KEM secret has done its job: wipe it here rather than
     *     waiting for teardown (Security Req 4.12). */
    secure_mem_free(shared, KEX_SHARED_SECRET_BYTES);
    secure_mem_free(keys, SESSION_KEYS_LEN);
    secure_mem_free(ctx->ss_kem, MLKEM_SHARED_SECRET_BYTES);
    ctx->ss_kem = NULL;
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&msg, sizeof(msg));
    ctx->state = HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED;
    return HANDSHAKE_OK;

cancel_and_fail:
    /* Terminal failure after a successful lookup and a valid sig_A: the
     * entry is an orphan (no other context can complete it), so reclaim
     * its capacity now. cancel() also evicts it if it expired meanwhile. */
    (void)handshake_pending_cancel(ctx->pending, ctx->handshake_id);
fail_no_cancel:
    if (shared != NULL) {
        secure_mem_free(shared, KEX_SHARED_SECRET_BYTES);
    }
    if (keys != NULL) {
        secure_mem_free(keys, SESSION_KEYS_LEN);
    }
    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&msg, sizeof(msg));
    return fail_ctx(ctx, result); /* frees ss_kem */
}

handshake_status_t handshake_responder_finish(handshake_ctx_t *ctx) {
    handshake_status_t st = check_call(ctx, HANDSHAKE_ROLE_RESPONDER,
                                       HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    kex_keypair_free(&ctx->eph);
    sodium_memzero(ctx->peer_eph_pub, sizeof(ctx->peer_eph_pub));
    /* handshake_id is kept for the session layer's AD (see initiator_finish). */
    ctx->state = HANDSHAKE_STATE_ESTABLISHED;
    return HANDSHAKE_OK;
}

/* ============================================================================
 * Keys
 * ========================================================================= */

static handshake_status_t key_at(const handshake_ctx_t *ctx, size_t offset,
                                 const uint8_t **key_out) {
    if (key_out == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    *key_out = NULL;
    if (ctx == NULL) {
        return HANDSHAKE_ERR_INVALID_ARG;
    }
    if (ctx->state != HANDSHAKE_STATE_ESTABLISHED || !ctx->keys_committed ||
        ctx->session_keys == NULL) {
        return HANDSHAKE_ERR_UNEXPECTED_STATE;
    }
    *key_out = ctx->session_keys + offset;
    return HANDSHAKE_OK;
}

handshake_status_t handshake_session_key_c2s(const handshake_ctx_t *ctx, const uint8_t **key_out) {
    return key_at(ctx, C2S_OFFSET, key_out);
}

handshake_status_t handshake_session_key_s2c(const handshake_ctx_t *ctx, const uint8_t **key_out) {
    return key_at(ctx, S2C_OFFSET, key_out);
}

bool handshake_is_peer_confirmed(const handshake_ctx_t *ctx) {
    return ctx != NULL && ctx->role == HANDSHAKE_ROLE_RESPONDER &&
           ctx->state == HANDSHAKE_STATE_ESTABLISHED && ctx->keys_committed;
}
