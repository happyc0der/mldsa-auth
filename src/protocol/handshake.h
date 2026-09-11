#ifndef MLDSA_AUTH_PROTOCOL_HANDSHAKE_H
#define MLDSA_AUTH_PROTOCOL_HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kex.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "transcript.h"

/*
 * In-process ML-DSA-65 mutual-authentication handshake state machine
 * (spec §6.3). Step 4 scope: no transport, no session-layer traffic.
 *
 * ============================================================================
 * CONCURRENCY CONTRACT (v1) -- see spec §6.3.6.
 * handshake_ctx_t, keystore_t and handshake_pending_store_t are
 * NOT thread-safe. "Atomic" anywhere in this API means logically indivisible
 * ONLY when all calls into a given pending store are serialized by the
 * caller. A future transport/server integration must either:
 *   1. confine each pending store, and every responder context associated
 *      with it, to a single thread/event loop; or
 *   2. make lookup + expiry check + signature-result handling +
 *      consume_success one critical section per store.
 * No locking of any kind is implemented in v1.
 * ============================================================================
 *
 * FAIL-CLOSED SEMANTICS
 *   "Fail closed" means: no session key is ever derived into context state,
 *   marked valid, or retrievable unless the full check sequence for that
 *   role succeeded. It does NOT mean every error is terminal:
 *   - Terminal (-> HANDSHAKE_STATE_FAILED, no recovery): identity errors,
 *     session-ID echo mismatch, sig_B failure, X25519 failure, expiry,
 *     replay, auth-failure limit, resource exhaustion, internal errors.
 *   - Retryable (state and ledger entry unchanged), responder awaiting
 *     ClientAuth only: malformed ClientAuth, handshake_id mismatch, and a
 *     sig_A failure below HANDSHAKE_AUTH_FAILURE_LIMIT.
 *   - API misuse (wrong state, wrong role, NULL args, output buffer too
 *     small): error returned, state unchanged, no side effects.
 *
 * INITIATOR ESTABLISHED IS OPTIMISTIC
 *   handshake_initiator_finish() can only know that ClientAuth was CREATED,
 *   not that any transport delivered it or that the responder accepted it
 *   (a 3-message flow carries no such signal). Its keys are made available
 *   optimistically; the caller is responsible for transmitting ClientAuth
 *   before using them; the initiator's ESTABLISHED is local and unconfirmed
 *   until the first record from the responder is successfully opened by the
 *   session layer. Applications MUST NOT treat it as responder confirmation
 *   or use it to authorize irreversible actions -- gate those on
 *   handshake_is_peer_confirmed(), never on the state alone. Once a session
 *   has been created from this context (session_init_from_handshake()
 *   consumes it), session_is_peer_confirmed() is the authority.
 */

#define HANDSHAKE_PENDING_MAX 256u
#define HANDSHAKE_PENDING_TTL_MS_DEFAULT 30000u
#define HANDSHAKE_AUTH_FAILURE_LIMIT 3u /* N = 3 */

#define HANDSHAKE_DIR_C2S KEX_DIR_C2S /* 0x43 'C' -- alias; kex.h is the source of truth */
#define HANDSHAKE_DIR_S2C KEX_DIR_S2C /* 0x53 'S' */

#define HANDSHAKE_TRANSCRIPT_HASH_BYTES 32u

/* ----------------------------------------------------------------------------
 * Pending-handshake store (responder): a bounded, expiring, single-use
 * LEDGER of handshake_ids. It holds only handshake_id, TH_client_auth and
 * ledger metadata. It cannot route a ClientAuth to a context and cannot
 * complete a handshake: everything needed to complete one (ephemeral
 * scalar, peer X25519 key, pinned identity key, KDF inputs) lives only in
 * the responder context that created the ServerHello. In Step 4, ClientAuth
 * must be delivered to that same context; handshake_id-to-context routing
 * is deferred to transport integration.
 * ------------------------------------------------------------------------- */

/* Monotonic clock in milliseconds. NULL selects CLOCK_MONOTONIC. The
 * default clock fails CLOSED: if it cannot read the clock it reports
 * UINT64_MAX, which makes every entry read as expired. */
typedef uint64_t (*handshake_clock_fn)(void *clock_ctx);

/* The default clock above, exported so the session layer shares the same
 * fail-closed implementation. clock_ctx is ignored. */
uint64_t handshake_default_clock_ms(void *clock_ctx);

typedef enum {
    PENDING_SLOT_FREE = 0,
    PENDING_SLOT_ACTIVE,
    PENDING_SLOT_CONSUMED,
    PENDING_SLOT_AUTH_LIMITED,
    /* REPORTED-ONLY: never stored in an entry. handshake_pending_inspect()
     * reports this for an entry whose deadline has passed but which has not
     * been physically evicted yet. */
    PENDING_SLOT_EXPIRED
} pending_slot_state_t;

typedef enum {
    PENDING_OK = 0,
    PENDING_ERR_INVALID_ARG, /* also: duplicate handshake_id on insert */
    PENDING_ERR_NOT_FOUND,
    PENDING_ERR_EXPIRED,
    PENDING_ERR_CONSUMED,
    PENDING_ERR_AUTH_LIMIT,
    PENDING_ERR_FULL
} pending_status_t;

typedef struct {
    pending_slot_state_t state; /* FREE / ACTIVE / CONSUMED / AUTH_LIMITED */
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES];
    uint64_t deadline_ms; /* set once at insert; never extended */
    uint8_t failure_count;
} handshake_pending_entry_t;

typedef struct {
    handshake_pending_entry_t entries[HANDSHAKE_PENDING_MAX];
    size_t capacity;
    uint64_t ttl_ms;
    handshake_clock_fn clock_fn;
    void *clock_ctx;
} handshake_pending_store_t;

/* Initializes an empty store. 1 <= capacity <= HANDSHAKE_PENDING_MAX and
 * ttl_ms > 0, else PENDING_ERR_INVALID_ARG (store left unusable). */
pending_status_t handshake_pending_store_init(handshake_pending_store_t *s, size_t capacity,
                                              uint64_t ttl_ms, handshake_clock_fn clock_fn,
                                              void *clock_ctx);

/* Zeroes the whole store (idempotent). */
void handshake_pending_store_wipe(handshake_pending_store_t *s);

/* Sweeps expired entries first, then inserts an ACTIVE entry with
 * deadline = now + ttl (saturating). Never evicts a live, unexpired entry
 * to make room -> PENDING_ERR_FULL. A handshake_id already present ->
 * PENDING_ERR_INVALID_ARG. */
pending_status_t handshake_pending_insert(handshake_pending_store_t *s,
                                          const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                          const uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES]);

/* Checks expiry BEFORE slot state, then COPIES the digest into
 * caller-provided scratch. No borrowed pointer into the store is ever
 * returned. Expired -> PENDING_ERR_EXPIRED and the slot is physically
 * freed; CONSUMED/AUTH_LIMITED tombstones -> their status; absent ->
 * PENDING_ERR_NOT_FOUND. On every non-OK status the out buffer is zeroed,
 * so a caller that ignores the status cannot proceed on stale scratch. */
pending_status_t handshake_pending_get_digest(handshake_pending_store_t *s,
                                              const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                              uint8_t th_client_auth_out[HANDSHAKE_TRANSCRIPT_HASH_BYTES]);

/* Read-only introspection: mutates NOTHING (never evicts, never frees,
 * never touches failure_count) but reports LOGICAL expiry: an entry past
 * its deadline reports PENDING_ERR_EXPIRED / PENDING_SLOT_EXPIRED even
 * though its slot is still physically occupied. Physical eviction is the
 * job of get_digest(), insert(), sweep() and cancel(). */
pending_status_t handshake_pending_inspect(const handshake_pending_store_t *s,
                                           const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN],
                                           pending_slot_state_t *state_out,
                                           uint8_t *failure_count_out);

/* Records one sig_A failure. PENDING_OK while the entry stays ACTIVE;
 * PENDING_ERR_AUTH_LIMIT when THIS failure reaches the limit and
 * tombstones the entry. Never extends the deadline. */
pending_status_t handshake_pending_record_failure(handshake_pending_store_t *s,
                                                  const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]);

/* The commit point: tombstones an ACTIVE entry as CONSUMED ("atomic" under
 * caller serialization -- see the concurrency contract). Re-checks expiry,
 * so an entry that expired since get_digest() still fails here. */
pending_status_t handshake_pending_consume_success(handshake_pending_store_t *s,
                                                   const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]);

/* Applies the uniform expiry rule FIRST, then acts on what remains:
 *   ACTIVE, not expired              -> slot freed, PENDING_OK
 *   ACTIVE, expired                  -> slot freed now, PENDING_ERR_EXPIRED
 *   CONSUMED/AUTH_LIMITED, live      -> NO-OP, tombstone status returned
 *   CONSUMED/AUTH_LIMITED, expired   -> slot freed (ordinary expiry
 *                                       eviction), PENDING_ERR_EXPIRED
 *   absent                           -> PENDING_ERR_NOT_FOUND
 * An UNEXPIRED tombstone is never erased by cancel. */
pending_status_t handshake_pending_cancel(handshake_pending_store_t *s,
                                          const uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN]);

/* Number of LOGICALLY live entries: physically ACTIVE and not expired. */
size_t handshake_pending_active_count(const handshake_pending_store_t *s);

/* Physically frees every expired entry, of any state. */
void handshake_pending_sweep(handshake_pending_store_t *s);

/* ----------------------------------------------------------------------------
 * Handshake contexts
 * ------------------------------------------------------------------------- */

typedef enum { HANDSHAKE_ROLE_INITIATOR = 1, HANDSHAKE_ROLE_RESPONDER = 2 } handshake_role_t;

typedef enum {
    HANDSHAKE_STATE_NEW = 0,
    /* initiator */
    HANDSHAKE_STATE_CLIENT_HELLO_CREATED,
    HANDSHAKE_STATE_SERVER_HELLO_VERIFIED,
    HANDSHAKE_STATE_CLIENT_AUTH_CREATED,
    /* responder */
    HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED,
    HANDSHAKE_STATE_SERVER_HELLO_CREATED,
    HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED,
    /* both */
    HANDSHAKE_STATE_ESTABLISHED,
    HANDSHAKE_STATE_FAILED
} handshake_state_t;

typedef enum {
    HANDSHAKE_OK = 0,
    HANDSHAKE_ERR_INVALID_ARG,
    HANDSHAKE_ERR_UNEXPECTED_STATE,
    HANDSHAKE_ERR_MALFORMED,
    HANDSHAKE_ERR_UNKNOWN_IDENTITY,
    HANDSHAKE_ERR_IDENTITY_KEY_MISMATCH,
    HANDSHAKE_ERR_PEER_IDENTITY_MISMATCH, /* responder b_id != the peer the initiator dialed */
    HANDSHAKE_ERR_SESSION_ID_MISMATCH,
    HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH,
    HANDSHAKE_ERR_REPLAY,
    HANDSHAKE_ERR_EXPIRED,
    HANDSHAKE_ERR_SIGNATURE,          /* retryable on the responder, below the limit */
    HANDSHAKE_ERR_AUTH_FAILURE_LIMIT, /* terminal: N = 3 reached */
    HANDSHAKE_ERR_KEX,                /* X25519 failure, incl. low-order point */
    HANDSHAKE_ERR_RESOURCE_EXHAUSTED,
    HANDSHAKE_ERR_INTERNAL
} handshake_status_t;

/* Storage is caller-provided (init-on-caller-storage), so the struct is
 * visible here -- but EVERY FIELD IS PRIVATE to handshake.c. Do not read
 * or write fields directly. Identity keypairs, the keystore and the
 * pending store are BORROWED and must outlive the context. The context
 * owns exactly what it allocates: the ephemeral X25519 private scalar and
 * the session-key slots (both secure_mem). There is deliberately NO
 * shared-secret member: shared secrets exist only inside the call that
 * computes them, in a temporary secure_mem buffer wiped before return. */
typedef struct {
    handshake_role_t role;
    handshake_state_t state;

    uint8_t local_id[WIRE_ID_MAX_LEN];
    uint8_t local_id_len;
    const mldsa_keypair_t *local_keypair; /* borrowed */
    const keystore_t *keystore;           /* borrowed */
    handshake_pending_store_t *pending;   /* borrowed; responder only */

    uint8_t peer_id[WIRE_ID_MAX_LEN];
    uint8_t peer_id_len;
    const uint8_t *peer_pk; /* borrowed from the keystore */

    uint8_t session_id[WIRE_SESSION_ID_LEN];
    uint8_t ch_bytes[CLIENT_HELLO_MAX_ENCODED_LEN]; /* exact wire bytes */
    size_t ch_len;
    uint8_t peer_eph_pub[KEX_PUBLIC_KEY_BYTES];
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    uint8_t th_client_auth[HANDSHAKE_TRANSCRIPT_HASH_BYTES]; /* initiator only */

    kex_keypair_t eph;     /* private_key is secure_mem; NULL when absent */
    uint8_t *session_keys; /* secure_mem, 2*KEX_SESSION_KEY_BYTES: [c2s | s2c] */
    bool keys_committed;
} handshake_ctx_t;

/* Init must be called on fresh (or handshake_ctx_wipe'd) storage.
 * On success -> NEW. On failure the context is left FAILED and unusable.
 * local_keypair/keystore must outlive the context. */
handshake_status_t handshake_initiator_init(handshake_ctx_t *ctx,
                                            const uint8_t *local_id, size_t local_id_len,
                                            const mldsa_keypair_t *local_keypair,
                                            const keystore_t *keystore,
                                            const uint8_t *peer_id, size_t peer_id_len);

handshake_status_t handshake_responder_init(handshake_ctx_t *ctx,
                                            const uint8_t *local_id, size_t local_id_len,
                                            const mldsa_keypair_t *local_keypair,
                                            const keystore_t *keystore,
                                            handshake_pending_store_t *pending);

/* Idempotent; wipes and frees all secrets. Also the EXPLICIT CANCELLATION
 * path: a responder wiped while in SERVER_HELLO_CREATED first cancels its
 * pending entry, so an abandoned handshake stops consuming ledger capacity
 * immediately. In every other state the ledger is left untouched. The
 * context is left FAILED afterward. */
void handshake_ctx_wipe(handshake_ctx_t *ctx);

/* HANDSHAKE_STATE_FAILED for a NULL context. */
handshake_state_t handshake_get_state(const handshake_ctx_t *ctx);

/* Role of an initialized context. NULL args -> INVALID_ARG; a context whose
 * init failed, or that was wiped, -> UNEXPECTED_STATE. */
handshake_status_t handshake_get_role(const handshake_ctx_t *ctx, handshake_role_t *role_out);

/* Copies the 16-byte handshake_id (spec §6.3.3). It is public -- ClientAuth
 * carries it in the clear -- and is retained in ESTABLISHED so the session
 * layer can bind it into every record's AD (spec §6.4). Succeeds ONLY in
 * ESTABLISHED; otherwise returns UNEXPECTED_STATE with the output zeroed. */
handshake_status_t handshake_get_handshake_id(const handshake_ctx_t *ctx,
                                              uint8_t handshake_id_out[WIRE_HANDSHAKE_ID_LEN]);

/* --- Initiator ----------------------------------------------------------- */

/* NEW -> CLIENT_HELLO_CREATED. Writes the ClientHello into out. Output
 * buffer too small -> HANDSHAKE_ERR_INVALID_ARG, state stays NEW, no side
 * effects. Internal failure -> FAILED. */
handshake_status_t handshake_initiator_create_client_hello(handshake_ctx_t *ctx, uint8_t *out,
                                                           size_t out_cap, size_t *out_len);

/* CLIENT_HELLO_CREATED -> SERVER_HELLO_VERIFIED. Every failure is terminal
 * (-> FAILED). Authenticates B and B's ephemeral key; derives NO traffic
 * keys and retains NO shared secret. */
handshake_status_t handshake_initiator_verify_server_hello(handshake_ctx_t *ctx,
                                                           const uint8_t *sh, size_t sh_len);

/* SERVER_HELLO_VERIFIED -> CLIENT_AUTH_CREATED. Still no traffic keys.
 * Output buffer too small -> INVALID_ARG, state unchanged. */
handshake_status_t handshake_initiator_create_client_auth(handshake_ctx_t *ctx, uint8_t *out,
                                                          size_t out_cap, size_t *out_len);

/* CLIENT_AUTH_CREATED -> ESTABLISHED. Recomputes the X25519 shared secret,
 * derives c2s/s2c, wipes the temporary secret and the ephemeral scalar.
 * OPTIMISTIC -- see "INITIATOR ESTABLISHED IS OPTIMISTIC" above;
 * handshake_is_peer_confirmed() stays false. */
handshake_status_t handshake_initiator_finish(handshake_ctx_t *ctx);

/* --- Responder ----------------------------------------------------------- */

/* NEW -> CLIENT_HELLO_ACCEPTED. Unknown initiator id -> UNKNOWN_IDENTITY,
 * FAILED, and no pending entry is created. All failures terminal. */
handshake_status_t handshake_responder_accept_client_hello(handshake_ctx_t *ctx,
                                                           const uint8_t *ch, size_t ch_len);

/* CLIENT_HELLO_ACCEPTED -> SERVER_HELLO_CREATED. Signs sig_B, computes
 * TH_client_auth and handshake_id from the exact wire bytes, and inserts
 * the pending entry. Store full -> RESOURCE_EXHAUSTED, FAILED. Output
 * buffer too small -> INVALID_ARG, state unchanged, nothing inserted. */
handshake_status_t handshake_responder_create_server_hello(handshake_ctx_t *ctx, uint8_t *out,
                                                           size_t out_cap, size_t *out_len);

/* SERVER_HELLO_CREATED -> CLIENT_AUTH_VERIFIED. ClientAuth must come to the
 * SAME context that created the ServerHello.
 *   Retryable (state + entry unchanged): MALFORMED, HANDSHAKE_ID_MISMATCH,
 *     and SIGNATURE below the failure limit (which does count a failure).
 *   Terminal: EXPIRED, REPLAY, AUTH_FAILURE_LIMIT, KEX, INTERNAL.
 * Order after a valid sig_A: X25519 and KDF into temporary buffers, THEN
 * consume_success, THEN commit keys -- so a local failure never spends the
 * peer's entry (it cancels it instead) and no key is committed for a
 * handshake that was not committed exactly once. */
handshake_status_t handshake_responder_verify_client_auth(handshake_ctx_t *ctx,
                                                          const uint8_t *ca, size_t ca_len);

/* CLIENT_AUTH_VERIFIED -> ESTABLISHED. handshake_is_peer_confirmed() true. */
handshake_status_t handshake_responder_finish(handshake_ctx_t *ctx);

/* --- Keys ----------------------------------------------------------------- */

/* Borrowed pointer to a 32-byte key, valid until handshake_ctx_wipe().
 * Succeeds ONLY in ESTABLISHED; in every other state returns
 * HANDSHAKE_ERR_UNEXPECTED_STATE and sets *key_out = NULL. */
handshake_status_t handshake_session_key_c2s(const handshake_ctx_t *ctx, const uint8_t **key_out);
handshake_status_t handshake_session_key_s2c(const handshake_ctx_t *ctx, const uint8_t **key_out);

/* True only for a RESPONDER in ESTABLISHED (sig_A verified over a
 * transcript containing its own fresh nonce). False for an initiator in
 * ESTABLISHED (optimistic) and in every other state. */
bool handshake_is_peer_confirmed(const handshake_ctx_t *ctx);

#endif /* MLDSA_AUTH_PROTOCOL_HANDSHAKE_H */
