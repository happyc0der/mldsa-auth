#ifndef MLDSA_AUTHD_CONN_H
#define MLDSA_AUTHD_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"
#include "store.h"
#include "evloop.h"

/*
 * The per-connection protocol state machine (V4-8b).
 *
 *   AWAIT_CH -> AWAIT_CA -> SERVING -> CLOSING
 *
 * The handshake itself is the verified library's, unchanged: this layer only
 * decides WHICH public key is pinned before
 * handshake_responder_accept_client_hello() runs, feeds it the exact wire
 * bytes, and honours its retry semantics.
 *
 * THE DECOY FLOW (spec 7.3 / Req 6) is the reason the pin is chosen here
 * rather than by the library. The daemon peeks the ClientHello with
 * decode_client_hello() -- the same public decoder demo_app.c already uses --
 * asks the store, and pins EITHER the device's real key OR the store's decoy
 * key (a real ML-DSA-65 public key whose secret was discarded at store
 * creation). Unknown, revoked, superseded and disabled identities all collapse
 * to STORE_ERR_NOT_FOUND in one three-join query, so they all get the decoy
 * and all produce the SAME observable sequence as a known identity with a bad
 * signature: a real ServerHello signed by the real server key, then failure at
 * ClientAuth. accept_client_hello() can therefore never return
 * UNKNOWN_IDENTITY, which is precisely the enumeration channel being closed.
 *
 * Per-connection state is a slot in a caller-provided array; nothing is
 * allocated per connection. The scratch keystore is 64 KB of the ~91 KB slot
 * and holds exactly one entry -- the cost of not changing the library for
 * milestone A, recorded in docs/decisions.md with the alternative.
 */

/* Req 5's ceiling, not a value chosen below it by accident: a login code
 * expires in AT MOST 60 seconds. */
#define AUTHD_LOGIN_CODE_TTL_S 60u

typedef enum {
    CONN_STAGE_FREE = 0,
    CONN_STAGE_AWAIT_CH,   /* expecting the ClientHello */
    CONN_STAGE_AWAIT_CA,   /* ServerHello queued; expecting ClientAuth */
    CONN_STAGE_SERVING,    /* session live, LOGIN_CODE sent; expecting BYE */
    CONN_STAGE_CLOSING
} conn_stage_t;

typedef struct {
    conn_stage_t     stage;
    handshake_ctx_t  hs;
    session_t        sess;
    keystore_t       ks;        /* per-slot scratch: exactly one pin */

    uint8_t  handle[STORE_ID_MAX];
    size_t   handle_len;
    uint8_t  user_id[STORE_ID_MAX];
    size_t   user_id_len;

    /* The session's handshake_id, kept because ROTATE's digest binds to it
     * (spec 6.3) and session_init_from_handshake CONSUMES the handshake
     * context. session_t holds a copy but every field of it is private to
     * session.c, and V4 decision 3 rules out changing the library for
     * milestone A -- so this copy is paid for honestly: wiped in conn_reset,
     * probed by the wipe test, and carrying its own mutation. */
    uint8_t  handshake_id[STORE_HSID_BYTES];
    int      hsid_set;

    int      decoy;             /* 1 = the pin is the decoy, not a real key */
    int      hs_live;           /* a handshake_ctx_t needs wiping */
    int      rotated;           /* one ROTATE per session; see authd_conn.c */
} authd_conn_t;

/* Everything the connection layer needs that is not per-connection. One
 * instance, passed to the event loop as its user pointer. */
typedef struct {
    authd_conn_t *conns;
    size_t        n_conns;

    store_t                   *store;
    const mldsa_keypair_t     *server_kp;     /* borrowed */
    const uint8_t             *server_id;     /* borrowed */
    size_t                     server_id_len;
    handshake_pending_store_t *pending;       /* borrowed */

    /* The loop, so the API can close the connections a revocation invalidates
     * (Req 9). The daemon owns both the store and the slots, so this needs no
     * "store hook": revoking a row and closing its sessions happen in one
     * process, in one thread, in that order. */
    evloop_t *ev;

    uint32_t pad_bucket;
    uint32_t rotation_due_age_s;   /* 0 = never hint; spec defines no cadence */
    uint32_t code_ttl_s;

    /* Recovery policy (V4-9d, spec §10.3). These are FIELDS rather than
     * constants for one reason: the KDF at the spec's parameters costs ~0.1 s
     * per verification, and test_authd_localapi and fuzz_localapi would each
     * spend minutes per run issuing codes. They set them to libsodium's _MIN.
     * The daemon itself assigns the spec's values from recovery.h -- which is
     * what tools/audit/check_spec_constants.sh pins, since no test can observe
     * what authd_main.c writes here. They are deliberately NOT config keys:
     * §10.3 fixes them, and an operator who could set ops=1 would be
     * configuring away the defence. */
    unsigned long long recovery_ops;
    size_t             recovery_mem;
    int                recovery_lock_threshold;
    int64_t            recovery_lock_seconds;
    uint32_t           ticket_ttl_s;
    uint64_t started_ms;      /* for PING's uptime */
    uint64_t next_sweep_ms;

    /* TIME IS PUSHED IN, not read: the main loop sets these immediately
     * before each evloop_run_once() with the same values it gives the loop,
     * so ledger expiry, session clock and code expiry are all driven by one
     * injected clock and are exact in tests. This is also why evloop.h did
     * not need a signature change to carry the clock into the callback. */
    uint64_t now_ms;
    int64_t  now_unix;

    /* observable counters (tests and operators) */
    uint64_t logins_issued;
    uint64_t rotations;
    uint64_t recoveries_issued;
    uint64_t recoveries_used;
    /* Argon2id verifications actually performed. A locked user must add ZERO
     * to this; the error code alone cannot tell a lockout enforced before the
     * KDF from one enforced after it. */
    uint64_t recovery_kdf_calls;
    uint64_t decoy_pins;
    uint64_t handshakes_failed;
    uint64_t swept_tokens;
    uint64_t swept_codes;
    uint64_t swept_tickets;
} authd_app_t;

/* Clock adaptor for the pending store and the session: both take the
 * library's handshake_clock_fn and are given `app` as the context. */
uint64_t authd_app_clock(void *ctx);

/* Binds a slot to its connection record and resets it to AWAIT_CH. Called for
 * a freshly accepted slot; safe to call on a slot already bound. */
void authd_conn_bind(authd_app_t *app, authd_slot_t *slot);

/* The event-loop callbacks. */
ev_action_t authd_conn_on_frame(void *user, authd_slot_t *slot, const uint8_t *payload, size_t len);
void        authd_conn_on_close(void *user, authd_slot_t *slot);

const char *authd_conn_stage_name(conn_stage_t s);

/* Closes every live protocol connection authenticated as `handle` / belonging
 * to `user`, and returns how many were closed. Req 9's "live connections MUST
 * be closed" half: revoking the row is not enough while a session is open. */
size_t authd_app_close_handle(authd_app_t *app, const uint8_t *handle, size_t handle_len);
size_t authd_app_close_user(authd_app_t *app, const uint8_t *user_id, size_t user_id_len);

/* Runs the periodic sweep when due (TOKEN_SWEEP_INTERVAL_MS), logging the
 * counts (spec 11, 15). Cheap and idempotent; call once per loop iteration. */
void authd_app_maybe_sweep(authd_app_t *app);

#endif /* MLDSA_AUTHD_CONN_H */
