#ifndef MLDSA_AUTHD_STORE_H
#define MLDSA_AUTHD_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_wrap.h"   /* MLDSA_PUBLIC_KEY_BYTES */

/*
 * The daemon's persistence layer (V4-7), over a pinned in-tree SQLite. This is
 * the STORE: schema, atomic operations (one SQLite transaction each, spec
 * §9.3 / Req 14) and the append-only audit MAC chain (§9.2.4). It is the set
 * of correct, all-or-nothing building blocks; the lifecycle POLICY that
 * sequences them (recovery lockout counting, ticket/token TTL rules, the decoy
 * flow) belongs to the daemon and the local API (V4-8/V4-9).
 *
 * Threading: the store wraps one sqlite3* built with SQLITE_THREADSAFE=0 and
 * is NOT thread-safe by construction, matching the daemon's single event loop.
 *
 * All identifiers (handles, user ids) are opaque byte strings, 1..STORE_ID_MAX.
 * Public keys are exactly MLDSA_PUBLIC_KEY_BYTES. Token/code/ticket/state
 * values are never stored in the clear: the caller passes their 32-byte
 * SHA-256 (Req 4 / §5); recovery codes are passed as an Argon2id pwhash_str.
 */

#define STORE_ID_MAX            64u                       /* handle / user_id max bytes (WIRE_ID_MAX_LEN) */
#define STORE_PK_BYTES          MLDSA_PUBLIC_KEY_BYTES    /* 1952 */
#define STORE_STORE_ID_BYTES    16u
#define STORE_HASH_BYTES        32u                       /* SHA-256 of a token/code/ticket/state */
#define STORE_AUDIT_MAC_BYTES   32u                       /* crypto_auth output */
#define STORE_KEK_BYTES         32u                       /* envelope KEK fed to store_open */

typedef enum {
    STORE_OK = 0,
    STORE_ERR_ARG,          /* bad argument (NULL, out-of-range length) */
    STORE_ERR_IO,           /* open/create/backup filesystem failure */
    STORE_ERR_DB,           /* an sqlite call failed unexpectedly */
    STORE_ERR_NOT_FOUND,    /* no matching active row */
    STORE_ERR_CONFLICT,     /* uniqueness / re-enroll-with-different-key (Req 7) */
    STORE_ERR_STATE,        /* operation illegal in the current row state */
    STORE_ERR_SCHEMA,       /* store schema newer than this build */
    STORE_ERR_CRYPTO,       /* key derivation / RNG failure */
    STORE_ERR_CORRUPT       /* audit chain verification failed */
} store_status_t;

typedef enum { STORE_ROLE_OPERATOR = 0, STORE_ROLE_USER = 1 } store_role_t;

typedef struct store store_t;

const char *store_status_name(store_status_t st);

/* Opens (creating if absent) the store at `path`, sets the spec pragmas (WAL,
 * synchronous=FULL, foreign_keys=ON), creates the schema, and on first use
 * generates store_id(16) and decoy_pk(1952) into meta. `kek` is the 32-byte
 * envelope KEK (from keyfile_open): key_audit = HKDF-SHA256(ikm=kek,
 * salt=store_id, info="mldsa-authd/v1/audit-mac") is derived and held in
 * secure memory for the store's lifetime. On any failure *out is NULL. */
store_status_t store_open(const char *path, const uint8_t kek[STORE_KEK_BYTES], store_t **out);

/* Closes and frees; wipes key_audit. Idempotent on NULL. */
void store_close(store_t *s);

/* meta accessors (read-only, no transaction). */
store_status_t store_get_store_id(const store_t *s, uint8_t out[STORE_STORE_ID_BYTES]);
store_status_t store_get_decoy_pk(const store_t *s, uint8_t out[STORE_PK_BYTES]);

/* --- users ------------------------------------------------------------- */
store_status_t store_add_user(store_t *s, const uint8_t *user_id, size_t user_id_len, store_role_t role);
/* disable: user->disabled AND that user's tokens deleted, one transaction + audit.
 * enable: user->active (devices keep their own status). */
store_status_t store_disable_user(store_t *s, const uint8_t *user_id, size_t user_id_len,
                                  const char *by, const uint8_t *reason, size_t reason_len);
store_status_t store_enable_user(store_t *s, const uint8_t *user_id, size_t user_id_len, const char *by);

/* --- devices / keys ---------------------------------------------------- */
/* Enroll a fresh handle with its first active key. Rejects a pk already present
 * anywhere (CONFLICT, invariant 2). A KNOWN handle with a DIFFERENT active key
 * is rejected and audited (CONFLICT, Req 7); with the SAME key it is idempotent
 * (OK, no new audit row). `via` is "site"|"recovery"|"operator". */
store_status_t store_enroll_device(store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   const uint8_t *user_id, size_t user_id_len,
                                   const uint8_t pk[STORE_PK_BYTES],
                                   const char *via, const char *by,
                                   const uint8_t *label, size_t label_len);

/* Rotate: insert new_pk active, set the current active key superseded
 * (valid_to=now, superseded_by_hsid=hsid), optionally delete the handle's
 * tokens (drop_tokens != 0), append one audit row -- ALL OR NOTHING (§9.3).
 * new_pk must not exist anywhere (CONFLICT). */
store_status_t store_rotate_key(store_t *s,
                                const uint8_t *handle, size_t handle_len,
                                const uint8_t new_pk[STORE_PK_BYTES],
                                const uint8_t *hsid, size_t hsid_len,
                                int drop_tokens);

/* Revoke a device: device and its active key -> revoked, delete its tokens,
 * one transaction + audit. */
store_status_t store_revoke_device(store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   const char *by, const uint8_t *reason, size_t reason_len);

/* The §9.2.3 lookup: returns the active public key ONLY when the key is active,
 * the device is active and the user is active (one query, three joins).
 * Read-only, no transaction, no audit. NOT_FOUND otherwise. On OK, pk_out and
 * (optionally) user_id_out/role_out are filled. */
store_status_t store_lookup_active(const store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   uint8_t pk_out[STORE_PK_BYTES],
                                   uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out,
                                   store_role_t *role_out);

/* Record a successful handshake's last_seen (daemon calls after auth). */
store_status_t store_touch_last_seen(store_t *s, const uint8_t *handle, size_t handle_len);

/* --- tokens ------------------------------------------------------------ */
store_status_t store_add_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES],
                               const uint8_t *user_id, size_t user_id_len,
                               const uint8_t *handle, size_t handle_len,
                               const uint8_t *hsid, size_t hsid_len,
                               int64_t issued_at, int64_t expires_at, int64_t idle_expires_at);
/* Verifies a token hash is present and unexpired at `now`; on OK updates
 * last_verified_at and slides idle_expires_at by (idle_expires_at-issued...) is
 * a policy concern -- V4-7 only refreshes last_verified_at. Fills out fields. */
store_status_t store_verify_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES], int64_t now,
                                  uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out);
store_status_t store_delete_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES]);
store_status_t store_delete_tokens_for_handle(store_t *s, const uint8_t *handle, size_t handle_len);
store_status_t store_delete_tokens_for_user(store_t *s, const uint8_t *user_id, size_t user_id_len);

/* --- login codes ------------------------------------------------------- */
store_status_t store_add_login_code(store_t *s, const uint8_t code_hash[STORE_HASH_BYTES],
                                    const uint8_t *user_id, size_t user_id_len,
                                    const uint8_t *handle, size_t handle_len,
                                    const uint8_t *hsid, size_t hsid_len,
                                    const uint8_t state_hash[STORE_HASH_BYTES],
                                    int64_t issued_at, int64_t expires_at);
/* Single-use consume: the code must exist, be unused and unexpired at `now`,
 * and its stored state_hash must equal `state_hash` (login-CSRF binding). On OK
 * it is marked used (one transaction) and the bound user/handle/hsid returned. */
store_status_t store_consume_login_code(store_t *s, const uint8_t code_hash[STORE_HASH_BYTES],
                                        const uint8_t state_hash[STORE_HASH_BYTES], int64_t now,
                                        uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out,
                                        uint8_t *handle_out, size_t handle_cap, size_t *handle_len_out);

/* --- recovery codes / enrollment tickets (primitives; policy in V4-9) --- */
store_status_t store_add_recovery_code(store_t *s, const uint8_t *user_id, size_t user_id_len,
                                       const char *pwhash_str, int64_t issued_at);
/* Marks a specific recovery code row used (by code_id). */
store_status_t store_mark_recovery_used(store_t *s, int64_t code_id, const char *used_from, int64_t used_at);
store_status_t store_add_ticket(store_t *s, const uint8_t ticket_hash[STORE_HASH_BYTES],
                                const uint8_t *user_id, size_t user_id_len,
                                int64_t issued_at, int64_t expires_at);
store_status_t store_consume_ticket(store_t *s, const uint8_t ticket_hash[STORE_HASH_BYTES], int64_t now,
                                    uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out);

/* --- audit chain ------------------------------------------------------- */
/* Copies the current head MAC (all-zero if the log is empty). */
store_status_t store_audit_head_mac(const store_t *s, uint8_t out[STORE_AUDIT_MAC_BYTES]);
/* Walks the whole chain, recomputing every MAC from key_audit; returns
 * STORE_ERR_CORRUPT on the first mismatch or a broken prev_mac link, else OK. */
store_status_t store_audit_verify(const store_t *s);

/* --- backup ------------------------------------------------------------ */
/* Consistent snapshot via `VACUUM INTO` to `dest_path` (must not exist). */
store_status_t store_backup(store_t *s, const char *dest_path);

#endif /* MLDSA_AUTHD_STORE_H */
