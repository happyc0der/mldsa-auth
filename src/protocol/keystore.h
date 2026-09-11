#ifndef MLDSA_AUTH_PROTOCOL_KEYSTORE_H
#define MLDSA_AUTH_PROTOCOL_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_wrap.h" /* MLDSA_PUBLIC_KEY_BYTES */
#include "transcript.h" /* WIRE_ID_MIN_LEN / WIRE_ID_MAX_LEN */

/*
 * Trust-on-first-use (TOFU) public key pinning store (spec §6.2), v1:
 * in-memory only, fixed capacity.
 *
 * Identities are opaque 1..64-byte strings compared by explicit length and
 * then byte content (sodium_memcmp) -- never as C strings: no strcmp, no
 * strlen, no reliance on NUL termination.
 *
 * Only PUBLIC keys live here, so ordinary memory is used; no secret
 * material is ever stored in or copied into the keystore. Local identity
 * private keys are borrowed by handshake contexts, never placed here.
 *
 * NOT thread-safe in v1 -- see the concurrency contract in handshake.h
 * and spec §6.3.6.
 *
 * Security Req 4.7 ("re-registration with a different key is rejected and
 * logged"): rejection is enforced here and surfaced as the distinct status
 * KEYSTORE_ERR_KEY_MISMATCH. This library has no logging facility in v1,
 * so emitting the log record is the caller's responsibility; the distinct
 * status is the hook for it.
 */

#define KEYSTORE_MAX_ENTRIES 32u /* ~64 KB total: heap- or static-allocate */

typedef enum {
    KEYSTORE_OK = 0,
    KEYSTORE_OK_ALREADY_PRESENT, /* same id + byte-identical key: idempotent */
    KEYSTORE_ERR_INVALID_ARG,
    KEYSTORE_ERR_NOT_FOUND,
    KEYSTORE_ERR_KEY_MISMATCH, /* same id, different key: never replaced */
    KEYSTORE_ERR_FULL
} keystore_status_t;

typedef struct {
    uint8_t id[WIRE_ID_MAX_LEN];
    uint8_t id_len; /* 0 = free slot, else WIRE_ID_MIN_LEN..WIRE_ID_MAX_LEN */
    uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES];
} keystore_entry_t;

typedef struct {
    keystore_entry_t entries[KEYSTORE_MAX_ENTRIES];
    size_t count;
} keystore_t;

/* Initializes an empty keystore. */
void keystore_init(keystore_t *ks);

/* Zeroes the whole keystore (idempotent). */
void keystore_wipe(keystore_t *ks);

/* Pins `public_key` for `id`. Never replaces an existing pin:
 *   - new id                        -> KEYSTORE_OK
 *   - known id, identical key       -> KEYSTORE_OK_ALREADY_PRESENT (no change)
 *   - known id, DIFFERENT key       -> KEYSTORE_ERR_KEY_MISMATCH (no change)
 *   - store full                    -> KEYSTORE_ERR_FULL (no change)
 *   - NULL args / id_len not 1..64  -> KEYSTORE_ERR_INVALID_ARG (no change) */
keystore_status_t keystore_add(keystore_t *ks, const uint8_t *id, size_t id_len,
                               const uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES]);

/* Looks up the pinned key for `id`. On KEYSTORE_OK sets *public_key_out to
 * a borrowed pointer into the keystore, valid for the keystore's lifetime
 * (entries are never moved or removed once added). On any other status
 * *public_key_out is set to NULL. Unknown id -> KEYSTORE_ERR_NOT_FOUND. */
keystore_status_t keystore_lookup(const keystore_t *ks, const uint8_t *id, size_t id_len,
                                  const uint8_t **public_key_out);

/* Number of pinned identities. */
size_t keystore_count(const keystore_t *ks);

#endif /* MLDSA_AUTH_PROTOCOL_KEYSTORE_H */
