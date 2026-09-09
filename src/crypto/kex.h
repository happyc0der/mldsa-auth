#ifndef MLDSA_AUTH_CRYPTO_KEX_H
#define MLDSA_AUTH_CRYPTO_KEX_H

#include <stddef.h>
#include <stdint.h>

/*
 * X25519 ECDH + HKDF-SHA256 key exchange, via libsodium. v1 scope:
 * classical X25519 only -- hybrid X25519 + ML-KEM-768 is deferred to a v2
 * milestone (Section 10 decision).
 */

#define KEX_PUBLIC_KEY_BYTES 32u
#define KEX_PRIVATE_KEY_BYTES 32u
#define KEX_SHARED_SECRET_BYTES 32u
#define KEX_SESSION_KEY_BYTES 32u /* == crypto_aead_chacha20poly1305_ietf_KEYBYTES */

typedef struct {
    uint8_t public_key[KEX_PUBLIC_KEY_BYTES];
    uint8_t *private_key; /* secure_mem_alloc'd, KEX_PRIVATE_KEY_BYTES bytes;
                           * NULL if this keypair holds no key. */
} kex_keypair_t;

/* Generates a fresh X25519 ephemeral keypair into *kp. Returns 0 on
 * success. On failure, *kp is left with a zeroed public_key and a NULL
 * private_key. */
int kex_keypair_generate(kex_keypair_t *kp);

/* Wipes and frees kp->private_key. No-op if kp is NULL or already
 * freed. */
void kex_keypair_free(kex_keypair_t *kp);

/* Computes the X25519 shared secret between our private key and the
 * peer's public key.
 *
 * Returns 0 on success. Returns nonzero -- with shared_secret left
 * UNTOUCHED -- if libsodium's crypto_scalarmult() rejects the input.
 * libsodium checks for and rejects known low-order/small-order Curve25519
 * points internally, but signals this ONLY via crypto_scalarmult's own
 * int return value; this function's whole job on top of calling
 * crypto_scalarmult is checking that return value and treating nonzero
 * as a hard failure. Callers MUST treat any nonzero return from this
 * function as a handshake failure and must never use the output buffer
 * after a nonzero return. */
int kex_shared_secret(uint8_t shared_secret[KEX_SHARED_SECRET_BYTES],
                       const kex_keypair_t *kp,
                       const uint8_t peer_public_key[KEX_PUBLIC_KEY_BYTES]);

/* Generic HKDF-SHA256 (RFC 5869): extract-then-expand `okm_len` bytes of
 * output keying material from `ikm`, salted with `salt`, bound to `info`.
 * Exposed at this granularity (rather than only via
 * kex_derive_session_key() below) so it can be tested directly against
 * RFC 5869's own published test vectors, independent of this project's
 * specific info-string construction.
 *
 * `salt` may be NULL iff salt_len == 0; `info` may be NULL iff
 * info_len == 0. `ikm` must not be NULL. okm_len must be
 * <= crypto_kdf_hkdf_sha256_BYTES_MAX (8160). Returns 0 on success. */
int kex_hkdf_sha256(uint8_t *okm, size_t okm_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len);

/* Derives one direction's session key per Section 6.3:
 *   HKDF-SHA256(shared_secret, salt=session_id,
 *               info = "mldsa-auth-v1" || a_id || b_id || direction)
 * `direction` is a single byte distinguishing the two directions (e.g.
 * 'C' for client-to-server, 'S' for server-to-client) -- call this twice,
 * once per direction, to get independent c2s/s2c keys that are never
 * reused bidirectionally (Section 6.3). Returns 0 on success. */
int kex_derive_session_key(uint8_t session_key[KEX_SESSION_KEY_BYTES],
                            const uint8_t shared_secret[KEX_SHARED_SECRET_BYTES],
                            const uint8_t *session_id, size_t session_id_len,
                            const uint8_t *a_id, size_t a_id_len,
                            const uint8_t *b_id, size_t b_id_len,
                            uint8_t direction);

#endif /* MLDSA_AUTH_CRYPTO_KEX_H */
