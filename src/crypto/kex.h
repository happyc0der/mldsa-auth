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

/* Normative KDF direction bytes (spec §6.3). Single source of truth:
 * handshake.h's HANDSHAKE_DIR_* are direct aliases of these. */
#define KEX_DIR_C2S 0x43u /* 'C' -- initiator-to-responder */
#define KEX_DIR_S2C 0x53u /* 'S' -- responder-to-initiator */

/* Identity/salt bounds the KDF info construction enforces. These mirror
 * the wire-format constants (WIRE_ID_MIN_LEN/WIRE_ID_MAX_LEN/
 * WIRE_SESSION_ID_LEN in protocol/transcript.h); they are restated here so
 * this crypto-layer module does not depend on the protocol layer, and
 * handshake.c static-asserts the two sets are equal so they cannot drift. */
#define KEX_ID_MIN_LEN 1u
#define KEX_ID_MAX_LEN 64u
#define KEX_SESSION_ID_LEN 16u

/* Literal domain-separation label for the KDF info (17 bytes, no NUL). */
#define KEX_KDF_LABEL "mldsa-auth/v1/kdf"

/* 17 label + 1 separator + 1 len + 64 id + 1 len + 64 id + 1 direction */
#define KEX_KDF_INFO_MAX_LEN 149u

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

/* Builds the exact normative KDF info bytes (spec §6.3) into
 * caller-provided storage:
 *
 *   kdf_info = "mldsa-auth/v1/kdf" || 0x00 ||
 *              a_id_len_u8 || a_id || b_id_len_u8 || b_id || direction_u8
 *
 * a_id is ALWAYS the initiator's id and b_id ALWAYS the responder's,
 * regardless of which side computes. Each variable-length id is preceded
 * by its own length byte, which makes the encoding injective: an earlier
 * unprefixed "label || a_id || b_id || direction" form let
 * (a="ab", b="c") and (a="a", b="bc") produce identical bytes.
 *
 * Validates -- all before writing a single byte -- that out/out_len/a_id/
 * b_id are non-NULL, 1 <= a_id_len <= 64, 1 <= b_id_len <= 64, direction
 * is exactly KEX_DIR_C2S or KEX_DIR_S2C, and out_cap holds the full
 * result. On failure returns nonzero, writes nothing to out, and leaves
 * *out_len untouched. Exposed (not static) so tests can check the exact
 * bytes against an independently hand-built expected buffer. */
int kex_build_kdf_info(uint8_t *out, size_t out_cap, size_t *out_len,
                       const uint8_t *a_id, size_t a_id_len,
                       const uint8_t *b_id, size_t b_id_len,
                       uint8_t direction);

/* Derives one direction's session key per spec §6.3:
 *   HKDF-SHA256(IKM = shared_secret, salt = session_id (exactly 16 bytes),
 *               info = kex_build_kdf_info(a_id, b_id, direction), L = 32)
 * Callers pass identities with explicit lengths and never concatenate
 * anything themselves -- the info layout is owned entirely by
 * kex_build_kdf_info(), with the same validation. Call once per
 * direction to get independent c2s/s2c keys that are never reused
 * bidirectionally. Returns 0 on success; on failure session_key is left
 * untouched. */
int kex_derive_session_key(uint8_t session_key[KEX_SESSION_KEY_BYTES],
                            const uint8_t shared_secret[KEX_SHARED_SECRET_BYTES],
                            const uint8_t *session_id, size_t session_id_len,
                            const uint8_t *a_id, size_t a_id_len,
                            const uint8_t *b_id, size_t b_id_len,
                            uint8_t direction);

#endif /* MLDSA_AUTH_CRYPTO_KEX_H */
