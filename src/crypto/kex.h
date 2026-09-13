#ifndef MLDSA_AUTH_CRYPTO_KEX_H
#define MLDSA_AUTH_CRYPTO_KEX_H

#include <stddef.h>
#include <stdint.h>

/*
 * X25519 ECDH + HKDF-SHA256 key exchange, via libsodium.
 *
 * v2 derives session keys from a HYBRID secret: the X25519 shared secret
 * AND the ML-KEM-768 shared secret (src/crypto/mlkem_wrap.h), combined by
 * HKDF-SHA256's extract step over IKM = ss_x || ss_k in that fixed order
 * (spec-v2 6.3.7). Neither secret is ever used alone, so the session
 * survives the failure of either assumption. The X25519 half below is
 * unchanged from v1 -- only the key schedule is hybrid.
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

/* Length of the transcript digest bound into the v2 KDF info. Mirrors
 * HANDSHAKE_TRANSCRIPT_HASH_BYTES / crypto_hash_sha256_BYTES; restated
 * here so this crypto-layer module stays independent of the protocol
 * layer, exactly like the KEX_ID and KEX_SESSION_ID_LEN constants above. */
#define KEX_TRANSCRIPT_HASH_BYTES 32u

/* Literal domain-separation label for the v2 KDF info (17 bytes, no NUL). */
#define KEX_KDF_V2_LABEL "mldsa-auth/v2/kdf"

/* 17 label + 1 separator + 1 len + id + 1 len + id + 32 digest + 1
 * direction, with each id 1..64 bytes (spec-v2 6.3.7). */
#define KEX_KDF_V2_INFO_MIN_LEN 55u
#define KEX_KDF_V2_INFO_MAX_LEN 181u

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
 * kex_derive_session_key_v2() below) so it can be tested directly against
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

/* --- v2 hybrid key schedule (spec-v2 6.3.7) ---------------------------- */

/* Builds the exact normative v2 KDF info bytes into caller-provided
 * storage:
 *
 *   kdf_info = "mldsa-auth/v2/kdf" || 0x00 ||
 *              a_id_len_u8 || a_id || b_id_len_u8 || b_id ||
 *              th_client_auth (32) || direction_u8
 *
 * The v1 layout with one fixed-length field inserted before the direction
 * byte. a_id is ALWAYS the initiator's id and b_id ALWAYS the responder's,
 * regardless of which side computes, so both peers build byte-identical
 * info. Injectivity is unchanged: each variable-length id still carries
 * its own length byte, and the label, digest and direction are all
 * fixed-length.
 *
 * th_client_auth is TH_client_auth (spec-v2 6.3.3) -- the digest sig_A is
 * verified against. Binding it makes a derived key valid only for the
 * exact transcript that produced it, which is what stops key material,
 * and in particular a captured ML-KEM ciphertext, from being transplanted
 * between handshakes.
 *
 * Validates -- all before writing a single byte -- that out/out_len/a_id/
 * b_id/th_client_auth are non-NULL, 1 <= a_id_len <= 64, 1 <= b_id_len
 * <= 64, direction is exactly KEX_DIR_C2S or KEX_DIR_S2C, and out_cap
 * holds the full result. On failure returns nonzero, writes nothing to
 * out, and leaves *out_len untouched. Exposed (not static) so tests can
 * check the exact bytes against an independently hand-built buffer. */
int kex_build_kdf_info_v2(uint8_t *out, size_t out_cap, size_t *out_len,
                          const uint8_t *a_id, size_t a_id_len,
                          const uint8_t *b_id, size_t b_id_len,
                          const uint8_t th_client_auth[KEX_TRANSCRIPT_HASH_BYTES],
                          uint8_t direction);

/* Derives one direction's session key per spec-v2 6.3.7:
 *   HKDF-SHA256(IKM  = ss_x || ss_k (64 bytes, THIS order),
 *               salt = session_id (exactly 16 bytes),
 *               info = kex_build_kdf_info_v2(...),
 *               L    = 32)
 *
 * ss_x is the X25519 shared secret (kex_shared_secret, low-order points
 * already rejected) and ss_k the ML-KEM-768 shared secret (mlkem_encaps
 * on the responder, mlkem_decaps on the initiator). HKDF's extract step
 * IS the combiner; neither secret is ever used alone, so an implementation
 * that dropped ss_k would interoperate with itself perfectly while
 * silently losing all post-quantum protection. That class of bug is
 * invisible to round-trip tests and is pinned instead by byte-exact
 * vectors computed outside this codebase (tests/test_handshake.c, D3).
 *
 * Call once per direction to get independent c2s/s2c keys that are never
 * reused bidirectionally. Returns 0 on success; on failure session_key is
 * left untouched. Every intermediate (IKM, info, scratch key) is wiped on
 * every path. */
int kex_derive_session_key_v2(uint8_t session_key[KEX_SESSION_KEY_BYTES],
                              const uint8_t ss_x[KEX_SHARED_SECRET_BYTES],
                              const uint8_t ss_k[KEX_SHARED_SECRET_BYTES],
                              const uint8_t *session_id, size_t session_id_len,
                              const uint8_t *a_id, size_t a_id_len,
                              const uint8_t *b_id, size_t b_id_len,
                              const uint8_t th_client_auth[KEX_TRANSCRIPT_HASH_BYTES],
                              uint8_t direction);

#endif /* MLDSA_AUTH_CRYPTO_KEX_H */
