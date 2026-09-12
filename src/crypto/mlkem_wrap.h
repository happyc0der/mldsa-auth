#ifndef MLDSA_AUTH_CRYPTO_MLKEM_WRAP_H
#define MLDSA_AUTH_CRYPTO_MLKEM_WRAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * ML-KEM-768 (FIPS 203) key encapsulation, wrapping liboqs's OQS_KEM.
 * No custom cryptographic primitives (Security Requirement 4.1) -- this
 * is a thin wrapper; every key-generation, encapsulation and
 * decapsulation operation happens inside liboqs (mlkem-native).
 *
 * v2 uses ML-KEM-768 as the post-quantum half of the hybrid key exchange
 * (spec-v2 6.3, 6.3.7). It is never used alone: the session key is
 * derived from the X25519 secret AND the ML-KEM secret together.
 *
 * The sizes below are liboqs's own published constants
 * (OQS_KEM_ml_kem_768_length_public_key / _secret_key / _ciphertext /
 * _shared_secret in src/kem/ml_kem/kem_ml_kem.h), matching Security
 * Requirement 4.6 (encapsulation key 1184 B, ciphertext 1088 B). They are
 * static-asserted against liboqs's macros at compile time and cross-checked
 * against the OQS_KEM object's reported lengths at run time.
 *
 * FIPS 203 vocabulary: the "encapsulation key" ek is the public key and the
 * "decapsulation key" dk is the secret key. The field names below keep the
 * mldsa_wrap convention (public_key / secret_key) so the two wrappers read
 * alike.
 *
 * FAILURE SEMANTICS (pinned by tests/test_vectors.c):
 *   - mlkem_encaps FAILS on a malformed encapsulation key: mlkem-native
 *     implements FIPS 203 7.2's modulus check.
 *   - mlkem_decaps FAILS on a corrupted decapsulation key: FIPS 203 7.3's
 *     hash check.
 *   - mlkem_decaps NEVER fails on the ciphertext. A tampered ciphertext is
 *     implicitly rejected: decapsulation returns 0 and a pseudorandom
 *     secret that does not match the encapsulator's (Security Req 4.11).
 *     Callers must not treat a successful decapsulation as proof that the
 *     ciphertext was genuine; only the record layer's authentication can
 *     show that both sides derived the same key.
 * On any failure the output buffers (ct, ss) are zeroed, never left
 * holding a partial or implicit-rejection value.
 */

#define MLKEM_PUBLIC_KEY_BYTES 1184u   /* encapsulation key ek */
#define MLKEM_SECRET_KEY_BYTES 2400u   /* decapsulation key dk (secure_mem) */
#define MLKEM_CIPHERTEXT_BYTES 1088u
#define MLKEM_SHARED_SECRET_BYTES 32u

typedef struct {
    uint8_t public_key[MLKEM_PUBLIC_KEY_BYTES];
    uint8_t *secret_key; /* secure_mem_alloc'd, MLKEM_SECRET_KEY_BYTES bytes;
                          * NULL if this keypair holds no key (freed, or
                          * generation failed). */
} mlkem_keypair_t;

/* Generates a fresh ML-KEM-768 keypair into *kp. On failure, *kp is left
 * with a zeroed public_key and a NULL secret_key -- there is nothing for
 * the caller to free. Returns 0 on success, nonzero on failure. */
int mlkem_keypair_generate(mlkem_keypair_t *kp);

/* Wipes and frees kp->secret_key (via secure_mem_free) and zeroes
 * kp->public_key. No-op if kp is NULL or already freed. */
void mlkem_keypair_free(mlkem_keypair_t *kp);

/* Encapsulates to the peer's encapsulation key: writes the ciphertext to
 * send and the shared secret to keep. The caller chooses ss's memory class
 * (the handshake passes secure_mem). Returns 0 on success; nonzero on
 * failure -- including a malformed encapsulation key -- with ct and ss
 * zeroed. */
int mlkem_encaps(uint8_t ct[MLKEM_CIPHERTEXT_BYTES],
                 uint8_t ss[MLKEM_SHARED_SECRET_BYTES],
                 const uint8_t ek[MLKEM_PUBLIC_KEY_BYTES]);

/* Decapsulates a received ciphertext with our decapsulation key. Returns 0
 * on success -- which a tampered ciphertext ALSO produces, with a different
 * secret (implicit rejection) -- and nonzero only for a NULL/freed keypair
 * or a decapsulation key that fails FIPS 203's hash check, with ss zeroed. */
int mlkem_decaps(uint8_t ss[MLKEM_SHARED_SECRET_BYTES],
                 const uint8_t ct[MLKEM_CIPHERTEXT_BYTES],
                 const mlkem_keypair_t *kp);

#endif /* MLDSA_AUTH_CRYPTO_MLKEM_WRAP_H */
