#ifndef MLDSA_AUTH_CRYPTO_MLDSA_WRAP_H
#define MLDSA_AUTH_CRYPTO_MLDSA_WRAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * ML-DSA-65 (FIPS 204) signing/verification, wrapping liboqs's OQS_SIG.
 * No custom cryptographic primitives (Security Requirement 4.1) -- this
 * is a thin wrapper; all actual signing/verification happens inside
 * liboqs.
 *
 * The sizes below are liboqs's own published constants for ML-DSA-65
 * (OQS_SIG_ml_dsa_65_length_public_key / _length_secret_key /
 * _length_signature, confirmed in liboqs's src/sig/ml_dsa/sig_ml_dsa.h),
 * matching Security Requirement 4.6 exactly (1952 / -- / 3309 bytes).
 * mldsa_keypair_generate() cross-checks them against liboqs's own
 * reported lengths at runtime rather than trusting the macros blindly.
 *
 * ML-DSA-65 signatures are fixed-length (not variable up to a maximum):
 * every valid signature is exactly MLDSA_SIGNATURE_MAX_BYTES long.
 */

#define MLDSA_PUBLIC_KEY_BYTES 1952u
#define MLDSA_SECRET_KEY_BYTES 4032u
#define MLDSA_SIGNATURE_MAX_BYTES 3309u

typedef struct {
    uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES];
    uint8_t *secret_key; /* secure_mem_alloc'd, MLDSA_SECRET_KEY_BYTES bytes;
                          * NULL if this keypair holds no key (freed, or
                          * generation failed). */
} mldsa_keypair_t;

/* Generates a fresh ML-DSA-65 keypair into *kp. On failure, *kp is left
 * with a zeroed public_key and a NULL secret_key -- there is nothing for
 * the caller to free. Returns 0 on success, nonzero on failure. */
int mldsa_keypair_generate(mldsa_keypair_t *kp);

/* Wipes and frees kp->secret_key (via secure_mem_free) and zeroes
 * kp->public_key. No-op if kp is NULL or already freed. */
void mldsa_keypair_free(mldsa_keypair_t *kp);

/* Signs `msg` (msg_len bytes, may be NULL only if msg_len == 0) with
 * kp->secret_key. Writes the signature into sig_out (caller-allocated,
 * at least MLDSA_SIGNATURE_MAX_BYTES bytes) and sets *sig_len to the
 * actual signature length. Returns 0 on success, nonzero on failure
 * (including a NULL/freed kp->secret_key). */
int mldsa_sign(uint8_t *sig_out, size_t *sig_len,
               const uint8_t *msg, size_t msg_len,
               const mldsa_keypair_t *kp);

/* Verifies `sig` (sig_len bytes) over `msg` (msg_len bytes, may be NULL
 * only if msg_len == 0) against public_key. Returns 0 if and only if the
 * signature is valid; returns nonzero for an invalid signature OR any
 * other error -- callers must treat every nonzero return as "reject",
 * with no distinction between "invalid" and "couldn't check". */
int mldsa_verify(const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len,
                  const uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES]);

#endif /* MLDSA_AUTH_CRYPTO_MLDSA_WRAP_H */
