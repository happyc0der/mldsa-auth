#include "mlkem_wrap.h"

#include "secure_mem.h"

#include <oqs/oqs.h>
#include <sodium.h>
#include <string.h>

/* A liboqs bump that changes ML-KEM-768's sizes must fail here, at compile
 * time, not at run time in a handshake. */
_Static_assert(OQS_KEM_ml_kem_768_length_public_key == MLKEM_PUBLIC_KEY_BYTES, "ML-KEM-768 ek size");
_Static_assert(OQS_KEM_ml_kem_768_length_secret_key == MLKEM_SECRET_KEY_BYTES, "ML-KEM-768 dk size");
_Static_assert(OQS_KEM_ml_kem_768_length_ciphertext == MLKEM_CIPHERTEXT_BYTES, "ML-KEM-768 ct size");
_Static_assert(OQS_KEM_ml_kem_768_length_shared_secret == MLKEM_SHARED_SECRET_BYTES, "ML-KEM-768 ss size");

/* Instantiates the KEM and cross-checks liboqs's own reported lengths
 * against the sizes this wrapper was written for (the same runtime
 * defence mldsa_wrap uses, on top of the static asserts above). */
static OQS_KEM *kem_new_checked(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return NULL;
    }
    if (kem->length_public_key != MLKEM_PUBLIC_KEY_BYTES || kem->length_secret_key != MLKEM_SECRET_KEY_BYTES ||
        kem->length_ciphertext != MLKEM_CIPHERTEXT_BYTES || kem->length_shared_secret != MLKEM_SHARED_SECRET_BYTES) {
        OQS_KEM_free(kem);
        return NULL;
    }
    return kem;
}

int mlkem_keypair_generate(mlkem_keypair_t *kp) {
    if (kp == NULL) {
        return -1;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;

    OQS_KEM *kem = kem_new_checked();
    if (kem == NULL) {
        return -1;
    }
    uint8_t *secret_key = secure_mem_alloc(MLKEM_SECRET_KEY_BYTES);
    if (secret_key == NULL) {
        OQS_KEM_free(kem);
        return -1;
    }

    const OQS_STATUS rc = OQS_KEM_keypair(kem, kp->public_key, secret_key);
    OQS_KEM_free(kem);

    /* liboqs casts mlkem-native's int status straight to OQS_STATUS, so
     * "anything but success" is the only safe test. */
    if (rc != OQS_SUCCESS) {
        secure_mem_free(secret_key, MLKEM_SECRET_KEY_BYTES);
        memset(kp->public_key, 0, sizeof(kp->public_key));
        return -1;
    }
    kp->secret_key = secret_key;
    return 0;
}

void mlkem_keypair_free(mlkem_keypair_t *kp) {
    if (kp == NULL) {
        return;
    }
    if (kp->secret_key != NULL) {
        secure_mem_free(kp->secret_key, MLKEM_SECRET_KEY_BYTES);
        kp->secret_key = NULL;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
}

int mlkem_encaps(uint8_t ct[MLKEM_CIPHERTEXT_BYTES], uint8_t ss[MLKEM_SHARED_SECRET_BYTES],
                 const uint8_t ek[MLKEM_PUBLIC_KEY_BYTES]) {
    if (ct == NULL || ss == NULL) {
        return -1;
    }
    if (ek == NULL) {
        memset(ct, 0, MLKEM_CIPHERTEXT_BYTES);
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }

    OQS_KEM *kem = kem_new_checked();
    if (kem == NULL) {
        memset(ct, 0, MLKEM_CIPHERTEXT_BYTES);
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }
    const OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, ek);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        /* FIPS 203 7.2 modulus check failed (malformed ek), or an internal
         * error: leave nothing behind that could be mistaken for a key. */
        memset(ct, 0, MLKEM_CIPHERTEXT_BYTES);
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }
    return 0;
}

int mlkem_decaps(uint8_t ss[MLKEM_SHARED_SECRET_BYTES], const uint8_t ct[MLKEM_CIPHERTEXT_BYTES],
                 const mlkem_keypair_t *kp) {
    if (ss == NULL) {
        return -1;
    }
    if (ct == NULL || kp == NULL || kp->secret_key == NULL) {
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }

    OQS_KEM *kem = kem_new_checked();
    if (kem == NULL) {
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }
    const OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, kp->secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        /* FIPS 203 7.3 hash check failed (corrupted dk), or an internal
         * error. A tampered CIPHERTEXT does not come through here: that is
         * implicit rejection, which reports success with a different ss. */
        sodium_memzero(ss, MLKEM_SHARED_SECRET_BYTES);
        return -1;
    }
    return 0;
}
