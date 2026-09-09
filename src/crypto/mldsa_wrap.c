#include "mldsa_wrap.h"

#include "secure_mem.h"

#include <oqs/oqs.h>
#include <string.h>

#define MLDSA_ALG_NAME "ML-DSA-65"

int mldsa_keypair_generate(mldsa_keypair_t *kp) {
    if (kp == NULL) {
        return -1;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;

    OQS_SIG *sig = OQS_SIG_new(MLDSA_ALG_NAME);
    if (sig == NULL) {
        return -1;
    }
    if (sig->length_public_key != MLDSA_PUBLIC_KEY_BYTES ||
        sig->length_secret_key != MLDSA_SECRET_KEY_BYTES) {
        /* liboqs's own reported sizes disagree with what this wrapper was
         * written against -- refuse rather than risk a buffer mismatch. */
        OQS_SIG_free(sig);
        return -1;
    }

    uint8_t *secret_key = secure_mem_alloc(MLDSA_SECRET_KEY_BYTES);
    if (secret_key == NULL) {
        OQS_SIG_free(sig);
        return -1;
    }

    OQS_STATUS rc = OQS_SIG_keypair(sig, kp->public_key, secret_key);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        secure_mem_free(secret_key, MLDSA_SECRET_KEY_BYTES);
        memset(kp->public_key, 0, sizeof(kp->public_key));
        return -1;
    }

    kp->secret_key = secret_key;
    return 0;
}

void mldsa_keypair_free(mldsa_keypair_t *kp) {
    if (kp == NULL) {
        return;
    }
    if (kp->secret_key != NULL) {
        secure_mem_free(kp->secret_key, MLDSA_SECRET_KEY_BYTES);
        kp->secret_key = NULL;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
}

int mldsa_sign(uint8_t *sig_out, size_t *sig_len,
               const uint8_t *msg, size_t msg_len,
               const mldsa_keypair_t *kp) {
    if (sig_out == NULL || sig_len == NULL || kp == NULL || kp->secret_key == NULL) {
        return -1;
    }
    if (msg == NULL && msg_len != 0) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(MLDSA_ALG_NAME);
    if (sig == NULL) {
        return -1;
    }
    if (sig->length_signature != MLDSA_SIGNATURE_MAX_BYTES) {
        OQS_SIG_free(sig);
        return -1;
    }

    size_t out_len = 0;
    OQS_STATUS rc = OQS_SIG_sign(sig, sig_out, &out_len, msg, msg_len, kp->secret_key);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        return -1;
    }
    *sig_len = out_len;
    return 0;
}

int mldsa_verify(const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig_bytes, size_t sig_len,
                  const uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES]) {
    if (sig_bytes == NULL || public_key == NULL) {
        return -1;
    }
    if (msg == NULL && msg_len != 0) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(MLDSA_ALG_NAME);
    if (sig == NULL) {
        return -1;
    }

    OQS_STATUS rc = OQS_SIG_verify(sig, msg, msg_len, sig_bytes, sig_len, public_key);
    OQS_SIG_free(sig);

    return (rc == OQS_SUCCESS) ? 0 : -1;
}
