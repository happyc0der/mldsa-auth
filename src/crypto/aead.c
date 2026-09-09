#include "aead.h"

#include <sodium.h>

int aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *ad, size_t ad_len,
                  const uint8_t nonce[AEAD_NONCE_BYTES],
                  const uint8_t key[AEAD_KEY_BYTES]) {
    if (ciphertext == NULL || ciphertext_len == NULL || nonce == NULL || key == NULL) {
        return -1;
    }
    if (msg == NULL && msg_len != 0) {
        return -1;
    }
    if (ad == NULL && ad_len != 0) {
        return -1;
    }

    unsigned long long out_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &out_len,
        msg, (unsigned long long)msg_len,
        ad, (unsigned long long)ad_len,
        NULL, nonce, key);

    if (rc != 0) {
        return -1;
    }
    *ciphertext_len = (size_t)out_len;
    return 0;
}

int aead_decrypt(uint8_t *msg, size_t *msg_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *ad, size_t ad_len,
                  const uint8_t nonce[AEAD_NONCE_BYTES],
                  const uint8_t key[AEAD_KEY_BYTES]) {
    if (msg == NULL || msg_len == NULL || ciphertext == NULL || nonce == NULL || key == NULL) {
        return -1;
    }
    if (ad == NULL && ad_len != 0) {
        return -1;
    }
    if (ciphertext_len < AEAD_TAG_BYTES) {
        return -1;
    }

    unsigned long long out_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        msg, &out_len,
        NULL,
        ciphertext, (unsigned long long)ciphertext_len,
        ad, (unsigned long long)ad_len,
        nonce, key);

    if (rc != 0) {
        /* Authentication failed (or another error) -- reject. Per
         * libsodium's contract, msg's contents are unspecified on
         * failure; the caller must not use them. */
        return -1;
    }
    *msg_len = (size_t)out_len;
    return 0;
}
