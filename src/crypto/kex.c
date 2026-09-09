#include "kex.h"

#include "secure_mem.h"

#include <sodium.h>
#include <string.h>

int kex_keypair_generate(kex_keypair_t *kp) {
    if (kp == NULL) {
        return -1;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->private_key = NULL;

    uint8_t *sk = secure_mem_alloc(KEX_PRIVATE_KEY_BYTES);
    if (sk == NULL) {
        return -1;
    }
    randombytes_buf(sk, KEX_PRIVATE_KEY_BYTES);

    if (crypto_scalarmult_base(kp->public_key, sk) != 0) {
        secure_mem_free(sk, KEX_PRIVATE_KEY_BYTES);
        memset(kp->public_key, 0, sizeof(kp->public_key));
        return -1;
    }

    kp->private_key = sk;
    return 0;
}

void kex_keypair_free(kex_keypair_t *kp) {
    if (kp == NULL) {
        return;
    }
    if (kp->private_key != NULL) {
        secure_mem_free(kp->private_key, KEX_PRIVATE_KEY_BYTES);
        kp->private_key = NULL;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
}

int kex_shared_secret(uint8_t shared_secret[KEX_SHARED_SECRET_BYTES],
                       const kex_keypair_t *kp,
                       const uint8_t peer_public_key[KEX_PUBLIC_KEY_BYTES]) {
    if (shared_secret == NULL || kp == NULL || kp->private_key == NULL || peer_public_key == NULL) {
        return -1;
    }

    uint8_t tmp[KEX_SHARED_SECRET_BYTES];
    int rc = crypto_scalarmult(tmp, kp->private_key, peer_public_key);
    if (rc != 0) {
        /* crypto_scalarmult() returns nonzero when it rejects the input
         * (e.g. a known low-order/small-order point) -- this is the
         * check the whole function exists for. Hard failure: wipe the
         * scratch buffer and never let its contents reach the caller. */
        sodium_memzero(tmp, sizeof tmp);
        return -1;
    }

    memcpy(shared_secret, tmp, sizeof tmp);
    sodium_memzero(tmp, sizeof tmp);
    return 0;
}

int kex_hkdf_sha256(uint8_t *okm, size_t okm_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len) {
    if (okm == NULL || ikm == NULL) {
        return -1;
    }
    if (salt == NULL && salt_len != 0) {
        return -1;
    }
    if (info == NULL && info_len != 0) {
        return -1;
    }
    if (okm_len > crypto_kdf_hkdf_sha256_BYTES_MAX) {
        return -1;
    }

    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    int rc = crypto_kdf_hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len);
    if (rc != 0) {
        sodium_memzero(prk, sizeof prk);
        return -1;
    }

    rc = crypto_kdf_hkdf_sha256_expand(okm, okm_len, (const char *)info, info_len, prk);
    sodium_memzero(prk, sizeof prk);
    return (rc == 0) ? 0 : -1;
}

int kex_derive_session_key(uint8_t session_key[KEX_SESSION_KEY_BYTES],
                            const uint8_t shared_secret[KEX_SHARED_SECRET_BYTES],
                            const uint8_t *session_id, size_t session_id_len,
                            const uint8_t *a_id, size_t a_id_len,
                            const uint8_t *b_id, size_t b_id_len,
                            uint8_t direction) {
    static const char kLabel[] = "mldsa-auth-v1";
    const size_t label_len = sizeof(kLabel) - 1; /* exclude the NUL */

    if (session_key == NULL || shared_secret == NULL) {
        return -1;
    }
    if (session_id == NULL && session_id_len != 0) {
        return -1;
    }
    if (a_id == NULL && a_id_len != 0) {
        return -1;
    }
    if (b_id == NULL && b_id_len != 0) {
        return -1;
    }

    /* client_id is spec'd as UTF-8, <= 64 bytes (Section 6.1), so two of
     * them plus the fixed label and a 1-byte direction comfortably fit a
     * generous fixed-size stack buffer without needing a heap allocation
     * here. */
    uint8_t info[16 + 64 + 64 + 1];
    if (label_len + a_id_len + b_id_len + 1 > sizeof(info)) {
        return -1;
    }

    size_t off = 0;
    memcpy(info + off, kLabel, label_len);
    off += label_len;
    if (a_id_len > 0) {
        memcpy(info + off, a_id, a_id_len);
        off += a_id_len;
    }
    if (b_id_len > 0) {
        memcpy(info + off, b_id, b_id_len);
        off += b_id_len;
    }
    info[off] = direction;
    off += 1;

    int rc = kex_hkdf_sha256(session_key, KEX_SESSION_KEY_BYTES,
                              shared_secret, KEX_SHARED_SECRET_BYTES,
                              session_id, session_id_len,
                              info, off);
    sodium_memzero(info, sizeof info);
    return rc;
}
