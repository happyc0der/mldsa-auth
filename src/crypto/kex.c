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

/* --- v2 hybrid key schedule (spec-v2 6.3.7) ---------------------------- */

_Static_assert(sizeof(KEX_KDF_V2_LABEL) - 1 == 17u,
               "v2 KDF label must be exactly 17 bytes");
_Static_assert(KEX_KDF_V2_INFO_MAX_LEN == (sizeof(KEX_KDF_V2_LABEL) - 1) + 1u + 1u + KEX_ID_MAX_LEN + 1u +
                                              KEX_ID_MAX_LEN + 1u + KEX_TRANSCRIPT_HASH_BYTES,
               "KEX_KDF_V2_INFO_MAX_LEN must match the normative layout");
_Static_assert(KEX_KDF_V2_INFO_MIN_LEN == (sizeof(KEX_KDF_V2_LABEL) - 1) + 1u + 1u + KEX_ID_MIN_LEN + 1u +
                                              KEX_ID_MIN_LEN + 1u + KEX_TRANSCRIPT_HASH_BYTES,
               "KEX_KDF_V2_INFO_MIN_LEN must match the normative layout");
/* The bounds spec-v2 6.3.7 states in words, pinned as numbers. (This
 * previously derived the maximum from the v1 macro; v1's key schedule was
 * deleted in V2-5, so the spec's literals are the reference.) */
_Static_assert(KEX_KDF_V2_INFO_MIN_LEN == 55u, "spec-v2 6.3.7: kdf_info minimum");
_Static_assert(KEX_KDF_V2_INFO_MAX_LEN == 181u, "spec-v2 6.3.7: kdf_info maximum");

int kex_build_kdf_info_v2(uint8_t *out, size_t out_cap, size_t *out_len,
                          const uint8_t *a_id, size_t a_id_len,
                          const uint8_t *b_id, size_t b_id_len,
                          const uint8_t th_client_auth[KEX_TRANSCRIPT_HASH_BYTES],
                          uint8_t direction) {
    static const char kLabel[] = KEX_KDF_V2_LABEL;
    const size_t label_len = sizeof(kLabel) - 1; /* the NUL is not part of the info */

    if (out == NULL || out_len == NULL || a_id == NULL || b_id == NULL || th_client_auth == NULL) {
        return -1;
    }
    if (a_id_len < KEX_ID_MIN_LEN || a_id_len > KEX_ID_MAX_LEN) {
        return -1;
    }
    if (b_id_len < KEX_ID_MIN_LEN || b_id_len > KEX_ID_MAX_LEN) {
        return -1;
    }
    if (direction != KEX_DIR_C2S && direction != KEX_DIR_S2C) {
        return -1;
    }

    const size_t needed = label_len + 1u + 1u + a_id_len + 1u + b_id_len + KEX_TRANSCRIPT_HASH_BYTES + 1u;
    if (out_cap < needed) {
        return -1;
    }

    size_t off = 0;
    memcpy(out + off, kLabel, label_len);
    off += label_len;
    out[off++] = 0x00;
    out[off++] = (uint8_t)a_id_len;
    memcpy(out + off, a_id, a_id_len);
    off += a_id_len;
    out[off++] = (uint8_t)b_id_len;
    memcpy(out + off, b_id, b_id_len);
    off += b_id_len;
    memcpy(out + off, th_client_auth, KEX_TRANSCRIPT_HASH_BYTES);
    off += KEX_TRANSCRIPT_HASH_BYTES;
    out[off++] = direction;

    *out_len = off;
    return 0;
}

int kex_derive_session_key_v2(uint8_t session_key[KEX_SESSION_KEY_BYTES],
                              const uint8_t ss_x[KEX_SHARED_SECRET_BYTES],
                              const uint8_t ss_k[KEX_SHARED_SECRET_BYTES],
                              const uint8_t *session_id, size_t session_id_len,
                              const uint8_t *a_id, size_t a_id_len,
                              const uint8_t *b_id, size_t b_id_len,
                              const uint8_t th_client_auth[KEX_TRANSCRIPT_HASH_BYTES],
                              uint8_t direction) {
    if (session_key == NULL || ss_x == NULL || ss_k == NULL || session_id == NULL) {
        return -1;
    }
    if (session_id_len != KEX_SESSION_ID_LEN) {
        return -1;
    }

    uint8_t info[KEX_KDF_V2_INFO_MAX_LEN];
    size_t info_len = 0;
    if (kex_build_kdf_info_v2(info, sizeof info, &info_len,
                              a_id, a_id_len, b_id, b_id_len, th_client_auth, direction) != 0) {
        return -1;
    }

    /* The hybrid combiner: both secrets concatenated in this fixed order
     * as HKDF-SHA256's input keying material. Nothing else combines them,
     * and neither is ever used alone. */
    uint8_t ikm[2u * KEX_SHARED_SECRET_BYTES];
    memcpy(ikm, ss_x, KEX_SHARED_SECRET_BYTES);
    memcpy(ikm + KEX_SHARED_SECRET_BYTES, ss_k, KEX_SHARED_SECRET_BYTES);

    /* Derive into scratch so session_key is untouched on failure. */
    uint8_t okm[KEX_SESSION_KEY_BYTES];
    int rc = kex_hkdf_sha256(okm, sizeof okm,
                             ikm, sizeof ikm,
                             session_id, session_id_len,
                             info, info_len);
    sodium_memzero(ikm, sizeof ikm);
    sodium_memzero(info, sizeof info);
    if (rc != 0) {
        sodium_memzero(okm, sizeof okm);
        return -1;
    }

    memcpy(session_key, okm, sizeof okm);
    sodium_memzero(okm, sizeof okm);
    return 0;
}
