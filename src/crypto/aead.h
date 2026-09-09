#ifndef MLDSA_AUTH_CRYPTO_AEAD_H
#define MLDSA_AUTH_CRYPTO_AEAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * ChaCha20-Poly1305 session encrypt/decrypt, via libsodium. Uses the
 * IETF variant specifically (12-byte nonce, 16-byte tag) -- Section 6.4's
 * wire format uses the 8-byte big-endian sequence number, zero-padded to
 * 12 bytes, as the AEAD nonce, which is the IETF variant's nonce size
 * (the original/non-IETF ChaCha20-Poly1305 construction takes an 8-byte
 * nonce and would not fit).
 */

#define AEAD_KEY_BYTES 32u   /* crypto_aead_chacha20poly1305_ietf_KEYBYTES */
#define AEAD_NONCE_BYTES 12u /* crypto_aead_chacha20poly1305_ietf_NPUBBYTES */
#define AEAD_TAG_BYTES 16u   /* crypto_aead_chacha20poly1305_ietf_ABYTES */

/* Encrypts `msg_len` bytes from `msg` (may be NULL only if msg_len == 0)
 * into `ciphertext` (caller-allocated, at least msg_len + AEAD_TAG_BYTES
 * bytes), authenticating `ad` (may be NULL only if ad_len == 0)
 * alongside it without encrypting it. Writes the actual ciphertext+tag
 * length into *ciphertext_len. Returns 0 on success, nonzero on failure
 * -- callers must not use the (possibly partially-written) output buffer
 * after a nonzero return. No internal heap allocation. */
int aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *ad, size_t ad_len,
                  const uint8_t nonce[AEAD_NONCE_BYTES],
                  const uint8_t key[AEAD_KEY_BYTES]);

/* Decrypts and authenticates `ciphertext_len` bytes from `ciphertext`
 * (which must include the trailing AEAD_TAG_BYTES-byte tag, and must be
 * at least AEAD_TAG_BYTES bytes long) into `msg` (caller-allocated, at
 * least ciphertext_len - AEAD_TAG_BYTES bytes), authenticating `ad`
 * (may be NULL only if ad_len == 0). Writes the plaintext length into
 * *msg_len. Returns 0 on success (authentication verified), nonzero on
 * ANY failure, including authentication failure -- callers MUST treat
 * every nonzero return as "reject this message" and must not use the
 * (possibly partially-written, unauthenticated) output buffer after a
 * nonzero return. No internal heap allocation. */
int aead_decrypt(uint8_t *msg, size_t *msg_len,
                  const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *ad, size_t ad_len,
                  const uint8_t nonce[AEAD_NONCE_BYTES],
                  const uint8_t key[AEAD_KEY_BYTES]);

#endif /* MLDSA_AUTH_CRYPTO_AEAD_H */
