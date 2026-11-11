/*
 * The MLDSAEK1 envelope, read by the specification alone (V4-15c, CLAIMS D1).
 *
 * Deployment spec §12 says the envelope composes crypto_pwhash and
 * crypto_aead_xchacha20poly1305_ietf "without modifying either". Every other
 * envelope test is a round trip through keyfile.c, so a change made the same
 * way in its seal AND its open -- a shorter associated data, another Argon2
 * variant -- still round-trips. Only the client-core KAT golden would notice,
 * and that golden was produced by this same code: a regression pin, not
 * conformance. Here the envelope is read with nothing but §12's table and
 * raw libsodium, in both directions:
 *
 *   code -> spec   keyfile_seal_buf seals; raw crypto_pwhash and raw
 *                  crypto_aead_xchacha20poly1305_ietf_decrypt open it.
 *   spec -> code   raw libsodium seals, byte by byte from §12;
 *                  keyfile_open_buf opens it.
 *
 * The offsets are restated below from §12 on purpose, not taken from
 * keyfile.h: an independent reader must not share the reader under test.
 *
 * Version 0x02, the server's key file (V4-108, erratum 79), is read the same
 * two ways: its plaintext is the image followed by a 32-byte store root key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>
#include "keyfile.h"
#include "demo_keys.h"
#include "mldsa_wrap.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { printf("PASS: %s\n", msg); } \
    else { printf("FAIL: %s\n", msg); g_fail = 1; } } while (0)

/* §12, the MLDSAEK1 layout */
#define SPEC_OFF_VERSION   8u
#define SPEC_OFF_KDF       9u
#define SPEC_OFF_OPS      10u   /* big-endian, 4 bytes */
#define SPEC_OFF_MEM      14u   /* big-endian, 8 bytes */
#define SPEC_OFF_SALT     22u   /* 16 bytes */
#define SPEC_OFF_AEAD     38u
#define SPEC_OFF_NONCE    39u   /* 24 bytes */
#define SPEC_OFF_CTLEN    63u   /* big-endian, 4 bytes */
#define SPEC_HEADER       67u   /* bytes [0, 67) are the AEAD's associated data */
#define SPEC_TAG          16u
#define SPEC_KEY          32u
#define SPEC_ROOT         32u   /* version 0x02 only: the store root key after the image */
#define SPEC_OPS           1u                 /* §12's floor, so the test is quick */
#define SPEC_MEM          (8u * 1024u * 1024u)

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | (uint64_t)be32(p + 4);
}
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32)); put_be32(p + 4, (uint32_t)v);
}

static const uint8_t ID[] = { 's','r','v' };
static const char PASS[] = "spec passphrase";

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }

    mldsa_keypair_t kp;
    CHECK(mldsa_keypair_generate(&kp) == 0, "fixture: an identity");
    const size_t img_len = demo_keys_sk2_image_len(sizeof ID);
    uint8_t *img = (uint8_t *)sodium_malloc(img_len);
    uint8_t *pt = (uint8_t *)sodium_malloc(img_len);
    const size_t total = keyfile_sealed_len(img_len);
    uint8_t *env = (uint8_t *)malloc(total);
    uint8_t *env2 = (uint8_t *)malloc(total);
    if (img == NULL || pt == NULL || env == NULL || env2 == NULL) { printf("FAIL: allocation\n"); return 1; }
    CHECK(demo_keys_build_sk2_image(img, img_len, ID, sizeof ID, &kp) == DEMO_KEYS_OK, "fixture: its MLDSASK2 image");

    /* ---- code -> spec ---- */
    CHECK(keyfile_seal_buf(env, total, img, img_len, PASS, strlen(PASS), SPEC_OPS, SPEC_MEM) == KEYFILE_OK,
          "code->spec: keyfile_seal_buf seals the image (ops 1, 8 MiB)");
    CHECK(total == SPEC_HEADER + img_len + SPEC_TAG && memcmp(env, "MLDSAEK1", 8) == 0 &&
              env[SPEC_OFF_VERSION] == 0x01 && env[SPEC_OFF_KDF] == 0x01 && env[SPEC_OFF_AEAD] == 0x01 &&
              be32(env + SPEC_OFF_OPS) == SPEC_OPS && be64(env + SPEC_OFF_MEM) == SPEC_MEM &&
              be32(env + SPEC_OFF_CTLEN) == img_len + SPEC_TAG,
          "code->spec: every header field sits where §12's table puts it");

    uint8_t key[SPEC_KEY];
    CHECK(crypto_pwhash(key, sizeof key, PASS, strlen(PASS), env + SPEC_OFF_SALT,
                        (unsigned long long)be32(env + SPEC_OFF_OPS), (size_t)be64(env + SPEC_OFF_MEM),
                        crypto_pwhash_ALG_ARGON2ID13) == 0,
          "code->spec: raw crypto_pwhash (Argon2id13) derives a key from the header's own salt, ops and mem");
    unsigned long long mlen = 0;
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, env + SPEC_HEADER,
                                                     be32(env + SPEC_OFF_CTLEN), env, SPEC_HEADER,
                                                     env + SPEC_OFF_NONCE, key) == 0 &&
              mlen == img_len && memcmp(pt, img, img_len) == 0,
          "code->spec: raw XChaCha20-Poly1305 with AAD = bytes [0, 67) opens it to the exact MLDSASK2 image");
    { mldsa_keypair_t got;
      uint8_t kek[SPEC_KEY];
      CHECK(keyfile_open_buf(env, total, ID, sizeof ID, PASS, strlen(PASS), &got, kek) == KEYFILE_OK &&
                sodium_memcmp(kek, key, sizeof key) == 0,
            "code->spec: the raw key IS the KEK keyfile_open_buf derives -- same KDF, same parameters");
      mldsa_keypair_free(&got);
      sodium_memzero(kek, sizeof kek); }

    /* The negative controls: what §12 authenticates and derives is load-bearing. */
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, env + SPEC_HEADER,
                                                     be32(env + SPEC_OFF_CTLEN), NULL, 0,
                                                     env + SPEC_OFF_NONCE, key) != 0,
          "code->spec: with NO associated data the decrypt fails -- the header is authenticated");
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, env + SPEC_HEADER,
                                                     be32(env + SPEC_OFF_CTLEN), env, SPEC_OFF_CTLEN,
                                                     env + SPEC_OFF_NONCE, key) != 0,
          "code->spec: with AAD = bytes [0, 63) the decrypt fails -- ct_len is authenticated too");
    /* Argon2i's floor is opslimit 3, so the variants are compared there, on
     * the envelope's own salt and memlimit. */
    { uint8_t key_id[SPEC_KEY], key_i[SPEC_KEY];
      CHECK(crypto_pwhash(key_id, sizeof key_id, PASS, strlen(PASS), env + SPEC_OFF_SALT,
                          3ull, (size_t)SPEC_MEM, crypto_pwhash_ALG_ARGON2ID13) == 0 &&
                crypto_pwhash(key_i, sizeof key_i, PASS, strlen(PASS), env + SPEC_OFF_SALT,
                              3ull, (size_t)SPEC_MEM, crypto_pwhash_ALG_ARGON2I13) == 0 &&
                sodium_memcmp(key_i, key_id, sizeof key_id) != 0,
            "code->spec: Argon2i13 derives a DIFFERENT key from Argon2id13 -- the variant is part of the format");
      sodium_memzero(key_id, sizeof key_id);
      sodium_memzero(key_i, sizeof key_i); }
    /* ...and so is the memlimit: the key must come from the cost the header
     * states, not from some other one. */
    { uint8_t key_half[SPEC_KEY];
      CHECK(crypto_pwhash(key_half, sizeof key_half, PASS, strlen(PASS), env + SPEC_OFF_SALT,
                          (unsigned long long)SPEC_OPS, (size_t)(SPEC_MEM / 2u), crypto_pwhash_ALG_ARGON2ID13) == 0 &&
                sodium_memcmp(key_half, key, sizeof key) != 0,
            "code->spec: half the stated memlimit derives a DIFFERENT key -- the header's cost is the cost paid");
      sodium_memzero(key_half, sizeof key_half); }

    /* ---- spec -> code ---- */
    memcpy(env2, "MLDSAEK1", 8);
    env2[SPEC_OFF_VERSION] = 0x01;
    env2[SPEC_OFF_KDF] = 0x01;
    put_be32(env2 + SPEC_OFF_OPS, SPEC_OPS);
    put_be64(env2 + SPEC_OFF_MEM, SPEC_MEM);
    randombytes_buf(env2 + SPEC_OFF_SALT, 16);
    env2[SPEC_OFF_AEAD] = 0x01;
    randombytes_buf(env2 + SPEC_OFF_NONCE, 24);
    put_be32(env2 + SPEC_OFF_CTLEN, (uint32_t)(img_len + SPEC_TAG));
    uint8_t key2[SPEC_KEY];
    unsigned long long clen = 0;
    CHECK(crypto_pwhash(key2, sizeof key2, PASS, strlen(PASS), env2 + SPEC_OFF_SALT, SPEC_OPS, SPEC_MEM,
                        crypto_pwhash_ALG_ARGON2ID13) == 0 &&
              crypto_aead_xchacha20poly1305_ietf_encrypt(env2 + SPEC_HEADER, &clen, img, img_len, env2,
                                                         SPEC_HEADER, NULL, env2 + SPEC_OFF_NONCE, key2) == 0 &&
              clen == img_len + SPEC_TAG,
          "spec->code: an envelope is built from §12 with raw libsodium");
    { mldsa_keypair_t got;
      CHECK(keyfile_open_buf(env2, total, ID, sizeof ID, PASS, strlen(PASS), &got, NULL) == KEYFILE_OK &&
                memcmp(got.public_key, kp.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
            "spec->code: keyfile_open_buf opens the hand-built envelope, to the same identity");
      mldsa_keypair_free(&got); }

    /* ---- version 0x02: the server's key file (V4-108, erratum 79) ----
     * Same header, same associated data; the plaintext is the MLDSASK2 image
     * followed by a 32-byte store root key, so ct_len is 32 more. */
    { const size_t total_v2 = SPEC_HEADER + img_len + SPEC_ROOT + SPEC_TAG;
      uint8_t *env3 = (uint8_t *)malloc(total_v2);
      uint8_t *file = (uint8_t *)malloc(total_v2 + 1u);
      uint8_t *pt2 = (uint8_t *)sodium_malloc(img_len + SPEC_ROOT);
      uint8_t root[SPEC_ROOT], key3[SPEC_KEY];
      if (env3 == NULL || file == NULL || pt2 == NULL) { printf("FAIL: allocation (v2)\n"); return 1; }
      randombytes_buf(root, sizeof root);

      /* spec -> code */
      memcpy(pt2, img, img_len);
      memcpy(pt2 + img_len, root, SPEC_ROOT);
      memcpy(env3, "MLDSAEK1", 8);
      env3[SPEC_OFF_VERSION] = 0x02;
      env3[SPEC_OFF_KDF] = 0x01;
      put_be32(env3 + SPEC_OFF_OPS, SPEC_OPS);
      put_be64(env3 + SPEC_OFF_MEM, SPEC_MEM);
      randombytes_buf(env3 + SPEC_OFF_SALT, 16);
      env3[SPEC_OFF_AEAD] = 0x01;
      randombytes_buf(env3 + SPEC_OFF_NONCE, 24);
      put_be32(env3 + SPEC_OFF_CTLEN, (uint32_t)(img_len + SPEC_ROOT + SPEC_TAG));
      clen = 0;
      CHECK(crypto_pwhash(key3, sizeof key3, PASS, strlen(PASS), env3 + SPEC_OFF_SALT, SPEC_OPS, SPEC_MEM,
                          crypto_pwhash_ALG_ARGON2ID13) == 0 &&
                crypto_aead_xchacha20poly1305_ietf_encrypt(env3 + SPEC_HEADER, &clen, pt2, img_len + SPEC_ROOT,
                                                           env3, SPEC_HEADER, NULL, env3 + SPEC_OFF_NONCE,
                                                           key3) == 0 &&
                clen == img_len + SPEC_ROOT + SPEC_TAG,
            "spec->code v2: a version-2 envelope is built from §12 with raw libsodium");
      { mldsa_keypair_t got;
        uint8_t out[SPEC_KEY];
        memset(out, 0, sizeof out);
        CHECK(keyfile_open_buf(env3, total_v2, ID, sizeof ID, PASS, strlen(PASS), &got, out) == KEYFILE_OK &&
                  memcmp(got.public_key, kp.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
              "spec->code v2: keyfile_open_buf opens the hand-built version-2 envelope, to the same identity");
        CHECK(sodium_memcmp(out, root, SPEC_ROOT) == 0 && sodium_memcmp(out, key3, SPEC_KEY) != 0,
              "spec->code v2: what it returns is the sealed root key, not the passphrase-derived key");
        mldsa_keypair_free(&got);
        sodium_memzero(out, sizeof out); }

      /* code -> spec: keyfile_seal_root writes a file, raw libsodium reads it */
      { char dir[64], ek[96];
        size_t got_len = 0;
        snprintf(dir, sizeof dir, "/tmp/authd_es_XXXXXX");
        if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 1; }
        snprintf(ek, sizeof ek, "%s/srv.ek", dir);
        CHECK(keyfile_seal_root(ek, img, img_len, root, PASS, strlen(PASS), SPEC_OPS, SPEC_MEM) == KEYFILE_OK,
              "code->spec v2: keyfile_seal_root seals the image with a given root key");
        { FILE *f = fopen(ek, "rb");
          if (f != NULL) { got_len = fread(file, 1, total_v2 + 1u, f); (void)fclose(f); } }
        CHECK(got_len == total_v2 && memcmp(file, "MLDSAEK1", 8) == 0 && file[SPEC_OFF_VERSION] == 0x02 &&
                  file[SPEC_OFF_KDF] == 0x01 && file[SPEC_OFF_AEAD] == 0x01 &&
                  be32(file + SPEC_OFF_CTLEN) == img_len + SPEC_ROOT + SPEC_TAG,
              "code->spec v2: the file is 67 + image + 32 + 16 bytes, version 0x02, ct_len 32 more than version 1");
        mlen = 0;
        memset(pt2, 0, img_len + SPEC_ROOT);
        CHECK(got_len == total_v2 &&
                  crypto_pwhash(key3, sizeof key3, PASS, strlen(PASS), file + SPEC_OFF_SALT,
                                (unsigned long long)be32(file + SPEC_OFF_OPS), (size_t)be64(file + SPEC_OFF_MEM),
                                crypto_pwhash_ALG_ARGON2ID13) == 0 &&
                  crypto_aead_xchacha20poly1305_ietf_decrypt(pt2, &mlen, NULL, file + SPEC_HEADER,
                                                             be32(file + SPEC_OFF_CTLEN), file, SPEC_HEADER,
                                                             file + SPEC_OFF_NONCE, key3) == 0 &&
                  mlen == img_len + SPEC_ROOT && memcmp(pt2, img, img_len) == 0 &&
                  sodium_memcmp(pt2 + img_len, root, SPEC_ROOT) == 0,
              "code->spec v2: raw libsodium opens it to the exact image followed by the exact root key");
        (void)unlink(ek);
        (void)rmdir(dir); }

      sodium_memzero(root, sizeof root);
      sodium_memzero(key3, sizeof key3);
      sodium_free(pt2);
      free(env3);
      free(file); }

    sodium_memzero(key, sizeof key);
    sodium_memzero(key2, sizeof key2);
    sodium_free(img);
    sodium_free(pt);
    free(env);
    free(env2);
    mldsa_keypair_free(&kp);
    printf("%s: test_envelope_spec\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
