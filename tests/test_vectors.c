/*
 * Step 2 known-answer tests for the crypto wrappers (mldsa_wrap, kex,
 * aead). Every expected value below is transcribed verbatim from an
 * external, non-invented source -- an RFC, or a vendored liboqs/
 * libsodium file -- cited at each vector. No expected value here is
 * derived from this project's own implementation; the ML-DSA-65 KAT
 * reference hash is read live from liboqs's own vendored kats.json
 * rather than copied into this source at all.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <oqs/rand_nist.h>
#include <sodium.h>

#include "mldsa_wrap.h"
#include "kex.h"
#include "aead.h"
#include "secure_mem.h"

#ifndef MLDSA_AUTH_LIBOQS_KATS_SIG_JSON
#error "MLDSA_AUTH_LIBOQS_KATS_SIG_JSON must be defined by the build (see tests/CMakeLists.txt)"
#endif

static int g_failures = 0;

#define CHECK(cond, name)                    \
    do {                                      \
        if (cond) {                           \
            printf("PASS: %s\n", name);       \
        } else {                               \
            printf("FAIL: %s\n", name);       \
            g_failures++;                      \
        }                                      \
    } while (0)

/* ---------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------- */

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len != NULL) {
        *out_len = n;
    }
    return buf;
}

/* Deliberately minimal, non-general scan for `"<alg_name>": { ... ,
 * "single": "<64 hex chars>", ... }` inside liboqs's own
 * tests/KATs/sig/kats.json -- NOT a JSON parser, just enough structure
 * to pull one field out of one specific, fixed-format vendored file. */
static int extract_single_hash(const char *json, const char *alg_name, char out[65]) {
    char needle[128];
    int n = snprintf(needle, sizeof needle, "\"%s\"", alg_name);
    if (n <= 0 || (size_t)n >= sizeof needle) {
        return -1;
    }

    const char *p = strstr(json, needle);
    if (p == NULL) {
        return -1;
    }
    p = strstr(p, "\"single\"");
    if (p == NULL) {
        return -1;
    }
    p = strchr(p, ':');
    if (p == NULL) {
        return -1;
    }
    p = strchr(p, '"');
    if (p == NULL) {
        return -1;
    }
    p++;
    const char *end = strchr(p, '"');
    if (end == NULL || (size_t)(end - p) != 64) {
        return -1;
    }
    memcpy(out, p, 64);
    out[64] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------
 * Test 1 + 2: ML-DSA-65 KAT, and tampered-input rejection.
 *
 * Test 1 reproduces liboqs's own official single-vector KAT record
 * (count = 0) by driving liboqs's public deterministic NIST-KAT RNG API
 * through OUR mldsa_wrap functions, in the exact format liboqs's own
 * tests/kat_sig.c emits, then compares SHA-256(record) against the
 * "single" hash for "ML-DSA-65" read live from liboqs's vendored
 * tests/KATs/sig/kats.json.
 * ------------------------------------------------------------------- */

static uint8_t g_kat_msg[64];
static size_t g_kat_msg_len = 0;
static uint8_t g_kat_sig[MLDSA_SIGNATURE_MAX_BYTES];
static size_t g_kat_sig_len = 0;
static uint8_t g_kat_pk[MLDSA_PUBLIC_KEY_BYTES];
static int g_kat_available = 0;

static void append_hex(char *buf, size_t buf_cap, size_t *off, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len && *off + 2 < buf_cap; i++) {
        int n = snprintf(buf + *off, buf_cap - *off, "%02X", data[i]);
        if (n > 0) {
            *off += (size_t)n;
        }
    }
}

static void test_mldsa65_kat(void) {
    /* Same seeding liboqs's own tests/kat_sig.c uses (entropy_input[i] =
     * i, then draw this record's own seed + message from that stream). */
    uint8_t entropy_input[48];
    for (size_t i = 0; i < sizeof entropy_input; i++) {
        entropy_input[i] = (uint8_t)i;
    }

    OQS_randombytes_nist_kat_init_256bit(entropy_input, NULL);
    OQS_randombytes_custom_algorithm(OQS_randombytes_nist_kat);

    uint8_t seed[48];
    OQS_randombytes(seed, sizeof seed);

    const size_t msg_len = 33; /* count = 0 -> mlen = 33 * (count + 1) */
    uint8_t msg[33];
    OQS_randombytes(msg, msg_len);

    /* Reseed with this record's own seed before keypair/sign, exactly
     * like liboqs's OQS_KAT_PRNG_seed(prng, seed, NULL). */
    OQS_randombytes_nist_kat_init_256bit(seed, NULL);

    mldsa_keypair_t kp;
    if (mldsa_keypair_generate(&kp) != 0) {
        printf("FAIL: mldsa65_kat (mldsa_keypair_generate failed)\n");
        g_failures++;
        return;
    }

    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sig_len = 0;
    if (mldsa_sign(sig, &sig_len, msg, msg_len, &kp) != 0) {
        printf("FAIL: mldsa65_kat (mldsa_sign failed)\n");
        mldsa_keypair_free(&kp);
        g_failures++;
        return;
    }

    int verify_ok = (mldsa_verify(msg, msg_len, sig, sig_len, kp.public_key) == 0);

    /* Build the record text in liboqs's own kat_sig.c format:
     *   count = 0
     *   seed = <hex>
     *   mlen = <dec>
     *   msg = <hex>
     *   pk = <hex>
     *   sk = <hex>
     *   smlen = <dec>
     *   sm = <hex of sig || msg>
     * (no trailing blank line -- this is the only/last record). */
    static char record[32768];
    size_t off = 0;
    off += (size_t)snprintf(record + off, sizeof record - off, "count = 0\n");
    off += (size_t)snprintf(record + off, sizeof record - off, "seed = ");
    append_hex(record, sizeof record, &off, seed, sizeof seed);
    off += (size_t)snprintf(record + off, sizeof record - off, "\n");
    off += (size_t)snprintf(record + off, sizeof record - off, "mlen = %zu\n", msg_len);
    off += (size_t)snprintf(record + off, sizeof record - off, "msg = ");
    append_hex(record, sizeof record, &off, msg, msg_len);
    off += (size_t)snprintf(record + off, sizeof record - off, "\n");
    off += (size_t)snprintf(record + off, sizeof record - off, "pk = ");
    append_hex(record, sizeof record, &off, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
    off += (size_t)snprintf(record + off, sizeof record - off, "\n");
    off += (size_t)snprintf(record + off, sizeof record - off, "sk = ");
    append_hex(record, sizeof record, &off, kp.secret_key, MLDSA_SECRET_KEY_BYTES);
    off += (size_t)snprintf(record + off, sizeof record - off, "\n");
    off += (size_t)snprintf(record + off, sizeof record - off, "smlen = %zu\n", sig_len + msg_len);
    off += (size_t)snprintf(record + off, sizeof record - off, "sm = ");
    append_hex(record, sizeof record, &off, sig, sig_len);
    append_hex(record, sizeof record, &off, msg, msg_len);
    off += (size_t)snprintf(record + off, sizeof record - off, "\n");

    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, (const unsigned char *)record, off);
    char digest_hex[2 * crypto_hash_sha256_BYTES + 1];
    sodium_bin2hex(digest_hex, sizeof digest_hex, digest, sizeof digest);

    size_t json_len = 0;
    char *json = read_file(MLDSA_AUTH_LIBOQS_KATS_SIG_JSON, &json_len);
    if (json == NULL) {
        fprintf(stderr,
                "FAIL: mldsa65_kat -- expected liboqs KAT reference file not found at: %s\n"
                "      (partial rebuild? liboqs's KAT-file layout changed?)\n",
                MLDSA_AUTH_LIBOQS_KATS_SIG_JSON);
        g_failures++;
        mldsa_keypair_free(&kp);
        return;
    }

    char expected_hash[65];
    int found = (extract_single_hash(json, "ML-DSA-65", expected_hash) == 0);
    free(json);

    if (!found) {
        fprintf(stderr,
                "FAIL: mldsa65_kat -- could not find \"ML-DSA-65\".\"single\" inside: %s\n",
                MLDSA_AUTH_LIBOQS_KATS_SIG_JSON);
        g_failures++;
        mldsa_keypair_free(&kp);
        return;
    }

    int hash_matches = (strcasecmp(digest_hex, expected_hash) == 0);
    CHECK(verify_ok, "mldsa65_kat: mldsa_verify accepts the freshly-generated signature");
    CHECK(hash_matches, "mldsa65_kat: SHA-256(KAT record) matches liboqs's published single-vector hash");

    if (verify_ok && hash_matches) {
        memcpy(g_kat_msg, msg, msg_len);
        g_kat_msg_len = msg_len;
        memcpy(g_kat_sig, sig, sig_len);
        g_kat_sig_len = sig_len;
        memcpy(g_kat_pk, kp.public_key, sizeof kp.public_key);
        g_kat_available = 1;
    }

    mldsa_keypair_free(&kp);
}

static void test_mldsa65_tampered_rejection(void) {
    if (!g_kat_available) {
        printf("FAIL: mldsa65_tampered_rejection (no valid KAT triple from test 1 -- skipped)\n");
        g_failures++;
        return;
    }

    uint8_t tampered_msg[sizeof g_kat_msg];
    memcpy(tampered_msg, g_kat_msg, g_kat_msg_len);
    tampered_msg[0] ^= 0x01; /* flip a single bit of the message */

    int msg_rc = mldsa_verify(tampered_msg, g_kat_msg_len, g_kat_sig, g_kat_sig_len, g_kat_pk);
    CHECK(msg_rc != 0, "mldsa65_tampered_rejection: verify rejects a single flipped message byte");

    uint8_t tampered_sig[sizeof g_kat_sig];
    memcpy(tampered_sig, g_kat_sig, g_kat_sig_len);
    tampered_sig[0] ^= 0x01; /* flip a single bit of the signature */

    int sig_rc = mldsa_verify(g_kat_msg, g_kat_msg_len, tampered_sig, g_kat_sig_len, g_kat_pk);
    CHECK(sig_rc != 0, "mldsa65_tampered_rejection: verify rejects a single flipped signature byte");
}

/* ---------------------------------------------------------------------
 * Test 3 + 4: X25519 RFC 7748 vector, and low-order-point rejection.
 *
 * alice_sk / bob_sk and the small-order point are the exact bytes from
 * libsodium's own vendored test/default/scalarmult.c; the expected
 * public keys and shared secret are libsodium's own recorded expected
 * output for that test (test/default/scalarmult.exp) -- these are also
 * RFC 7748 Section 6.1's published values verbatim.
 * ------------------------------------------------------------------- */

static const uint8_t RFC7748_ALICE_SK[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
    0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
};

static const uint8_t RFC7748_BOB_SK[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
    0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
};

static const uint8_t RFC7748_ALICE_PK_EXPECTED[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
    0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
};

static const uint8_t RFC7748_BOB_PK_EXPECTED[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2,
    0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
};

static const uint8_t RFC7748_SHARED_SECRET_EXPECTED[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4,
    0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
    0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
};

static const uint8_t X25519_SMALL_ORDER_POINT[32] = {
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa,
    0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
    0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
};

/* Builds a kex_keypair_t from a known private scalar (for feeding fixed
 * RFC test vectors through the real kex_* functions, rather than
 * generating a random keypair). Aborts the test run on allocation
 * failure -- this is test-only scaffolding, not library code. */
static void kex_keypair_from_known_sk(kex_keypair_t *kp, const uint8_t sk[KEX_PRIVATE_KEY_BYTES]) {
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->private_key = secure_mem_alloc(KEX_PRIVATE_KEY_BYTES);
    if (kp->private_key == NULL) {
        fprintf(stderr, "FATAL: secure_mem_alloc failed in test helper\n");
        exit(EXIT_FAILURE);
    }
    memcpy(kp->private_key, sk, KEX_PRIVATE_KEY_BYTES);
}

static void test_x25519_rfc7748_vector(void) {
    kex_keypair_t alice = {0}, bob = {0};
    kex_keypair_from_known_sk(&alice, RFC7748_ALICE_SK);
    kex_keypair_from_known_sk(&bob, RFC7748_BOB_SK);

    CHECK(crypto_scalarmult_base(alice.public_key, alice.private_key) == 0 &&
              memcmp(alice.public_key, RFC7748_ALICE_PK_EXPECTED, 32) == 0,
          "x25519_rfc7748: Alice's derived public key matches RFC 7748 Section 6.1");
    CHECK(crypto_scalarmult_base(bob.public_key, bob.private_key) == 0 &&
              memcmp(bob.public_key, RFC7748_BOB_PK_EXPECTED, 32) == 0,
          "x25519_rfc7748: Bob's derived public key matches RFC 7748 Section 6.1");

    uint8_t shared_a[KEX_SHARED_SECRET_BYTES];
    uint8_t shared_b[KEX_SHARED_SECRET_BYTES];
    int rc_a = kex_shared_secret(shared_a, &alice, bob.public_key);
    int rc_b = kex_shared_secret(shared_b, &bob, alice.public_key);

    CHECK(rc_a == 0 && memcmp(shared_a, RFC7748_SHARED_SECRET_EXPECTED, 32) == 0,
          "x25519_rfc7748: kex_shared_secret(Alice, Bob's pk) matches RFC 7748 Section 6.1");
    CHECK(rc_b == 0 && memcmp(shared_b, RFC7748_SHARED_SECRET_EXPECTED, 32) == 0,
          "x25519_rfc7748: kex_shared_secret(Bob, Alice's pk) matches RFC 7748 Section 6.1");

    kex_keypair_free(&alice);
    kex_keypair_free(&bob);
}

static void test_x25519_low_order_point_rejection(void) {
    kex_keypair_t bob = {0};
    kex_keypair_from_known_sk(&bob, RFC7748_BOB_SK);

    uint8_t shared[KEX_SHARED_SECRET_BYTES];
    memset(shared, 0x42, sizeof shared); /* sentinel: must remain untouched on rejection */
    int rc = kex_shared_secret(shared, &bob, X25519_SMALL_ORDER_POINT);

    /* libsodium's own test/default/scalarmult.c asserts
     * crypto_scalarmult(k, bobsk, small_order_p) == -1 for this exact
     * vector -- kex_shared_secret() must propagate that rejection, not
     * silently accept whatever landed in the output buffer. */
    CHECK(rc != 0, "x25519_low_order_point: kex_shared_secret rejects a known low-order point");

    static const uint8_t sentinel[KEX_SHARED_SECRET_BYTES] = {
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    };
    CHECK(memcmp(shared, sentinel, sizeof shared) == 0,
          "x25519_low_order_point: output buffer left untouched on rejection");

    kex_keypair_free(&bob);
}

/* ---------------------------------------------------------------------
 * Test 5: HKDF-SHA256, RFC 5869 Appendix A.1 Test Case 1.
 * ------------------------------------------------------------------- */

static const uint8_t RFC5869_IKM[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const uint8_t RFC5869_SALT[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c,
};

static const uint8_t RFC5869_INFO[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};

static const uint8_t RFC5869_OKM_EXPECTED[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
    0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
    0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
};

static void test_hkdf_rfc5869_vector(void) {
    uint8_t okm[sizeof RFC5869_OKM_EXPECTED];
    int rc = kex_hkdf_sha256(okm, sizeof okm,
                              RFC5869_IKM, sizeof RFC5869_IKM,
                              RFC5869_SALT, sizeof RFC5869_SALT,
                              RFC5869_INFO, sizeof RFC5869_INFO);
    CHECK(rc == 0 && memcmp(okm, RFC5869_OKM_EXPECTED, sizeof okm) == 0,
          "hkdf_rfc5869: kex_hkdf_sha256 matches RFC 5869 Appendix A.1 Test Case 1");
}

/* ---------------------------------------------------------------------
 * Test 6: ChaCha20-Poly1305 IETF, RFC 8439 vector (via libsodium's own
 * vendored test/default/aead_chacha20poly13052.c, tests[0]).
 * ------------------------------------------------------------------- */

static const uint8_t RFC8439_KEY[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
    0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

static const uint8_t RFC8439_NONCE[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};

static const uint8_t RFC8439_AD[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

static const uint8_t RFC8439_PLAINTEXT[114] = {
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
    0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
    0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
    0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
    0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
    0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
};

static const uint8_t RFC8439_CIPHERTEXT_EXPECTED[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
};

static const uint8_t RFC8439_TAG_EXPECTED[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
    0xd0, 0x60, 0x06, 0x91,
};

static void test_chacha20poly1305_rfc8439_vector(void) {
    uint8_t ciphertext[sizeof RFC8439_PLAINTEXT + AEAD_TAG_BYTES];
    size_t ciphertext_len = 0;
    int enc_rc = aead_encrypt(ciphertext, &ciphertext_len,
                               RFC8439_PLAINTEXT, sizeof RFC8439_PLAINTEXT,
                               RFC8439_AD, sizeof RFC8439_AD,
                               RFC8439_NONCE, RFC8439_KEY);

    int ct_matches = (enc_rc == 0) &&
                      (ciphertext_len == sizeof RFC8439_PLAINTEXT + AEAD_TAG_BYTES) &&
                      (memcmp(ciphertext, RFC8439_CIPHERTEXT_EXPECTED, sizeof RFC8439_CIPHERTEXT_EXPECTED) == 0) &&
                      (memcmp(ciphertext + sizeof RFC8439_CIPHERTEXT_EXPECTED, RFC8439_TAG_EXPECTED, AEAD_TAG_BYTES) == 0);
    CHECK(ct_matches, "chacha20poly1305_rfc8439: aead_encrypt matches RFC 8439's published ciphertext+tag");

    uint8_t decrypted[sizeof RFC8439_PLAINTEXT];
    size_t decrypted_len = 0;
    int dec_rc = aead_decrypt(decrypted, &decrypted_len,
                               ciphertext, ciphertext_len,
                               RFC8439_AD, sizeof RFC8439_AD,
                               RFC8439_NONCE, RFC8439_KEY);
    CHECK(dec_rc == 0 && decrypted_len == sizeof RFC8439_PLAINTEXT &&
              memcmp(decrypted, RFC8439_PLAINTEXT, sizeof RFC8439_PLAINTEXT) == 0,
          "chacha20poly1305_rfc8439: aead_decrypt recovers the original plaintext");

    /* Tamper with one ciphertext byte and confirm decryption fails --
     * the same "rejection path actually rejects" principle as tests 2
     * and 4, applied to the AEAD tag check. */
    uint8_t tampered[sizeof ciphertext];
    memcpy(tampered, ciphertext, ciphertext_len);
    tampered[0] ^= 0x01;
    uint8_t scratch[sizeof RFC8439_PLAINTEXT];
    size_t scratch_len = 0;
    int tamper_rc = aead_decrypt(scratch, &scratch_len, tampered, ciphertext_len,
                                  RFC8439_AD, sizeof RFC8439_AD, RFC8439_NONCE, RFC8439_KEY);
    CHECK(tamper_rc != 0, "chacha20poly1305_rfc8439: aead_decrypt rejects a tampered ciphertext");
}

/* ---------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------- */

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return EXIT_FAILURE;
    }
    OQS_init();

    test_mldsa65_kat();
    test_mldsa65_tampered_rejection();
    test_x25519_rfc7748_vector();
    test_x25519_low_order_point_rejection();
    test_hkdf_rfc5869_vector();
    test_chacha20poly1305_rfc8439_vector();

    OQS_destroy();

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
