/*
 * Per-primitive costs (spec §5.2: "benchmarked individually as well as
 * end-to-end, so regressions are traceable to a specific operation").
 *
 * Every row here is one public API call with its state prepared outside the
 * timed region. Keys come from the real RNG; nothing secret is printed.
 */

#include "bench_common.h"

#include "aead.h"
#include "demo_keys.h"
#include "kex.h"
#include "mldsa_wrap.h"
#include "transcript.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TH_LEN 32u /* the protocol signs a 32-byte transcript hash */

static const uint8_t ID_A[] = "alice";
static const uint8_t ID_B[] = "bob";

/* One shared fixture: real keys, real messages, buffers sized from the
 * wire-format maxima so nothing allocates inside a timed region. */
typedef struct {
    mldsa_keypair_t sig_kp;
    kex_keypair_t kex_kp;
    kex_keypair_t kex_peer;

    uint8_t th[TH_LEN];
    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sig_len;

    uint8_t shared[KEX_SHARED_SECRET_BYTES];
    uint8_t session_key[KEX_SESSION_KEY_BYTES];
    uint8_t kdf_info[KEX_KDF_INFO_MAX_LEN];
    size_t kdf_info_len;
    uint8_t session_id[KEX_SESSION_ID_LEN];

    client_hello_t ch;
    server_hello_t sh;
    client_auth_t ca;
    uint8_t ch_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh_bytes[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t shu_bytes[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
    uint8_t ca_bytes[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len;
    size_t sh_len;
    size_t shu_len;
    size_t ca_len;
    uint8_t digest[32];

    uint8_t aead_key[AEAD_KEY_BYTES];
    uint8_t aead_nonce[AEAD_NONCE_BYTES];
    uint8_t ad[47];
    size_t payload_len;
    uint8_t *pt;
    uint8_t *ct;
    uint8_t *out;
    size_t ct_len;

    char key_dir[512];
    char key_path[600];
} fix_t;

static fix_t g;

/* ---- setup --------------------------------------------------------------- */

static void build_messages(void) {
    memcpy(g.ch.id, ID_A, sizeof(ID_A) - 1u);
    g.ch.id_len = (uint8_t)(sizeof(ID_A) - 1u);
    memcpy(g.ch.ephemeral_pub, g.kex_kp.public_key, KEX_PUBLIC_KEY_BYTES);
    randombytes_buf(g.ch.session_id, sizeof(g.ch.session_id));
    randombytes_buf(g.ch.nonce, sizeof(g.ch.nonce));
    BENCH_REQUIRE(encode_client_hello(&g.ch, g.ch_bytes, sizeof(g.ch_bytes), &g.ch_len) == 0,
                  "encode_client_hello");

    memcpy(g.sh.id, ID_B, sizeof(ID_B) - 1u);
    g.sh.id_len = (uint8_t)(sizeof(ID_B) - 1u);
    memcpy(g.sh.ephemeral_pub, g.kex_peer.public_key, KEX_PUBLIC_KEY_BYTES);
    randombytes_buf(g.sh.nonce, sizeof(g.sh.nonce));
    memcpy(g.sh.session_id_echo, g.ch.session_id, sizeof(g.ch.session_id));
    BENCH_REQUIRE(encode_server_hello_unsigned(&g.sh, g.shu_bytes, sizeof(g.shu_bytes), &g.shu_len) == 0,
                  "encode_server_hello_unsigned");
    BENCH_REQUIRE(transcript_hash_server_auth(g.ch_bytes, g.ch_len, g.shu_bytes, g.shu_len, g.th) == 0,
                  "transcript_hash_server_auth");
    BENCH_REQUIRE(mldsa_sign(g.sig, &g.sig_len, g.th, TH_LEN, &g.sig_kp) == 0, "mldsa_sign");
    memcpy(g.sh.sig, g.sig, g.sig_len);
    g.sh.sig_len = (uint16_t)g.sig_len;
    BENCH_REQUIRE(encode_server_hello(&g.sh, g.sh_bytes, sizeof(g.sh_bytes), &g.sh_len) == 0,
                  "encode_server_hello");

    BENCH_REQUIRE(transcript_handshake_id(g.ch_bytes, g.ch_len, g.sh_bytes, g.sh_len, g.ca.handshake_id) == 0,
                  "transcript_handshake_id");
    memcpy(g.ca.sig, g.sig, g.sig_len);
    g.ca.sig_len = (uint16_t)g.sig_len;
    BENCH_REQUIRE(encode_client_auth(&g.ca, g.ca_bytes, sizeof(g.ca_bytes), &g.ca_len) == 0,
                  "encode_client_auth");
}

static void setup(void) {
    BENCH_REQUIRE(mldsa_keypair_generate(&g.sig_kp) == 0, "mldsa_keypair_generate");
    BENCH_REQUIRE(kex_keypair_generate(&g.kex_kp) == 0 && kex_keypair_generate(&g.kex_peer) == 0,
                  "kex_keypair_generate");
    randombytes_buf(g.session_id, sizeof(g.session_id));
    randombytes_buf(g.aead_key, sizeof(g.aead_key));
    randombytes_buf(g.aead_nonce, sizeof(g.aead_nonce));
    randombytes_buf(g.ad, sizeof(g.ad));
    build_messages();

    g.pt = malloc(65536u);
    g.ct = malloc(65536u + AEAD_TAG_BYTES);
    g.out = malloc(65536u);
    BENCH_REQUIRE(g.pt != NULL && g.ct != NULL && g.out != NULL, "payload buffers");
    randombytes_buf(g.pt, 65536u);

    /* A real MLDSASK2 identity file in a private temp dir, for the loader
     * row. Removed at exit; never inside the repository. */
    const char *tmp = getenv("TMPDIR");
    snprintf(g.key_dir, sizeof(g.key_dir), "%s/mldsa-bench-keys-XXXXXX",
             (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    BENCH_REQUIRE(mkdtemp(g.key_dir) != NULL, "mkdtemp");
    BENCH_REQUIRE(demo_keys_generate_files(g.key_dir, ID_A, sizeof(ID_A) - 1u) == DEMO_KEYS_OK,
                  "demo_keys_generate_files");
    snprintf(g.key_path, sizeof(g.key_path), "%s/alice.sk", g.key_dir);
}

static void teardown(void) {
    char p[600];
    snprintf(p, sizeof(p), "%s/alice.sk", g.key_dir);
    (void)unlink(p);
    snprintf(p, sizeof(p), "%s/alice.pub", g.key_dir);
    (void)unlink(p);
    (void)rmdir(g.key_dir);
    mldsa_keypair_free(&g.sig_kp);
    kex_keypair_free(&g.kex_kp);
    kex_keypair_free(&g.kex_peer);
    sodium_memzero(g.shared, sizeof(g.shared));
    sodium_memzero(g.session_key, sizeof(g.session_key));
    sodium_memzero(g.aead_key, sizeof(g.aead_key));
    free(g.pt);
    free(g.ct);
    free(g.out);
}

/* ---- work callbacks ------------------------------------------------------ */

static void w_mldsa_keypair(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        mldsa_keypair_t kp;
        BENCH_REQUIRE(mldsa_keypair_generate(&kp) == 0, "mldsa_keypair_generate");
        mldsa_keypair_free(&kp);
    }
}

static void w_mldsa_sign(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t len = 0;
        BENCH_REQUIRE(mldsa_sign(g.sig, &len, g.th, TH_LEN, &g.sig_kp) == 0, "mldsa_sign");
    }
}

static void w_mldsa_verify(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(mldsa_verify(g.th, TH_LEN, g.sig, g.sig_len, g.sig_kp.public_key) == 0,
                      "mldsa_verify");
    }
}

static void w_kex_keypair(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        kex_keypair_t kp;
        BENCH_REQUIRE(kex_keypair_generate(&kp) == 0, "kex_keypair_generate");
        kex_keypair_free(&kp);
    }
}

static void w_kex_shared(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(kex_shared_secret(g.shared, &g.kex_kp, g.kex_peer.public_key) == 0,
                      "kex_shared_secret");
    }
}

static void w_kdf_info(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(kex_build_kdf_info(g.kdf_info, sizeof(g.kdf_info), &g.kdf_info_len, ID_A,
                                         sizeof(ID_A) - 1u, ID_B, sizeof(ID_B) - 1u,
                                         KEX_DIR_C2S) == 0,
                      "kex_build_kdf_info");
    }
}

static void w_derive_key(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(kex_derive_session_key(g.session_key, g.shared, g.session_id,
                                             sizeof(g.session_id), ID_A, sizeof(ID_A) - 1u, ID_B,
                                             sizeof(ID_B) - 1u, KEX_DIR_C2S) == 0,
                      "kex_derive_session_key");
    }
}

static void w_th_server(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(transcript_hash_server_auth(g.ch_bytes, g.ch_len, g.shu_bytes, g.shu_len,
                                                  g.digest) == 0,
                      "transcript_hash_server_auth");
    }
}

static void w_th_client(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(transcript_hash_client_auth(g.ch_bytes, g.ch_len, g.sh_bytes, g.sh_len,
                                                  g.digest) == 0,
                      "transcript_hash_client_auth");
    }
}

static void w_hs_id(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(transcript_handshake_id(g.ch_bytes, g.ch_len, g.sh_bytes, g.sh_len,
                                              g.digest) == 0,
                      "transcript_handshake_id");
    }
}

static void w_encode_ch(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(encode_client_hello(&g.ch, g.ch_bytes, sizeof(g.ch_bytes), &n) == 0, "encode ch");
    }
}

static void w_encode_sh(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(encode_server_hello(&g.sh, g.sh_bytes, sizeof(g.sh_bytes), &n) == 0, "encode sh");
    }
}

static void w_encode_ca(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(encode_client_auth(&g.ca, g.ca_bytes, sizeof(g.ca_bytes), &n) == 0, "encode ca");
    }
}

static void w_decode_ch(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        client_hello_t m;
        size_t used = 0;
        BENCH_REQUIRE(decode_client_hello(g.ch_bytes, g.ch_len, &m, &used) == 0, "decode ch");
    }
}

static void w_decode_sh(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        static server_hello_t m; /* 3.3 KB: static, so no stack churn in the loop */
        size_t used = 0;
        BENCH_REQUIRE(decode_server_hello(g.sh_bytes, g.sh_len, &m, &used) == 0, "decode sh");
    }
}

static void w_decode_ca(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        static client_auth_t m;
        size_t used = 0;
        BENCH_REQUIRE(decode_client_auth(g.ca_bytes, g.ca_len, &m, &used) == 0, "decode ca");
    }
}

static void w_aead_encrypt(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(aead_encrypt(g.ct, &g.ct_len, g.pt, g.payload_len, g.ad, sizeof(g.ad),
                                   g.aead_nonce, g.aead_key) == 0,
                      "aead_encrypt");
    }
}

static void w_aead_decrypt(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(aead_decrypt(g.out, &n, g.ct, g.ct_len, g.ad, sizeof(g.ad), g.aead_nonce,
                                   g.aead_key) == 0,
                      "aead_decrypt");
    }
}

static void w_load_identity(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        mldsa_keypair_t kp;
        BENCH_REQUIRE(demo_keys_load_identity(g.key_path, ID_A, sizeof(ID_A) - 1u, &kp) == DEMO_KEYS_OK,
                      "demo_keys_load_identity");
        mldsa_keypair_free(&kp);
    }
}

/* ---- main ---------------------------------------------------------------- */

static void payload_rows(size_t len, const char *note) {
    g.payload_len = len;
    /* One encryption outside the timed region, so decrypt has a valid record. */
    BENCH_REQUIRE(aead_encrypt(g.ct, &g.ct_len, g.pt, len, g.ad, sizeof(g.ad), g.aead_nonce,
                               g.aead_key) == 0,
                  "aead_encrypt setup");
    bench_result_t r = bench_run("aead_encrypt (ChaCha20-Poly1305)", note, NULL, w_aead_encrypt, NULL, 0,
                                 (double)len);
    bench_report(&r);
    r = bench_run("aead_decrypt (ChaCha20-Poly1305)", note, NULL, w_aead_decrypt, NULL, 0, (double)len);
    bench_report(&r);
}

int main(int argc, char **argv) {
    bench_init(argc, argv, "primitives");
    setup();

    bench_section("ML-DSA-65 (liboqs)");
    bench_result_t r = bench_run("mldsa_keypair_generate", "", NULL, w_mldsa_keypair, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("mldsa_sign", "32 B msg", NULL, w_mldsa_sign, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("mldsa_verify", "32 B msg", NULL, w_mldsa_verify, NULL, 0, 0.0);
    bench_report(&r);

    bench_section("X25519 + HKDF-SHA256 (libsodium)");
    r = bench_run("kex_keypair_generate", "", NULL, w_kex_keypair, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("kex_shared_secret", "", NULL, w_kex_shared, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("kex_build_kdf_info", "", NULL, w_kdf_info, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("kex_derive_session_key", "", NULL, w_derive_key, NULL, 0, 0.0);
    bench_report(&r);

    bench_section("Transcript hashing (SHA-256)");
    r = bench_run("transcript_hash_server_auth", "", NULL, w_th_server, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("transcript_hash_client_auth", "", NULL, w_th_client, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("transcript_handshake_id", "", NULL, w_hs_id, NULL, 0, 0.0);
    bench_report(&r);

    bench_section("Wire format");
    r = bench_run("encode_client_hello", "", NULL, w_encode_ch, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("decode_client_hello", "", NULL, w_decode_ch, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("encode_server_hello", "", NULL, w_encode_sh, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("decode_server_hello", "", NULL, w_decode_sh, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("encode_client_auth", "", NULL, w_encode_ca, NULL, 0, 0.0);
    bench_report(&r);
    r = bench_run("decode_client_auth", "", NULL, w_decode_ca, NULL, 0, 0.0);
    bench_report(&r);

    bench_section("AEAD by payload size");
    payload_rows(64u, "64 B");
    payload_rows(1024u, "1 KiB");
    payload_rows(65536u, "64 KiB");

    bench_section("Demo key files (reference apps, not the protocol)");
    r = bench_run("demo_keys_load_identity (MLDSASK2)", "", NULL, w_load_identity, NULL, 0, 0.0);
    bench_report(&r);

    teardown();
    bench_finish("primitives");
    return 0;
}
