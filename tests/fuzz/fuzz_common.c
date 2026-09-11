#include "fuzz_common.h"

#include <oqs/rand.h>
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fuzz_verbose = 0;
void (*fuzz_failure_hook)(void) = NULL;
const uint8_t fuzz_empty[1] = {0};
const uint8_t FUZZ_ID_A[FUZZ_ID_A_LEN] = {'a', 'l', 'i', 'c', 'e'};
const uint8_t FUZZ_ID_B[FUZZ_ID_B_LEN] = {'b', 'o', 'b'};
uint64_t fuzz_clock_now = FUZZ_CLOCK_T0;

_Noreturn void fuzz_fail(const char *file, int line, const char *cond, const char *msg) {
    fprintf(stderr, "FUZZ ORACLE FAILURE [%s] %s:%d: %s -- %s\n", fuzz_target_name, file, line, msg, cond);
    fflush(stderr);
    if (fuzz_failure_hook != NULL) {
        void (*hook)(void) = fuzz_failure_hook;
        fuzz_failure_hook = NULL; /* never recurse */
        hook();
    }
    abort();
}

uint8_t fuzz_selector(const uint8_t *data, size_t size, uint8_t fallback) {
    return (size == 0 || data == NULL) ? fallback : data[0];
}

void fuzz_payload(const uint8_t *data, size_t size, const uint8_t **p, size_t *n) {
    if (size == 0 || data == NULL) {
        *p = fuzz_empty;
        *n = 0;
    } else {
        *p = (size > 1) ? data + 1 : fuzz_empty;
        *n = size - 1;
    }
}

const uint8_t *fuzz_ptr(const uint8_t *data, size_t size) {
    return (size == 0 || data == NULL) ? fuzz_empty : data;
}

uint64_t fuzz_clock_fn(void *ctx) {
    (void)ctx;
    return fuzz_clock_now;
}

/* =====================================================================
 * Deterministic RNG (TEST ONLY): ChaCha20 keystream under a fixed key, one
 * fresh 64-bit nonce per request: nonce = stream << 40 | request counter.
 * ===================================================================== */

static const char DRBG_KEY_TEXT[] = "mldsa-auth/v1/fuzz-drbg/testonly"; /* public, test-only */
_Static_assert(sizeof(DRBG_KEY_TEXT) - 1u == crypto_stream_chacha20_KEYBYTES, "DRBG key is 32 bytes");
#define DRBG_KEY ((const unsigned char *)DRBG_KEY_TEXT)
static uint64_t g_stream = FUZZ_STREAM_HANDSHAKE;
static uint64_t g_counter = 0;

static void drbg_fill(uint8_t *out, size_t n) {
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    const uint64_t v = (g_stream << 40) | (g_counter++ & 0xFFFFFFFFFFull);
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(v >> (8u * i));
    }
    if (n != 0) {
        (void)crypto_stream_chacha20(out, n, nonce, DRBG_KEY);
    }
}

static const char *det_name(void) {
    return "mldsa-auth-fuzz-deterministic-TEST-ONLY";
}
static uint32_t det_random(void) {
    uint8_t b[4];
    drbg_fill(b, sizeof(b));
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void det_stir(void) {
}
static void det_buf(void *const buf, const size_t size) {
    drbg_fill((uint8_t *)buf, size);
}
static int det_close(void) {
    return 0;
}
static randombytes_implementation g_det_impl = {det_name, det_random, det_stir, NULL, det_buf, det_close};

static void det_oqs(uint8_t *out, size_t n) {
    drbg_fill(out, n);
}

void fuzz_rng_reset_stream(uint32_t stream) {
    g_stream = stream;
    g_counter = 0;
}

void fuzz_rng_reset(void) {
    fuzz_rng_reset_stream(FUZZ_STREAM_HANDSHAKE);
}

/* =====================================================================
 * Fixtures
 * ===================================================================== */

static fuzz_identities_t g_ids;
static fuzz_transcript_t g_tr;
static handshake_pending_store_t g_fixture_store;
static int g_initialized = 0;

static void fixture_fatal(const char *what) {
    fprintf(stderr, "FUZZ FIXTURE FAILURE [%s]: %s\n", fuzz_target_name, what);
    abort();
}

void fuzz_regenerate_identity_a(mldsa_keypair_t *kp) {
    fuzz_rng_reset_stream(FUZZ_STREAM_IDENTITY_A);
    if (mldsa_keypair_generate(kp) != 0) {
        fixture_fatal("identity A keygen");
    }
}

static void build_transcript(void) {
    handshake_ctx_t ini;
    handshake_ctx_t res;
    if (handshake_pending_store_init(&g_fixture_store, 4, HANDSHAKE_PENDING_TTL_MS_DEFAULT, fuzz_clock_fn, NULL) !=
        PENDING_OK) {
        fixture_fatal("pending store");
    }
    fuzz_rng_reset();
    if (handshake_initiator_init(&ini, FUZZ_ID_A, FUZZ_ID_A_LEN, &g_ids.kp_a, &g_ids.ks_initiator, FUZZ_ID_B,
                                 FUZZ_ID_B_LEN) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini, g_tr.ch, sizeof(g_tr.ch), &g_tr.ch_len) != HANDSHAKE_OK ||
        handshake_responder_init(&res, FUZZ_ID_B, FUZZ_ID_B_LEN, &g_ids.kp_b, &g_ids.ks_responder,
                                 &g_fixture_store) != HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&res, g_tr.ch, g_tr.ch_len) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&res, g_tr.sh, sizeof(g_tr.sh), &g_tr.sh_len) != HANDSHAKE_OK ||
        handshake_initiator_verify_server_hello(&ini, g_tr.sh, g_tr.sh_len) != HANDSHAKE_OK ||
        handshake_initiator_create_client_auth(&ini, g_tr.ca, sizeof(g_tr.ca), &g_tr.ca_len) != HANDSHAKE_OK ||
        handshake_responder_verify_client_auth(&res, g_tr.ca, g_tr.ca_len) != HANDSHAKE_OK ||
        handshake_responder_finish(&res) != HANDSHAKE_OK || handshake_initiator_finish(&ini) != HANDSHAKE_OK) {
        fixture_fatal("canonical handshake");
    }
    const uint8_t *k = NULL;
    if (handshake_get_handshake_id(&ini, g_tr.handshake_id) != HANDSHAKE_OK ||
        handshake_session_key_c2s(&ini, &k) != HANDSHAKE_OK) {
        fixture_fatal("transcript accessors");
    }
    memcpy(g_tr.c2s, k, sizeof(g_tr.c2s));
    if (handshake_session_key_s2c(&ini, &k) != HANDSHAKE_OK) {
        fixture_fatal("s2c accessor");
    }
    memcpy(g_tr.s2c, k, sizeof(g_tr.s2c));
    handshake_ctx_wipe(&ini);
    handshake_ctx_wipe(&res);
    handshake_pending_store_wipe(&g_fixture_store);
}

static void common_cleanup(void) {
    mldsa_keypair_free(&g_ids.kp_a);
    mldsa_keypair_free(&g_ids.kp_b);
    keystore_wipe(&g_ids.ks_responder);
    keystore_wipe(&g_ids.ks_initiator);
    sodium_memzero(&g_tr, sizeof(g_tr));
}

void fuzz_common_init(void) {
    if (g_initialized) {
        return;
    }
    g_initialized = 1;
    /* Must precede sodium_init(). */
    if (randombytes_set_implementation(&g_det_impl) != 0) {
        fixture_fatal("randombytes_set_implementation");
    }
    OQS_randombytes_custom_algorithm(det_oqs);
    if (sodium_init() < 0) {
        fixture_fatal("sodium_init");
    }
    fprintf(stderr, "[%s] DETERMINISTIC RNG - TEST ONLY (tests/fuzz): all keys, nonces and signatures are "
                    "reproducible and must never be used outside fuzzing\n",
            fuzz_target_name);

    fuzz_rng_reset_stream(FUZZ_STREAM_IDENTITY_A);
    if (mldsa_keypair_generate(&g_ids.kp_a) != 0) {
        fixture_fatal("keygen A");
    }
    fuzz_rng_reset_stream(FUZZ_STREAM_IDENTITY_B);
    if (mldsa_keypair_generate(&g_ids.kp_b) != 0) {
        fixture_fatal("keygen B");
    }
    keystore_init(&g_ids.ks_responder);
    keystore_init(&g_ids.ks_initiator);
    if (keystore_add(&g_ids.ks_responder, FUZZ_ID_A, FUZZ_ID_A_LEN, g_ids.kp_a.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ids.ks_initiator, FUZZ_ID_B, FUZZ_ID_B_LEN, g_ids.kp_b.public_key) != KEYSTORE_OK) {
        fixture_fatal("keystores");
    }
    build_transcript();
    (void)atexit(common_cleanup);
}

const fuzz_identities_t *fuzz_identities(void) {
    return &g_ids;
}

const fuzz_transcript_t *fuzz_genuine_transcript(void) {
    return &g_tr;
}

/* =====================================================================
 * Chunked inputs
 * ===================================================================== */

void fuzz_chunks_init(fuzz_chunks_t *c, const uint8_t *p, size_t n, unsigned prefix_bytes, unsigned max_chunks) {
    c->p = p;
    c->n = n;
    c->off = 0;
    c->count = 0;
    c->max_chunks = max_chunks;
    c->prefix_bytes = prefix_bytes;
}

bool fuzz_chunks_next(fuzz_chunks_t *c, const uint8_t **chunk, size_t *len) {
    if (c->count >= c->max_chunks) {
        return false;
    }
    if (c->n == 0) {
        if (c->count == 0) {
            c->count++;
            *chunk = fuzz_empty;
            *len = 0;
            return true;
        }
        return false;
    }
    if (c->off >= c->n) {
        return false;
    }
    size_t rem = c->n - c->off;
    size_t take;
    if (rem < c->prefix_bytes) {
        take = rem; /* a partial length prefix: the rest is one raw chunk */
    } else {
        size_t want = 0;
        for (unsigned i = 0; i < c->prefix_bytes; i++) {
            want = (want << 8) | c->p[c->off + i];
        }
        c->off += c->prefix_bytes;
        rem -= c->prefix_bytes;
        take = (want < rem) ? want : rem;
    }
    *chunk = (take != 0) ? c->p + c->off : fuzz_empty;
    *len = take;
    c->off += take;
    c->count++;
    return true;
}

size_t fuzz_seed_put_chunk(uint8_t *seed, size_t seed_len, size_t cap, unsigned prefix_bytes, const uint8_t *chunk,
                           size_t len) {
    if (seed_len + prefix_bytes + len > cap) {
        fixture_fatal("seed buffer too small");
    }
    for (unsigned i = 0; i < prefix_bytes; i++) {
        seed[seed_len + i] = (uint8_t)(len >> (8u * (prefix_bytes - 1u - i)));
    }
    if (len != 0) {
        memcpy(seed + seed_len + prefix_bytes, chunk, len);
    }
    return seed_len + prefix_bytes + len;
}
