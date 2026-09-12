/*
 * Steady-state record-layer throughput at 64 B, 1 KiB and 64 KiB
 * (spec §5.4; 64 KiB is exactly SESSION_MAX_PLAINTEXT_BYTES).
 *
 * Live sessions are built from real handshakes, so these are the
 * actual protocol paths: sequence numbers, associated data and the 25-byte
 * record overhead included. MiB/s is computed from the PLAINTEXT bytes each
 * iteration actually moves.
 *
 * session_seal is batch-timed (it is stateless between calls apart from the
 * sequence number). session_open needs a fresh, correctly-sequenced record
 * per call, so its batch is sealed in the untimed prepare step.
 *
 * The receiver accepts EXACTLY the next expected sequence number -- a gap is
 * terminal (session.h) -- so seal-only rows would desynchronize any receiver
 * sharing their session. Each row family therefore gets its OWN established
 * session pair, from its own handshake.
 */

#include "bench_common.h"

#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"
#include "transcript.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ID_A[] = "bench-initiator";
static const uint8_t ID_B[] = "bench-responder";
#define ID_A_LEN (sizeof(ID_A) - 1u)
#define ID_B_LEN (sizeof(ID_B) - 1u)

#define OPEN_BATCH 32u /* records pre-sealed per timed open sample */

static mldsa_keypair_t g_kp_a;
static mldsa_keypair_t g_kp_b;
static keystore_t g_ks;
static handshake_pending_store_t g_store;

/* One established pair: the initiator seals, the responder opens, so both
 * sides exercise the c2s direction exactly as the protocol does. */
typedef struct {
    session_t tx;
    session_t rx;
} pair_t;

static pair_t g_seal; /* seal-only rows: rx stays idle by design */
static pair_t g_open; /* open rows: prepare seals, the timed region opens */
static pair_t g_rt;   /* seal+open round trip */

static uint8_t *g_pt;
static uint8_t *g_out;      /* one record */
static uint8_t *g_records;  /* OPEN_BATCH records, pre-sealed */
static size_t g_rec_len[OPEN_BATCH];
static size_t g_payload;

/* Stride between pre-sealed records: the largest record this bench seals. */
#define REC_STRIDE (65536u + SESSION_OVERHEAD_BYTES)

/* ---- fixture: one real handshake per pair -------------------------------- */

static void establish(pair_t *pair) {
    handshake_ctx_t ini;
    handshake_ctx_t res;
    static uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    static uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    static uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0;
    size_t sh_len = 0;
    size_t ca_len = 0;

    memset(&ini, 0, sizeof(ini));
    memset(&res, 0, sizeof(res));
    BENCH_REQUIRE(handshake_initiator_init(&ini, ID_A, ID_A_LEN, &g_kp_a, &g_ks, ID_B, ID_B_LEN) ==
                          HANDSHAKE_OK &&
                      handshake_responder_init(&res, ID_B, ID_B_LEN, &g_kp_b, &g_ks, &g_store) ==
                          HANDSHAKE_OK,
                  "handshake init");
    BENCH_REQUIRE(
        handshake_initiator_create_client_hello(&ini, ch, sizeof(ch), &ch_len) == HANDSHAKE_OK &&
            handshake_responder_accept_client_hello(&res, ch, ch_len) == HANDSHAKE_OK &&
            handshake_responder_create_server_hello(&res, sh, sizeof(sh), &sh_len) == HANDSHAKE_OK &&
            handshake_initiator_verify_server_hello(&ini, sh, sh_len) == HANDSHAKE_OK &&
            handshake_initiator_create_client_auth(&ini, ca, sizeof(ca), &ca_len) == HANDSHAKE_OK &&
            handshake_responder_verify_client_auth(&res, ca, ca_len) == HANDSHAKE_OK &&
            handshake_initiator_finish(&ini) == HANDSHAKE_OK &&
            handshake_responder_finish(&res) == HANDSHAKE_OK,
        "handshake");

    /* session_init_from_handshake consumes (wipes) each context. */
    BENCH_REQUIRE(session_init_from_handshake(&pair->tx, &ini, NULL, NULL, NULL) == SESSION_OK &&
                      session_init_from_handshake(&pair->rx, &res, NULL, NULL, NULL) == SESSION_OK,
                  "session_init_from_handshake");
    BENCH_REQUIRE(session_get_state(&pair->tx) == SESSION_STATE_ACTIVE &&
                      session_get_state(&pair->rx) == SESSION_STATE_ACTIVE,
                  "both sessions must be ACTIVE");
    sodium_memzero(ch, sizeof(ch));
    sodium_memzero(sh, sizeof(sh));
    sodium_memzero(ca, sizeof(ca));
}

/* Sequence numbers advance for the whole run; the soft rekey threshold is
 * 2^32 records, far beyond any benchmark, and session_seal keeps working
 * until the hard limit. */
static void w_seal(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(session_seal(&g_seal.tx, g_pt, g_payload, g_out, REC_STRIDE, &n) == SESSION_OK,
                      "session_seal");
    }
}

static void prep_open(void *ctx, size_t k) {
    (void)ctx;
    BENCH_REQUIRE(k <= OPEN_BATCH, "open batch too large");
    for (size_t i = 0; i < k; i++) {
        BENCH_REQUIRE(session_seal(&g_open.tx, g_pt, g_payload, g_records + i * REC_STRIDE,
                                   REC_STRIDE, &g_rec_len[i]) == SESSION_OK,
                      "session_seal (open fixture)");
    }
}

static void w_open(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t n = 0;
        BENCH_REQUIRE(session_open(&g_open.rx, g_records + i * REC_STRIDE, g_rec_len[i], g_out,
                                   REC_STRIDE, &n) == SESSION_OK,
                      "session_open");
        BENCH_REQUIRE(n == g_payload, "session_open returned %zu bytes, expected %zu", n, g_payload);
    }
}

static void w_roundtrip(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        size_t rec = 0;
        size_t got = 0;
        BENCH_REQUIRE(session_seal(&g_rt.tx, g_pt, g_payload, g_records, REC_STRIDE, &rec) == SESSION_OK &&
                          session_open(&g_rt.rx, g_records, rec, g_out, REC_STRIDE, &got) == SESSION_OK,
                      "seal+open round trip");
        BENCH_REQUIRE(got == g_payload, "round trip returned %zu bytes, expected %zu", got, g_payload);
    }
}

static void size_rows(size_t len, const char *note) {
    g_payload = len;
    bench_result_t r = bench_run("session_seal", note, NULL, w_seal, NULL, 0, (double)len);
    bench_report(&r);
    r = bench_run("session_open", note, prep_open, w_open, NULL, OPEN_BATCH, (double)len);
    bench_report(&r);
    r = bench_run("session_seal + session_open", note, NULL, w_roundtrip, NULL, 0, (double)len);
    bench_report(&r);
}

int main(int argc, char **argv) {
    bench_init(argc, argv, "session");

    BENCH_REQUIRE(mldsa_keypair_generate(&g_kp_a) == 0 && mldsa_keypair_generate(&g_kp_b) == 0,
                  "identity keypairs");
    keystore_init(&g_ks);
    BENCH_REQUIRE(keystore_add(&g_ks, ID_A, ID_A_LEN, g_kp_a.public_key) == KEYSTORE_OK &&
                      keystore_add(&g_ks, ID_B, ID_B_LEN, g_kp_b.public_key) == KEYSTORE_OK,
                  "keystore_add");
    BENCH_REQUIRE(handshake_pending_store_init(&g_store, 8u, 60000u, NULL, NULL) == PENDING_OK,
                  "handshake_pending_store_init");

    g_pt = malloc(65536u);
    g_out = malloc(REC_STRIDE);
    g_records = malloc((size_t)OPEN_BATCH * REC_STRIDE);
    BENCH_REQUIRE(g_pt != NULL && g_out != NULL && g_records != NULL, "payload buffers");
    randombytes_buf(g_pt, 65536u);

    establish(&g_seal);
    establish(&g_open);
    establish(&g_rt);

    bench_env_line("record overhead", "%u B per record (9 B header + 16 B tag)",
                   (unsigned)SESSION_OVERHEAD_BYTES);

    bench_section("Record layer throughput (ChaCha20-Poly1305, per record)");
    size_rows(64u, "64 B");
    size_rows(1024u, "1 KiB");
    size_rows(65536u, "64 KiB");

    session_wipe(&g_seal.tx);
    session_wipe(&g_seal.rx);
    session_wipe(&g_open.tx);
    session_wipe(&g_open.rx);
    session_wipe(&g_rt.tx);
    session_wipe(&g_rt.rx);
    handshake_pending_store_wipe(&g_store);
    keystore_wipe(&g_ks);
    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);
    sodium_memzero(g_pt, 65536u);
    free(g_pt);
    free(g_out);
    free(g_records);
    bench_finish("session");
    return 0;
}
