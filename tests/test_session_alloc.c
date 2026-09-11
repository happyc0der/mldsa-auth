/*
 * S23 -- zero-allocation proof for the session hot path (spec §5 req 5,
 * §8 Step 5 exit criteria), Gate 1 of the approved Step 5 plan.
 *
 * GATE 1 (required, every build): this executable links
 * tests/counting_secure_mem.c in place of the library's secure_mem.o, so
 * every secure allocation and free anywhere in mldsa_core is counted.
 * sodium_malloc allocates with mmap on this platform, so no malloc-level
 * tool could see these allocations at all. Before trusting a zero, the test
 * proves the counter is live: session_init_from_handshake() must count
 * exactly one allocation.
 *
 * Ordinary-heap freedom is proven structurally and portably by Gate 2
 * (tests/check_session_no_alloc.cmake, CTest "session_no_alloc_scan").
 *
 * OPTIONAL DIAGNOSTIC ONLY: with -DMLDSA_MALLOC_DIAG=ON on macOS (non-ASan),
 * the steady state is also run under libmalloc's malloc_logger hook. It is
 * not a public API contract, it never affects the exit status, and no
 * correctness claim rests on it. Otherwise it prints SKIP.
 *
 * Nothing is printed while counters are being compared across a window
 * (stdio allocates lazily); results are checked afterwards.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sodium.h>

#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"

/* Provided by tests/counting_secure_mem.c. */
extern size_t counting_secure_mem_allocs;
extern size_t counting_secure_mem_frees;

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

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MLDSA_UNDER_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#define MLDSA_UNDER_ASAN 1
#endif

#if defined(MLDSA_MALLOC_DIAG) && defined(__APPLE__) && !defined(MLDSA_UNDER_ASAN)
#define MLDSA_DIAG_ACTIVE 1
/* libmalloc's allocation-logging hook (exported by libsystem_malloc; used by
 * MallocStackLogging). Not a stable public API -- diagnostic use only. */
typedef void(malloc_logger_t)(uint32_t type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                              uintptr_t result, uint32_t num_hot_frames_to_skip);
extern malloc_logger_t *malloc_logger;
static volatile size_t g_diag_events = 0;
static void diag_logger(uint32_t type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t result,
                        uint32_t num_hot_frames_to_skip) {
    (void)type;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)result;
    (void)num_hot_frames_to_skip;
    g_diag_events = g_diag_events + 1;
}
#endif

static void fatal(const char *what) {
    fprintf(stderr, "FATAL fixture failure: %s\n", what);
    exit(EXIT_FAILURE);
}

static const uint8_t ID_A[] = {'a', 'l', 'i', 'c', 'e'};
static const uint8_t ID_B[] = {'b', 'o', 'b'};

static mldsa_keypair_t g_kp_a, g_kp_b;
static keystore_t g_ks;
static handshake_pending_store_t g_store;

typedef struct {
    handshake_ctx_t ini;
    handshake_ctx_t res;
} hs_t;

static void hs_establish(hs_t *h) {
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0;
    size_t sh_len = 0;
    size_t ca_len = 0;
    memset(h, 0, sizeof(*h));
    if (handshake_initiator_init(&h->ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_responder_init(&h->res, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &g_store) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&h->ini, ch, sizeof(ch), &ch_len) != HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&h->res, ch, ch_len) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&h->res, sh, sizeof(sh), &sh_len) != HANDSHAKE_OK ||
        handshake_initiator_verify_server_hello(&h->ini, sh, sh_len) != HANDSHAKE_OK ||
        handshake_initiator_create_client_auth(&h->ini, ca, sizeof(ca), &ca_len) != HANDSHAKE_OK ||
        handshake_responder_verify_client_auth(&h->res, ca, ca_len) != HANDSHAKE_OK ||
        handshake_responder_finish(&h->res) != HANDSHAKE_OK || handshake_initiator_finish(&h->ini) != HANDSHAKE_OK) {
        fatal("handshake did not reach ESTABLISHED");
    }
}

static void hs_wipe(hs_t *h) {
    handshake_ctx_wipe(&h->ini);
    handshake_ctx_wipe(&h->res);
}

static uint8_t g_pt_in[SESSION_MAX_PLAINTEXT_BYTES];
static uint8_t g_pt_out[SESSION_MAX_PLAINTEXT_BYTES];
static uint8_t g_rec[SESSION_MAX_RECORD_BYTES];

#define ROUNDS 1000

/* The steady state: seal/open in both directions at every benchmark size,
 * plus the two queries. Returns 1 iff every record round-tripped. */
static int steady_state(session_t *a, session_t *b) {
    static const size_t sizes[] = {0, 64, 1024, SESSION_MAX_PLAINTEXT_BYTES};
    int ok = 1;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        for (int r = 0; r < ROUNDS; r++) {
            session_t *pairs[2][2] = {{a, b}, {b, a}};
            for (int d = 0; d < 2; d++) {
                size_t rec_len = 0;
                size_t got = 0;
                ok &= session_seal(pairs[d][0], sizes[i] ? g_pt_in : NULL, sizes[i], g_rec, sizeof(g_rec),
                                   &rec_len) == SESSION_OK;
                ok &= session_open(pairs[d][1], g_rec, rec_len, g_pt_out, sizeof(g_pt_out), &got) == SESSION_OK;
                ok &= got == sizes[i];
            }
            ok &= !session_rekey_due(a) && !session_rekey_due(b);
            ok &= session_is_peer_confirmed(a) && session_is_peer_confirmed(b);
        }
    }
    return ok;
}

static void run_malloc_diagnostic(void) {
#if defined(MLDSA_DIAG_ACTIVE)
    hs_t h;
    session_t a;
    session_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    hs_establish(&h);
    if (session_init_from_handshake(&a, &h.ini, NULL, NULL, NULL) != SESSION_OK ||
        session_init_from_handshake(&b, &h.res, NULL, NULL, NULL) != SESSION_OK) {
        fatal("diagnostic session init");
    }
    malloc_logger_t *prev = malloc_logger;
    g_diag_events = 0;
    malloc_logger = diag_logger;
    void *volatile probe = malloc(16);
    free(probe);
    const size_t control = g_diag_events;
    g_diag_events = 0;
    const int ok = steady_state(&a, &b);
    const size_t events = g_diag_events;
    malloc_logger = prev;

    if (control == 0) {
        printf("SKIP: malloc_logger diagnostic unavailable (control malloc(16) not observed)\n");
    } else {
        printf("DIAG: malloc_logger control observed %zu event(s); steady-state malloc-family events: %zu "
               "(round trips %s)%s\n",
               control, events, ok ? "ok" : "FAILED",
               events ? "  <-- DIAG WARNING (informational only, exit status unaffected)" : "");
    }
    session_wipe(&a);
    session_wipe(&b);
    hs_wipe(&h);
#elif defined(MLDSA_MALLOC_DIAG) && defined(MLDSA_UNDER_ASAN)
    printf("SKIP: malloc_logger diagnostic not run under ASan (ASan replaces the allocator)\n");
#elif defined(MLDSA_MALLOC_DIAG)
    printf("SKIP: malloc_logger diagnostic is macOS-only\n");
#else
    printf("SKIP: malloc_logger diagnostic not enabled (optional; configure with -DMLDSA_MALLOC_DIAG=ON)\n");
#endif
}

int main(void) {
    /* Unbuffered (no stdio buffer allocation either), so every PASS/FAIL line
     * already reported survives even if a later check crashes the process. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return EXIT_FAILURE;
    }
    if (mldsa_keypair_generate(&g_kp_a) != 0 || mldsa_keypair_generate(&g_kp_b) != 0) {
        fatal("mldsa_keypair_generate");
    }
    keystore_init(&g_ks);
    if (keystore_add(&g_ks, ID_A, sizeof(ID_A), g_kp_a.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ks, ID_B, sizeof(ID_B), g_kp_b.public_key) != KEYSTORE_OK) {
        fatal("keystore_add");
    }
    if (handshake_pending_store_init(&g_store, 16, HANDSHAKE_PENDING_TTL_MS_DEFAULT, NULL, NULL) != PENDING_OK) {
        fatal("handshake_pending_store_init");
    }
    randombytes_buf(g_pt_in, sizeof(g_pt_in));

    /* --- Negative control + setup: exactly one secure allocation per init. */
    hs_t h1;
    hs_establish(&h1);
    session_t a;
    session_t b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    size_t a0 = counting_secure_mem_allocs;
    const session_status_t st_a = session_init_from_handshake(&a, &h1.ini, NULL, NULL, NULL);
    const size_t init_a_allocs = counting_secure_mem_allocs - a0;
    a0 = counting_secure_mem_allocs;
    const session_status_t st_b = session_init_from_handshake(&b, &h1.res, NULL, NULL, NULL);
    const size_t init_b_allocs = counting_secure_mem_allocs - a0;
    CHECK(st_a == SESSION_OK && init_a_allocs == 1 && st_b == SESSION_OK && init_b_allocs == 1,
          "S23: session_init_from_handshake performs exactly one secure allocation per session "
          "(negative control: proves the counting allocator is the one linked)");

    /* First record confirms the initiator before the measured window. */
    size_t l = 0;
    size_t got = 0;
    if (session_seal(&b, NULL, 0, g_rec, sizeof(g_rec), &l) != SESSION_OK ||
        session_open(&a, g_rec, l, g_pt_out, sizeof(g_pt_out), &got) != SESSION_OK) {
        fatal("confirmation record");
    }

    /* --- Measured window: steady state plus one terminal failure path. */
    a0 = counting_secure_mem_allocs;
    size_t f0 = counting_secure_mem_frees;
    const int round_trips_ok = steady_state(&a, &b);
    session_status_t st_fail = SESSION_ERR_INTERNAL;
    if (session_seal(&a, g_pt_in, 64, g_rec, sizeof(g_rec), &l) == SESSION_OK) {
        g_rec[l - 1] ^= 0x01;
        st_fail = session_open(&b, g_rec, l, g_pt_out, sizeof(g_pt_out), &got);
    }
    const size_t window_allocs = counting_secure_mem_allocs - a0;
    const size_t window_frees = counting_secure_mem_frees - f0;

    CHECK(round_trips_ok, "S23: 8000 seal/open pairs (1000 x {0, 64, 1024, 65536} B, both directions) "
                          "all round-tripped, with rekey_due/is_peer_confirmed queried every round");
    CHECK(st_fail == SESSION_ERR_AUTH, "S23: the measured window includes one terminal AUTH failure");
    CHECK(window_allocs == 0 && window_frees == 0,
          "S23: steady-state seal/open/rekey_due/is_peer_confirmed and a terminal failure: "
          "0 secure allocations, 0 secure frees");

    /* --- Teardown counts. */
    f0 = counting_secure_mem_frees;
    session_wipe(&a);
    const size_t wipe1 = counting_secure_mem_frees - f0;
    /* Reported BEFORE the second wipe, which would be a real double free
     * (and could crash) if the key pointer had survived the first. */
    CHECK(wipe1 == 1 && a.keys == NULL,
          "S23: session_wipe frees exactly one secure allocation and clears the key pointer");
    session_wipe(&a);
    const size_t wipe_total = counting_secure_mem_frees - f0;
    CHECK(wipe_total == 1, "S23+: a second session_wipe frees nothing more (no double free)");
    f0 = counting_secure_mem_frees;
    session_wipe(&b); /* b is FAILED: its zeroed key block is still owned until now */
    CHECK(counting_secure_mem_frees - f0 == 1, "S23+: wiping a FAILED session frees its key block exactly once");
    hs_wipe(&h1);

    session_t z;
    memset(&z, 0, sizeof(z));
    f0 = counting_secure_mem_frees;
    session_wipe(&z);
    session_wipe(&z);
    CHECK(counting_secure_mem_frees - f0 == 0, "S23+: wiping a zero-initialized session (twice) frees nothing");

    /* --- A rejected reinit creates (and leaks) nothing. */
    hs_t h2;
    hs_t h3;
    hs_establish(&h2);
    hs_establish(&h3);
    session_t c;
    memset(&c, 0, sizeof(c));
    if (session_init_from_handshake(&c, &h2.ini, NULL, NULL, NULL) != SESSION_OK) {
        fatal("reinit fixture");
    }
    a0 = counting_secure_mem_allocs;
    f0 = counting_secure_mem_frees;
    const session_status_t st_re = session_init_from_handshake(&c, &h3.ini, NULL, NULL, NULL);
    CHECK(st_re == SESSION_ERR_UNEXPECTED_STATE && counting_secure_mem_allocs - a0 == 0 &&
              counting_secure_mem_frees - f0 == 0,
          "S23+: a rejected reinit performs 0 secure allocations and 0 frees (nothing overwritten or leaked)");
    session_wipe(&c);
    hs_wipe(&h2);
    hs_wipe(&h3);

    run_malloc_diagnostic();

    handshake_pending_store_wipe(&g_store);
    keystore_wipe(&g_ks);
    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
