/*
 * The decoy flow's timing, measured (V4-65; audit F17 and F135, spec §7.3).
 *
 * §7.3's promise: a ClientHello naming a handle that is unknown, revoked,
 * superseded or disabled gets a ServerHello indistinguishable from one for a
 * real device -- the daemon pins a decoy key instead of refusing -- so a
 * prober cannot tell which handles are enrolled. Tests check the outcomes
 * (CLAIMS D6): every class gets a verifiable ServerHello of the same length
 * and the same client-side failure. Nothing measured the TIMING: F17 says
 * nothing measured timing at all. This does, for that one step.
 *
 * How. The real daemon (the test harness's, in-process, over loopback TCP)
 * answers ClientHellos for three handles of the same length -- one enrolled,
 * one never seen, one enrolled and then revoked -- in an order drawn at
 * random so drift lands on every class alike. Each sample is the time from
 * sending the ClientHello to holding the whole ServerHello. The harness clock
 * moves 11 s before each one, so every handshake meets a pending ledger whose
 * entries have all expired, the same for every class. A second section times
 * the store's step alone, in-process, to say where a difference comes from.
 *
 * The test is dudect's (Reparaz, Balasch, Verbauwhede 2017): Welch's t
 * between two classes, on all samples and again with the slow tail cut at
 * pooled percentiles, since timing noise is one-sided. dudect's rule of
 * thumb: |t| above 4.5 is evidence of a difference. Below it is NOT proof of
 * none -- only that this many samples on this machine did not show one. The
 * hand control in docs/decisions.md (V4-65) puts the default's reach at about
 * 2-5 us. MLDSA_DECOY_SAMPLES=100000 reaches below 1 us, and found F135: an
 * enrolled handle's lookup is about 0.3 us slower than a miss.
 *
 * A measurement, not a gate: bench_smoke runs it with a handful of samples to
 * keep it building and running, and asserts only that every ServerHello
 * verified and every unknown and revoked sample took the decoy path.
 */
#include "bench_common.h"
#include "authd_harness.h"

#include <math.h>
#include <stdint.h>

enum { HANDLE_LEN = 34 };
enum { REAL, UNKNOWN, REVOKED, CLASSES };
static const char *const class_name[CLASSES] = { "real", "unknown", "revoked" };

typedef struct {
    double *v;
    size_t n;
} sample_t;

static int cmp_double(const void *a, const void *b)
{
    const double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Welch's t over the samples of each class at or below `cut`. */
static double welch_t(const sample_t *a, const sample_t *b, double cut, size_t *na_out, size_t *nb_out)
{
    double sa = 0, sb = 0, qa = 0, qb = 0;
    size_t na = 0, nb = 0;
    for (size_t i = 0; i < a->n; i++) { if (a->v[i] <= cut) { sa += a->v[i]; qa += a->v[i] * a->v[i]; na++; } }
    for (size_t i = 0; i < b->n; i++) { if (b->v[i] <= cut) { sb += b->v[i]; qb += b->v[i] * b->v[i]; nb++; } }
    *na_out = na; *nb_out = nb;
    if (na < 2 || nb < 2) { return 0.0; }
    const double ma = sa / (double)na, mb = sb / (double)nb;
    const double va = (qa - (double)na * ma * ma) / (double)(na - 1);
    const double vb = (qb - (double)nb * mb * mb) / (double)(nb - 1);
    const double se = sqrt(va / (double)na + vb / (double)nb);
    return (se > 0.0) ? (ma - mb) / se : 0.0;
}

static double median_of(const sample_t *s)
{
    double *c = malloc(s->n * sizeof *c);
    BENCH_REQUIRE(c != NULL, "median buffer");
    memcpy(c, s->v, s->n * sizeof *c);
    qsort(c, s->n, sizeof *c, cmp_double);
    const double m = c[s->n / 2];
    free(c);
    return m;
}

/* Welch's t between two classes at five cuts of their pooled samples (all,
 * then the slow tail trimmed), printed; returns the largest |t|. */
static double compare(const char *title, const sample_t *a, const sample_t *b)
{
    printf("\n  %s\n", title);
    sample_t pooled = { malloc((a->n + b->n) * sizeof(double)), 0 };
    BENCH_REQUIRE(pooled.v != NULL, "pooled buffer");
    memcpy(pooled.v, a->v, a->n * sizeof(double));
    memcpy(pooled.v + a->n, b->v, b->n * sizeof(double));
    pooled.n = a->n + b->n;
    qsort(pooled.v, pooled.n, sizeof(double), cmp_double);
    static const double pcts[] = { 1.0, 0.99, 0.90, 0.75, 0.50 };
    double worst = 0.0;
    for (size_t k = 0; k < sizeof pcts / sizeof pcts[0]; k++) {
        const size_t idx = (pcts[k] >= 1.0) ? pooled.n - 1u : (size_t)(pcts[k] * (double)(pooled.n - 1u));
        size_t na = 0, nb = 0;
        const double t = welch_t(a, b, pooled.v[idx], &na, &nb);
        printf("    cut at the %3.0f%% pooled percentile (%.1f us): t = %+.2f  (n %zu / %zu)\n",
               pcts[k] * 100.0, pooled.v[idx], t, na, nb);
        if (fabs(t) > fabs(worst)) { worst = t; }
    }
    printf("    max |t| = %.2f over %zu + %zu samples -- %s\n", fabs(worst), a->n, b->n,
           bench_smoke_mode ? "smoke mode: too few samples to read" :
           (fabs(worst) > 4.5 ? "ABOVE dudect's 4.5: a timing difference"
                              : "below dudect's 4.5: no difference shown at this sample size"));
    free(pooled.v);
    return fabs(worst);
}

/* Receives one frame, running the daemon's loop with a ZERO poll timeout
 * between reads. The harness's h_recv_frame ticks with a 5 ms timeout before
 * each read, so once the daemon is idle every read waited 5 ms: the first
 * measurement here was 12.5 ms a sample, nearly all of it sleep, in 5 ms
 * steps that would bury any difference of microseconds. */
static int recv_frame_spin(h_daemon_t *d, int fd, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t hdr[4];
    size_t got = 0;
    for (long i = 0; i < 50000000L && got < 4u; i++) {
        (void)evloop_run_once(&d->ev, 0, d->app.now_ms);
        const ssize_t n = recv(fd, hdr + got, 4u - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; } else if (n == 0) { return -1; }
    }
    if (got != 4u) { return -1; }
    const uint32_t len = h_get_be32(hdr);
    if (len == 0u || (size_t)len > cap) { return -1; }
    got = 0;
    for (long i = 0; i < 50000000L && got < (size_t)len; i++) {
        (void)evloop_run_once(&d->ev, 0, d->app.now_ms);
        const ssize_t n = recv(fd, out + got, (size_t)len - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; } else if (n == 0) { return -1; }
    }
    if (got != (size_t)len) { return -1; }
    *out_len = got;
    return 0;
}

/* One ClientHello -> ServerHello round trip; returns the time in us, or a
 * negative number if the ServerHello did not arrive or did not verify. */
static double one_sample(h_daemon_t *d, const uint8_t *handle, const mldsa_keypair_t *kp)
{
    h_client_t c;
    memset(&c, 0, sizeof c);
    c.fd = -1;
    keystore_init(&c.pins);
    double us = -1.0;
    uint8_t buf[AUTHD_FRAME_MAX];
    size_t n = 0, sh = 0;
    d->app.now_ms += 11000u;                 /* every earlier pending entry has expired */
    if (keystore_add(&c.pins, H_SERVER_ID, sizeof H_SERVER_ID, d->server_kp.public_key) != KEYSTORE_OK) { goto out; }
    c.fd = h_dial(d->port);
    if (c.fd < 0 || !H_PUMP_UNTIL(d, evloop_active(&d->ev) >= 1u)) { goto out; }
    if (handshake_initiator_init(&c.hs, handle, HANDLE_LEN, kp, &c.pins, H_SERVER_ID, sizeof H_SERVER_ID) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&c.hs, buf, sizeof buf, &n) != HANDSHAKE_OK) {
        goto out;
    }
    const uint64_t t0 = bench_now_ns();
    if (h_send_frame(c.fd, buf, n) != 0 || recv_frame_spin(d, c.fd, buf, sizeof buf, &sh) != 0) { goto out; }
    const uint64_t t1 = bench_now_ns();
    if (handshake_initiator_verify_server_hello(&c.hs, buf, sh) == HANDSHAKE_OK) {
        us = (double)(t1 - t0) / 1000.0;
    }
out:
    /* Reset, not FIN: a client that closes first keeps its port in TIME_WAIT,
     * and 8,000 connections a run exhausted macOS's ephemeral ports when runs
     * followed each other (the hand control's third run failed at its first
     * connect). SO_LINGER 0 frees the port at close. */
    if (c.fd >= 0) {
        const struct linger lg = { 1, 0 };
        (void)setsockopt(c.fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    }
    h_client_close(&c);
    (void)H_PUMP_UNTIL(d, evloop_active(&d->ev) == 0u);
    return us;
}

int main(int argc, char **argv)
{
    bench_init(argc, argv, "decoy");
    /* MLDSA_DECOY_SAMPLES overrides the count, for a run with more power than
     * the default's: in V4-65's hand controls, 4,000 a class showed 5 us
     * twice, 2 us once in two runs, and 1 us in neither. */
    size_t per_class = bench_smoke_mode ? 8u : 4000u;
    const char *want = getenv("MLDSA_DECOY_SAMPLES");
    if (!bench_smoke_mode && want != NULL) {
        char *end = NULL;
        const unsigned long v = strtoul(want, &end, 10);
        BENCH_REQUIRE(end != want && *end == '\0' && v >= 2ul && v <= 1000000ul,
                      "MLDSA_DECOY_SAMPLES is a count from 2 to 1000000 (got \"%s\")", want);
        per_class = (size_t)v;
    }
    bench_env_line("samples", "%zu per class, interleaved at random", per_class);

    char dir[] = "/tmp/mldsa-decoy-XXXXXX";
    BENCH_REQUIRE(mkdtemp(dir) != NULL, "a scratch directory");
    h_daemon_t d;
    BENCH_REQUIRE(h_start(&d, dir, "decoy.sqlite3", 0) == 0, "the harness daemon starts");

    /* Three handles of the same length: one enrolled, one never seen, and one
     * enrolled and then revoked. §7.3 gives the last two the same decoy. */
    uint8_t handles[CLASSES][HANDLE_LEN];
    for (size_t k = 0; k < CLASSES; k++) {
        int dup;
        do {
            memcpy(handles[k], "d1", 2);
            for (size_t i = 2; i < HANDLE_LEN; i++) { handles[k][i] = "0123456789abcdef"[randombytes_uniform(16)]; }
            dup = 0;
            for (size_t j = 0; j < k; j++) { dup |= (memcmp(handles[j], handles[k], HANDLE_LEN) == 0); }
        } while (dup);
    }
    mldsa_keypair_t kp[CLASSES];
    for (size_t k = 0; k < CLASSES; k++) {
        BENCH_REQUIRE(mldsa_keypair_generate(&kp[k]) == 0, "device key %zu", k);
    }
    static const uint8_t user[] = { 'u', '1' };
    BENCH_REQUIRE(store_add_user(d.store, user, sizeof user, STORE_ROLE_USER) == STORE_OK &&
                  store_enroll_device(d.store, handles[REAL], HANDLE_LEN, user, sizeof user, kp[REAL].public_key,
                                      "site", "bench", NULL, 0) == STORE_OK &&
                  store_enroll_device(d.store, handles[REVOKED], HANDLE_LEN, user, sizeof user,
                                      kp[REVOKED].public_key, "site", "bench", NULL, 0) == STORE_OK &&
                  store_revoke_device(d.store, handles[REVOKED], HANDLE_LEN, "bench", NULL, 0) == STORE_OK,
                  "the real handle is enrolled and the revoked one enrolled and revoked");

    /* A balanced order, shuffled. */
    const size_t total = CLASSES * per_class;
    uint8_t *order = malloc(total);
    BENCH_REQUIRE(order != NULL, "order buffer");
    for (size_t i = 0; i < total; i++) { order[i] = (uint8_t)(i / per_class); }
    for (size_t i = total - 1u; i > 0; i--) {
        const size_t j = randombytes_uniform((uint32_t)(i + 1u));
        const uint8_t t = order[i]; order[i] = order[j]; order[j] = t;
    }
    sample_t c[CLASSES];
    for (size_t k = 0; k < CLASSES; k++) {
        c[k].v = malloc(per_class * sizeof(double));
        c[k].n = 0;
        BENCH_REQUIRE(c[k].v != NULL, "sample buffer");
    }
    for (size_t i = 0; i < total; i++) {
        const size_t k = order[i];
        const double us = one_sample(&d, handles[k], &kp[k]);
        BENCH_REQUIRE(us >= 0.0, "a ServerHello for the %s handle arrived and verified (sample %zu)", class_name[k], i);
        c[k].v[c[k].n++] = us;
    }
    BENCH_REQUIRE(d.app.decoy_pins == c[UNKNOWN].n + c[REVOKED].n,
                  "every unknown- and revoked-handle sample took the decoy path (%llu of %zu)",
                  (unsigned long long)d.app.decoy_pins, c[UNKNOWN].n + c[REVOKED].n);

    bench_section("ClientHello -> ServerHello by handle");
    for (size_t k = 0; k < CLASSES; k++) {
        printf("  %-8s n=%zu  median %.1f us\n", class_name[k], c[k].n, median_of(&c[k]));
    }
    compare("real vs unknown: does a ServerHello reveal that a handle is enrolled?", &c[REAL], &c[UNKNOWN]);
    compare("revoked vs unknown: does a decoy reveal that a handle was once enrolled?", &c[REVOKED], &c[UNKNOWN]);

    /* The store's step alone, in-process: the lookup on_client_hello makes,
     * plus the decoy key's copy when it misses. Same order, same classes, no
     * socket, so a difference here is the store's and not the network's. */
    bench_section("store_lookup_active (+ the decoy copy on a miss), in-process");
    sample_t l[CLASSES];
    for (size_t k = 0; k < CLASSES; k++) {
        l[k].v = malloc(per_class * sizeof(double));
        l[k].n = 0;
        BENCH_REQUIRE(l[k].v != NULL, "sample buffer");
    }
    for (size_t i = 0; i < total; i++) {
        const size_t k = order[i];
        uint8_t pk[STORE_PK_BYTES], uid[STORE_ID_MAX];
        size_t uid_len = 0;
        const uint64_t t0 = bench_now_ns();
        store_status_t st = store_lookup_active(d.store, handles[k], HANDLE_LEN, pk, uid, sizeof uid, &uid_len, NULL);
        if (st != STORE_OK) { st = store_get_decoy_pk(d.store, pk); }
        const uint64_t t1 = bench_now_ns();
        BENCH_REQUIRE(st == STORE_OK && (k == REAL) == (uid_len != 0u), "the %s handle's lookup", class_name[k]);
        l[k].v[l[k].n++] = (double)(t1 - t0) / 1000.0;
    }
    for (size_t k = 0; k < CLASSES; k++) {
        printf("  %-8s n=%zu  median %.2f us\n", class_name[k], l[k].n, median_of(&l[k]));
    }
    compare("real vs unknown", &l[REAL], &l[UNKNOWN]);
    compare("revoked vs unknown", &l[REVOKED], &l[UNKNOWN]);
    for (size_t k = 0; k < CLASSES; k++) { free(l[k].v); }

    for (size_t k = 0; k < CLASSES; k++) { free(c[k].v); }
    free(order);
    for (size_t k = 0; k < CLASSES; k++) { mldsa_keypair_free(&kp[k]); }
    h_stop(&d);
    /* The store and its WAL files, then the directory: nothing else is made here. */
    static const char *const files[] = { "decoy.sqlite3", "decoy.sqlite3-wal", "decoy.sqlite3-shm" };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        char path[256];
        (void)snprintf(path, sizeof path, "%s/%s", dir, files[i]);
        (void)unlink(path);
    }
    (void)rmdir(dir);
    bench_finish("decoy");
    return 0;
}
