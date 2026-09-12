#ifndef MLDSA_AUTH_BENCH_COMMON_H
#define MLDSA_AUTH_BENCH_COMMON_H

#include <stddef.h>
#include <stdint.h>

/*
 * Step 8 benchmark harness (spec §5, §8 Step 8).
 *
 * MEASUREMENT ONLY. Nothing here is part of the protocol, and no bench
 * target links into src/ or apps/ -- benches are consumers of the same
 * public APIs the tests use. Keys come from the REAL RNG (never the fuzz
 * test RNG), and no key, nonce, plaintext or ciphertext byte is ever
 * printed: output is aggregate timing only.
 *
 * Timing model. Two op shapes need different treatment:
 *   - Stateless, repeatable ops (AEAD, hashing, encode/decode) are far
 *     faster than the clock's resolution, so they are BATCH-timed: one
 *     sample covers k iterations and the per-iteration cost is sample/k.
 *     k is calibrated so a batch lasts ~BENCH_BATCH_TARGET_NS.
 *   - Stateful ops (each handshake phase, session_open on a fresh record)
 *     need untimed setup before every sample. Those pass a prepare
 *     callback, which runs outside the timed region, and usually k = 1.
 *
 * Statistics are computed over SAMPLES (each normalized to per-iteration).
 * The median is the headline; min is the least noise-contaminated estimate
 * of true cost; p99 exposes scheduling noise. Every row also reports k and
 * the sample count so a reader can judge the numbers.
 */

#define BENCH_MAX_SAMPLES 4096u
#define BENCH_BATCH_TARGET_NS 20000.0 /* ~20 us per batch when auto-calibrating */

/* Called with the batch size before each timed sample; must leave `ctx`
 * ready for exactly k work iterations. Never timed. */
typedef void (*bench_prepare_fn)(void *ctx, size_t k);

/* Performs exactly k iterations of the operation being measured. */
typedef void (*bench_work_fn)(void *ctx, size_t k);

typedef struct {
    const char *name;
    const char *note; /* payload size, or other qualifier; "" if none */
    size_t batch;     /* k: iterations per timed sample */
    size_t samples;
    uint64_t iters; /* samples * k */
    double min_ns;  /* all *_ns are PER ITERATION */
    double median_ns;
    double p90_ns;
    double p99_ns;
    double mean_ns;
    double stddev_ns;
    double bytes_per_iter; /* 0 for latency-only rows */
} bench_result_t;

/* --smoke: tiny iteration counts for the CTest bench_smoke gate.
 * --csv:   machine-readable rows instead of a table. */
extern int bench_smoke_mode;
extern int bench_csv_mode;

/* Parses flags, initializes libsodium and liboqs, requests a
 * performance-core QoS class on Apple, and prints the environment block
 * (suppressed in CSV mode except as comments). */
void bench_init(int argc, char **argv, const char *suite_name);

/* Adds one "key: value" line to the environment block. Callers use it for
 * facts only they know (granted socket buffer sizes, for example). */
void bench_env_line(const char *key, const char *fmt, ...);

void bench_section(const char *title);

bench_result_t bench_run(const char *name, const char *note, bench_prepare_fn prepare,
                         bench_work_fn work, void *ctx, size_t k_hint, double bytes_per_iter);

/* Prints one row in the active output format. */
void bench_report(const bench_result_t *r);

uint64_t bench_now_ns(void);

/* Empirically measured smallest nonzero clock step, in nanoseconds. */
double bench_clock_resolution_ns(void);

void bench_finish(const char *suite_name);

/* Prints the message and exits nonzero. Benchmarks fail loudly rather than
 * reporting a number produced by a broken setup. */
void bench_fail(const char *fmt, ...);

#define BENCH_REQUIRE(cond, ...)   \
    do {                           \
        if (!(cond)) {             \
            bench_fail(__VA_ARGS__); \
        }                          \
    } while (0)

#endif /* MLDSA_AUTH_BENCH_COMMON_H */
