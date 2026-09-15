#include "bench_common.h"

#include <sodium.h>
#include <oqs/oqs.h>

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h> /* sysconf(): POSIX, needed by the Linux environment block */

#if defined(__APPLE__)
#include <pthread/qos.h>
#include <sys/sysctl.h>
#endif

int bench_smoke_mode = 0;
int bench_csv_mode = 0;

static double g_clock_res_ns = 0.0;
static double g_samples[BENCH_MAX_SAMPLES];
static int g_row_printed = 0;
static const char *g_suite = "";

/* ---- failure ------------------------------------------------------------- */

void bench_fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "BENCH FAILED: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

/* ---- clock --------------------------------------------------------------- */

/* The clock is chosen at startup, not assumed: on macOS CLOCK_MONOTONIC
 * reports in whole microseconds, which would quantize every unbatched row
 * (an ML-DSA verify would be measured in 1 us steps). CLOCK_MONOTONIC_RAW
 * and CLOCK_UPTIME_RAW resolve to ~41 ns here. Candidates are measured and
 * the finest one wins; the winner and its measured resolution are printed
 * with every result. */
static clockid_t g_clockid = CLOCK_MONOTONIC;
static const char *g_clock_name = "CLOCK_MONOTONIC";

uint64_t bench_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(g_clockid, &ts) != 0) {
        bench_fail("clock_gettime(%s) failed", g_clock_name);
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Smallest nonzero step a clock actually reports. */
static double measure_resolution_of(clockid_t id) {
    double best = 1e9;
    for (int i = 0; i < 1000; i++) {
        struct timespec a;
        struct timespec b;
        if (clock_gettime(id, &a) != 0) {
            return -1.0;
        }
        do {
            if (clock_gettime(id, &b) != 0) {
                return -1.0;
            }
        } while (b.tv_sec == a.tv_sec && b.tv_nsec == a.tv_nsec);
        const double d =
            (double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec);
        if (d < best) {
            best = d;
        }
    }
    return best;
}

static void select_clock(void) {
    const struct {
        clockid_t id;
        const char *name;
    } candidates[] = {
#if defined(CLOCK_MONOTONIC_RAW)
        {CLOCK_MONOTONIC_RAW, "CLOCK_MONOTONIC_RAW"},
#endif
#if defined(CLOCK_UPTIME_RAW)
        {CLOCK_UPTIME_RAW, "CLOCK_UPTIME_RAW"},
#endif
        {CLOCK_MONOTONIC, "CLOCK_MONOTONIC"},
    };
    double best = -1.0;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        const double r = measure_resolution_of(candidates[i].id);
        if (r > 0.0 && (best < 0.0 || r < best)) {
            best = r;
            g_clockid = candidates[i].id;
            g_clock_name = candidates[i].name;
        }
    }
    if (best < 0.0) {
        bench_fail("no usable monotonic clock");
    }
    g_clock_res_ns = best;
}

double bench_clock_resolution_ns(void) {
    return g_clock_res_ns;
}

/* ---- environment --------------------------------------------------------- */

void bench_env_line(const char *key, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf(bench_csv_mode ? "# %-26s " : "  %-26s ", key);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

#if defined(__APPLE__)
static void sysctl_str(const char *name, char *out, size_t cap) {
    size_t n = cap;
    if (sysctlbyname(name, out, &n, NULL, 0) != 0) {
        snprintf(out, cap, "unknown");
    }
}

static long sysctl_long(const char *name) {
    int64_t v = 0;
    size_t n = sizeof(v);
    if (sysctlbyname(name, &v, &n, NULL, 0) != 0) {
        return -1;
    }
    return (long)v;
}

/* A core count macOS cannot report has to SAY so. sysctl_long() returns -1
 * for an absent key, and a raw -1 in a published environment block is exactly
 * the unknown-with-no-reason V3-2 forbade: GitHub's macOS runner is a VM with
 * no efficiency perflevel, and printed "3 performance + -1 efficiency cores"
 * (found by V3-3's CI, fixed here). The format string is unchanged, so on a
 * machine where both keys exist -- the M4 Pro every published figure was
 * measured on -- the line is byte-identical to before. */
static void core_count(const char *name, char *out, size_t cap) {
    const long v = sysctl_long(name);
    if (v < 0) {
        (void)snprintf(out, cap, "unknown (no %s)", name);
    } else {
        (void)snprintf(out, cap, "%ld", v);
    }
}
#elif defined(__linux__)
/* A value that could not be read is reported as "unknown (<why>)" -- never
 * omitted and never guessed. An absent line cannot be told apart from a
 * platform with nothing to say; an explicit "unknown" can be falsified. */
static void unknown(char *out, size_t cap, const char *why) {
    snprintf(out, cap, "unknown (%s)", why);
}

/* First "key<sep>value" line of a colon-separated file such as /proc/cpuinfo. */
static void proc_field(const char *path, const char *key, char *out, size_t cap) {
    /* The reason names the field and the file it was sought in: a reader of a
     * published block must be able to check the claim, not just read "unknown". */
    char why[160];
    snprintf(why, sizeof(why), "no %s in %s", key, path);
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        snprintf(why, sizeof(why), "cannot read %s", path);
        unknown(out, cap, why);
        return;
    }
    char line[512];
    const size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, key, klen) != 0) {
            continue;
        }
        char *colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t') {
            v++;
        }
        v[strcspn(v, "\n")] = '\0';
        if (*v != '\0') {
            snprintf(out, cap, "%s", v);
            (void)fclose(f);
            return;
        }
    }
    (void)fclose(f);
    unknown(out, cap, why);
}

/* One-line /sys file (cpufreq governor, DMI vendor, ...). */
static void sys_str(const char *path, char *out, size_t cap, const char *why) {
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        unknown(out, cap, why);
        return;
    }
    char line[256] = {0};
    if (fgets(line, sizeof(line), f) == NULL) {
        (void)fclose(f);
        unknown(out, cap, why);
        return;
    }
    (void)fclose(f);
    line[strcspn(line, "\n")] = '\0';
    snprintf(out, cap, "%s", line[0] != '\0' ? line : "unknown (empty file)");
}
#endif

/* Which ML-DSA-65 backend liboqs will actually execute.
 *
 * This mirrors liboqs's own dispatch in src/sig/ml_dsa/sig_ml_dsa_65.c
 * exactly, using the same public predicate it branches on
 * (OQS_CPU_has_extension, oqs/common.h), so the backend this reports
 * cannot drift from the backend that runs. Under OQS_DIST_BUILD the
 * choice is a runtime CPU-feature branch taken on every sign/verify;
 * without it the choice was fixed at build time. */
static const char *mldsa_backend(int *runtime_dispatch_out) {
#if defined(OQS_DIST_BUILD)
    *runtime_dispatch_out = 1;
#else
    *runtime_dispatch_out = 0;
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
        OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
        return "AVX2-optimized (x86_64)";
    }
    return "portable reference (C)";
#else
    return "AVX2-optimized (x86_64)";
#endif
#elif defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
        return "NEON-optimized (aarch64)";
    }
    return "portable reference (C)";
#else
    return "NEON-optimized (aarch64)";
#endif
#else
    return "portable reference (C)";
#endif
}

/* Same construction as mldsa_backend(), mirroring liboqs's dispatch in
 * src/kem/ml_kem/kem_ml_kem_768.c (x86_64 needs AVX2 + BMI2 + POPCNT;
 * aarch64 needs NEON). */
static const char *mlkem_backend(int *runtime_dispatch_out) {
#if defined(OQS_DIST_BUILD)
    *runtime_dispatch_out = 1;
#else
    *runtime_dispatch_out = 0;
#endif
#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
        OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
        return "AVX2-optimized (x86_64)";
    }
    return "portable reference (C)";
#else
    return "AVX2-optimized (x86_64)";
#endif
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
        return "NEON-optimized (aarch64)";
    }
    return "portable reference (C)";
#else
    return "NEON-optimized (aarch64)";
#endif
#else
    return "portable reference (C)";
#endif
}

static void print_environment(const char *suite_name) {
    printf(bench_csv_mode ? "# mldsa-auth bench: %s\n" : "mldsa-auth bench: %s\n", suite_name);

    struct utsname u;
    if (uname(&u) == 0) {
        bench_env_line("os", "%s %s %s", u.sysname, u.release, u.machine);
    }
#if defined(__APPLE__)
    char cpu[256];
    sysctl_str("machdep.cpu.brand_string", cpu, sizeof(cpu));
    /* The degraded path is unreachable on a machine where both perflevel keys
     * exist -- every Apple Silicon Mac -- so it is exercised directly rather
     * than left to a runner nobody benchmarks on. Without this the V3-5
     * mutation U2 (sentinel printed raw, the exact V3-3 defect) SURVIVES on
     * this hardware and cannot be compiled at all on Linux: unkillable
     * everywhere the campaigns run, while still broken in production. */
    char probe[96];
    core_count("hw.perflevel_nonexistent.mldsa_probe", probe, sizeof(probe));
    BENCH_REQUIRE(strncmp(probe, "unknown (", 9) == 0,
                  "core_count must report an absent sysctl as unknown (<why>), got '%s'", probe);

    char p_cores[96];
    char e_cores[96];
    core_count("hw.perflevel0.logicalcpu", p_cores, sizeof(p_cores));
    core_count("hw.perflevel1.logicalcpu", e_cores, sizeof(e_cores));
    bench_env_line("cpu", "%s (%s performance + %s efficiency cores)", cpu, p_cores, e_cores);
#elif defined(__linux__)
    /* x86_64 /proc/cpuinfo carries "model name"; arm64 does not, so that path
     * degrades to an explicit unknown rather than inventing a chip. Cores are
     * a plain online count: macOS reports a performance/efficiency split and
     * Linux has no universal equivalent, so none is faked. */
    char cpu[256];
    proc_field("/proc/cpuinfo", "model name", cpu, sizeof(cpu));
    bench_env_line("cpu", "%s (%ld logical cores online)", cpu, sysconf(_SC_NPROCESSORS_ONLN));

    /* No macOS analogue, and not optional: a powersave governor can halve
     * throughput, so a Linux timing is uninterpretable without it. */
    char gov[128];
    char turbo[128];
    sys_str("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", gov, sizeof(gov),
            "no cpufreq sysfs: frequency is not under OS control here");
    sys_str("/sys/devices/system/cpu/intel_pstate/no_turbo", turbo, sizeof(turbo),
            "not an intel_pstate system");
    bench_env_line("cpu scaling", "governor %s, intel_pstate no_turbo %s", gov, turbo);

    /* CI runners are shared VMs; a reader must be able to tell that from
     * bare metal before trusting a median. */
    char virt[128];
    sys_str("/sys/class/dmi/id/sys_vendor", virt, sizeof(virt), "no /sys/class/dmi/id/sys_vendor");
    bench_env_line("virtualization", "DMI vendor %s", virt);
#else
    bench_env_line("cpu", "unknown (unsupported platform)");
#endif
#if defined(__clang_version__)
    bench_env_line("compiler", "clang %s", __clang_version__);
#elif defined(__VERSION__)
    bench_env_line("compiler", "%s", __VERSION__);
#endif
    bench_env_line("build type", "%s", BENCH_BUILD_TYPE);
    bench_env_line("c flags", "%s", BENCH_C_FLAGS);

    int runtime_dispatch = 0;
    const char *backend = mldsa_backend(&runtime_dispatch);
    bench_env_line("liboqs", "%s", OQS_version());
    bench_env_line("ml-dsa backend", "%s, selected at %s%s", backend,
                   runtime_dispatch ? "run time" : "build time",
                   runtime_dispatch ? " (OQS_DIST_BUILD=ON: a CPU-feature branch per sign/verify)"
                                    : " (OQS_DIST_BUILD=OFF: no per-call branch)");
    int kem_runtime_dispatch = 0;
    const char *kem_backend = mlkem_backend(&kem_runtime_dispatch);
    bench_env_line("ml-kem backend", "%s, selected at %s%s", kem_backend,
                   kem_runtime_dispatch ? "run time" : "build time",
                   kem_runtime_dispatch ? " (OQS_DIST_BUILD=ON: a CPU-feature branch per encaps/decaps)"
                                        : " (OQS_DIST_BUILD=OFF: no per-call branch)");
    bench_env_line("libsodium", "%s", sodium_version_string());

#if defined(__APPLE__)
    const qos_class_t qos = qos_class_self();
    const char *qos_name = qos == QOS_CLASS_USER_INTERACTIVE  ? "USER_INTERACTIVE"
                           : qos == QOS_CLASS_USER_INITIATED  ? "USER_INITIATED"
                           : qos == QOS_CLASS_DEFAULT         ? "DEFAULT"
                           : qos == QOS_CLASS_UTILITY         ? "UTILITY"
                           : qos == QOS_CLASS_BACKGROUND      ? "BACKGROUND"
                                                              : "UNSPECIFIED";
    bench_env_line("qos class", "%s (requested USER_INTERACTIVE: performance cores)", qos_name);
#endif
    bench_env_line("clock", "%s, measured resolution %.1f ns", g_clock_name, g_clock_res_ns);
    if (bench_smoke_mode) {
        bench_env_line("mode", "SMOKE (tiny iteration counts; NOT a benchmark result)");
    }
}

/* ---- init / output ------------------------------------------------------- */

void bench_init(int argc, char **argv, const char *suite_name) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--smoke") == 0) {
            bench_smoke_mode = 1;
        } else if (strcmp(argv[i], "--csv") == 0) {
            bench_csv_mode = 1;
        } else {
            bench_fail("usage: %s [--smoke] [--csv]", argv[0]);
        }
    }
    if (sodium_init() < 0) {
        bench_fail("sodium_init");
    }
    OQS_init();
#if defined(__APPLE__)
    /* Apple Silicon schedules threads across performance and efficiency
     * cores; an unhinted benchmark can land on an E-core and report a cost
     * that has nothing to do with the code. Ask for the interactive class,
     * then report what was actually granted. */
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    g_suite = suite_name;
    select_clock();
    print_environment(suite_name);
}

void bench_section(const char *title) {
    if (bench_csv_mode) {
        printf("# --- %s ---\n", title);
        return;
    }
    printf("\n%s\n", title);
    printf("  %-34s %-9s %10s %10s %10s %10s %8s %9s\n", "operation", "payload", "median", "min",
           "p90", "p99", "batch", "samples");
}

static void print_csv_header_once(void) {
    if (g_row_printed) {
        return;
    }
    printf("\"suite\",\"operation\",\"payload\",batch,samples,iters,min_ns,median_ns,p90_ns,p99_ns,"
           "mean_ns,stddev_ns,bytes_per_iter,mib_per_s,ops_per_s\n");
    g_row_printed = 1;
}

static void human_time(double ns, char *out, size_t cap) {
    if (ns < 1000.0) {
        snprintf(out, cap, "%.1f ns", ns);
    } else if (ns < 1000000.0) {
        snprintf(out, cap, "%.2f us", ns / 1000.0);
    } else {
        snprintf(out, cap, "%.3f ms", ns / 1000000.0);
    }
}

void bench_report(const bench_result_t *r) {
    const double ops_per_s = (r->median_ns > 0.0) ? 1e9 / r->median_ns : 0.0;
    const double mib_per_s =
        (r->bytes_per_iter > 0.0 && r->median_ns > 0.0)
            ? (r->bytes_per_iter * 1e9) / (r->median_ns * 1024.0 * 1024.0)
            : 0.0;

    if (bench_csv_mode) {
        print_csv_header_once();
        /* Text fields are quoted: operation names contain commas. */
        printf("\"%s\",\"%s\",\"%s\",%zu,%zu,%llu,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.0f,%.2f,%.0f\n", g_suite,
               r->name, r->note, r->batch, r->samples, (unsigned long long)r->iters, r->min_ns,
               r->median_ns, r->p90_ns, r->p99_ns, r->mean_ns, r->stddev_ns, r->bytes_per_iter,
               mib_per_s, ops_per_s);
        return;
    }

    char med[32];
    char mn[32];
    char p90[32];
    char p99[32];
    human_time(r->median_ns, med, sizeof(med));
    human_time(r->min_ns, mn, sizeof(mn));
    human_time(r->p90_ns, p90, sizeof(p90));
    human_time(r->p99_ns, p99, sizeof(p99));
    printf("  %-34s %-9s %10s %10s %10s %10s %8zu %9zu", r->name, r->note, med, mn, p90, p99,
           r->batch, r->samples);
    if (r->bytes_per_iter > 0.0) {
        printf("   %8.1f MiB/s", mib_per_s);
    }
    printf("\n");
}

void bench_finish(const char *suite_name) {
    if (!bench_csv_mode) {
        printf("\n%s: done%s\n", suite_name,
               bench_smoke_mode ? " (smoke mode: correctness only, numbers are meaningless)" : "");
    }
}

/* ---- the driver ---------------------------------------------------------- */

static int cmp_double(const void *a, const void *b) {
    const double x = *(const double *)a;
    const double y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Percentile of a sorted array, nearest-rank. */
static double pct(const double *sorted, size_t n, double p) {
    if (n == 0) {
        return 0.0;
    }
    size_t idx = (size_t)ceil(p * (double)n) - 1u;
    if (idx >= n) {
        idx = n - 1u;
    }
    return sorted[idx];
}

bench_result_t bench_run(const char *name, const char *note, bench_prepare_fn prepare,
                         bench_work_fn work, void *ctx, size_t k_hint, double bytes_per_iter) {
    const double min_total_ns = bench_smoke_mode ? 2e6 : 2e8;  /* 2 ms smoke, 200 ms real */
    const size_t min_samples = bench_smoke_mode ? 3u : 25u;

    size_t k = k_hint;
    if (k == 0) {
        /* Calibrate: grow the batch until one lasts ~BENCH_BATCH_TARGET_NS,
         * so the clock's resolution contributes a negligible share. */
        k = 1;
        for (;;) {
            if (prepare != NULL) {
                prepare(ctx, k);
            }
            const uint64_t t0 = bench_now_ns();
            work(ctx, k);
            const double dt = (double)(bench_now_ns() - t0);
            if (dt >= BENCH_BATCH_TARGET_NS || k >= (1u << 20)) {
                break;
            }
            const double grow = (dt > 0.0) ? (BENCH_BATCH_TARGET_NS / dt) : 8.0;
            size_t next = (size_t)((double)k * ((grow < 8.0) ? grow : 8.0)) + 1u;
            if (next <= k) {
                next = k + 1u;
            }
            k = next;
        }
        if (bench_smoke_mode && k > 64u) {
            k = 64u;
        }
    }

    /* Warmup: one full batch, discarded. Pulls code and data into cache and
     * lets the CPU settle at its working frequency, so the first real sample
     * is not an outlier (mutation M4 removes this deliberately). */
    if (prepare != NULL) {
        prepare(ctx, k);
    }
    work(ctx, k);

    size_t n = 0;
    double total = 0.0;
    while (n < BENCH_MAX_SAMPLES && (n < min_samples || total < min_total_ns)) {
        if (prepare != NULL) {
            prepare(ctx, k);
        }
        const uint64_t t0 = bench_now_ns();
        work(ctx, k);
        const uint64_t t1 = bench_now_ns();
        const double per_iter = (double)(t1 - t0) / (double)k;
        g_samples[n++] = per_iter;
        total += (double)(t1 - t0);
    }

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += g_samples[i];
    }
    const double mean = sum / (double)n;
    double var = 0.0;
    for (size_t i = 0; i < n; i++) {
        const double d = g_samples[i] - mean;
        var += d * d;
    }
    var = (n > 1u) ? var / (double)(n - 1u) : 0.0;

    qsort(g_samples, n, sizeof(g_samples[0]), cmp_double);

    bench_result_t r;
    memset(&r, 0, sizeof(r));
    r.name = name;
    r.note = (note != NULL) ? note : "";
    r.batch = k;
    r.samples = n;
    r.iters = (uint64_t)n * (uint64_t)k;
    r.min_ns = g_samples[0];
    r.median_ns = pct(g_samples, n, 0.50);
    r.p90_ns = pct(g_samples, n, 0.90);
    r.p99_ns = pct(g_samples, n, 0.99);
    r.mean_ns = mean;
    r.stddev_ns = sqrt(var);
    r.bytes_per_iter = bytes_per_iter;

    BENCH_REQUIRE(r.median_ns > 0.0, "%s: measured a zero median -- the clock or the batch size is "
                                     "wrong (resolution %.1f ns, batch %zu)",
                  name, g_clock_res_ns, k);
    return r;
}
