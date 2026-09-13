/*
 * Portable driver for the Step 7 fuzz targets: built with ANY compiler (it
 * does not need libFuzzer), linked with one fuzz_<t>.c.
 *
 *   fuzz_<t>_replay FILE...          reproduce specific inputs (verbose)
 *   fuzz_<t>_replay --ci --dict D --regressions DIR --iterations N --seed S
 *        1. the empty input (passed as NULL, 0: any access is a bug)
 *        2. every in-memory seed
 *        3. every committed regression input in DIR
 *        4. N deterministic mutations of the seeds (xorshift64*, fixed seed)
 *   fuzz_<t>_replay --write-seeds DIR   write the seed corpus (build dir only)
 *   fuzz_<t>_replay <target command>    e.g. fuzz_keys_replay --scan-secret
 *
 * The mutation smoke is the FALLBACK when libFuzzer is unavailable. It is NOT
 * coverage-guided; it only exercises the harness oracles on perturbed seeds.
 * Every input is passed in an exact-size heap buffer so AddressSanitizer
 * catches any read past its end.
 */

#include "fuzz_common.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    char *name;
    uint8_t *data;
    size_t len;
} blob_t;

typedef struct {
    blob_t *v;
    size_t n;
    size_t cap;
} blobs_t;

static void die(const char *what) {
    fprintf(stderr, "fuzz_%s_replay: %s\n", fuzz_target_name, what);
    exit(2);
}

static void blobs_push(blobs_t *b, const char *name, const uint8_t *data, size_t len) {
    if (b->n == b->cap) {
        b->cap = b->cap ? 2 * b->cap : 32;
        b->v = realloc(b->v, b->cap * sizeof(*b->v));
        if (b->v == NULL) {
            die("out of memory");
        }
    }
    blob_t *e = &b->v[b->n++];
    e->name = strdup(name != NULL ? name : "");
    e->len = len;
    e->data = malloc(len ? len : 1);
    if (e->name == NULL || e->data == NULL) {
        die("out of memory");
    }
    if (len != 0) {
        memcpy(e->data, data, len);
    }
}

static void emit_to_blobs(void *ctx, const char *name, const uint8_t *data, size_t len) {
    blobs_push((blobs_t *)ctx, name, data, len);
}

/* The input currently running, saved as a crash artifact if an oracle fails. */
static const uint8_t *g_cur;
static size_t g_cur_len;
static const char *g_cur_label = "input";

static void save_failing_input(void) {
    char name[256];
    snprintf(name, sizeof(name), "crash-%s-replay-%s", fuzz_target_name, g_cur_label);
    FILE *f = fopen(name, "wb");
    if (f != NULL) {
        if (g_cur_len != 0) {
            (void)fwrite(g_cur, 1, g_cur_len, f);
        }
        fclose(f);
        fprintf(stderr, "fuzz_%s_replay: failing input (%zu bytes) saved to ./%s\n", fuzz_target_name, g_cur_len,
                name);
    }
}

/* Runs one input from an exact-size heap copy (NULL for the empty input). */
static void run_one(const uint8_t *data, size_t len) {
    if (len == 0) {
        g_cur = NULL;
        g_cur_len = 0;
        (void)LLVMFuzzerTestOneInput(NULL, 0);
        return;
    }
    uint8_t *copy = malloc(len);
    if (copy == NULL) {
        die("out of memory");
    }
    memcpy(copy, data, len);
    g_cur = copy;
    g_cur_len = len;
    (void)LLVMFuzzerTestOneInput(copy, len);
    g_cur = NULL;
    free(copy);
}

static int read_file(const char *path, uint8_t **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    size_t cap = 4096;
    size_t n = 0;
    uint8_t *buf = malloc(cap);
    for (;;) {
        if (buf == NULL) {
            fclose(f);
            return -1;
        }
        if (n == cap) {
            if (cap >= (size_t)64 << 20) {
                free(buf);
                fclose(f);
                return -1;
            }
            cap *= 2;
            uint8_t *grown = realloc(buf, cap);
            if (grown == NULL) {
                free(buf); /* realloc leaves the old block allocated on failure */
                fclose(f);
                return -1;
            }
            buf = grown;
            continue;
        }
        const size_t want = cap - n;
        const size_t r = fread(buf + n, 1, want, f);
        n += r;
        if (r < want) {
            break; /* short read: EOF or error -- ferror() below decides which */
        }
    }
    const int err = ferror(f);
    fclose(f);
    if (err) {
        free(buf);
        return -1;
    }
    *data = buf;
    *len = n;
    return 0;
}

/* ---- libFuzzer-format dictionary -------------------------------------------- */

static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static void load_dict(const char *path, blobs_t *tokens) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        die("cannot open dictionary");
    }
    char line[4096];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *q = strchr(line, '"');
        char *hash = strchr(line, '#');
        if (q == NULL || (hash != NULL && hash < q)) {
            continue;
        }
        uint8_t tok[512];
        size_t n = 0;
        for (char *s = q + 1; *s != '\0' && *s != '"' && n < sizeof(tok); s++) {
            if (*s == '\\' && s[1] == 'x' && hexval(s[2]) >= 0 && hexval(s[3]) >= 0) {
                tok[n++] = (uint8_t)(hexval(s[2]) * 16 + hexval(s[3]));
                s += 3;
            } else if (*s == '\\' && (s[1] == '\\' || s[1] == '"')) {
                tok[n++] = (uint8_t)s[1];
                s += 1;
            } else {
                tok[n++] = (uint8_t)*s;
            }
        }
        if (n > 0) {
            blobs_push(tokens, "token", tok, n);
        }
    }
    fclose(f);
}

/* ---- deterministic mutator ---------------------------------------------------- */

static uint64_t g_x = 1;

static uint64_t xr(void) {
    g_x ^= g_x >> 12;
    g_x ^= g_x << 25;
    g_x ^= g_x >> 27;
    return g_x * UINT64_C(2685821657736338717);
}

static size_t mutate(uint8_t *buf, size_t len, size_t cap, const blobs_t *dict) {
    static const uint8_t boundary[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
    const unsigned ops = 1u + (unsigned)(xr() % 4u);
    for (unsigned k = 0; k < ops; k++) {
        switch (xr() % 8u) {
        case 0: /* flip a bit */
            if (len) {
                buf[xr() % len] ^= (uint8_t)(1u << (xr() % 8u));
            }
            break;
        case 1: /* random byte */
            if (len) {
                buf[xr() % len] = (uint8_t)xr();
            }
            break;
        case 2: /* boundary byte */
            if (len) {
                buf[xr() % len] = boundary[xr() % sizeof(boundary)];
            }
            break;
        case 3: { /* insert or overwrite with a dictionary token */
            if (dict->n == 0) {
                break;
            }
            const blob_t *t = &dict->v[xr() % dict->n];
            const size_t pos = xr() % (len + 1u);
            if (xr() & 1u) {
                if (len + t->len <= cap) {
                    memmove(buf + pos + t->len, buf + pos, len - pos);
                    memcpy(buf + pos, t->data, t->len);
                    len += t->len;
                }
            } else if (pos + t->len <= len) {
                memcpy(buf + pos, t->data, t->len);
            }
            break;
        }
        case 4: { /* delete a range */
            if (len) {
                const size_t pos = xr() % len;
                const size_t n = 1u + xr() % (len - pos);
                memmove(buf + pos, buf + pos + n, len - pos - n);
                len -= n;
            }
            break;
        }
        case 5: { /* duplicate a range */
            if (len) {
                const size_t src = xr() % len;
                size_t n = 1u + xr() % (len - src);
                if (n > cap - len) {
                    n = cap - len;
                }
                const size_t pos = xr() % (len + 1u);
                memmove(buf + pos + n, buf + pos, len - pos);
                /* the source may have shifted if it was at or after pos */
                const size_t s2 = (src >= pos) ? src + n : src;
                memmove(buf + pos, buf + s2, n);
                len += n;
            }
            break;
        }
        case 6: /* truncate */
            len = xr() % (len + 1u);
            break;
        default: { /* extend with random bytes */
            size_t n = 1u + xr() % 16u;
            if (n > cap - len) {
                n = cap - len;
            }
            for (size_t i = 0; i < n; i++) {
                buf[len + i] = (uint8_t)xr();
            }
            len += n;
            break;
        }
        }
    }
    return len;
}

/* ---- modes -------------------------------------------------------------------- */

static int name_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static size_t run_regressions(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) {
        die("cannot open regressions directory");
    }
    char **names = NULL;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue; /* ".", "..", ".gitkeep" */
        }
        names = realloc(names, (n + 1) * sizeof(*names));
        if (names == NULL || (names[n] = strdup(e->d_name)) == NULL) {
            die("out of memory");
        }
        n++;
    }
    closedir(d);
    qsort(names, n, sizeof(*names), name_cmp);
    for (size_t i = 0; i < n; i++) {
        char path[4096];
        uint8_t *data = NULL;
        size_t len = 0;
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        if (read_file(path, &data, &len) != 0) {
            die("cannot read a regression input");
        }
        printf("fuzz_%s_replay: regression %s (%zu bytes)\n", fuzz_target_name, names[i], len);
        run_one(data, len);
        free(data);
        free(names[i]);
    }
    free(names);
    return n;
}

static int cmd_ci(int argc, char **argv) {
    const char *dict_path = NULL;
    const char *reg_dir = NULL;
    unsigned long long iterations = 1000;
    unsigned long long seed = 1;
    for (int i = 2; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--dict") == 0) {
            dict_path = argv[i + 1];
        } else if (strcmp(argv[i], "--regressions") == 0) {
            reg_dir = argv[i + 1];
        } else if (strcmp(argv[i], "--iterations") == 0) {
            iterations = strtoull(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--seed") == 0) {
            seed = strtoull(argv[i + 1], NULL, 10);
        } else {
            die("unknown --ci option");
        }
    }

    run_one(NULL, 0);
    printf("fuzz_%s_replay: empty input: ok\n", fuzz_target_name);

    blobs_t seeds = {0};
    fuzz_target_seeds(emit_to_blobs, &seeds);
    for (size_t i = 0; i < seeds.n; i++) {
        /* A seed the target cannot accept is a HARNESS defect: the
         * mutation loop below used to silently truncate it to `cap`, so a
         * fuzz_target_max_len left behind after a message grew would
         * quietly shrink the corpus instead of failing. Fail loudly. */
        if (seeds.v[i].len > fuzz_target_max_len) {
            fprintf(stderr, "fuzz_%s_replay: seed \"%s\" is %zu bytes, over the target maximum of %zu\n",
                    fuzz_target_name, seeds.v[i].name, seeds.v[i].len, fuzz_target_max_len);
            die("seed longer than fuzz_target_max_len (raise it; do not truncate the corpus)");
        }
        run_one(seeds.v[i].data, seeds.v[i].len);
    }
    printf("fuzz_%s_replay: seeds: %zu ok\n", fuzz_target_name, seeds.n);

    if (reg_dir != NULL) {
        const size_t r = run_regressions(reg_dir);
        printf("fuzz_%s_replay: regressions: %zu ok\n", fuzz_target_name, r);
    }

    blobs_t dict = {0};
    if (dict_path != NULL) {
        load_dict(dict_path, &dict);
    }
    const size_t cap = fuzz_target_max_len;
    uint8_t *buf = malloc(cap);
    if (buf == NULL || seeds.n == 0) {
        die("no buffer or no seeds");
    }
    g_x = seed ? seed : 1;
    for (unsigned long long it = 0; it < iterations; it++) {
        const blob_t *s = &seeds.v[xr() % seeds.n];
        size_t len = s->len; /* <= cap: checked above, not truncated here */
        memcpy(buf, s->data, len);
        len = mutate(buf, len, cap, &dict);
        run_one(buf, len);
    }
    printf("fuzz_%s_replay: mutations: %llu ok (dictionary: %zu tokens, seed %llu; deterministic fallback, NOT "
           "coverage-guided)\n",
           fuzz_target_name, iterations, dict.n, seed);
    free(buf);
    return 0;
}

static const char *g_seed_dir;

static void emit_to_dir(void *ctx, const char *name, const uint8_t *data, size_t len) {
    unsigned *count = (unsigned *)ctx;
    char path[4096];
    snprintf(path, sizeof(path), "%s/%03u-%s", g_seed_dir, (*count)++, name);
    FILE *f = fopen(path, "wb");
    if (f == NULL || (len != 0 && fwrite(data, 1, len, f) != len) || fclose(f) != 0) {
        die("cannot write a seed file");
    }
}

static int cmd_write_seeds(const char *dir) {
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        die("cannot create the seed directory");
    }
    g_seed_dir = dir;
    unsigned count = 0;
    fuzz_target_seeds(emit_to_dir, &count);
    printf("fuzz_%s_replay: wrote %u seeds to %s\n", fuzz_target_name, count, dir);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    (void)LLVMFuzzerInitialize(&argc, &argv);
    fuzz_failure_hook = save_failing_input;
    if (argc >= 2) {
        const int r = fuzz_target_command(argc, argv);
        if (r >= 0) {
            return r;
        }
    }
    if (argc >= 2 && strcmp(argv[1], "--ci") == 0) {
        return cmd_ci(argc, argv);
    }
    if (argc == 3 && strcmp(argv[1], "--write-seeds") == 0) {
        return cmd_write_seeds(argv[2]);
    }
    if (argc < 2 || argv[1][0] == '-') {
        fprintf(stderr,
                "usage: fuzz_%s_replay FILE... | --ci --dict D --regressions DIR --iterations N --seed S | "
                "--write-seeds DIR\n",
                fuzz_target_name);
        return 2;
    }
    fuzz_verbose = 1;
    for (int i = 1; i < argc; i++) {
        uint8_t *data = NULL;
        size_t len = 0;
        if (read_file(argv[i], &data, &len) != 0) {
            fprintf(stderr, "fuzz_%s_replay: cannot read %s\n", fuzz_target_name, argv[i]);
            return 2;
        }
        run_one(data, len);
        printf("fuzz_%s_replay: %s (%zu bytes): no oracle failure\n", fuzz_target_name, argv[i], len);
        free(data);
    }
    return 0;
}
