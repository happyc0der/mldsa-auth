/*
 * F5 fuzz_keys -- the Step 6 demo key-file loaders, through the REAL
 * file-based API (candidate files go to a 0600 temp file under $TMPDIR).
 *
 * Selector: bit 0 mode (0 public, 1 identity); bits 1-2 expected id
 * (0 "alice", 1 "a", 2 a fixed 64-character id, 3 "alice").
 *
 *   PUBLIC MODE: the payload IS the candidate public-key file (public data).
 *   IDENTITY MODE: the payload is an edit program, never file bytes. The
 *     fixture identity template -- "MLDSASK1" || 5 || "alice" || pk || sk --
 *     is regenerated IN MEMORY from the fixed test RNG for every input, the
 *     program edits a working copy, and only then is it written to the temp
 *     file. A stored identity-mode input therefore never contains key bytes.
 *
 * Grammar (bounded, total; every byte string is a valid program):
 *   program := count ops*      count = payload[0] % 9; empty payload = 0 ops
 *   op      := opcode operands opcode = byte % 8; stops early when bytes run out
 *   0 TRUNCATE  off16          L = off16 % (L+1)
 *   1 SET_BYTE  off16 v8       buf[off16 % L] = v8          (no-op if L == 0)
 *   2 FLIP_BIT  off16 b8       buf[off16 % L] ^= 1 << (b8&7)
 *   3 OVERWRITE off16 n8 lit   n = n8 % 33 (clipped); write at off16 % (L+1)
 *   4 DUPLICATE src16 n16      append buf[src16 % L ..] (n16 % 257 bytes, clipped)
 *   5 APPEND    n8 lit         n = n8 % 33 (clipped); append
 *   6 MAGIC     m8             first 8 bytes := one of 4 magics (L grows to 8)
 *   7 ID_LEN    v8             buf[8] = v8 when L > 8
 *   Capacity 8192; offsets are 2-byte big-endian.
 *
 * Extra command: --scan-secret FILE... / --scan-secret-dirs DIR... fails if
 * any file contains an ML-DSA secret-key file layout or any 16-byte window of
 * the fixture secret key (regenerated in memory). This is the repository
 * admission gate for committed fuzz inputs.
 */

#include "fuzz_common.h"

#include "demo_keys.h"
#include "secure_mem.h"

#include <sodium.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *const fuzz_target_name = "keys";
const size_t fuzz_target_max_len = 8192;

#define CAP 8192u
#define HDR 9u
#define PUB_LEN(idl) (HDR + (size_t)(idl) + MLDSA_PUBLIC_KEY_BYTES)
#define SK_LEN(idl) (PUB_LEN(idl) + MLDSA_SECRET_KEY_BYTES)
#define TEMPLATE_LEN SK_LEN(FUZZ_ID_A_LEN) /* 6002 */

static const char ID64_TEXT[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
_Static_assert(sizeof(ID64_TEXT) - 1u == 64u, "64-character id");

static const struct {
    const uint8_t *id;
    size_t len;
} EXPECT[4] = {
    {FUZZ_ID_A, FUZZ_ID_A_LEN},
    {(const uint8_t *)"a", 1},
    {(const uint8_t *)ID64_TEXT, 64},
    {FUZZ_ID_A, FUZZ_ID_A_LEN},
};

static const uint8_t MAGICS[4][8] = {
    {'M', 'L', 'D', 'S', 'A', 'S', 'K', '1'},
    {'M', 'L', 'D', 'S', 'A', 'P', 'K', '1'},
    {'M', 'L', 'D', 'S', 'A', 'S', 'K', '0'},
    {0, 0, 0, 0, 0, 0, 0, 0},
};

static char g_dir[PATH_MAX];
static char g_path[PATH_MAX];
static uint8_t *g_work; /* secure_mem, CAP bytes */
static uint8_t g_pubfile[PUB_LEN(64)];

/* ---- temp file ---------------------------------------------------------------- */

static void write_candidate(const uint8_t *p, size_t n) {
    const int fd = open(g_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    FUZZ_ASSERT(fd >= 0, "temp file open");
    size_t off = 0;
    while (off < n) {
        const ssize_t w = write(fd, p + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        FUZZ_ASSERT(w > 0, "temp file write");
        off += (size_t)w;
    }
    FUZZ_ASSERT(close(fd) == 0, "temp file close");
}

static void clear_candidate(void) {
    const int fd = open(g_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void cleanup(void) {
    if (g_path[0] != '\0') {
        (void)unlink(g_path);
    }
    if (g_dir[0] != '\0') {
        (void)rmdir(g_dir);
    }
    if (g_work != NULL) {
        secure_mem_free(g_work, CAP);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fuzz_common_init();
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/mldsa-fuzz-keys-XXXXXX", (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    FUZZ_ASSERT(mkdtemp(g_dir) != NULL, "mkdtemp");
    snprintf(g_path, sizeof(g_path), "%s/input", g_dir);
    g_work = secure_mem_alloc(CAP);
    FUZZ_ASSERT(g_work != NULL, "secure buffer");
    (void)atexit(cleanup);
    return 0;
}

/* ---- identity template (regenerated at runtime, never stored) ----------------- */

/* Rebuilds the fixture identity from the fixed test RNG into `kp` and writes
 * the template file bytes into g_work. Returns the template length. */
static size_t build_template(mldsa_keypair_t *kp) {
    fuzz_regenerate_identity_a(kp);
    FUZZ_ASSERT(sodium_memcmp(kp->public_key, fuzz_identities()->kp_a.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
                "the runtime template must reproduce the fixture identity exactly");
    memcpy(g_work, MAGICS[0], 8);
    g_work[8] = (uint8_t)FUZZ_ID_A_LEN;
    memcpy(g_work + HDR, FUZZ_ID_A, FUZZ_ID_A_LEN);
    memcpy(g_work + HDR + FUZZ_ID_A_LEN, kp->public_key, MLDSA_PUBLIC_KEY_BYTES);
    memcpy(g_work + HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES, kp->secret_key, MLDSA_SECRET_KEY_BYTES);
    return TEMPLATE_LEN;
}

static unsigned rd16(const uint8_t *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

/* Applies the mutation program; returns the new length. Total and bounded. */
static size_t apply_program(uint8_t *buf, size_t L, const uint8_t *p, size_t n, unsigned *ops_done) {
    size_t i = 0;
    const unsigned count = (n > 0) ? p[i++] % 9u : 0u;
    *ops_done = 0;
    for (unsigned k = 0; k < count && i < n; k++) {
        const unsigned op = p[i++] % 8u;
        const size_t left = n - i;
        switch (op) {
        case 0: /* TRUNCATE off16 */
            if (left < 2) {
                return L;
            }
            L = rd16(p + i) % (L + 1u);
            i += 2;
            break;
        case 1: /* SET_BYTE off16 v8 */
            if (left < 3) {
                return L;
            }
            if (L != 0) {
                buf[rd16(p + i) % L] = p[i + 2];
            }
            i += 3;
            break;
        case 2: /* FLIP_BIT off16 b8 */
            if (left < 3) {
                return L;
            }
            if (L != 0) {
                buf[rd16(p + i) % L] ^= (uint8_t)(1u << (p[i + 2] & 7u));
            }
            i += 3;
            break;
        case 3: { /* OVERWRITE off16 n8 lit[n] */
            if (left < 3) {
                return L;
            }
            const size_t pos = rd16(p + i) % (L + 1u);
            size_t cnt = p[i + 2] % 33u;
            i += 3;
            if (cnt > n - i) {
                cnt = n - i;
            }
            size_t w = cnt;
            if (pos + w > CAP) {
                w = CAP - pos;
            }
            memcpy(buf + pos, p + i, w);
            if (pos + w > L) {
                L = pos + w;
            }
            i += cnt;
            break;
        }
        case 4: { /* DUPLICATE src16 n16 */
            if (left < 4) {
                return L;
            }
            if (L != 0) {
                const size_t idx = rd16(p + i) % L;
                size_t cnt = rd16(p + i + 2) % 257u;
                if (cnt > L - idx) {
                    cnt = L - idx;
                }
                if (cnt > CAP - L) {
                    cnt = CAP - L;
                }
                memmove(buf + L, buf + idx, cnt);
                L += cnt;
            }
            i += 4;
            break;
        }
        case 5: { /* APPEND n8 lit[n] */
            if (left < 1) {
                return L;
            }
            size_t cnt = p[i] % 33u;
            i += 1;
            if (cnt > n - i) {
                cnt = n - i;
            }
            size_t w = cnt;
            if (w > CAP - L) {
                w = CAP - L;
            }
            memcpy(buf + L, p + i, w);
            L += w;
            i += cnt;
            break;
        }
        case 6: /* MAGIC m8 */
            if (left < 1) {
                return L;
            }
            if (L < 8) {
                memset(buf + L, 0, 8 - L);
                L = 8;
            }
            memcpy(buf, MAGICS[p[i] % 4u], 8);
            i += 1;
            break;
        default: /* ID_LEN v8 */
            if (left < 1) {
                return L;
            }
            if (L > 8) {
                buf[8] = p[i];
            }
            i += 1;
            break;
        }
        (*ops_done)++;
    }
    return L;
}

/* ---- reference model ------------------------------------------------------------ */

enum { M_FORMAT, M_ID_MISMATCH, M_VALID };

static int model(const uint8_t *b, size_t L, int secret, const uint8_t *eid, size_t elen) {
    const size_t extra = secret ? MLDSA_SECRET_KEY_BYTES : 0u;
    if (L < PUB_LEN(1) + extra || L > PUB_LEN(64) + extra) {
        return M_FORMAT;
    }
    if (memcmp(b, secret ? MAGICS[0] : MAGICS[1], 8) != 0) {
        return M_FORMAT;
    }
    const size_t idl = b[8];
    if (idl < 1u || idl > 64u || L != PUB_LEN(idl) + extra) {
        return M_FORMAT;
    }
    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {
        return M_ID_MISMATCH;
    }
    return M_VALID;
}

static const char *model_name(int m) {
    return m == M_FORMAT ? "format" : (m == M_ID_MISMATCH ? "id-mismatch" : "structurally-valid");
}

static void run_public(const uint8_t *p, size_t n, const uint8_t *eid, size_t elen) {
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    memset(pk, 0xA5, sizeof(pk));
    write_candidate(p, n);
    const demo_keys_status_t st = demo_keys_load_public(g_path, eid, elen, pk);
    const int m = model(p, n, 0, eid, elen);
    if (m == M_VALID) {
        FUZZ_ASSERT(st == DEMO_KEYS_OK, "public: a structurally valid file must load");
        FUZZ_ASSERT(memcmp(pk, p + HDR + p[8], MLDSA_PUBLIC_KEY_BYTES) == 0, "public: loaded key == file key bytes");
    } else {
        FUZZ_ASSERT(st == (m == M_FORMAT ? DEMO_KEYS_ERR_FORMAT : DEMO_KEYS_ERR_ID_MISMATCH),
                    "public: status disagrees with the reference model");
        FUZZ_ASSERT(sodium_is_zero(pk, sizeof(pk)), "public: output zeroed on failure");
    }
}

static void run_identity(const uint8_t *p, size_t n, const uint8_t *eid, size_t elen) {
    mldsa_keypair_t tkp;
    mldsa_keypair_t kp;
    memset(&tkp, 0, sizeof(tkp));
    memset(&kp, 0, sizeof(kp));
    const size_t tlen = build_template(&tkp);
    uint8_t tsha[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(tsha, g_work, tlen);

    unsigned ops = 0;
    const size_t L = apply_program(g_work, tlen, p, n, &ops);
    int same = 0;
    if (L == tlen) {
        /* Compare against the template without keeping a second copy: the
         * header, id and both key regions must be byte-identical. */
        same = memcmp(g_work, MAGICS[0], 8) == 0 && g_work[8] == FUZZ_ID_A_LEN &&
               memcmp(g_work + HDR, FUZZ_ID_A, FUZZ_ID_A_LEN) == 0 &&
               sodium_memcmp(g_work + HDR + FUZZ_ID_A_LEN, tkp.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0 &&
               sodium_memcmp(g_work + HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES, tkp.secret_key,
                             MLDSA_SECRET_KEY_BYTES) == 0;
    }
    const int m = model(g_work, L, 1, eid, elen);
    write_candidate(g_work, L);
    const demo_keys_status_t st = demo_keys_load_identity(g_path, eid, elen, &kp);
    clear_candidate();

    if (fuzz_verbose) {
        char hex[2 * 8 + 1];
        sodium_bin2hex(hex, sizeof(hex), tsha, 8);
        fprintf(stderr,
                "[keys] identity mode: template regenerated at runtime from the fixed test RNG (%zu bytes, "
                "sha256 %s...); program: %zu bytes, %u ops applied; working length %zu; expected id '%.*s'; "
                "model %s; status %s\n",
                tlen, hex, n, ops, L, (int)elen, (const char *)eid, model_name(m), demo_keys_status_name(st));
    }

    if (m == M_FORMAT) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_FORMAT, "identity: FORMAT expected");
    } else if (m == M_ID_MISMATCH) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_ID_MISMATCH, "identity: ID_MISMATCH expected");
    } else {
        FUZZ_ASSERT(st == DEMO_KEYS_OK || st == DEMO_KEYS_ERR_KEY_MISMATCH || st == DEMO_KEYS_ERR_CRYPTO,
                    "identity: a structurally valid file yields OK, KEY_MISMATCH or CRYPTO");
        if (same) {
            FUZZ_ASSERT(st == DEMO_KEYS_OK, "identity: the unmodified fixture template must load");
        }
    }
    if (st == DEMO_KEYS_OK) {
        /* The loader's DOCUMENTED contract: its single sign/verify self-test
         * passed, and the loaded key is exactly the file's bytes. Deliberately
         * NOT asserted: that an accepted key signs every message correctly.
         * Fuzzing showed (regression t0-corruption-accepted-*) that a key with
         * a corrupted t0 component passes the one-shot self-test ~75% of the
         * time yet ~32% of its signatures fail to verify -- an OPEN Step 6
         * finding recorded in docs/decisions.md, to be fixed in apps/. */
        const size_t idl = g_work[8];
        FUZZ_ASSERT(kp.secret_key != NULL &&
                        memcmp(kp.public_key, g_work + HDR + idl, MLDSA_PUBLIC_KEY_BYTES) == 0 &&
                        sodium_memcmp(kp.secret_key, g_work + HDR + idl + MLDSA_PUBLIC_KEY_BYTES,
                                      MLDSA_SECRET_KEY_BYTES) == 0,
                    "identity: OK must load exactly the file's key bytes");
    } else {
        FUZZ_ASSERT(kp.secret_key == NULL && sodium_is_zero(kp.public_key, MLDSA_PUBLIC_KEY_BYTES),
                    "identity: nothing is left loaded on failure");
    }
    mldsa_keypair_free(&kp);
    mldsa_keypair_free(&tkp);
    sodium_memzero(g_work, CAP);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const uint8_t sel = fuzz_selector(data, size, 0);
    const uint8_t *p = NULL;
    size_t n = 0;
    fuzz_payload(data, size, &p, &n);
    const unsigned e = (sel >> 1) & 3u;
    if (sel & 1u) {
        run_identity(p, n, EXPECT[e].id, EXPECT[e].len);
    } else {
        run_public(p, n, EXPECT[e].id, EXPECT[e].len);
    }
    return 0;
}

/* ---- seeds (public files hold only public data; identity seeds are programs) ---- */

static size_t pub_file(uint8_t *out, const uint8_t *id, size_t idl) {
    memcpy(out, MAGICS[1], 8);
    out[8] = (uint8_t)idl;
    memcpy(out + HDR, id, idl);
    memcpy(out + HDR + idl, fuzz_identities()->kp_a.public_key, MLDSA_PUBLIC_KEY_BYTES);
    return PUB_LEN(idl);
}

static void emit_sel(fuzz_emit_fn emit, void *ctx, const char *name, uint8_t sel, const uint8_t *p, size_t n) {
    static uint8_t seed[1 + CAP];
    seed[0] = sel;
    if (n != 0) {
        memcpy(seed + 1, p, n);
    }
    emit(ctx, name, seed, 1 + n);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    emit(ctx, "empty", fuzz_empty, 0);
    for (unsigned e = 0; e < 3; e++) {
        const size_t n = pub_file(g_pubfile, EXPECT[e].id, EXPECT[e].len);
        char name[64];
        snprintf(name, sizeof(name), "public-valid-id%zu", EXPECT[e].len);
        emit_sel(emit, ctx, name, (uint8_t)(e << 1), g_pubfile, n);
    }
    size_t n = pub_file(g_pubfile, FUZZ_ID_A, FUZZ_ID_A_LEN);
    emit_sel(emit, ctx, "public-wrong-expected-id", 1u << 1, g_pubfile, n); /* alice's file, expects "a" */
    emit_sel(emit, ctx, "public-truncated", 0, g_pubfile, n - 1u);
    g_pubfile[n] = 0x00;
    emit_sel(emit, ctx, "public-extended", 0, g_pubfile, n + 1u);
    g_pubfile[0] ^= 0x01;
    emit_sel(emit, ctx, "public-wrong-magic", 0, g_pubfile, n);
    g_pubfile[0] ^= 0x01;
    g_pubfile[8] = 0;
    emit_sel(emit, ctx, "public-idlen-0", 0, g_pubfile, n);
    g_pubfile[8] = 65;
    emit_sel(emit, ctx, "public-idlen-65", 0, g_pubfile, n);
    sodium_memzero(g_pubfile, sizeof(g_pubfile));

    /* Identity mode: mutation programs only (selector 0x01 = identity, "alice"). */
    const unsigned t = TEMPLATE_LEN;
    const uint8_t zero_ops[] = {0};
    const uint8_t trunc_last[] = {1, 0, (uint8_t)((t - 1u) >> 8), (uint8_t)(t - 1u)};
    const uint8_t append1[] = {1, 5, 1, 0x00};
    const uint8_t magic_pk[] = {1, 6, 1};
    const uint8_t idlen0[] = {1, 7, 0};
    const uint8_t idlen65[] = {1, 7, 65};
    const unsigned pkoff = HDR + FUZZ_ID_A_LEN + 100u;
    const unsigned skoff = HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES + 100u;
    const uint8_t flip_pk[] = {1, 2, (uint8_t)(pkoff >> 8), (uint8_t)pkoff, 0};
    const uint8_t flip_sk[] = {1, 2, (uint8_t)(skoff >> 8), (uint8_t)skoff, 0};
    const uint8_t trunc0[] = {1, 0, 0, 0};
    emit_sel(emit, ctx, "identity-0-ops", 1, zero_ops, sizeof(zero_ops));
    emit_sel(emit, ctx, "identity-empty-program", 1, fuzz_empty, 0);
    emit_sel(emit, ctx, "identity-truncate-last", 1, trunc_last, sizeof(trunc_last));
    emit_sel(emit, ctx, "identity-append-1", 1, append1, sizeof(append1));
    emit_sel(emit, ctx, "identity-magic-pk1", 1, magic_pk, sizeof(magic_pk));
    emit_sel(emit, ctx, "identity-idlen-0", 1, idlen0, sizeof(idlen0));
    emit_sel(emit, ctx, "identity-idlen-65", 1, idlen65, sizeof(idlen65));
    emit_sel(emit, ctx, "identity-flip-pk", 1, flip_pk, sizeof(flip_pk));
    emit_sel(emit, ctx, "identity-flip-sk", 1, flip_sk, sizeof(flip_sk));
    emit_sel(emit, ctx, "identity-truncate-0", 1, trunc0, sizeof(trunc0));
    emit_sel(emit, ctx, "identity-wrong-expected-id", 3, zero_ops, sizeof(zero_ops)); /* expects "a" */
}

/* ---- repository admission gate: --scan-secret ------------------------------------- */

typedef struct {
    uint64_t key;
    uint32_t idx;
} window_t;

static int window_cmp(const void *a, const void *b) {
    const uint64_t x = ((const window_t *)a)->key;
    const uint64_t y = ((const window_t *)b)->key;
    return (x > y) - (x < y);
}

static uint64_t load64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

typedef struct {
    window_t *win;
    size_t nwin;
    const uint8_t *sk;
    unsigned files;
    unsigned violations;
    unsigned token_only;
} scan_t;

/* A secret-key file layout: magic, a plausible id length, room for both keys,
 * and a key region that is binary (> 10% non-text bytes). Source and
 * dictionary files that merely mention the magic are text, so they are
 * reported as "token only". */
static int looks_like_key_layout(const uint8_t *b, size_t n, size_t o) {
    const size_t idl = (o + 8u < n) ? b[o + 8] : 0u;
    if (idl < 1u || idl > 64u || n - o < SK_LEN(idl)) {
        return 0;
    }
    const uint8_t *key = b + o + HDR + idl;
    const size_t klen = MLDSA_PUBLIC_KEY_BYTES + MLDSA_SECRET_KEY_BYTES;
    size_t binary = 0;
    for (size_t i = 0; i < klen; i++) {
        const uint8_t c = key[i];
        binary += !(c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c < 0x7f));
    }
    return binary * 10u > klen;
}

static void scan_buffer(scan_t *s, const char *path, const uint8_t *b, size_t n) {
    int token = 0;
    for (size_t o = 0; o + 8u <= n; o++) {
        if (memcmp(b + o, MAGICS[0], 8) != 0) {
            continue;
        }
        if (looks_like_key_layout(b, n, o)) {
            printf("VIOLATION: %s: secret-key file layout at offset %zu\n", path, o);
            s->violations++;
        } else {
            token = 1;
        }
    }
    for (size_t o = 0; o + 16u <= n; o++) {
        const window_t k = {load64(b + o), 0};
        window_t *hit = bsearch(&k, s->win, s->nwin, sizeof(window_t), window_cmp);
        if (hit == NULL) {
            continue;
        }
        /* Several windows may share the first 8 bytes: check neighbors. */
        while (hit > s->win && (hit - 1)->key == k.key) {
            hit--;
        }
        for (; hit < s->win + s->nwin && hit->key == k.key; hit++) {
            if (memcmp(b + o, s->sk + hit->idx, 16) == 0) {
                printf("VIOLATION: %s: 16-byte window of the fixture secret key at offset %zu\n", path, o);
                s->violations++;
                break;
            }
        }
    }
    if (token) {
        printf("token only: %s (bare \"MLDSASK1\" magic, no key-file layout)\n", path);
        s->token_only++;
    }
    s->files++;
}

static void scan_path(scan_t *s, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        printf("VIOLATION: cannot stat %s\n", path);
        s->violations++;
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d == NULL) {
            s->violations++;
            return;
        }
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            char sub[PATH_MAX];
            snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
            scan_path(s, sub);
        }
        closedir(d);
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        return;
    }
    FILE *f = fopen(path, "rb");
    uint8_t *buf = malloc((size_t)st.st_size + 1u);
    if (f == NULL || buf == NULL) {
        printf("VIOLATION: cannot read %s\n", path);
        s->violations++;
        if (f != NULL) {
            fclose(f);
        }
        free(buf);
        return;
    }
    const size_t n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    scan_buffer(s, path, buf, n);
    free(buf);
}

int fuzz_target_command(int argc, char **argv) {
    const int files = (strcmp(argv[1], "--scan-secret") == 0);
    const int dirs = (strcmp(argv[1], "--scan-secret-dirs") == 0);
    if (!files && !dirs) {
        return -1;
    }
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof(kp));
    fuzz_regenerate_identity_a(&kp); /* in memory only */
    scan_t s;
    memset(&s, 0, sizeof(s));
    s.sk = kp.secret_key;
    s.nwin = MLDSA_SECRET_KEY_BYTES - 16u + 1u;
    s.win = malloc(s.nwin * sizeof(window_t));
    FUZZ_ASSERT(s.win != NULL, "scan buffer");
    for (size_t i = 0; i < s.nwin; i++) {
        s.win[i].key = load64(kp.secret_key + i);
        s.win[i].idx = (uint32_t)i;
    }
    qsort(s.win, s.nwin, sizeof(window_t), window_cmp);
    for (int i = 2; i < argc; i++) {
        scan_path(&s, argv[i]);
    }
    sodium_memzero(s.win, s.nwin * sizeof(window_t));
    free(s.win);
    mldsa_keypair_free(&kp);
    printf("scan-secret: %u file(s) scanned, %u violation(s), %u token-only file(s)\n", s.files, s.violations,
           s.token_only);
    return s.violations == 0 ? 0 : 1;
}
