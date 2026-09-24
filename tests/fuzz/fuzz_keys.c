/*
 * F5 fuzz_keys -- the Step 6 demo key-file loaders, through the REAL
 * file-based API (candidate files go to a 0600 temp file under $TMPDIR).
 *
 * Selector: bit 0 mode (0 public, 1 identity); bits 1-2 expected id
 * (0 "alice", 1 "a", 2 a fixed 64-character id, 3 "alice"); bit 3, in
 * identity mode only, calls demo_keys_migrate_legacy() instead of the loader
 * (V2-9), so the legacy MLDSASK1 reader is fuzzed by the same programs
 * against its own independent model.
 *
 *   PUBLIC MODE: the payload IS the candidate public-key file (public data).
 *   IDENTITY MODE: the payload is an edit program, never file bytes. The
 *     fixture identity template -- the Step 7.1 MLDSASK2 file
 *     "MLDSASK2" || 5 || "alice" || pk || sk || digest (6030 bytes) -- is
 *     regenerated IN MEMORY from the fixed test RNG for every input (digest
 *     computed by this harness with its OWN copy of the label), the program
 *     edits a working copy, and only then is it written to the temp file. A
 *     stored identity-mode input therefore never contains key bytes.
 *
 * Grammar v2 (bounded, total; every byte string is a valid program; v2 only
 * changed the MAGIC table -- index 2 is now the legacy MLDSASK1 magic):
 *   program := count ops*      count = payload[0] % 9; empty payload = 0 ops
 *   op      := opcode operands opcode = byte % 8; stops early when bytes run out
 *   0 TRUNCATE  off16          L = off16 % (L+1)
 *   1 SET_BYTE  off16 v8       buf[off16 % L] = v8          (no-op if L == 0)
 *   2 FLIP_BIT  off16 b8       buf[off16 % L] ^= 1 << (b8&7)
 *   3 OVERWRITE off16 n8 lit   n = n8 % 33 (clipped); write at off16 % (L+1)
 *   4 DUPLICATE src16 n16      append buf[src16 % L ..] (n16 % 257 bytes, clipped)
 *   5 APPEND    n8 lit         n = n8 % 33 (clipped); append
 *   6 MAGIC     m8             first 8 bytes := MAGICS[m8 % 4] (L grows to 8):
 *                              MLDSASK2, MLDSAPK1, MLDSASK1 (legacy), 8 x 0x00
 *   7 ID_LEN    v8             buf[8] = v8 when L > 8
 *   Capacity 8192; offsets are 2-byte big-endian.
 *
 * Extra command: --scan-secret FILE... / --scan-secret-dirs DIR... fails if
 * any file contains an ML-DSA secret-key file layout (MLDSASK1 or MLDSASK2
 * magic followed by an id and binary key material) or any 16-byte window of
 * the SECRET regions of the fixture secret key (regenerated in memory).
 * Windows lying entirely inside rho or tr are excluded: both are derivable
 * from the PUBLIC key, and the scanner proves that derivability, and runs
 * its own negative controls, before every scan (V2-8). This is the
 * repository admission gate for committed fuzz inputs.
 */

#include "fuzz_common.h"

#include "demo_keys.h"
#include "secure_mem.h"

#include <oqs/sha3.h> /* OQS_SHA3_shake256, for the tr derivability proof */
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
#define SK_BODY_LEN(idl) (PUB_LEN(idl) + MLDSA_SECRET_KEY_BYTES) /* also the whole legacy MLDSASK1 file */
#define SK2_LEN(idl) (SK_BODY_LEN(idl) + 32u)
#define TEMPLATE_LEN SK2_LEN(FUZZ_ID_A_LEN)
_Static_assert(TEMPLATE_LEN == 6030u, "MLDSASK2 template for \"alice\" is 6025 + 5 bytes");

/* This harness's OWN copy of the integrity label and its own length rule, so
 * the model is independent of apps/demo_keys.c: a label/length/NUL slip made
 * symmetrically by keygen and the loader still disagrees with this digest. */
static const char HARNESS_LABEL[] = "mldsa-auth/v1/demo-key-integrity";
#define HARNESS_LABEL_LEN (sizeof(HARNESS_LABEL) - 1u)

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

/* Grammar v2 MAGIC table: 0 valid secret, 1 public, 2 LEGACY secret, 3 zeros. */
enum { MAGIC_SK2 = 0, MAGIC_PK1 = 1, MAGIC_SK1 = 2 };
static const uint8_t MAGICS[4][8] = {
    {'M', 'L', 'D', 'S', 'A', 'S', 'K', '2'},
    {'M', 'L', 'D', 'S', 'A', 'P', 'K', '1'},
    {'M', 'L', 'D', 'S', 'A', 'S', 'K', '1'},
    {0, 0, 0, 0, 0, 0, 0, 0},
};

static char g_dir[PATH_MAX];
static char g_path[PATH_MAX];
static char g_out[PATH_MAX]; /* migrate-mode output; unlinked after every input */
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
    if (g_out[0] != '\0') {
        (void)unlink(g_out);
    }
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
    /* Checked, not assumed: these are a mkdtemp() directory plus a short
     * literal, so truncation means this harness is wrong. gcc's
     * -Wformat-truncation cannot prove the bound and fails the build under
     * -Werror (clang does not implement the analysis). */
    FUZZ_ASSERT(snprintf(g_path, sizeof(g_path), "%s/input", g_dir) < (int)sizeof(g_path),
                "temp input path too long");
    FUZZ_ASSERT(snprintf(g_out, sizeof(g_out), "%s/migrated", g_dir) < (int)sizeof(g_out),
                "temp output path too long");
    g_work = secure_mem_alloc(CAP);
    FUZZ_ASSERT(g_work != NULL, "secure buffer");
    (void)atexit(cleanup);
    return 0;
}

/* ---- identity template (regenerated at runtime, never stored) ----------------- */

/* SHA-256(label || 0x00 || b[8, body_end)) -- id_len, id, pk, sk. */
static void harness_digest(uint8_t out[32], const uint8_t *b, size_t body_end) {
    static const uint8_t zero = 0x00;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)HARNESS_LABEL, HARNESS_LABEL_LEN);
    crypto_hash_sha256_update(&st, &zero, 1);
    crypto_hash_sha256_update(&st, b + 8, body_end - 8);
    crypto_hash_sha256_final(&st, out);
    sodium_memzero(&st, sizeof(st));
}

/* Rebuilds the fixture identity from the fixed test RNG into `kp` and writes
 * the MLDSASK2 template file bytes into g_work. Returns the template length. */
static size_t build_template(mldsa_keypair_t *kp) {
    fuzz_regenerate_identity_a(kp);
    FUZZ_ASSERT(sodium_memcmp(kp->public_key, fuzz_identities()->kp_a.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
                "the runtime template must reproduce the fixture identity exactly");
    memcpy(g_work, MAGICS[MAGIC_SK2], 8);
    g_work[8] = (uint8_t)FUZZ_ID_A_LEN;
    memcpy(g_work + HDR, FUZZ_ID_A, FUZZ_ID_A_LEN);
    memcpy(g_work + HDR + FUZZ_ID_A_LEN, kp->public_key, MLDSA_PUBLIC_KEY_BYTES);
    memcpy(g_work + HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES, kp->secret_key, MLDSA_SECRET_KEY_BYTES);
    harness_digest(g_work + SK_BODY_LEN(FUZZ_ID_A_LEN), g_work, SK_BODY_LEN(FUZZ_ID_A_LEN));
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

enum { M_FORMAT, M_ID_MISMATCH, M_VALID, M_UNSUPPORTED, M_INTEGRITY, M_NOT_LEGACY };

/* Public files: MLDSAPK1, unchanged by Step 7.1. */
static int model_public(const uint8_t *b, size_t L, const uint8_t *eid, size_t elen) {
    if (L < PUB_LEN(1) || L > PUB_LEN(64)) {
        return M_FORMAT;
    }
    if (memcmp(b, MAGICS[MAGIC_PK1], 8) != 0) {
        return M_FORMAT;
    }
    const size_t idl = b[8];
    if (idl < 1u || idl > 64u || L != PUB_LEN(idl)) {
        return M_FORMAT;
    }
    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {
        return M_ID_MISMATCH;
    }
    return M_VALID;
}

/* Secret files, model v2 (Step 7.1), first failure wins: size bounds ->
 * legacy magic -> magic -> id_len and exact size -> digest (recomputed HERE
 * with the harness's own label) -> id. */
static int model_secret(const uint8_t *b, size_t L, const uint8_t *eid, size_t elen) {
    if (L < HDR || L > SK2_LEN(64)) {
        return M_FORMAT;
    }
    if (memcmp(b, MAGICS[MAGIC_SK1], 8) == 0) {
        return M_UNSUPPORTED;
    }
    if (memcmp(b, MAGICS[MAGIC_SK2], 8) != 0) {
        return M_FORMAT;
    }
    const size_t idl = b[8];
    if (idl < 1u || idl > 64u || L != SK2_LEN(idl)) {
        return M_FORMAT;
    }
    uint8_t d[32];
    harness_digest(d, b, SK_BODY_LEN(idl));
    const int intact = (sodium_memcmp(d, b + SK_BODY_LEN(idl), 32) == 0);
    sodium_memzero(d, sizeof(d));
    if (!intact) {
        return M_INTEGRITY;
    }
    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {
        return M_ID_MISMATCH;
    }
    return M_VALID;
}

/* Migration model (V2-9), first failure wins and deliberately NOT sharing
 * code with model_secret: size bounds -> current magic (NOT_LEGACY) ->
 * legacy magic -> id_len and exact LEGACY size (no digest) -> id. There is
 * no digest to check; what remains is the sign/verify self-test, whose
 * verdict this model does not predict (OK / KEY_MISMATCH / CRYPTO). */
static int model_migrate(const uint8_t *b, size_t L, const uint8_t *eid, size_t elen) {
    if (L < HDR || L > SK2_LEN(64)) {
        return M_FORMAT;
    }
    if (memcmp(b, MAGICS[MAGIC_SK2], 8) == 0) {
        return M_NOT_LEGACY;
    }
    if (memcmp(b, MAGICS[MAGIC_SK1], 8) != 0) {
        return M_FORMAT;
    }
    const size_t idl = b[8];
    if (idl < 1u || idl > 64u || L != SK_BODY_LEN(idl)) {
        return M_FORMAT;
    }
    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {
        return M_ID_MISMATCH;
    }
    return M_VALID;
}

static const char *model_name(int m) {
    switch (m) {
    case M_FORMAT: return "format";
    case M_ID_MISMATCH: return "id-mismatch";
    case M_UNSUPPORTED: return "unsupported-version";
    case M_INTEGRITY: return "integrity";
    case M_NOT_LEGACY: return "not-a-legacy-file";
    default: return "structurally-valid";
    }
}

static void run_public(const uint8_t *p, size_t n, const uint8_t *eid, size_t elen) {
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    memset(pk, 0xA5, sizeof(pk));
    write_candidate(p, n);
    const demo_keys_status_t st = demo_keys_load_public(g_path, eid, elen, pk);
    const int m = model_public(p, n, eid, elen);
    /* V4-13a: the in-memory parser is what the file loader now calls, and what
     * the client core calls with no file at all -- same bytes, same verdict,
     * same key. */
    {
        uint8_t bk[MLDSA_PUBLIC_KEY_BYTES];
        memset(bk, 0x5A, sizeof(bk));
        const demo_keys_status_t bs = demo_keys_parse_public(p, n, eid, elen, bk);
        FUZZ_ASSERT(bs == st, "public: parse_public (buffer) and load_public (file) disagree");
        FUZZ_ASSERT(memcmp(bk, pk, sizeof(bk)) == 0, "public: buffer and file paths return different key bytes");
    }
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
        uint8_t d[32];
        harness_digest(d, g_work, SK_BODY_LEN(FUZZ_ID_A_LEN)); /* digest of the ORIGINAL body */
        same = memcmp(g_work, MAGICS[MAGIC_SK2], 8) == 0 && g_work[8] == FUZZ_ID_A_LEN &&
               memcmp(g_work + HDR, FUZZ_ID_A, FUZZ_ID_A_LEN) == 0 &&
               sodium_memcmp(g_work + HDR + FUZZ_ID_A_LEN, tkp.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0 &&
               sodium_memcmp(g_work + HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES, tkp.secret_key,
                             MLDSA_SECRET_KEY_BYTES) == 0 &&
               sodium_memcmp(g_work + SK_BODY_LEN(FUZZ_ID_A_LEN), d, 32) == 0;
        sodium_memzero(d, sizeof(d));
    }
    const int m = model_secret(g_work, L, eid, elen);
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
    } else if (m == M_UNSUPPORTED) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_UNSUPPORTED_VERSION, "identity: legacy MLDSASK1 -> UNSUPPORTED_VERSION expected");
    } else if (m == M_INTEGRITY) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_INTEGRITY, "identity: digest mismatch -> INTEGRITY expected");
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
        /* OK => the digest matched (the model agreed above) and the loaded
         * key is exactly the file's bytes. Step 7 found (regression
         * t0-corruption-original-*) that the old MLDSASK1 loader's one-shot
         * sign/verify self-test accepted a key with a corrupted t0 component
         * ~75% of the time; since Step 7.1 every stored byte is covered by the
         * digest, so any such edit is predicted -- and required -- to fail
         * with INTEGRITY (regression t0-corruption-rejected-*). */
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

/* Migrate mode (V2-9): the same mutation program, but the candidate file is
 * offered to demo_keys_migrate_legacy() instead of the loader. The input
 * file must never be modified, and an output must exist ONLY on success. */
static void run_migrate(const uint8_t *p, size_t n, const uint8_t *eid, size_t elen) {
    mldsa_keypair_t tkp;
    memset(&tkp, 0, sizeof(tkp));
    const size_t tlen = build_template(&tkp);
    unsigned ops = 0;
    const size_t L = apply_program(g_work, tlen, p, n, &ops);

    const int m = model_migrate(g_work, L, eid, elen);
    uint8_t in_sha[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(in_sha, g_work, L);
    (void)unlink(g_out);
    write_candidate(g_work, L);
    const demo_keys_status_t st = demo_keys_migrate_legacy(g_path, g_out, eid, elen);

    if (fuzz_verbose) {
        fprintf(stderr, "[keys] migrate mode: program %zu bytes, %u ops; working length %zu; model %s; status %s\n",
                n, ops, L, model_name(m), demo_keys_status_name(st));
    }

    if (m == M_FORMAT) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_FORMAT, "migrate: FORMAT expected");
    } else if (m == M_NOT_LEGACY) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_NOT_LEGACY, "migrate: an MLDSASK2 input must report NOT_LEGACY");
    } else if (m == M_ID_MISMATCH) {
        FUZZ_ASSERT(st == DEMO_KEYS_ERR_ID_MISMATCH, "migrate: ID_MISMATCH expected");
    } else {
        FUZZ_ASSERT(st == DEMO_KEYS_OK || st == DEMO_KEYS_ERR_KEY_MISMATCH || st == DEMO_KEYS_ERR_CRYPTO,
                    "migrate: a structurally valid legacy file yields OK, KEY_MISMATCH or CRYPTO");
    }

    struct stat out_st;
    const int out_exists = (lstat(g_out, &out_st) == 0);
    if (st == DEMO_KEYS_OK) {
        FUZZ_ASSERT(out_exists && S_ISREG(out_st.st_mode) && (out_st.st_mode & 0777) == 0600,
                    "migrate: success must leave a regular 0600 output file");
        /* The output is a loadable MLDSASK2 carrying the input's own keys,
         * with a digest this harness recomputes from its OWN label copy. */
        static uint8_t outbuf[CAP];
        const int fd = open(g_out, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        FUZZ_ASSERT(fd >= 0, "migrate: output open");
        const ssize_t rd = read(fd, outbuf, sizeof(outbuf));
        (void)close(fd);
        const size_t idl = g_work[8];
        FUZZ_ASSERT(rd > 0 && (size_t)rd == SK2_LEN(idl), "migrate: output size is 6025 + id_len");
        uint8_t want[32];
        harness_digest(want, outbuf, SK_BODY_LEN(idl));
        FUZZ_ASSERT(memcmp(outbuf, MAGICS[MAGIC_SK2], 8) == 0 &&
                        memcmp(outbuf + HDR, g_work + HDR, idl + MLDSA_PUBLIC_KEY_BYTES) == 0 &&
                        sodium_memcmp(outbuf + HDR + idl + MLDSA_PUBLIC_KEY_BYTES,
                                      g_work + HDR + idl + MLDSA_PUBLIC_KEY_BYTES, MLDSA_SECRET_KEY_BYTES) == 0 &&
                        sodium_memcmp(outbuf + SK_BODY_LEN(idl), want, 32) == 0,
                    "migrate: the output carries the input's keys under a correct MLDSASK2 digest");
        /* The migrated file is a correct MLDSASK2 file for the bytes it was
         * given -- asserted above. Whether it LOADS is a separate question:
         * ML-DSA signing is randomized, so the sign/verify self-test is
         * probabilistic, and a key that passed it during migration can fail
         * it here. (The fuzzer found this independently of T14.2.) What must
         * never happen is INTEGRITY or FORMAT: those would mean migration
         * wrote a file that disagrees with its own digest or layout. */
        mldsa_keypair_t lkp;
        const demo_keys_status_t lst = demo_keys_load_identity(g_out, eid, elen, &lkp);
        FUZZ_ASSERT(lst == DEMO_KEYS_OK || lst == DEMO_KEYS_ERR_KEY_MISMATCH || lst == DEMO_KEYS_ERR_CRYPTO,
                    "migrate: the migrated file must load, or fail only the randomized self-test");
        if (lst == DEMO_KEYS_OK) {
            mldsa_keypair_free(&lkp);
        }
        sodium_memzero(outbuf, sizeof(outbuf));
    } else {
        FUZZ_ASSERT(!out_exists, "migrate: a refused migration must leave no output file");
    }

    /* The source is read-only to this command, always. */
    static uint8_t inbuf[CAP];
    const int ifd = open(g_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FUZZ_ASSERT(ifd >= 0, "migrate: input reopen");
    const ssize_t ird = read(ifd, inbuf, sizeof(inbuf));
    (void)close(ifd);
    uint8_t after_sha[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(after_sha, inbuf, (ird > 0) ? (size_t)ird : 0u);
    FUZZ_ASSERT(ird >= 0 && (size_t)ird == L && sodium_memcmp(in_sha, after_sha, sizeof(in_sha)) == 0,
                "migrate: the input file is never modified");
    sodium_memzero(inbuf, sizeof(inbuf));

    (void)unlink(g_out);
    clear_candidate();
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
        if ((sel >> 3) & 1u) {
            run_migrate(p, n, EXPECT[e].id, EXPECT[e].len);
        } else {
            run_identity(p, n, EXPECT[e].id, EXPECT[e].len);
        }
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
    const uint8_t idlen6[] = {1, 7, 6};
    const uint8_t magic_legacy[] = {1, 6, MAGIC_SK1};
    const unsigned pkoff = HDR + FUZZ_ID_A_LEN + 100u;
    const unsigned skoff = HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES + 100u;
    const unsigned idoff = HDR + 2u;
    const unsigned dlast = t - 1u;          /* digest[31] */
    const unsigned t0off = (unsigned)SK_BODY_LEN(FUZZ_ID_A_LEN) - MLDSA_SECRET_KEY_BYTES + 2642u; /* 4608 */
    const uint8_t flip_pk[] = {1, 2, (uint8_t)(pkoff >> 8), (uint8_t)pkoff, 0};
    const uint8_t flip_sk[] = {1, 2, (uint8_t)(skoff >> 8), (uint8_t)skoff, 0};
    const uint8_t flip_id[] = {1, 2, (uint8_t)(idoff >> 8), (uint8_t)idoff, 0};
    const uint8_t flip_dlast[] = {1, 2, (uint8_t)(dlast >> 8), (uint8_t)dlast, 7};
    const uint8_t t0_overwrite[] = {1, 3, (uint8_t)(t0off >> 8), (uint8_t)t0off, 3, 0x70, 0x3c, 0x8d};
    const uint8_t trunc_digest[] = {1, 0, (uint8_t)((t - 32u) >> 8), (uint8_t)(t - 32u)};
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
    emit_sel(emit, ctx, "identity-flip-id", 1, flip_id, sizeof(flip_id));
    emit_sel(emit, ctx, "identity-flip-digest-last", 1, flip_dlast, sizeof(flip_dlast));
    emit_sel(emit, ctx, "identity-t0-overwrite", 1, t0_overwrite, sizeof(t0_overwrite));
    emit_sel(emit, ctx, "identity-magic-legacy", 1, magic_legacy, sizeof(magic_legacy));
    emit_sel(emit, ctx, "identity-truncate-digest", 1, trunc_digest, sizeof(trunc_digest));
    emit_sel(emit, ctx, "identity-idlen-6", 1, idlen6, sizeof(idlen6));
    emit_sel(emit, ctx, "identity-wrong-expected-id", 3, zero_ops, sizeof(zero_ops)); /* expects "a" */

    /* Migrate mode (V2-9), selector 0x09 = identity | migrate, id "alice".
     * "Legacy" = set the MLDSASK1 magic and truncate away the 32-byte
     * digest: 6030 -> 5998, which is exactly LEGACY_FILE_LEN(5). */
    const unsigned leg = (unsigned)(t - 32u); /* 5998 */
    const unsigned short_leg = leg - 1u;      /* 5997: one byte short */
    const uint8_t to_legacy[] = {2, 6, MAGIC_SK1, 0, (uint8_t)(leg >> 8), (uint8_t)leg};
    const uint8_t to_legacy_short[] = {2, 6, MAGIC_SK1, 0, (uint8_t)(short_leg >> 8), (uint8_t)short_leg};
    const uint8_t legacy_flip_pk[] = {3,   6, MAGIC_SK1, 0, (uint8_t)(leg >> 8), (uint8_t)leg,
                                      2,   (uint8_t)(pkoff >> 8), (uint8_t)pkoff, 0};
    emit_sel(emit, ctx, "identity-migrate-legacy-ok", 9, to_legacy, sizeof(to_legacy));
    emit_sel(emit, ctx, "identity-migrate-sk2-input", 9, zero_ops, sizeof(zero_ops));
    emit_sel(emit, ctx, "identity-migrate-wrong-id", 11, to_legacy, sizeof(to_legacy)); /* expects "a" */
    emit_sel(emit, ctx, "identity-migrate-flip-pk", 9, legacy_flip_pk, sizeof(legacy_flip_pk));
    emit_sel(emit, ctx, "identity-migrate-truncated", 9, to_legacy_short, sizeof(to_legacy_short));
}

/* ---- repository admission gate: --scan-secret ------------------------------------- */

/* FIPS 204 ML-DSA-65 secret-key layout, taken from the code that packs it --
 * liboqs's mldsa-native mld_pack_sk_rho_key_tr_s2() / mld_unpack_sk() and
 * params.h (SEEDBYTES 32, TRBYTES 64, K 6, L 5, ETA 4 -> POLYETA 128,
 * POLYT0 416):
 *
 *   rho [0,32)  K [32,64)  tr [64,128)  s1 [128,768)  s2 [768,1536)  t0 [1536,4032)
 *
 * rho IS pk[0..32) and tr IS SHAKE256(pk, 64), so a 16-byte window lying
 * entirely inside either one is computable by anyone holding the public key
 * and reveals nothing secret. Every other window -- including the 45 that
 * straddle a boundary, e.g. rho[17..32) || K[0] -- contains at least one
 * secret byte and is kept. Both identities are PROVEN at run time in
 * derivable_from_public() before any exclusion is applied. */
#define SK_RHO_LEN 32u
#define SK_K_OFF 32u
#define SK_TR_OFF 64u
#define SK_TR_LEN 64u
#define SK_S1_OFF 128u
#define SCAN_WINDOW 16u
_Static_assert(SK_S1_OFF + 5u * 128u + 6u * 128u + 6u * 416u == MLDSA_SECRET_KEY_BYTES,
               "ML-DSA-65 sk = rho|K|tr|s1(L=5)|s2(K=6)|t0(K=6), ETA=4 (POLYETA 128), POLYT0 416");
_Static_assert(SK_K_OFF == SK_RHO_LEN && SK_TR_OFF == SK_K_OFF + 32u && SK_S1_OFF == SK_TR_OFF + SK_TR_LEN,
               "the regions are contiguous in that order");

#define SCAN_TOTAL_WINDOWS (MLDSA_SECRET_KEY_BYTES - SCAN_WINDOW + 1u)                                 /* 4017 */
#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 1u) + (SK_TR_LEN - SCAN_WINDOW + 1u))         /* 17 + 49 */
#define SCAN_KEPT_WINDOWS (SCAN_TOTAL_WINDOWS - SCAN_PUBLIC_WINDOWS)                                   /* 3951 */
_Static_assert(SCAN_TOTAL_WINDOWS == 4017u, "4032 - 16 + 1");
_Static_assert(SCAN_PUBLIC_WINDOWS == 66u, "17 windows inside rho, 49 inside tr");
_Static_assert(SCAN_KEPT_WINDOWS == 3951u, "every window holding at least one secret byte");

/* True only when the window at `o` lies ENTIRELY inside rho or entirely
 * inside tr. A window that straddles a boundary holds secret bytes. */
static int window_is_public(size_t o) {
    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);
}

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
    unsigned layout_violations;
    unsigned window_violations;
    unsigned token_only;
    int quiet; /* controls scan in-memory buffers; their findings are counted, not printed */
} scan_t;

/* A secret-key file layout (MLDSASK1 or MLDSASK2 -- both hold a secret key):
 * magic, a plausible id length, room for both keys, and a key region that is
 * binary (> 10% non-text bytes). Source and dictionary files that merely
 * mention a magic are text, so they are reported as "token only". */
static int looks_like_key_layout(const uint8_t *b, size_t n, size_t o) {
    const size_t idl = (o + 8u < n) ? b[o + 8] : 0u;
    if (idl < 1u || idl > 64u || n - o < SK_BODY_LEN(idl)) {
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
        if (memcmp(b + o, MAGICS[MAGIC_SK2], 8) != 0 && memcmp(b + o, MAGICS[MAGIC_SK1], 8) != 0) {
            continue;
        }
        if (looks_like_key_layout(b, n, o)) {
            if (!s->quiet) {
                printf("VIOLATION: %s: secret-key file layout at offset %zu\n", path, o);
            }
            s->violations++;
            s->layout_violations++;
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
                if (!s->quiet) {
                    printf("VIOLATION: %s: 16-byte window of the fixture secret key at offset %zu "
                           "(secret-key offset %u)\n",
                           path, o, hit->idx);
                }
                s->violations++;
                s->window_violations++;
                break;
            }
        }
    }
    if (token) {
        if (!s->quiet) {
            printf("token only: %s (bare \"MLDSASK1\"/\"MLDSASK2\" magic, no key-file layout)\n", path);
        }
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

/* An exclusion is applied ONLY to bytes this scanner can itself derive from
 * the public key, and it proves both identities here, on the regenerated
 * fixture, before every scan. A failure is not a narrower scan -- it stops
 * the gate, because a layout this code no longer understands must never be
 * allowed to decide what counts as secret. */
static int derivable_from_public(const mldsa_keypair_t *kp) {
    int ok = 1;
    if (memcmp(kp->secret_key, kp->public_key, SK_RHO_LEN) != 0) {
        printf("SCANNER ABORT: sk[0..32) != pk[0..32) -- rho is not the shared public prefix this scanner assumes\n");
        ok = 0;
    }
    uint8_t tr[SK_TR_LEN];
    OQS_SHA3_shake256(tr, sizeof(tr), kp->public_key, MLDSA_PUBLIC_KEY_BYTES);
    if (sodium_memcmp(tr, kp->secret_key + SK_TR_OFF, sizeof(tr)) != 0) {
        printf("SCANNER ABORT: sk[64..128) != SHAKE256(pk, 64) -- tr is not derivable as this scanner assumes\n");
        ok = 0;
    }
    sodium_memzero(tr, sizeof(tr));
    return ok;
}

/* ---- built-in negative controls (run before every scan) --------------------------- */

/* The scanner proves its own rules still fire before it is allowed to admit
 * anything -- the session_no_alloc_scan pattern. Every control buffer is
 * built in memory from the regenerated fixture and wiped; none touches disk. */

typedef struct {
    unsigned layout;
    unsigned window;
    unsigned token;
} counts_t;

static counts_t control_scan(const scan_t *base, const uint8_t *b, size_t n) {
    scan_t t = *base; /* shares the window table; own counters */
    t.files = 0;
    t.violations = 0;
    t.layout_violations = 0;
    t.window_violations = 0;
    t.token_only = 0;
    t.quiet = 1;
    scan_buffer(&t, "<control>", b, n);
    const counts_t c = {t.layout_violations, t.window_violations, t.token_only};
    return c;
}

static int control_check(const char *id, const char *what, counts_t got, unsigned layout, unsigned window,
                         unsigned token) {
    const int ok = (got.layout == layout && got.window == window && got.token == token);
    printf("%s: scanner control %s: %s (layout %u, window %u, token-only %u; expected %u/%u/%u)\n",
           ok ? "PASS" : "FAIL", id, what, got.layout, got.window, got.token, layout, window, token);
    return ok;
}

/* The fixture identity file, laid out HERE so the controls do not depend on
 * the fuzz harness's own template helper. legacy=1 is the MLDSASK1 form (no
 * trailing digest). */
static size_t control_key_file(uint8_t *out, const mldsa_keypair_t *kp, int legacy) {
    memcpy(out, MAGICS[legacy ? MAGIC_SK1 : MAGIC_SK2], 8);
    out[8] = (uint8_t)FUZZ_ID_A_LEN;
    memcpy(out + HDR, FUZZ_ID_A, FUZZ_ID_A_LEN);
    memcpy(out + HDR + FUZZ_ID_A_LEN, kp->public_key, MLDSA_PUBLIC_KEY_BYTES);
    memcpy(out + HDR + FUZZ_ID_A_LEN + MLDSA_PUBLIC_KEY_BYTES, kp->secret_key, MLDSA_SECRET_KEY_BYTES);
    if (legacy) {
        return SK_BODY_LEN(FUZZ_ID_A_LEN); /* 5998 */
    }
    harness_digest(out + SK_BODY_LEN(FUZZ_ID_A_LEN), out, SK_BODY_LEN(FUZZ_ID_A_LEN));
    return SK2_LEN(FUZZ_ID_A_LEN); /* 6030 */
}

static int run_controls(const scan_t *base, const mldsa_keypair_t *kp) {
    const uint8_t *sk = kp->secret_key;
    int ok = 1;

    /* C1/C2: a real secret-key file is still refused, by BOTH rules. */
    uint8_t *f = secure_mem_alloc(SK2_LEN(FUZZ_ID_A_LEN));
    FUZZ_ASSERT(f != NULL, "control key-file buffer");
    size_t n = control_key_file(f, kp, 0);
    ok &= control_check("C1", "the fixture MLDSASK2 identity file is refused", control_scan(base, f, n), 1,
                        SCAN_KEPT_WINDOWS, 0);
    n = control_key_file(f, kp, 1);
    ok &= control_check("C2", "a legacy MLDSASK1 identity file is refused", control_scan(base, f, n), 1,
                        SCAN_KEPT_WINDOWS, 0);
    sodium_memzero(f, SK2_LEN(FUZZ_ID_A_LEN));
    secure_mem_free(f, SK2_LEN(FUZZ_ID_A_LEN));

    /* C3: the generated public-mode seed files -- the artifact class this
     * step makes admissible (17 window hits each before V2-8). */
    for (unsigned e = 0; e < 3; e++) {
        const size_t pn = pub_file(g_pubfile, EXPECT[e].id, EXPECT[e].len);
        char id[8];
        char what[96];
        snprintf(id, sizeof(id), "C3.%u", e + 1u);
        snprintf(what, sizeof(what), "a public-key file (id length %zu) is clean", EXPECT[e].len);
        ok &= control_check(id, what, control_scan(base, g_pubfile, pn), 0, 0, 0);
    }
    sodium_memzero(g_pubfile, sizeof(g_pubfile));

    /* C4: the excluded regions themselves, alone and together. */
    uint8_t cat[SK_RHO_LEN + SK_TR_LEN];
    memcpy(cat, sk, SK_RHO_LEN);
    memcpy(cat + SK_RHO_LEN, sk + SK_TR_OFF, SK_TR_LEN);
    ok &= control_check("C4.1", "rho alone is not flagged (it is pk[0..32))", control_scan(base, sk, SK_RHO_LEN), 0,
                        0, 0);
    ok &= control_check("C4.2", "tr alone is not flagged (it is SHAKE256(pk, 64))",
                        control_scan(base, sk + SK_TR_OFF, SK_TR_LEN), 0, 0, 0);
    ok &= control_check("C4.3", "rho || tr together are not flagged", control_scan(base, cat, sizeof(cat)), 0, 0, 0);
    sodium_memzero(cat, sizeof(cat));

    /* C5: the two boundaries, one window either side of each. */
    ok &= control_check("C5.1", "sk[16..32) -- the last window inside rho -- is not flagged",
                        control_scan(base, sk + 16, SCAN_WINDOW), 0, 0, 0);
    ok &= control_check("C5.2", "sk[17..33) -- the first window touching K -- IS flagged",
                        control_scan(base, sk + 17, SCAN_WINDOW), 0, 1, 0);
    ok &= control_check("C5.3", "sk[112..128) -- the last window inside tr -- is not flagged",
                        control_scan(base, sk + 112, SCAN_WINDOW), 0, 0, 0);
    ok &= control_check("C5.4", "sk[113..129) -- the first window touching s1 -- IS flagged",
                        control_scan(base, sk + 113, SCAN_WINDOW), 0, 1, 0);

    /* C6: one window from each genuinely secret region, embedded in text. */
    static const struct {
        size_t off;
        const char *region;
    } SECRET_AT[3] = {{40, "K"}, {200, "s1"}, {2000, "t0"}};
    for (unsigned i = 0; i < 3; i++) {
        uint8_t buf[10u + SCAN_WINDOW + 10u];
        memcpy(buf, "prefix--->", 10);
        memcpy(buf + 10, sk + SECRET_AT[i].off, SCAN_WINDOW);
        memcpy(buf + 10 + SCAN_WINDOW, "<---suffix", 10);
        char id[8];
        char what[96];
        snprintf(id, sizeof(id), "C6.%u", i + 1u);
        snprintf(what, sizeof(what), "16 bytes of %s (sk[%zu..%zu)) inside text IS flagged", SECRET_AT[i].region,
                 SECRET_AT[i].off, SECRET_AT[i].off + SCAN_WINDOW);
        ok &= control_check(id, what, control_scan(base, buf, sizeof(buf)), 0, 1, 0);
        sodium_memzero(buf, sizeof(buf));
    }

    /* C7: prose that merely names the magic stays admissible. */
    static const char TOKEN_TEXT[] = "a source file that merely mentions MLDSASK2 in prose";
    ok &= control_check("C7", "bare MLDSASK2 text is token-only, not a violation",
                        control_scan(base, (const uint8_t *)TOKEN_TEXT, sizeof(TOKEN_TEXT) - 1u), 0, 0, 1);
    return ok;
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
    if (!derivable_from_public(&kp)) {
        mldsa_keypair_free(&kp);
        return 1;
    }
    scan_t s;
    memset(&s, 0, sizeof(s));
    s.sk = kp.secret_key;
    s.win = malloc(SCAN_KEPT_WINDOWS * sizeof(window_t));
    FUZZ_ASSERT(s.win != NULL, "scan buffer");
    size_t w = 0;
    for (size_t i = 0; i + SCAN_WINDOW <= MLDSA_SECRET_KEY_BYTES; i++) {
        if (window_is_public(i)) {
            continue; /* computable from pk: rho, or tr = SHAKE256(pk, 64) */
        }
        /* Checked BEFORE the write: if window_is_public() and the layout
         * arithmetic ever disagree, this must fail by name, not by
         * overrunning the table. (V2-8 mutation X1 overran it.) */
        FUZZ_ASSERT(w < SCAN_KEPT_WINDOWS, "more kept windows than the layout arithmetic allows");
        s.win[w].key = load64(kp.secret_key + i);
        s.win[w].idx = (uint32_t)i;
        w++;
    }
    FUZZ_ASSERT(w == SCAN_KEPT_WINDOWS, "fewer kept windows than the layout arithmetic requires");
    s.nwin = w;
    qsort(s.win, s.nwin, sizeof(window_t), window_cmp);

    if (!run_controls(&s, &kp)) {
        printf("scan-secret: REFUSING TO SCAN -- the scanner's own controls failed; no file was admitted\n");
        sodium_memzero(s.win, s.nwin * sizeof(window_t));
        free(s.win);
        mldsa_keypair_free(&kp);
        return 1;
    }
    for (int i = 2; i < argc; i++) {
        scan_path(&s, argv[i]);
    }
    sodium_memzero(s.win, s.nwin * sizeof(window_t));
    free(s.win);
    mldsa_keypair_free(&kp);
    printf("scan-secret: %u file(s) scanned, %u violation(s) (%u layout, %u window), %u token-only file(s)\n",
           s.files, s.violations, s.layout_violations, s.window_violations, s.token_only);
    return s.violations == 0 ? 0 : 1;
}
