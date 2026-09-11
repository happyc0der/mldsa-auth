#include "demo_keys.h"

#include "secure_mem.h"

#include <sodium.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HDR_LEN (DEMO_KEY_MAGIC_LEN + 1u)
#define PUB_FILE_LEN(idl) (HDR_LEN + (size_t)(idl) + MLDSA_PUBLIC_KEY_BYTES)
/* MLDSASK2: everything the digest covers ends at SK2_BODY_LEN; the digest follows. */
#define SK2_BODY_LEN(idl) (PUB_FILE_LEN(idl) + MLDSA_SECRET_KEY_BYTES)
#define SK2_FILE_LEN(idl) (SK2_BODY_LEN(idl) + DEMO_KEY_DIGEST_BYTES)
#define INTEGRITY_LABEL_LEN (sizeof(DEMO_KEY_INTEGRITY_LABEL) - 1u) /* never hard-coded */

static const uint8_t SELFTEST_MSG[] = "mldsa-auth/v1/demo-key-selftest";

_Static_assert(sizeof(DEMO_KEY_MAGIC_PUBLIC) - 1u == DEMO_KEY_MAGIC_LEN, "magic length");
_Static_assert(sizeof(DEMO_KEY_MAGIC_SECRET) - 1u == DEMO_KEY_MAGIC_LEN, "magic length");
_Static_assert(sizeof(DEMO_KEY_MAGIC_SECRET_LEGACY) - 1u == DEMO_KEY_MAGIC_LEN, "magic length");
_Static_assert(DEMO_KEY_DIGEST_BYTES == crypto_hash_sha256_BYTES, "digest is SHA-256");
_Static_assert(SK2_FILE_LEN(1) == 6026u && SK2_FILE_LEN(64) == 6089u, "SK2_LEN(idl) = 6025 + idl");

const char *demo_keys_status_name(demo_keys_status_t st) {
    switch (st) {
    case DEMO_KEYS_OK: return "ok";
    case DEMO_KEYS_ERR_ARG: return "invalid-argument";
    case DEMO_KEYS_ERR_EXISTS: return "already-exists";
    case DEMO_KEYS_ERR_IO: return "io-error";
    case DEMO_KEYS_ERR_PERMISSIONS: return "unsafe-permissions";
    case DEMO_KEYS_ERR_FORMAT: return "bad-format";
    case DEMO_KEYS_ERR_ID_MISMATCH: return "id-mismatch";
    case DEMO_KEYS_ERR_KEY_MISMATCH: return "key-mismatch";
    case DEMO_KEYS_ERR_CRYPTO: return "crypto-error";
    case DEMO_KEYS_ERR_INTEGRITY: return "integrity-check-failed";
    case DEMO_KEYS_ERR_UNSUPPORTED_VERSION:
        return "unsupported-format-version (legacy MLDSASK1 key file: regenerate it with keygen)";
    }
    return "unknown";
}

int demo_keys_id_filename_safe(const uint8_t *id, size_t len) {
    if (id == NULL || len < 1u || len > 64u || id[0] == '.') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        const uint8_t c = id[i];
        const int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                       c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* ---- raw file I/O (EINTR-safe, exact counts) ------------------------------ */

static int write_all_fd(int fd, const uint8_t *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t w = write(fd, p + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int read_all_fd(int fd, uint8_t *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t r = read(fd, p + off, n - off);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int path_for(char out[PATH_MAX], const char *dir, const char *prefix, const uint8_t *id, size_t id_len,
                    const char *ext) {
    const int n = snprintf(out, PATH_MAX, "%s/%s%.*s%s", dir, prefix, (int)id_len, (const char *)id, ext);
    return (n < 0 || (size_t)n >= PATH_MAX) ? -1 : 0;
}

/* mkdir -p with mode 0700 for every directory it creates (existing ones are
 * left as they are). */
static int make_dirs(const char *dir) {
    char path[PATH_MAX];
    const size_t n = strnlen(dir, PATH_MAX);
    if (n == 0 || n >= PATH_MAX) {
        return -1;
    }
    memcpy(path, dir, n + 1u);
    for (size_t i = 1; i <= n; i++) {
        if (path[i] == '/' || path[i] == '\0') {
            const char saved = path[i];
            path[i] = '\0';
            if (mkdir(path, 0700) != 0 && errno != EEXIST) {
                return -1;
            }
            path[i] = saved;
        }
    }
    return 0;
}

static void put_header(uint8_t *hdr, const char *magic, const uint8_t *id, size_t id_len) {
    memcpy(hdr, magic, DEMO_KEY_MAGIC_LEN);
    hdr[DEMO_KEY_MAGIC_LEN] = (uint8_t)id_len;
    memcpy(hdr + HDR_LEN, id, id_len);
}

/* SHA-256(label || 0x00 || id_len || id || public_key || secret_key). The
 * hash state is derived from the secret key and is wiped before returning. */
static void integrity_digest(uint8_t out[DEMO_KEY_DIGEST_BYTES], uint8_t id_len, const uint8_t *id,
                             const uint8_t *public_key, const uint8_t *secret_key) {
    static const uint8_t separator = 0x00;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)DEMO_KEY_INTEGRITY_LABEL, INTEGRITY_LABEL_LEN);
    crypto_hash_sha256_update(&st, &separator, 1);
    crypto_hash_sha256_update(&st, &id_len, 1);
    crypto_hash_sha256_update(&st, id, id_len);
    crypto_hash_sha256_update(&st, public_key, MLDSA_PUBLIC_KEY_BYTES);
    crypto_hash_sha256_update(&st, secret_key, MLDSA_SECRET_KEY_BYTES);
    crypto_hash_sha256_final(&st, out);
    sodium_memzero(&st, sizeof(st));
}

/* ---- generate ------------------------------------------------------------- */

/* Creates `path` with O_EXCL and `mode`, writes all bytes, fsyncs, closes.
 * Sets *created as soon as the file exists (so the caller can unlink it). */
static int write_new_file(const char *path, const uint8_t *p, size_t n, mode_t mode, int *created) {
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) {
        return -1;
    }
    *created = 1;
    const int ok = write_all_fd(fd, p, n) == 0 && fsync(fd) == 0;
    const int closed = close(fd) == 0;
    return (ok && closed) ? 0 : -1;
}

/* Best-effort durability for the new directory entries. */
static void fsync_dir(const char *dir) {
    const int fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)fsync(fd);
        (void)close(fd);
    }
}

demo_keys_status_t demo_keys_generate_files(const char *dir, const uint8_t *id, size_t id_len) {
    char sk_path[PATH_MAX];
    char pub_path[PATH_MAX];
    char sk_tmp[PATH_MAX];
    char pub_tmp[PATH_MAX];
    char tmp_ext[64];
    uint8_t pub_file[PUB_FILE_LEN(64)];
    struct stat st;
    mldsa_keypair_t kp;
    uint8_t *img = NULL;
    size_t img_len = 0;
    int sk_tmp_made = 0;
    int pub_tmp_made = 0;
    int sk_linked = 0;
    int pub_linked = 0;
    demo_keys_status_t result = DEMO_KEYS_ERR_IO;

    memset(&kp, 0, sizeof(kp));
    (void)snprintf(tmp_ext, sizeof(tmp_ext), ".tmp.%ld", (long)getpid());
    if (dir == NULL || !demo_keys_id_filename_safe(id, id_len) || path_for(sk_path, dir, "", id, id_len, ".sk") != 0 ||
        path_for(pub_path, dir, "", id, id_len, ".pub") != 0) {
        return DEMO_KEYS_ERR_ARG;
    }
    /* Hidden temp names ("." prefix: demo ids cannot start with '.'). */
    char sk_ext[80];
    char pub_ext[80];
    (void)snprintf(sk_ext, sizeof(sk_ext), ".sk%s", tmp_ext);
    (void)snprintf(pub_ext, sizeof(pub_ext), ".pub%s", tmp_ext);
    if (path_for(sk_tmp, dir, ".", id, id_len, sk_ext) != 0 || path_for(pub_tmp, dir, ".", id, id_len, pub_ext) != 0) {
        return DEMO_KEYS_ERR_ARG;
    }
    if (make_dirs(dir) != 0) {
        return DEMO_KEYS_ERR_IO;
    }
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return DEMO_KEYS_ERR_IO;
    }
    /* Fast, clear refusal; link() below is the atomic no-clobber guarantee. */
    if (lstat(sk_path, &st) == 0 || lstat(pub_path, &st) == 0) {
        return DEMO_KEYS_ERR_EXISTS;
    }
    if (mldsa_keypair_generate(&kp) != 0) {
        return DEMO_KEYS_ERR_CRYPTO;
    }

    /* The whole secret-key file image lives in secure memory. */
    img_len = SK2_FILE_LEN(id_len);
    img = secure_mem_alloc(img_len);
    if (img == NULL) {
        result = DEMO_KEYS_ERR_CRYPTO;
        goto out;
    }
    put_header(img, DEMO_KEY_MAGIC_SECRET, id, id_len);
    memcpy(img + HDR_LEN + id_len, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
    memcpy(img + HDR_LEN + id_len + MLDSA_PUBLIC_KEY_BYTES, kp.secret_key, MLDSA_SECRET_KEY_BYTES);
    integrity_digest(img + SK2_BODY_LEN(id_len), (uint8_t)id_len, id, kp.public_key, kp.secret_key);

    put_header(pub_file, DEMO_KEY_MAGIC_PUBLIC, id, id_len);
    memcpy(pub_file + HDR_LEN + id_len, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);

    if (write_new_file(sk_tmp, img, img_len, 0600, &sk_tmp_made) != 0 ||
        write_new_file(pub_tmp, pub_file, PUB_FILE_LEN(id_len), 0644, &pub_tmp_made) != 0) {
        goto out;
    }
    /* Publish: link() is atomic and fails with EEXIST instead of clobbering. */
    if (link(sk_tmp, sk_path) != 0) {
        result = (errno == EEXIST) ? DEMO_KEYS_ERR_EXISTS : DEMO_KEYS_ERR_IO;
        goto out;
    }
    sk_linked = 1;
    if (link(pub_tmp, pub_path) != 0) {
        result = (errno == EEXIST) ? DEMO_KEYS_ERR_EXISTS : DEMO_KEYS_ERR_IO;
        goto out;
    }
    pub_linked = 1;
    fsync_dir(dir);
    result = DEMO_KEYS_OK;

out:
    if (sk_tmp_made) {
        (void)unlink(sk_tmp);
    }
    if (pub_tmp_made) {
        (void)unlink(pub_tmp);
    }
    if (result != DEMO_KEYS_OK) {
        if (sk_linked) {
            (void)unlink(sk_path); /* roll back a half-published identity */
        }
        if (pub_linked) {
            (void)unlink(pub_path);
        }
    }
    if (img != NULL) {
        secure_mem_free(img, img_len);
    }
    mldsa_keypair_free(&kp);
    return result;
}

/* ---- load ------------------------------------------------------------------- */

/* Public-key files (MLDSAPK1): opens path (no symlinks), checks it is a
 * regular file of exactly the size its header implies, and validates magic
 * and id. On DEMO_KEYS_OK *fd_out is open, positioned just after the id. */
static demo_keys_status_t open_public(const char *path, const uint8_t *expect_id, size_t expect_len, int *fd_out) {
    uint8_t hdr[HDR_LEN];
    uint8_t id[64];
    struct stat st;

    *fd_out = -1;
    if (path == NULL || expect_id == NULL || expect_len < 1u || expect_len > 64u) {
        return DEMO_KEYS_ERR_ARG;
    }
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return DEMO_KEYS_ERR_IO;
    }
    demo_keys_status_t r = DEMO_KEYS_ERR_FORMAT;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        r = DEMO_KEYS_ERR_IO;
        goto fail;
    }
    if (st.st_size < 0 || (size_t)st.st_size < PUB_FILE_LEN(1) || (size_t)st.st_size > PUB_FILE_LEN(64)) {
        goto fail;
    }
    if (read_all_fd(fd, hdr, sizeof(hdr)) != 0 || memcmp(hdr, DEMO_KEY_MAGIC_PUBLIC, DEMO_KEY_MAGIC_LEN) != 0) {
        goto fail;
    }
    const size_t idl = hdr[DEMO_KEY_MAGIC_LEN];
    if (idl < 1u || idl > 64u || (size_t)st.st_size != PUB_FILE_LEN(idl) || read_all_fd(fd, id, idl) != 0) {
        goto fail;
    }
    if (idl != expect_len || memcmp(id, expect_id, idl) != 0) {
        r = DEMO_KEYS_ERR_ID_MISMATCH;
        goto fail;
    }
    *fd_out = fd;
    return DEMO_KEYS_OK;

fail:
    (void)close(fd);
    return r;
}

demo_keys_status_t demo_keys_load_identity(const char *sk_path, const uint8_t *expect_id, size_t id_len,
                                           mldsa_keypair_t *kp) {
    uint8_t hdr[HDR_LEN];
    uint8_t id[64];
    uint8_t stored[DEMO_KEY_DIGEST_BYTES];
    uint8_t computed[DEMO_KEY_DIGEST_BYTES];
    struct stat st;

    if (kp == NULL) {
        return DEMO_KEYS_ERR_ARG;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;
    if (sk_path == NULL || expect_id == NULL || id_len < 1u || id_len > 64u) {
        return DEMO_KEYS_ERR_ARG;
    }

    /* 1. No symlinks; a regular file owned by us, no group/other access. */
    const int fd = open(sk_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return DEMO_KEYS_ERR_IO;
    }
    demo_keys_status_t r = DEMO_KEYS_ERR_FORMAT;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        r = DEMO_KEYS_ERR_IO;
        goto fail;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        r = DEMO_KEYS_ERR_PERMISSIONS;
        goto fail;
    }
    /* 2. Bounded size (admits every legacy size, so step 4 can name it). */
    if (st.st_size < 0 || (size_t)st.st_size < HDR_LEN || (size_t)st.st_size > SK2_FILE_LEN(64)) {
        goto fail;
    }
    /* 3-4. Header and version. */
    if (read_all_fd(fd, hdr, sizeof(hdr)) != 0) {
        goto fail;
    }
    if (memcmp(hdr, DEMO_KEY_MAGIC_SECRET_LEGACY, DEMO_KEY_MAGIC_LEN) == 0) {
        r = DEMO_KEYS_ERR_UNSUPPORTED_VERSION;
        goto fail;
    }
    if (memcmp(hdr, DEMO_KEY_MAGIC_SECRET, DEMO_KEY_MAGIC_LEN) != 0) {
        goto fail;
    }
    /* 5. Exact size for the declared id length. */
    const size_t idl = hdr[DEMO_KEY_MAGIC_LEN];
    if (idl < 1u || idl > 64u || (size_t)st.st_size != SK2_FILE_LEN(idl)) {
        goto fail;
    }
    /* 6. Read; the secret key goes straight from the file into secure memory. */
    kp->secret_key = secure_mem_alloc(MLDSA_SECRET_KEY_BYTES);
    if (kp->secret_key == NULL) {
        r = DEMO_KEYS_ERR_CRYPTO;
        goto fail;
    }
    if (read_all_fd(fd, id, idl) != 0 || read_all_fd(fd, kp->public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 ||
        read_all_fd(fd, kp->secret_key, MLDSA_SECRET_KEY_BYTES) != 0 ||
        read_all_fd(fd, stored, sizeof(stored)) != 0) {
        goto fail;
    }
    (void)close(fd);

    /* 7. Integrity: constant-time comparison of all 32 bytes. */
    integrity_digest(computed, (uint8_t)idl, id, kp->public_key, kp->secret_key);
    const int intact = (sodium_memcmp(computed, stored, DEMO_KEY_DIGEST_BYTES) == 0);
    sodium_memzero(computed, sizeof(computed));
    sodium_memzero(stored, sizeof(stored));
    if (!intact) {
        mldsa_keypair_free(kp);
        return DEMO_KEYS_ERR_INTEGRITY;
    }
    /* 8. Identity (after integrity: a corrupted id reports INTEGRITY). */
    if (idl != id_len || memcmp(id, expect_id, idl) != 0) {
        mldsa_keypair_free(kp);
        return DEMO_KEYS_ERR_ID_MISMATCH;
    }
    /* 9. Defense in depth against a buggy writer pairing a mismatched pk/sk. */
    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sig_len = 0;
    if (mldsa_sign(sig, &sig_len, SELFTEST_MSG, sizeof(SELFTEST_MSG) - 1u, kp) != 0) {
        mldsa_keypair_free(kp);
        return DEMO_KEYS_ERR_CRYPTO;
    }
    if (mldsa_verify(SELFTEST_MSG, sizeof(SELFTEST_MSG) - 1u, sig, sig_len, kp->public_key) != 0) {
        mldsa_keypair_free(kp);
        return DEMO_KEYS_ERR_KEY_MISMATCH;
    }
    return DEMO_KEYS_OK;

fail:
    (void)close(fd);
    sodium_memzero(stored, sizeof(stored));
    mldsa_keypair_free(kp); /* no-op if nothing was allocated; always leaves pk zeroed */
    return r;
}

demo_keys_status_t demo_keys_load_public(const char *pub_path, const uint8_t *expect_id, size_t id_len,
                                         uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES]) {
    if (pk_out == NULL) {
        return DEMO_KEYS_ERR_ARG;
    }
    memset(pk_out, 0, MLDSA_PUBLIC_KEY_BYTES);
    int fd = -1;
    const demo_keys_status_t r = open_public(pub_path, expect_id, id_len, &fd);
    if (r != DEMO_KEYS_OK) {
        return r;
    }
    const int rd = read_all_fd(fd, pk_out, MLDSA_PUBLIC_KEY_BYTES);
    (void)close(fd);
    if (rd != 0) {
        memset(pk_out, 0, MLDSA_PUBLIC_KEY_BYTES);
        return DEMO_KEYS_ERR_FORMAT;
    }
    return DEMO_KEYS_OK;
}
