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
#define SK_FILE_LEN(idl) (PUB_FILE_LEN(idl) + MLDSA_SECRET_KEY_BYTES)

static const uint8_t SELFTEST_MSG[] = "mldsa-auth/v1/demo-key-selftest";

_Static_assert(sizeof(DEMO_KEY_MAGIC_PUBLIC) - 1u == DEMO_KEY_MAGIC_LEN, "magic length");
_Static_assert(sizeof(DEMO_KEY_MAGIC_SECRET) - 1u == DEMO_KEY_MAGIC_LEN, "magic length");

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

static int path_for(char out[PATH_MAX], const char *dir, const uint8_t *id, size_t id_len, const char *ext) {
    const int n = snprintf(out, PATH_MAX, "%s/%.*s%s", dir, (int)id_len, (const char *)id, ext);
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

/* ---- generate ------------------------------------------------------------- */

demo_keys_status_t demo_keys_generate_files(const char *dir, const uint8_t *id, size_t id_len) {
    char sk_path[PATH_MAX];
    char pub_path[PATH_MAX];
    uint8_t pub_file[PUB_FILE_LEN(64)];
    struct stat st;
    mldsa_keypair_t kp;
    uint8_t *sk_file = NULL;
    int fd_sk = -1;
    int fd_pub = -1;
    demo_keys_status_t result = DEMO_KEYS_ERR_IO;

    memset(&kp, 0, sizeof(kp));
    if (dir == NULL || !demo_keys_id_filename_safe(id, id_len) || path_for(sk_path, dir, id, id_len, ".sk") != 0 ||
        path_for(pub_path, dir, id, id_len, ".pub") != 0) {
        return DEMO_KEYS_ERR_ARG;
    }
    if (make_dirs(dir) != 0) {
        return DEMO_KEYS_ERR_IO;
    }
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return DEMO_KEYS_ERR_IO;
    }
    if (mldsa_keypair_generate(&kp) != 0) {
        return DEMO_KEYS_ERR_CRYPTO;
    }

    const size_t sk_len = SK_FILE_LEN(id_len);
    const size_t pub_len = PUB_FILE_LEN(id_len);
    sk_file = secure_mem_alloc(sk_len);
    if (sk_file == NULL) {
        result = DEMO_KEYS_ERR_CRYPTO;
        goto out;
    }
    put_header(sk_file, DEMO_KEY_MAGIC_SECRET, id, id_len);
    memcpy(sk_file + HDR_LEN + id_len, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
    memcpy(sk_file + HDR_LEN + id_len + MLDSA_PUBLIC_KEY_BYTES, kp.secret_key, MLDSA_SECRET_KEY_BYTES);
    put_header(pub_file, DEMO_KEY_MAGIC_PUBLIC, id, id_len);
    memcpy(pub_file + HDR_LEN + id_len, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);

    /* O_EXCL: never overwrite an existing identity. */
    fd_sk = open(sk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd_sk < 0) {
        result = (errno == EEXIST) ? DEMO_KEYS_ERR_EXISTS : DEMO_KEYS_ERR_IO;
        goto out;
    }
    fd_pub = open(pub_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd_pub < 0) {
        result = (errno == EEXIST) ? DEMO_KEYS_ERR_EXISTS : DEMO_KEYS_ERR_IO;
        (void)close(fd_sk);
        fd_sk = -1;
        (void)unlink(sk_path);
        goto out;
    }
    if (write_all_fd(fd_sk, sk_file, sk_len) != 0 || write_all_fd(fd_pub, pub_file, pub_len) != 0 ||
        fsync(fd_sk) != 0 || fsync(fd_pub) != 0) {
        (void)close(fd_sk);
        (void)close(fd_pub);
        fd_sk = fd_pub = -1;
        (void)unlink(sk_path);
        (void)unlink(pub_path);
        goto out;
    }
    const int c1 = close(fd_sk);
    const int c2 = close(fd_pub);
    fd_sk = fd_pub = -1;
    if (c1 != 0 || c2 != 0) {
        (void)unlink(sk_path);
        (void)unlink(pub_path);
        goto out;
    }
    result = DEMO_KEYS_OK;

out:
    if (sk_file != NULL) {
        secure_mem_free(sk_file, sk_len);
    }
    mldsa_keypair_free(&kp);
    return result;
}

/* ---- load ------------------------------------------------------------------- */

/* Opens path (no symlinks), checks it is a regular file of plausible size,
 * reads and validates the header and id. On DEMO_KEYS_OK *fd_out is open,
 * positioned just after the id. */
static demo_keys_status_t open_and_check(const char *path, const char *magic, int secret, const uint8_t *expect_id,
                                         size_t expect_len, int *fd_out) {
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
    if (secret && (st.st_uid != geteuid() || (st.st_mode & 077) != 0)) {
        r = DEMO_KEYS_ERR_PERMISSIONS;
        goto fail;
    }
    const size_t min_len = secret ? SK_FILE_LEN(1) : PUB_FILE_LEN(1);
    const size_t max_len = secret ? SK_FILE_LEN(64) : PUB_FILE_LEN(64);
    if (st.st_size < 0 || (size_t)st.st_size < min_len || (size_t)st.st_size > max_len) {
        goto fail;
    }
    if (read_all_fd(fd, hdr, sizeof(hdr)) != 0 || memcmp(hdr, magic, DEMO_KEY_MAGIC_LEN) != 0) {
        goto fail;
    }
    const size_t idl = hdr[DEMO_KEY_MAGIC_LEN];
    const size_t want = secret ? SK_FILE_LEN(idl) : PUB_FILE_LEN(idl);
    if (idl < 1u || idl > 64u || (size_t)st.st_size != want || read_all_fd(fd, id, idl) != 0) {
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
    if (kp == NULL) {
        return DEMO_KEYS_ERR_ARG;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;

    int fd = -1;
    demo_keys_status_t r = open_and_check(sk_path, DEMO_KEY_MAGIC_SECRET, 1, expect_id, id_len, &fd);
    if (r != DEMO_KEYS_OK) {
        return r;
    }
    kp->secret_key = secure_mem_alloc(MLDSA_SECRET_KEY_BYTES);
    if (kp->secret_key == NULL) {
        (void)close(fd);
        return DEMO_KEYS_ERR_CRYPTO;
    }
    /* The secret key goes straight from the file into secure memory. */
    const int rd = (read_all_fd(fd, kp->public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 ||
                    read_all_fd(fd, kp->secret_key, MLDSA_SECRET_KEY_BYTES) != 0);
    (void)close(fd);
    if (rd) {
        mldsa_keypair_free(kp);
        return DEMO_KEYS_ERR_FORMAT;
    }

    /* Self-test: the public key must verify a signature made with the secret key. */
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
}

demo_keys_status_t demo_keys_load_public(const char *pub_path, const uint8_t *expect_id, size_t id_len,
                                         uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES]) {
    if (pk_out == NULL) {
        return DEMO_KEYS_ERR_ARG;
    }
    memset(pk_out, 0, MLDSA_PUBLIC_KEY_BYTES);
    int fd = -1;
    const demo_keys_status_t r = open_and_check(pub_path, DEMO_KEY_MAGIC_PUBLIC, 0, expect_id, id_len, &fd);
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
