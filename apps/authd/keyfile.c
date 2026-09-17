#include "keyfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>
#include "secure_mem.h"

/* Field offsets within the KEYFILE_HEADER_LEN-byte header (the AEAD AAD). */
#define OFF_MAGIC    0u
#define OFF_VERSION  8u
#define OFF_KDFALG   9u
#define OFF_OPSLIMIT 10u
#define OFF_MEMLIMIT 14u
#define OFF_SALT     22u
#define OFF_AEADALG  38u
#define OFF_NONCE    39u
#define OFF_CTLEN    63u

_Static_assert(OFF_CTLEN + 4u == KEYFILE_HEADER_LEN, "header layout");
_Static_assert(crypto_pwhash_SALTBYTES == 16u, "salt width");
_Static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == 24u, "nonce width");
_Static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == 16u, "tag width");

const char *keyfile_status_name(keyfile_status_t st) {
    switch (st) {
    case KEYFILE_OK: return "ok";
    case KEYFILE_ERR_ARG: return "invalid-argument";
    case KEYFILE_ERR_IO: return "io-error";
    case KEYFILE_ERR_PERMISSIONS: return "unsafe-permissions";
    case KEYFILE_ERR_FORMAT: return "bad-format";
    case KEYFILE_ERR_PARAMS: return "kdf-parameters-out-of-range";
    case KEYFILE_ERR_DECRYPT: return "decryption-failed (wrong passphrase or tampered file)";
    case KEYFILE_ERR_EXISTS: return "already-exists";
    case KEYFILE_ERR_CRYPTO: return "crypto-error";
    case KEYFILE_ERR_IMAGE: return "decrypted-image-invalid";
    }
    return "unknown";
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(v >> (56 - 8 * i)); }
}
static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) { v = (v << 8) | p[i]; } return v;
}

static int params_ok(uint32_t ops, uint64_t mem) {
    return ops >= KEYFILE_OPSLIMIT_MIN && ops <= KEYFILE_OPSLIMIT_MAX &&
           mem >= KEYFILE_MEMLIMIT_MIN && mem <= KEYFILE_MEMLIMIT_MAX;
}

/* Derives the 32-byte AEAD key from the passphrase and salt into secure memory. */
static keyfile_status_t derive_key(uint8_t *key, const char *pass, size_t pass_len,
                                   const uint8_t *salt, uint32_t ops, uint64_t mem) {
    if (crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, pass, pass_len, salt,
                      (unsigned long long)ops, (size_t)mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return KEYFILE_ERR_CRYPTO; /* out of memory for the requested memlimit */
    }
    return KEYFILE_OK;
}

/* Atomic publish: temp file with O_EXCL, fsync, link() to the final name, then
 * fsync the directory -- the demo_keys.c idiom, so the envelope is never
 * written in place and never clobbers. */
static keyfile_status_t publish(const char *path, const uint8_t *buf, size_t len) {
    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp)) {
        return KEYFILE_ERR_ARG;
    }
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return (errno == EEXIST) ? KEYFILE_ERR_EXISTS : KEYFILE_ERR_IO;
    }
    keyfile_status_t r = KEYFILE_OK;
    size_t off = 0;
    while (off < len) {
        const ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) { continue; } r = KEYFILE_ERR_IO; break; }
        off += (size_t)w;
    }
    if (r == KEYFILE_OK && fsync(fd) != 0) { r = KEYFILE_ERR_IO; }
    (void)close(fd);
    if (r == KEYFILE_OK) {
        if (link(tmp, path) != 0) { r = (errno == EEXIST) ? KEYFILE_ERR_EXISTS : KEYFILE_ERR_IO; }
    }
    (void)unlink(tmp);
    if (r == KEYFILE_OK) {
        /* fsync the directory so the link is durable. */
        char dir[4096];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        const char *d = slash ? (slash == dir ? "/" : (*slash = '\0', dir)) : ".";
        const int dfd = open(d, O_RDONLY | O_CLOEXEC);
        if (dfd >= 0) { (void)fsync(dfd); (void)close(dfd); }
    }
    return r;
}

keyfile_status_t keyfile_parse_header(const uint8_t *buf, size_t total, keyfile_header_t *out) {
    if (buf == NULL || out == NULL) {
        return KEYFILE_ERR_ARG;
    }
    const size_t max_ct = demo_keys_sk2_image_len(64) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (total <= KEYFILE_HEADER_LEN || total > KEYFILE_HEADER_LEN + max_ct) {
        return KEYFILE_ERR_FORMAT;
    }
    if (memcmp(buf + OFF_MAGIC, KEYFILE_MAGIC, KEYFILE_MAGIC_LEN) != 0 ||
        buf[OFF_VERSION] != KEYFILE_VERSION || buf[OFF_KDFALG] != KEYFILE_KDF_ARGON2ID13 ||
        buf[OFF_AEADALG] != KEYFILE_AEAD_XCHACHA20POLY1305) {
        return KEYFILE_ERR_FORMAT;
    }
    const uint32_t ct_len = get_be32(buf + OFF_CTLEN);
    if ((size_t)ct_len != total - KEYFILE_HEADER_LEN || ct_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return KEYFILE_ERR_FORMAT;
    }
    const uint32_t ops = get_be32(buf + OFF_OPSLIMIT);
    const uint64_t mem = get_be64(buf + OFF_MEMLIMIT);
    if (!params_ok(ops, mem)) {
        return KEYFILE_ERR_PARAMS;
    }
    out->opslimit = ops;
    out->memlimit = mem;
    out->ct_len = ct_len;
    out->img_len = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    return KEYFILE_OK;
}

keyfile_status_t keyfile_seal(const char *out_path, const uint8_t *sk2_image, size_t image_len,
                              const char *passphrase, size_t pass_len,
                              uint32_t opslimit, uint64_t memlimit) {
    if (out_path == NULL || sk2_image == NULL || passphrase == NULL || image_len == 0u ||
        image_len > demo_keys_sk2_image_len(64)) {
        return KEYFILE_ERR_ARG;
    }
    if (!params_ok(opslimit, memlimit)) {
        return KEYFILE_ERR_PARAMS;
    }
    const size_t ct_len = image_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t total = KEYFILE_HEADER_LEN + ct_len;
    uint8_t *out = secure_mem_alloc(total);
    uint8_t *key = secure_mem_alloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (out == NULL || key == NULL) {
        if (out) { secure_mem_free(out, total); }
        if (key) { secure_mem_free(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES); }
        return KEYFILE_ERR_CRYPTO;
    }
    memcpy(out + OFF_MAGIC, KEYFILE_MAGIC, KEYFILE_MAGIC_LEN);
    out[OFF_VERSION] = KEYFILE_VERSION;
    out[OFF_KDFALG] = KEYFILE_KDF_ARGON2ID13;
    put_be32(out + OFF_OPSLIMIT, opslimit);
    put_be64(out + OFF_MEMLIMIT, memlimit);
    randombytes_buf(out + OFF_SALT, crypto_pwhash_SALTBYTES);
    out[OFF_AEADALG] = KEYFILE_AEAD_XCHACHA20POLY1305;
    randombytes_buf(out + OFF_NONCE, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    put_be32(out + OFF_CTLEN, (uint32_t)ct_len);

    keyfile_status_t r = derive_key(key, passphrase, pass_len, out + OFF_SALT, opslimit, memlimit);
    if (r == KEYFILE_OK) {
        unsigned long long clen = 0;
        /* header is the associated data, so the KDF parameters are authenticated */
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(out + KEYFILE_HEADER_LEN, &clen, sk2_image, image_len,
                                                       out, KEYFILE_HEADER_LEN, NULL, out + OFF_NONCE, key) != 0 ||
            clen != ct_len) {
            r = KEYFILE_ERR_CRYPTO;
        }
    }
    secure_mem_free(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (r == KEYFILE_OK) {
        r = publish(out_path, out, total);
    }
    secure_mem_free(out, total);
    return r;
}

keyfile_status_t keyfile_open(const char *ek_path, const uint8_t *expect_id, size_t id_len,
                              const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                              uint8_t *kek_out) {
    struct stat st;
    if (kek_out != NULL) {
        /* zeroed up front, so every failure path below leaves it clean */
        sodium_memzero(kek_out, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    }
    if (kp == NULL) {
        return KEYFILE_ERR_ARG;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;
    if (ek_path == NULL || expect_id == NULL || passphrase == NULL || id_len < 1u || id_len > 64u) {
        return KEYFILE_ERR_ARG;
    }
    const int fd = open(ek_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return KEYFILE_ERR_IO;
    }
    keyfile_status_t r = KEYFILE_ERR_FORMAT;
    const size_t max_ct = demo_keys_sk2_image_len(64) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    const size_t max_total = KEYFILE_HEADER_LEN + max_ct;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        r = KEYFILE_ERR_IO; goto done;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        r = KEYFILE_ERR_PERMISSIONS; goto done;
    }
    if (st.st_size < 0 || (size_t)st.st_size <= KEYFILE_HEADER_LEN || (size_t)st.st_size > max_total) {
        r = KEYFILE_ERR_FORMAT; goto done;
    }
    const size_t total = (size_t)st.st_size;
    uint8_t *buf = secure_mem_alloc(total);
    uint8_t *key = secure_mem_alloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    uint8_t *img = NULL;
    if (buf == NULL || key == NULL) { r = KEYFILE_ERR_CRYPTO; goto freebufs; }
    {
        size_t off = 0; ssize_t n;
        while (off < total && (n = read(fd, buf + off, total - off)) != 0) {
            if (n < 0) { if (errno == EINTR) { continue; } r = KEYFILE_ERR_IO; goto freebufs; }
            off += (size_t)n;
        }
        if (off != total) { r = KEYFILE_ERR_FORMAT; goto freebufs; }
    }
    keyfile_header_t hdr;
    r = keyfile_parse_header(buf, total, &hdr);
    if (r != KEYFILE_OK) { goto freebufs; }
    const uint32_t ct_len = hdr.ct_len;
    r = derive_key(key, passphrase, pass_len, buf + OFF_SALT, hdr.opslimit, hdr.memlimit);
    if (r != KEYFILE_OK) { goto freebufs; }

    const size_t img_len = hdr.img_len;
    img = secure_mem_alloc(img_len);
    if (img == NULL) { r = KEYFILE_ERR_CRYPTO; goto freebufs; }
    {
        unsigned long long mlen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(img, &mlen, NULL, buf + KEYFILE_HEADER_LEN, ct_len,
                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {
            r = KEYFILE_ERR_DECRYPT; goto freebufs;
        }
        /* The image validator runs the same digest/id/self-test as the file
         * loader; map any image failure to a single coarse status. */
        r = (demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp) == DEMO_KEYS_OK)
                ? KEYFILE_OK : KEYFILE_ERR_IMAGE;
        if (r == KEYFILE_OK && kek_out != NULL) {
            memcpy(kek_out, key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        }
    }
freebufs:
    if (img) { secure_mem_free(img, ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES); }
    if (key) { secure_mem_free(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES); }
    if (buf) { secure_mem_free(buf, total); }
done:
    (void)close(fd);
    return r;
}
