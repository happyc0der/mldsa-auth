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
_Static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == KEYFILE_ROOT_BYTES, "a v1 KEK stands in for the root key");

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
    case KEYFILE_ERR_ID_MISMATCH: return "id-mismatch (the key is another identity's: check server_id, --server-id or --handle)";
    case KEYFILE_ERR_CHANGED: return "changed-since-opened";
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
/* fsync the directory so a new or renamed entry is durable. */
static void fsync_parent_dir(const char *path) {
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    const char *d = slash ? (slash == dir ? "/" : (*slash = '\0', dir)) : ".";
    const int dfd = open(d, O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) { (void)fsync(dfd); (void)close(dfd); }
}

static keyfile_status_t publish_how(const char *path, const uint8_t *buf, size_t len, int over) {
    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp)) {
        return KEYFILE_ERR_ARG;
    }
    /* V4-179, F253: the name carries THIS process id, so whatever already
     * holds it was left by an earlier process that had the same id and died
     * before its unlink below. That answered EXISTS, which every caller
     * reports as the KEY file being there. It is removed and the name created
     * once more, still O_EXCL: unlink removes a symlink itself, never what it
     * points at. */
    int fd = -1;
    for (int attempt = 0; attempt < 2 && fd < 0; attempt++) {
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 && (errno != EEXIST || unlink(tmp) != 0)) {
            break;
        }
    }
    if (fd < 0) {
        return KEYFILE_ERR_IO;      /* the temporary file, not the key file */
    }
    keyfile_status_t r = KEYFILE_OK;
    size_t off = 0;
    while (off < len) {
        const ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) { continue; } r = KEYFILE_ERR_IO; break; }
        off += (size_t)w;
    }
    if (r == KEYFILE_OK && fsync(fd) != 0) { r = KEYFILE_ERR_IO; }
    if (close(fd) != 0 && r == KEYFILE_OK) { r = KEYFILE_ERR_IO; }   /* V4-370, F820 */
    if (r == KEYFILE_OK && over) {
        /* V4-371 (F823): keyfile_replace_sealed only. */
        if (rename(tmp, path) != 0) { r = KEYFILE_ERR_IO; }
    } else if (r == KEYFILE_OK) {
        if (link(tmp, path) != 0) { r = (errno == EEXIST) ? KEYFILE_ERR_EXISTS : KEYFILE_ERR_IO; }
    }
    (void)unlink(tmp);
    if (r == KEYFILE_OK) {
        fsync_parent_dir(path);
    }
    return r;
}

static keyfile_status_t publish(const char *path, const uint8_t *buf, size_t len) {
    return publish_how(path, buf, len, 0);
}

/* The largest key file there is: the version-2 bound. */
static size_t keyfile_max_total(void) {
    return KEYFILE_HEADER_LEN + demo_keys_sk2_image_len(64) + KEYFILE_ROOT_BYTES +
           crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

keyfile_status_t keyfile_parse_header(const uint8_t *buf, size_t total, keyfile_header_t *out) {
    if (buf == NULL || out == NULL) {
        return KEYFILE_ERR_ARG;
    }
    if (total <= KEYFILE_HEADER_LEN) {
        return KEYFILE_ERR_FORMAT;
    }
    if (memcmp(buf + OFF_MAGIC, KEYFILE_MAGIC, KEYFILE_MAGIC_LEN) != 0 ||
        (buf[OFF_VERSION] != KEYFILE_VERSION && buf[OFF_VERSION] != KEYFILE_VERSION_ROOT) ||
        buf[OFF_KDFALG] != KEYFILE_KDF_ARGON2ID13 ||
        buf[OFF_AEADALG] != KEYFILE_AEAD_XCHACHA20POLY1305) {
        return KEYFILE_ERR_FORMAT;
    }
    /* V4-108: a version-2 plaintext is the image followed by the 32-byte root
     * key, so every length bound moves by exactly that much -- and a version-2
     * file too short to hold a root key is refused here, before the KDF. */
    const uint32_t root_len = (buf[OFF_VERSION] == KEYFILE_VERSION_ROOT) ? KEYFILE_ROOT_BYTES : 0u;
    const size_t max_ct = demo_keys_sk2_image_len(64) + root_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (total > KEYFILE_HEADER_LEN + max_ct) {
        return KEYFILE_ERR_FORMAT;
    }
    const uint32_t ct_len = get_be32(buf + OFF_CTLEN);
    if ((size_t)ct_len != total - KEYFILE_HEADER_LEN ||
        ct_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES + root_len) {
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
    out->img_len = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES - root_len;
    out->root_len = root_len;
    out->version = buf[OFF_VERSION];
    return KEYFILE_OK;
}

size_t keyfile_sealed_len(size_t image_len) {
    if (image_len == 0u || image_len > demo_keys_sk2_image_len(64)) {
        return 0u;
    }
    return KEYFILE_HEADER_LEN + image_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

/* The one sealer. `sk2_image`/`image_len` are the PLAINTEXT: the image for a
 * version-1 envelope, the image followed by the root key for a version-2 one
 * (keyfile_seal_root builds that). The callers have checked the arguments and
 * that `out` holds KEYFILE_HEADER_LEN + image_len + the tag. */
static keyfile_status_t seal_core(uint8_t version, uint8_t *out, const uint8_t *sk2_image, size_t image_len,
                                  const char *passphrase, size_t pass_len,
                                  uint32_t opslimit, uint64_t memlimit) {
    if (!params_ok(opslimit, memlimit)) {
        return KEYFILE_ERR_PARAMS;
    }
    const size_t ct_len = image_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *key = secure_mem_alloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (key == NULL) {
        return KEYFILE_ERR_CRYPTO;
    }
    memcpy(out + OFF_MAGIC, KEYFILE_MAGIC, KEYFILE_MAGIC_LEN);
    out[OFF_VERSION] = version;
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
    if (r != KEYFILE_OK) {
        /* never hand back a half-built envelope: no header without its ciphertext */
        sodium_memzero(out, KEYFILE_HEADER_LEN + ct_len);
    }
    return r;
}

keyfile_status_t keyfile_seal_buf(uint8_t *out, size_t out_cap, const uint8_t *sk2_image, size_t image_len,
                                  const char *passphrase, size_t pass_len,
                                  uint32_t opslimit, uint64_t memlimit) {
    if (out == NULL || sk2_image == NULL || passphrase == NULL || image_len == 0u ||
        image_len > demo_keys_sk2_image_len(64) || out_cap < keyfile_sealed_len(image_len)) {
        return KEYFILE_ERR_ARG;
    }
    return seal_core(KEYFILE_VERSION, out, sk2_image, image_len, passphrase, pass_len, opslimit, memlimit);
}

keyfile_status_t keyfile_seal_root(const char *out_path, const uint8_t *sk2_image, size_t image_len,
                                   const uint8_t *root,
                                   const char *passphrase, size_t pass_len,
                                   uint32_t opslimit, uint64_t memlimit) {
    if (out_path == NULL || sk2_image == NULL || passphrase == NULL || image_len == 0u ||
        image_len > demo_keys_sk2_image_len(64)) {
        return KEYFILE_ERR_ARG;
    }
    const size_t pt_len = image_len + KEYFILE_ROOT_BYTES;
    const size_t total = KEYFILE_HEADER_LEN + pt_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *pt = secure_mem_alloc(pt_len);
    uint8_t *out = secure_mem_alloc(total);
    keyfile_status_t r = KEYFILE_ERR_CRYPTO;
    if (pt != NULL && out != NULL) {
        memcpy(pt, sk2_image, image_len);
        if (root != NULL) {
            memcpy(pt + image_len, root, KEYFILE_ROOT_BYTES);
        } else {
            randombytes_buf(pt + image_len, KEYFILE_ROOT_BYTES);
        }
        r = seal_core(KEYFILE_VERSION_ROOT, out, pt, pt_len, passphrase, pass_len, opslimit, memlimit);
        if (r == KEYFILE_OK) {
            r = publish(out_path, out, total);
        }
    }
    if (pt != NULL) { secure_mem_free(pt, pt_len); }
    if (out != NULL) { secure_mem_free(out, total); }
    return r;
}

keyfile_status_t keyfile_seal(const char *out_path, const uint8_t *sk2_image, size_t image_len,
                              const char *passphrase, size_t pass_len,
                              uint32_t opslimit, uint64_t memlimit) {
    const size_t total = keyfile_sealed_len(image_len);
    if (out_path == NULL || sk2_image == NULL || passphrase == NULL || total == 0u) {
        return KEYFILE_ERR_ARG;
    }
    uint8_t *out = secure_mem_alloc(total);
    if (out == NULL) {
        return KEYFILE_ERR_CRYPTO;
    }
    keyfile_status_t r = keyfile_seal_buf(out, total, sk2_image, image_len, passphrase, pass_len,
                                          opslimit, memlimit);
    if (r == KEYFILE_OK) {
        r = publish(out_path, out, total);
    }
    secure_mem_free(out, total);
    return r;
}

keyfile_status_t keyfile_write_sealed(const char *path, const uint8_t *buf, size_t len) {
    if (path == NULL || buf == NULL) {
        return KEYFILE_ERR_ARG;
    }
    /* Only a well-formed envelope may reach the disk: whatever produced `buf`
     * (the client core, in memory), this is the last point before it becomes
     * the only copy of an identity. */
    keyfile_header_t hdr;
    const keyfile_status_t hs = keyfile_parse_header(buf, len, &hdr);
    if (hs != KEYFILE_OK) {
        return hs;
    }
    return publish(path, buf, len);
}

keyfile_status_t keyfile_replace_sealed(const char *to, const uint8_t *buf, size_t len) {
    if (to == NULL || buf == NULL) {
        return KEYFILE_ERR_ARG;
    }
    keyfile_header_t hdr;
    const keyfile_status_t hs = keyfile_parse_header(buf, len, &hdr);
    if (hs != KEYFILE_OK) {
        return hs;
    }
    return publish_how(to, buf, len, 1);
}

keyfile_status_t keyfile_open_buf(const uint8_t *buf, size_t total, const uint8_t *expect_id, size_t id_len,
                                  const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                                  uint8_t *kek_out) {
    if (kek_out != NULL) {
        /* zeroed up front, so every failure path below leaves it clean */
        sodium_memzero(kek_out, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    }
    if (kp == NULL) {
        return KEYFILE_ERR_ARG;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
    kp->secret_key = NULL;
    if (buf == NULL || expect_id == NULL || passphrase == NULL || id_len < 1u || id_len > 64u) {
        return KEYFILE_ERR_ARG;
    }
    /* The header is validated -- sizes, algorithm ids, KDF bounds -- BEFORE a
     * byte of key-derivation work, so hostile bytes cost a parse, not Argon2id. */
    keyfile_header_t hdr;
    keyfile_status_t r = keyfile_parse_header(buf, total, &hdr);
    if (r != KEYFILE_OK) {
        return r;
    }
    const uint32_t ct_len = hdr.ct_len;
    uint8_t *key = secure_mem_alloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    uint8_t *img = NULL;
    if (key == NULL) { r = KEYFILE_ERR_CRYPTO; goto freebufs; }
    r = derive_key(key, passphrase, pass_len, buf + OFF_SALT, hdr.opslimit, hdr.memlimit);
    if (r != KEYFILE_OK) { goto freebufs; }

    const size_t img_len = hdr.img_len + hdr.root_len;   /* the whole plaintext */
    img = secure_mem_alloc(img_len);
    if (img == NULL) { r = KEYFILE_ERR_CRYPTO; goto freebufs; }
    {
        unsigned long long mlen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(img, &mlen, NULL, buf + KEYFILE_HEADER_LEN, ct_len,
                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {
            r = KEYFILE_ERR_DECRYPT; goto freebufs;
        }
        if (hdr.root_len != 0u) {
            mlen -= hdr.root_len;   /* version 2: the image is what precedes the root key */
        }
        /* The image validator runs the same digest/id/self-test as the file
         * loader; map any image failure to a single coarse status. */
        /* F443: an id that is not the one asked for is told apart. As
         * "decrypted-image-invalid" it read as a damaged key file, after the
         * passphrase had opened it, and the remedies that suggested -- a
         * restore, a new key -- were wrong; the same mismatch on server.pub
         * already says `id-mismatch`. */
        const demo_keys_status_t ims = demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp);
        r = (ims == DEMO_KEYS_OK) ? KEYFILE_OK
            : (ims == DEMO_KEYS_ERR_ID_MISMATCH) ? KEYFILE_ERR_ID_MISMATCH : KEYFILE_ERR_IMAGE;
        if (r == KEYFILE_OK && kek_out != NULL) {
            /* V4-108, F190: a version-2 file carries its store root key, and
             * a passphrase change reseals the same one. A version-1 file has
             * none, and its KEK stands in -- what every store written before
             * V4-108 is keyed from, so those keep verifying. */
            memcpy(kek_out, (hdr.root_len != 0u) ? img + mlen : key, KEYFILE_ROOT_BYTES);
        }
    }
freebufs:
    if (img) { secure_mem_free(img, ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES); }
    if (key) { secure_mem_free(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES); }
    return r;
}

/* What keyfile_open checks of the FILE before it reads it: it opens without
 * following a symlink, is a regular file, is this user's alone, and has a
 * size an envelope can have. Reads nothing. For the daemon's --check-config
 * (F337). Kept beside keyfile_open and not folded into it, so that the
 * open's own lines stay where the campaigns that mutate them expect;
 * tests/test_authd_keyfile.c holds the two to the same answer. */
keyfile_status_t keyfile_probe(const char *ek_path)
{
    if (ek_path == NULL) {
        return KEYFILE_ERR_ARG;
    }
    const int probe_fd = open(ek_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (probe_fd < 0) {
        return KEYFILE_ERR_IO;
    }
    const size_t max_total = KEYFILE_HEADER_LEN + demo_keys_sk2_image_len(64) + KEYFILE_ROOT_BYTES +
                             crypto_aead_xchacha20poly1305_ietf_ABYTES;
    struct stat st;
    keyfile_status_t r = KEYFILE_OK;
    if (fstat(probe_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        r = KEYFILE_ERR_IO;
    } else if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {   /* its owner's alone */
        r = KEYFILE_ERR_PERMISSIONS;
    } else if (st.st_size < 0 || (size_t)st.st_size <= KEYFILE_HEADER_LEN || (size_t)st.st_size > max_total) {
        r = KEYFILE_ERR_FORMAT;
    }
    (void)close(probe_fd);
    return r;
}

keyfile_status_t keyfile_open(const char *ek_path, const uint8_t *expect_id, size_t id_len,
                              const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                              uint8_t *kek_out) {
    return keyfile_open_digest(ek_path, expect_id, id_len, passphrase, pass_len, kp, kek_out, NULL);
}

keyfile_status_t keyfile_open_digest(const char *ek_path, const uint8_t *expect_id, size_t id_len,
                                     const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                                     uint8_t *kek_out, uint8_t digest_out[KEYFILE_DIGEST_BYTES]) {
    return keyfile_open_kept(ek_path, expect_id, id_len, passphrase, pass_len, kp, kek_out, digest_out,
                             NULL, NULL);
}

keyfile_status_t keyfile_open_kept(const char *ek_path, const uint8_t *expect_id, size_t id_len,
                                   const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                                   uint8_t *kek_out, uint8_t digest_out[KEYFILE_DIGEST_BYTES],
                                   uint8_t **sealed_out, size_t *sealed_len) {
    struct stat st;
    if (sealed_out != NULL) {
        *sealed_out = NULL;
    }
    if (sealed_len != NULL) {
        *sealed_len = 0;
    }
    if ((sealed_out == NULL) != (sealed_len == NULL) || (sealed_out != NULL && digest_out == NULL)) {
        return KEYFILE_ERR_ARG;
    }
    if (digest_out != NULL) {
        memset(digest_out, 0, KEYFILE_DIGEST_BYTES);
    }
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
    /* F297: O_NONBLOCK -- a FIFO is refused below, not waited on. */
    const int fd = open(ek_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return KEYFILE_ERR_IO;
    }
    keyfile_status_t r = KEYFILE_ERR_FORMAT;
    const size_t max_total = keyfile_max_total();
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
    uint8_t *fbuf = secure_mem_alloc(total);
    if (fbuf == NULL) { r = KEYFILE_ERR_CRYPTO; goto done; }
    {
        size_t off = 0; ssize_t n;
        while (off < total && (n = read(fd, fbuf + off, total - off)) != 0) {
            if (n < 0) { if (errno == EINTR) { continue; } r = KEYFILE_ERR_IO; goto freefile; }
            off += (size_t)n;
        }
        if (off != total) { r = KEYFILE_ERR_FORMAT; goto freefile; }
    }
    /* custody checked and bytes read: the rest is the buffer path, unchanged */
    r = keyfile_open_buf(fbuf, total, expect_id, id_len, passphrase, pass_len, kp, kek_out);
    if (r == KEYFILE_OK && digest_out != NULL &&
        crypto_generichash(digest_out, KEYFILE_DIGEST_BYTES, fbuf, total, NULL, 0) != 0) {
        memset(digest_out, 0, KEYFILE_DIGEST_BYTES);
        mldsa_keypair_free(kp);
        r = KEYFILE_ERR_CRYPTO;
    }
    if (r == KEYFILE_OK && sealed_out != NULL) {
        /* V4-371 (F823): the sealed bytes, kept. No secret: they are what is
         * on the disk. */
        uint8_t *copy = malloc(total);
        if (copy == NULL) {
            memset(digest_out, 0, KEYFILE_DIGEST_BYTES);
            mldsa_keypair_free(kp);
            r = KEYFILE_ERR_CRYPTO;
        } else {
            memcpy(copy, fbuf, total);
            *sealed_out = copy;
            *sealed_len = total;
        }
    }
freefile:
    secure_mem_free(fbuf, total);
done:
    (void)close(fd);
    return r;
}

keyfile_status_t keyfile_promote(const char *from, const char *to) {
    return keyfile_promote_expect(from, to, NULL);
}

keyfile_status_t keyfile_promote_expect(const char *from, const char *to,
                                        const uint8_t expect[KEYFILE_DIGEST_BYTES]) {
    if (from == NULL || to == NULL) {
        return KEYFILE_ERR_ARG;
    }
    /* Custody first: never promote something that is not ours, is not a
     * regular file, or that anyone else can read. The same three checks
     * keyfile_open applies -- a rename does not get to skip them. */
    /* V4-371 (F821): with `expect`, the file was opened under these same
     * checks a moment ago. One that now is not there, is not a regular file
     * or is not private is one that changed -- and that is the answer, not
     * "io-error", after which a caller said the file still held the key. */
    struct stat st;
    const int fd = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);   /* F297 */
    if (fd < 0) {
        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_IO;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)close(fd);
        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_IO;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
        (void)close(fd);
        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_PERMISSIONS;
    }
    if (expect != NULL && (st.st_size < 0 || (size_t)st.st_size > keyfile_max_total())) {
        /* V4-371 (F826): no key file is this long, so it is not read. A
         * 4 GiB file put there was hashed, five seconds under the lock. */
        (void)close(fd);
        return KEYFILE_ERR_CHANGED;
    }
    if (expect != NULL) {
        /* V4-370 (F817): the bytes, through this descriptor, against the
         * digest of the ones that were opened. Read in pieces: nothing here
         * is secret (the envelope is sealed). */
        crypto_generichash_state hs;
        uint8_t got[KEYFILE_DIGEST_BYTES], chunk[4096];
        ssize_t n;
        int bad = crypto_generichash_init(&hs, NULL, 0, sizeof got) != 0;
        while (!bad && (n = read(fd, chunk, sizeof chunk)) != 0) {
            if (n < 0) { if (errno == EINTR) { continue; } bad = 1; break; }
            bad = crypto_generichash_update(&hs, chunk, (size_t)n) != 0;
        }
        if (!bad) { bad = crypto_generichash_final(&hs, got, sizeof got) != 0; }
        if (bad) {
            (void)close(fd);
            return KEYFILE_ERR_IO;
        }
        if (memcmp(got, expect, sizeof got) != 0) {
            (void)close(fd);
            return KEYFILE_ERR_CHANGED;
        }
    }
    (void)close(fd);
    /* V4-370 (F817): two names for one file. rename(2) of a file onto a
     * hard link to itself does nothing and succeeds, which left .ek.next in
     * place after a "completed" rotation. `to` already is the file: drop the
     * other name. */
    struct stat tst;
    if (lstat(to, &tst) == 0 && tst.st_dev == st.st_dev && tst.st_ino == st.st_ino) {
        if (unlink(from) != 0) {
            return KEYFILE_ERR_IO;
        }
        fsync_parent_dir(to);
        return KEYFILE_OK;
    }

    /* THE ONE PLACE in this project that overwrites a key file, and it is
     * deliberate. Spec 12 says "never in place, never clobbering"; spec 10.2
     * says rotation "renames it over the current file". 10.2 is the more
     * specific rule and wins here, because the alternative -- publish beside,
     * then unlink -- has a window with two files and no way to tell which the
     * server accepted. rename(2) is atomic: after it there is exactly one key
     * file and it is the new one. (The contradiction between the two sections
     * is recorded as errata rather than resolved by editing either.) */
    if (rename(from, to) != 0) {
        return KEYFILE_ERR_IO;
    }
    fsync_parent_dir(to);
    return KEYFILE_OK;
}
