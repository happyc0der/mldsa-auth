#ifndef MLDSA_AUTH_APPS_DEMO_KEYS_H
#define MLDSA_AUTH_APPS_DEMO_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_wrap.h"

/*
 * DEMO-ONLY identity files for the reference apps. This is NOT a production
 * key-management scheme: secret keys are stored unencrypted, protected only
 * by file permissions. Production deployments need real key storage
 * (HSM/OS keychain, encrypted at rest) and a trust model beyond manual
 * pinning (spec §9).
 *
 *   <dir>/<id>.pub = "MLDSAPK1" || id_len (1) || id || public_key (1952)
 *
 *   <dir>/<id>.sk  = "MLDSASK2" || id_len (1) || id || public_key (1952)
 *                    || secret_key (4032) || digest (32)
 *     digest = SHA-256(DEMO_KEY_INTEGRITY_LABEL || 0x00
 *                      || id_len || id || public_key || secret_key)
 *     file size = 8 + 1 + id_len + 1952 + 4032 + 32 = 6025 + id_len
 *
 * The digest is checked (in constant time) before the key is used, so a
 * corrupted, truncated or mis-assembled secret-key file is rejected
 * deterministically at load time (Step 7.1; before that, a one-shot
 * sign/verify self-test accepted e.g. a damaged t0 component). The digest is
 * UNKEYED: it detects accidental corruption, not tampering -- anyone able to
 * write the 0600 file can recompute it, or simply replace the key.
 *
 * Legacy "MLDSASK1" secret-key files (no digest) are REJECTED with
 * DEMO_KEYS_ERR_UNSUPPORTED_VERSION; regenerate them with keygen.
 *
 * Generated files go to a directory the caller names -- by convention the
 * git-ignored demo-data/ -- and are never committed. Pinning is explicit:
 * the apps take --pin ID=FILE and the id inside the file must match ID.
 */

#define DEMO_KEY_MAGIC_LEN 8u
#define DEMO_KEY_MAGIC_PUBLIC "MLDSAPK1"
#define DEMO_KEY_MAGIC_SECRET "MLDSASK2"
#define DEMO_KEY_MAGIC_SECRET_LEGACY "MLDSASK1"
#define DEMO_KEY_INTEGRITY_LABEL "mldsa-auth/v1/demo-key-integrity" /* hashed without its NUL */
#define DEMO_KEY_DIGEST_BYTES 32u

typedef enum {
    DEMO_KEYS_OK = 0,
    DEMO_KEYS_ERR_ARG,
    DEMO_KEYS_ERR_EXISTS,       /* keygen never overwrites */
    DEMO_KEYS_ERR_IO,           /* includes a symlink (O_NOFOLLOW) */
    DEMO_KEYS_ERR_PERMISSIONS,  /* secret file not owned by us, or group/other bits set */
    DEMO_KEYS_ERR_FORMAT,       /* wrong magic, wrong size, bad id length */
    DEMO_KEYS_ERR_ID_MISMATCH,  /* embedded id != expected id */
    DEMO_KEYS_ERR_KEY_MISMATCH, /* public key does not match the secret key (self-test) */
    DEMO_KEYS_ERR_CRYPTO,
    DEMO_KEYS_ERR_INTEGRITY,          /* secret-key file digest mismatch (Step 7.1) */
    DEMO_KEYS_ERR_UNSUPPORTED_VERSION /* legacy MLDSASK1 secret-key file (Step 7.1) */
} demo_keys_status_t;

/* 1 iff id is 1..64 bytes of [A-Za-z0-9._-] not starting with '.' -- demo
 * ids also name the key files, so they must be filename-safe. */
int demo_keys_id_filename_safe(const uint8_t *id, size_t len);

/* Generates a fresh ML-DSA-65 identity and publishes <dir>/<id>.sk (MLDSASK2,
 * 0600) and <dir>/<id>.pub (0644) ATOMICALLY and without clobbering: each
 * file is written to a hidden temp file in the same directory (O_CREAT |
 * O_EXCL | O_NOFOLLOW, same mode), fsync'ed, then link()ed to its final name
 * (which fails if it exists). Creates dir -- and any missing parent
 * directories -- with mode 0700 if it does not exist. The id must be a
 * filename-safe demo id. */
demo_keys_status_t demo_keys_generate_files(const char *dir, const uint8_t *id, size_t id_len);

/* Loads an MLDSASK2 identity. Order: permissions -> size bounds -> magic
 * (MLDSASK1 -> UNSUPPORTED_VERSION) -> exact size -> read (secret key
 * directly into secure memory) -> constant-time digest check (INTEGRITY) ->
 * id (ID_MISMATCH) -> sign/verify self-test (KEY_MISMATCH). On any failure
 * *kp holds nothing (NULL secret key, zeroed public key). */
demo_keys_status_t demo_keys_load_identity(const char *sk_path, const uint8_t *expect_id, size_t id_len,
                                           mldsa_keypair_t *kp);

/* Loads a pinned public key; the embedded id must equal expect_id. */
demo_keys_status_t demo_keys_load_public(const char *pub_path, const uint8_t *expect_id, size_t id_len,
                                         uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES]);

const char *demo_keys_status_name(demo_keys_status_t st);

#endif /* MLDSA_AUTH_APPS_DEMO_KEYS_H */
