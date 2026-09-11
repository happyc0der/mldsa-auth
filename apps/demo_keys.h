#ifndef MLDSA_AUTH_APPS_DEMO_KEYS_H
#define MLDSA_AUTH_APPS_DEMO_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_wrap.h"

/*
 * DEMO-ONLY identity files for the Step 6 reference apps. This is NOT a
 * production key-management scheme: secret keys are stored unencrypted,
 * protected only by file permissions. Production deployments need real key
 * storage (HSM/OS keychain, encrypted at rest) and a trust model beyond
 * manual pinning (spec §9).
 *
 *   <dir>/<id>.pub = "MLDSAPK1" || id_len (1) || id || public_key (1952)
 *   <dir>/<id>.sk  = "MLDSASK1" || id_len (1) || id || public_key (1952) || secret_key (4032)
 *
 * Generated files go to a directory the caller names -- by convention the
 * git-ignored demo-data/ -- and are never committed. Pinning is explicit:
 * the apps take --pin ID=FILE and the id inside the file must match ID.
 */

#define DEMO_KEY_MAGIC_LEN 8u
#define DEMO_KEY_MAGIC_PUBLIC "MLDSAPK1"
#define DEMO_KEY_MAGIC_SECRET "MLDSASK1"

typedef enum {
    DEMO_KEYS_OK = 0,
    DEMO_KEYS_ERR_ARG,
    DEMO_KEYS_ERR_EXISTS,       /* keygen never overwrites */
    DEMO_KEYS_ERR_IO,           /* includes a symlink (O_NOFOLLOW) */
    DEMO_KEYS_ERR_PERMISSIONS,  /* secret file not owned by us, or group/other bits set */
    DEMO_KEYS_ERR_FORMAT,       /* wrong magic, wrong size, bad id length */
    DEMO_KEYS_ERR_ID_MISMATCH,  /* embedded id != expected id */
    DEMO_KEYS_ERR_KEY_MISMATCH, /* public key does not match the secret key (self-test) */
    DEMO_KEYS_ERR_CRYPTO
} demo_keys_status_t;

/* 1 iff id is 1..64 bytes of [A-Za-z0-9._-] not starting with '.' -- demo
 * ids also name the key files, so they must be filename-safe. */
int demo_keys_id_filename_safe(const uint8_t *id, size_t len);

/* Generates a fresh ML-DSA-65 identity and writes <dir>/<id>.sk (0600) and
 * <dir>/<id>.pub (0644), both O_CREAT|O_EXCL|O_NOFOLLOW (never overwrites).
 * Creates dir -- and any missing parent directories -- with mode 0700 if it
 * does not exist (existing directories are left untouched). The id must be a
 * filename-safe demo id (demo_parse_id). */
demo_keys_status_t demo_keys_generate_files(const char *dir, const uint8_t *id, size_t id_len);

/* Loads an identity. The secret key is read directly into secure memory; a
 * sign/verify self-test rejects a public key that does not match. On any
 * failure *kp holds nothing (NULL secret key, zeroed public key). */
demo_keys_status_t demo_keys_load_identity(const char *sk_path, const uint8_t *expect_id, size_t id_len,
                                           mldsa_keypair_t *kp);

/* Loads a pinned public key; the embedded id must equal expect_id. */
demo_keys_status_t demo_keys_load_public(const char *pub_path, const uint8_t *expect_id, size_t id_len,
                                         uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES]);

const char *demo_keys_status_name(demo_keys_status_t st);

#endif /* MLDSA_AUTH_APPS_DEMO_KEYS_H */
