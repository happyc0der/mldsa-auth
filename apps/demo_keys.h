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
 * Legacy "MLDSASK1" secret-key files (no digest) are REJECTED by the loader
 * with DEMO_KEYS_ERR_UNSUPPORTED_VERSION; regenerate them with keygen.
 *
 * demo_keys_migrate_legacy() converts one to MLDSASK2 when regenerating is
 * not free -- an identity whose public key peers have already pinned. It
 * writes a NEW file and never modifies or deletes the source. What it
 * cannot do is verify that source: a legacy file carries no digest, so the
 * only available check is the sign/verify self-test, and Step 7 measured
 * that test accepting a key with a corrupted t0 component in 11 of 20
 * cases. The digest in the migrated file therefore certifies the key bytes
 * AS THEY ARE NOW, not as keygen originally wrote them. The CLI prints that
 * in those words on every successful migration.
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
    DEMO_KEYS_ERR_INTEGRITY,           /* secret-key file digest mismatch (Step 7.1) */
    DEMO_KEYS_ERR_UNSUPPORTED_VERSION, /* legacy MLDSASK1 secret-key file (Step 7.1) */
    DEMO_KEYS_ERR_NOT_LEGACY           /* migrate-key input is already MLDSASK2 (V2-9) */
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

/* Publishes ONE public-key file (MLDSAPK1, mode 0644) at exactly `path`,
 * atomically and without clobbering: DEMO_KEYS_ERR_EXISTS if it is already
 * there. A full path rather than dir+id, because spec mldsa-authd 16 fixes the
 * server's file name as "server.pub" whatever the server's id happens to be.
 *
 * This exists because demo_keys_generate_files() also writes the plaintext
 * MLDSASK2 secret key, which spec mldsa-authd Req 10 forbids for every daemon
 * and CLI command. The authd keygen paths seal the secret with keyfile_seal()
 * and publish the public half with this. */
demo_keys_status_t demo_keys_write_public(const char *path, const uint8_t *id, size_t id_len,
                                          const uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES]);

/* Loads an MLDSASK2 identity. Order: permissions -> size bounds -> magic
 * (MLDSASK1 -> UNSUPPORTED_VERSION) -> exact size -> read (secret key
 * directly into secure memory) -> constant-time digest check (INTEGRITY) ->
 * id (ID_MISMATCH) -> sign/verify self-test (KEY_MISMATCH). On any failure
 * *kp holds nothing (NULL secret key, zeroed public key). */
demo_keys_status_t demo_keys_load_identity(const char *sk_path, const uint8_t *expect_id, size_t id_len,
                                           mldsa_keypair_t *kp);

/* The exact length of the MLDSASK2 image for an identity of id_len bytes
 * ("MLDSASK2" || id_len || id || pk || sk || digest), 6025 + id_len. Returns
 * 0 for an out-of-range id_len. */
size_t demo_keys_sk2_image_len(size_t id_len);

/* Validates an in-memory MLDSASK2 image and, on success, returns the keypair
 * with the secret key in secure memory. This is the shared validator: the file
 * loader above reads a file into a buffer and calls it, and the key-at-rest
 * envelope (keyfile.c, V4-6) decrypts into a buffer and calls it, so both
 * paths run the SAME digest/id/self-test checks and neither writes plaintext
 * to disk. The caller SHOULD hold the image in secure memory. Same status
 * codes and order as demo_keys_load_identity from the magic check onward. */
demo_keys_status_t demo_keys_load_identity_from_image(const uint8_t *img, size_t img_len,
                                                      const uint8_t *expect_id, size_t id_len,
                                                      mldsa_keypair_t *kp);

/* Builds an MLDSASK2 image (header, id, public key, secret key, integrity
 * digest) into img, which must hold demo_keys_sk2_image_len(id_len) bytes and
 * SHOULD be secure memory (it contains the secret key). Used by keygen and by
 * the envelope's keygen/rewrap. Returns OK or ARG. */
demo_keys_status_t demo_keys_build_sk2_image(uint8_t *img, size_t img_cap, const uint8_t *id, size_t id_len,
                                             const mldsa_keypair_t *kp);

/* Converts a legacy MLDSASK1 file at in_path into a new MLDSASK2 file at
 * out_path, published atomically (temp + link) with mode 0600. Order:
 * permissions -> size bounds -> magic (MLDSASK2 -> NOT_LEGACY, anything
 * else -> FORMAT) -> exact size -> read (secret key into secure memory) ->
 * id (ID_MISMATCH) -> sign/verify self-test (KEY_MISMATCH) -> refuse an
 * existing out_path (EXISTS) -> write.
 *
 * in_path is opened read-only and is NEVER modified or removed, and
 * out_path is never overwritten -- passing the same path for both fails
 * with EXISTS, so in-place migration is impossible by construction. On any
 * failure no output file is left behind. See the limitation above: success
 * does not mean the source was intact. */
demo_keys_status_t demo_keys_migrate_legacy(const char *in_path, const char *out_path, const uint8_t *expect_id,
                                            size_t id_len);

/* Loads a pinned public key; the embedded id must equal expect_id. */
demo_keys_status_t demo_keys_load_public(const char *pub_path, const uint8_t *expect_id, size_t id_len,
                                         uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES]);

const char *demo_keys_status_name(demo_keys_status_t st);

#endif /* MLDSA_AUTH_APPS_DEMO_KEYS_H */
