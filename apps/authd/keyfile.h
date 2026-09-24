#ifndef MLDSA_AUTH_APPS_AUTHD_KEYFILE_H
#define MLDSA_AUTH_APPS_AUTHD_KEYFILE_H

/* MLDSAEK1 -- an ML-DSA identity key encrypted at rest (spec mldsa-authd 12).
 *
 * The plaintext is the exact MLDSASK2 image demo_keys writes, so after
 * decryption the SAME validator (demo_keys_load_identity_from_image) checks
 * the digest, id and sign/verify self-test -- no second copy of that logic,
 * and no plaintext secret key ever touches the disk (Req 10).
 *
 * File layout (all integers big-endian). Bytes [0, KEYFILE_HEADER_LEN) are the
 * AEAD's ASSOCIATED DATA, so the KDF parameters are authenticated: a tampered
 * memlimit cannot turn start-up into a memory-exhaustion DoS. An AEAD is used
 * rather than crypto_secretbox precisely because secretbox authenticates
 * nothing outside the box.
 *
 *   magic     8   "MLDSAEK1"
 *   version   1   0x01
 *   kdf_alg   1   0x01 = Argon2id13
 *   opslimit  4   1..KEYFILE_OPSLIMIT_MAX
 *   memlimit  8   KEYFILE_MEMLIMIT_MIN..KEYFILE_MEMLIMIT_MAX bytes
 *   salt     16   crypto_pwhash_SALTBYTES
 *   aead_alg  1   0x01 = XChaCha20-Poly1305-IETF
 *   nonce    24   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
 *   ct_len    4   plaintext + tag
 *   ciphertext||tag  ct_len
 */

#include <stddef.h>
#include <stdint.h>
#include "mldsa_wrap.h"
#include "demo_keys.h"

#define KEYFILE_MAGIC "MLDSAEK1"
#define KEYFILE_MAGIC_LEN 8u
#define KEYFILE_VERSION 0x01u
#define KEYFILE_KDF_ARGON2ID13 0x01u
#define KEYFILE_AEAD_XCHACHA20POLY1305 0x01u
#define KEYFILE_HEADER_LEN 67u          /* magic..ct_len inclusive; the AEAD's AAD */

/* Accepted KDF parameter bounds. A file outside these is rejected before the
 * KDF runs, so a hostile file cannot request a gigabyte of scrypt/argon memory. */
#define KEYFILE_OPSLIMIT_MIN 1u
#define KEYFILE_OPSLIMIT_MAX 10u
#define KEYFILE_MEMLIMIT_MIN (8u * 1024u * 1024u)          /* 8 MiB */
#define KEYFILE_MEMLIMIT_MAX (1024u * 1024u * 1024u)       /* 1 GiB */

typedef enum {
    KEYFILE_OK = 0,
    KEYFILE_ERR_ARG,
    KEYFILE_ERR_IO,           /* open/read/write, includes a symlink (O_NOFOLLOW) */
    KEYFILE_ERR_PERMISSIONS,  /* not owned by us, or group/other bits set */
    KEYFILE_ERR_FORMAT,       /* wrong magic/version/alg, bad lengths, size out of range */
    KEYFILE_ERR_PARAMS,       /* KDF parameters outside the accepted bounds */
    KEYFILE_ERR_DECRYPT,      /* AEAD verification failed: wrong passphrase or tampering */
    KEYFILE_ERR_EXISTS,       /* output already present; never overwritten */
    KEYFILE_ERR_CRYPTO,       /* KDF/allocation failure */
    KEYFILE_ERR_IMAGE         /* decryption succeeded but the MLDSASK2 image is invalid */
} keyfile_status_t;

const char *keyfile_status_name(keyfile_status_t st);

/* The parsed, validated MLDSAEK1 header (everything before the KDF). */
typedef struct {
    uint32_t opslimit;
    uint64_t memlimit;
    uint32_t ct_len;   /* ciphertext + tag */
    uint32_t img_len;  /* plaintext (MLDSASK2 image) length */
} keyfile_header_t;

/* Validates the header of a `total`-byte candidate: size range, magic,
 * version, algorithm ids, ct_len consistency and the KDF parameter bounds --
 * stopping BEFORE the KDF, so it is safe to run on arbitrary attacker bytes
 * (the fuzz target does exactly that). Returns FORMAT, PARAMS or OK. */
keyfile_status_t keyfile_parse_header(const uint8_t *buf, size_t total, keyfile_header_t *out);

/* Seals an MLDSASK2 image (from demo_keys_build_sk2_image) under a passphrase,
 * publishing out_path atomically (temp + link, mode 0600); refuses an existing
 * out_path. opslimit/memlimit must be within the bounds above. */
keyfile_status_t keyfile_seal(const char *out_path, const uint8_t *sk2_image, size_t image_len,
                              const char *passphrase, size_t pass_len,
                              uint32_t opslimit, uint64_t memlimit);

/* Opens an MLDSAEK1 file and returns the validated keypair (secret key in
 * secure memory). Runs the shared MLDSASK2 validator after decryption, so a
 * wrong id is ID_MISMATCH-in-image (KEYFILE_ERR_IMAGE) and so on. */
/* `kek_out`, when non-NULL, receives the 32-byte envelope KEK (the Argon2id
 * output) on success. The store derives its audit-chain key from it
 * (key_audit = HKDF(ikm=KEK, salt=store_id, info="mldsa-authd/v1/audit-mac"),
 * spec 9.2.4), and store_id only exists after the store is created, so the
 * KEK -- not a pre-derived key -- is what must cross this boundary. It is
 * secret: the caller SHOULD pass secure memory and wipe it. On EVERY failure
 * path it is zeroed, never left holding a partial derivation. */
keyfile_status_t keyfile_open(const char *ek_path, const uint8_t *expect_id, size_t id_len,
                              const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                              uint8_t *kek_out);

/* ---- buffer in, buffer out (V4-13a) -----------------------------------------
 *
 * The same envelope with no file system: the client core -- and through it the
 * browser build, which has no files to open -- seals and opens in memory. The
 * file functions above are thin wrappers over these (custody and I/O around
 * them, nothing else), so there is one sealer and one opener, not two. */

/* The exact MLDSAEK1 size for an image_len-byte MLDSASK2 image; 0 when
 * image_len is outside (0, demo_keys_sk2_image_len(64)]. */
size_t keyfile_sealed_len(size_t image_len);

/* Seals into `out` (out_cap >= keyfile_sealed_len(image_len)). Same argument
 * rules, parameter bounds and statuses as keyfile_seal minus EXISTS/IO. On any
 * failure the first keyfile_sealed_len(image_len) bytes of `out` are zeroed,
 * so a caller can never persist a header without its ciphertext. */
keyfile_status_t keyfile_seal_buf(uint8_t *out, size_t out_cap, const uint8_t *sk2_image, size_t image_len,
                                  const char *passphrase, size_t pass_len,
                                  uint32_t opslimit, uint64_t memlimit);

/* Opens an in-memory envelope: keyfile_parse_header first -- so FORMAT and
 * PARAMS are decided before any key-derivation work -- then the KDF, the AEAD
 * and the shared MLDSASK2 validator. Same statuses, same *kp and kek_out
 * guarantees as keyfile_open (which reads the file and calls this). */
keyfile_status_t keyfile_open_buf(const uint8_t *buf, size_t total, const uint8_t *expect_id, size_t id_len,
                                  const char *passphrase, size_t pass_len, mldsa_keypair_t *kp,
                                  uint8_t *kek_out);

/* Publishes an already-sealed envelope at `path`, exactly as keyfile_seal
 * publishes (temp + link, mode 0600, EXISTS rather than overwrite) -- but only
 * after keyfile_parse_header accepts it, so nothing that is not a well-formed
 * MLDSAEK1 envelope can be written as a key file this way. Returns the parse
 * status (FORMAT/PARAMS) unchanged when it does not. */
keyfile_status_t keyfile_write_sealed(const char *path, const uint8_t *buf, size_t len);

/* Atomically replaces `to` with `from` (rename(2)), after checking `from`'s
 * custody the way keyfile_open does: O_NOFOLLOW, a regular file, owned by this
 * euid, no group or other permission bits.
 *
 * This is the ONLY function here that clobbers. Rotation needs it: spec 10.2
 * has the client write <handle>.ek.next and rename it over <handle>.ek when
 * the daemon acknowledges, and any non-atomic version leaves a window with two
 * key files and no way to know which one the server accepted. Do not reach for
 * it anywhere else -- keyfile_seal's refuse-if-exists is the rule, and this is
 * the documented exception. */
keyfile_status_t keyfile_promote(const char *from, const char *to);

#endif
