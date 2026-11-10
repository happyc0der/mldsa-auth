#ifndef MLDSA_AUTHD_SECRET_H
#define MLDSA_AUTHD_SECRET_H

/*
 * Reading a passphrase from a file (spec mldsa-authd 12).
 *
 * This lived as a static helper inside authd_main.c until V4-9b gave the
 * daemon two CLI siblings that open the same envelopes. Three copies of a
 * custody rule is three chances to relax one of them, so there is exactly one
 * implementation and all three callers share it.
 *
 * A passphrase is a FILE and never an environment variable or argv, both of
 * which other processes on the host can read.
 *
 * Custody, in the same order spec 12 applies to the key file itself:
 * O_NOFOLLOW, a regular file, owned by us, no group or other permission bits,
 * 1..AUTHD_PASSPHRASE_MAX bytes.
 *
 * ONE exception, for the deployment path itself (V4-99, erratum 74). A
 * systemd credential is NOT "a 0400 file owned by the service user", as this
 * header said until the runbook was first rehearsed on systemd. Measured on
 * Ubuntu 26.04 (systemd, LoadCredentialEncrypted=, User=): the file is owned
 * root:root, mode 0440, and the service user reads it through an ACL entry;
 * the group bits ARE the ACL mask. It lives on a private read-only tmpfs
 * (mode=700) that systemd mounts for the one service. So a file DIRECTLY in
 * the directory named by $CREDENTIALS_DIRECTORY (an absolute path, no
 * subdirectory, compared as a path prefix plus '/') is also accepted when it
 * is owned by root:root, nobody but its owner may write it, and it has no
 * "other" bit. Everywhere else, and for a root-owned file anywhere else, the
 * rule is unchanged. Root ownership adds no exposure: root can read either. ONE trailing newline is stripped, because
 * every editor and systemd-creds appends one -- and because a passphrase whose
 * meaning depends on whether an editor added a byte is a passphrase that will
 * one day stop opening its key.
 *
 * The buffer is secure memory. The caller MUST wipe it with
 * authd_secret_free() as soon as the KDF has consumed it.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    AUTHD_SECRET_OK = 0,
    AUTHD_SECRET_ERR_ARG,
    AUTHD_SECRET_ERR_OPEN,        /* cannot open, or it is a symlink (O_NOFOLLOW) */
    AUTHD_SECRET_ERR_NOT_REGULAR, /* directory, fifo, device */
    AUTHD_SECRET_ERR_OWNER,       /* not owned by this euid */
    AUTHD_SECRET_ERR_PERMISSIONS, /* any group or other bit set: mode must be 0600 */
    AUTHD_SECRET_ERR_SIZE,        /* empty, or over AUTHD_PASSPHRASE_MAX */
    AUTHD_SECRET_ERR_READ,        /* short read */
    AUTHD_SECRET_ERR_CRYPTO       /* secure_mem_alloc failed */
} authd_secret_status_t;

/* Spec 13: every failure prints a status name from the same enums the daemon
 * logs, so an operator can search for one string across the CLIs and the
 * journal. */
const char *authd_secret_status_name(authd_secret_status_t st);

/* The custody decision alone, on a file's already-fstat'ed owner, group and
 * mode -- so every case, the root-owned credential included, is testable
 * without root. creds_dir is $CREDENTIALS_DIRECTORY or NULL. Returns
 * AUTHD_SECRET_OK, AUTHD_SECRET_ERR_OWNER or AUTHD_SECRET_ERR_PERMISSIONS. */
authd_secret_status_t authd_secret_custody(const char *path, uid_t uid, gid_t gid, mode_t mode,
                                           uid_t euid, const char *creds_dir);

/* On success *out is a secure-memory buffer of *out_len bytes (never 0) that
 * the caller owns. On EVERY failure *out is NULL and *out_len is 0. */
authd_secret_status_t authd_secret_read(const char *path, uint8_t **out, size_t *out_len);

/* Wipes and frees. Idempotent on NULL. */
void authd_secret_free(uint8_t *p, size_t len);

#endif /* MLDSA_AUTHD_SECRET_H */
