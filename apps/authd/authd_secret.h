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
 * which other processes on the host can read. A systemd credential is a file
 * under $CREDENTIALS_DIRECTORY, so nothing changes for V4-11.
 *
 * Custody, in the same order spec 12 applies to the key file itself:
 * O_NOFOLLOW, a regular file, owned by us, no group or other permission bits,
 * 1..AUTHD_PASSPHRASE_MAX bytes. ONE trailing newline is stripped, because
 * every editor and systemd-creds appends one -- and because a passphrase whose
 * meaning depends on whether an editor added a byte is a passphrase that will
 * one day stop opening its key.
 *
 * The buffer is secure memory. The caller MUST wipe it with
 * authd_secret_free() as soon as the KDF has consumed it.
 */

#include <stddef.h>
#include <stdint.h>

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

/* On success *out is a secure-memory buffer of *out_len bytes (never 0) that
 * the caller owns. On EVERY failure *out is NULL and *out_len is 0. */
authd_secret_status_t authd_secret_read(const char *path, uint8_t **out, size_t *out_len);

/* Wipes and frees. Idempotent on NULL. */
void authd_secret_free(uint8_t *p, size_t len);

#endif /* MLDSA_AUTHD_SECRET_H */
