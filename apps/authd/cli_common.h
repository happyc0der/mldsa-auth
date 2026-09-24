#ifndef MLDSA_AUTH_APPS_AUTHD_CLI_COMMON_H
#define MLDSA_AUTH_APPS_AUTHD_CLI_COMMON_H

/*
 * What authd_admin (authd_cli.c) and authd_client (client_cli.c) share
 * (V4-13a): the exit statuses, the operator's KDF parameters, and the small
 * helpers that print a failure the same way in both binaries.
 *
 * Header-only and `static inline`, deliberately: these were file-static in
 * authd_cli.c until the client half moved out, and keeping them static keeps
 * their names out of every library's symbol table -- `failed` and `need` are
 * not names to export -- while both files still call them by the same names,
 * which mutation anchors quote.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#include <sodium.h>

#include "authd_secret.h"

/* Exit statuses, spec 13. */
#define EX_OK      0
#define EX_FAIL    1
#define EX_USAGE   2
#define EX_CONFIG  3

/* Argon2id for an operator's identity (spec 12), used by the admin's
 * enroll-side commands and by the client's keygen and rotate alike. Named,
 * because a literal 3 next to a literal 4 in two different files is how they
 * drift apart. The server's value stays in authd_cli.c, its only user. */
#define KDF_OPS_OPERATOR  3u
#define KDF_MEM_256MIB    (256u * 1024u * 1024u)

static inline int join(char *out, size_t cap, const char *dir, const char *name)
{
    const int n = snprintf(out, cap, "%s/%s", dir, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static inline int path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* One place that says "this option needs a value and did not get one", so the
 * message is identical for every subcommand of both binaries. */
static inline int unexpected(const char *prog, const char *sub, const char *arg)
{
    fprintf(stderr, "%s %s: unexpected argument '%s'\n", prog, sub, arg);
    return EX_USAGE;
}

static inline int need(const char *prog, const char *sub, const char *usage)
{
    fprintf(stderr, "usage: %s %s %s\n", prog, sub, usage);
    return EX_USAGE;
}

static inline int failed(const char *prog, const char *sub, const char *what, const char *status)
{
    fprintf(stderr, "%s %s: failed: %s: %s\n", prog, sub, what, status);
    return EX_FAIL;
}

/* Hex for the line protocol. `out` must hold 2*len+1 bytes. */
static inline void hexify(char *out, const void *p, size_t len)
{
    (void)sodium_bin2hex(out, 2u * len + 1u, (const unsigned char *)p, len);
}

/* Reads a passphrase file, printing the reason on failure. Configuration
 * problems -- a missing or badly-permissioned passphrase file IS one -- exit
 * 3, not 1. */
static inline int read_pass(const char *prog, const char *sub, const char *path,
                            uint8_t **out, size_t *out_len)
{
    const authd_secret_status_t st = authd_secret_read(path, out, out_len);
    if (st != AUTHD_SECRET_OK) {
        fprintf(stderr, "%s %s: passphrase file %s: %s\n", prog, sub, path,
                authd_secret_status_name(st));
        return EX_CONFIG;
    }
    return EX_OK;
}

#endif /* MLDSA_AUTH_APPS_AUTHD_CLI_COMMON_H */
