#ifndef MLDSA_AUTHD_CONFIG_H
#define MLDSA_AUTHD_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * The daemon's configuration (V4-8a): a strict `key = value` file, parsed
 * into a fixed struct with no allocation.
 *
 * Strictness is the point. The file is edited by an operator at 0600 on a
 * host where a mistake is a security change, so the parser fails closed on
 * everything ambiguous: an unknown key, a duplicate key, a value out of
 * range, a missing required key, an over-long line, a value with no key. It
 * never guesses and never silently defaults a key that was written wrongly --
 * the whole reason `--check-config` exists is so the operator sees the refusal
 * before systemd starts the service, not after.
 *
 * authd_config_parse() works on a BUFFER, not a path: that keeps it a pure
 * function of its bytes, which is what makes it fuzzable (fuzz_authd_config)
 * with an independent model. authd_config_load() is the thin file wrapper.
 */

#define AUTHD_CONFIG_MAX_BYTES   65536u   /* a config larger than this is refused outright */
#define AUTHD_CONFIG_MAX_LINE    1024u
#define AUTHD_PATH_MAX           255u
#define AUTHD_ID_MAX             64u      /* WIRE_ID_MAX_LEN */
#define AUTHD_PASSPHRASE_MAX     4096u    /* a passphrase file larger than this is refused */
#define AUTHD_MAX_UIDS           8u       /* == LISTENER_MAX_ALLOW */
#define AUTHD_LOCAL_SLOTS_MIN    1u
#define AUTHD_LOCAL_SLOTS_MAX    64u

/* Bounds. Each is enforced by the parser, and each has a mutation. */
#define AUTHD_SLOTS_MIN          1u
#define AUTHD_SLOTS_MAX          4096u
#define AUTHD_TIMEOUT_MS_MIN     100u
#define AUTHD_TIMEOUT_MS_MAX     600000u

typedef enum {
    AUTHD_CFG_OK = 0,
    AUTHD_CFG_ERR_IO,           /* file could not be read (load only) */
    AUTHD_CFG_ERR_TOO_LARGE,    /* over AUTHD_CONFIG_MAX_BYTES */
    AUTHD_CFG_ERR_LINE_LONG,    /* a line over AUTHD_CONFIG_MAX_LINE */
    AUTHD_CFG_ERR_SYNTAX,       /* not `key = value`, or an empty key */
    AUTHD_CFG_ERR_UNKNOWN_KEY,
    AUTHD_CFG_ERR_DUPLICATE_KEY,
    AUTHD_CFG_ERR_RANGE,        /* value outside the documented bounds */
    AUTHD_CFG_ERR_VALUE,        /* value malformed for its type */
    AUTHD_CFG_ERR_MISSING       /* a required key was absent */
} authd_config_status_t;

typedef struct {
    char     store_path[AUTHD_PATH_MAX + 1u];
    char     key_path[AUTHD_PATH_MAX + 1u];       /* the MLDSAEK1 server key */
    /* The passphrase that opens key_path, as a FILE -- never an environment
     * variable and never argv, both of which are readable by other processes.
     * A systemd credential is a file under $CREDENTIALS_DIRECTORY, so V4-11
     * points this at the credential and changes nothing else. Must be a
     * regular file, mode 0600, at most AUTHD_PASSPHRASE_MAX bytes. */
    char     key_passphrase_file[AUTHD_PATH_MAX + 1u];
    char     listen_unix[AUTHD_PATH_MAX + 1u];    /* proxy-facing Unix socket; "" = disabled */
    /* The local API (spec 8). Two sockets so an administrative command is
     * unreachable from the site's uid by construction, not by a flag. */
    char     site_socket[AUTHD_PATH_MAX + 1u];
    char     admin_socket[AUTHD_PATH_MAX + 1u];
    uid_t    site_uids[AUTHD_MAX_UIDS];
    size_t   n_site_uids;
    uid_t    admin_uids[AUTHD_MAX_UIDS];
    size_t   n_admin_uids;
    uint32_t max_local_slots;
    uint8_t  server_id[AUTHD_ID_MAX];
    size_t   server_id_len;
    uint16_t listen_port;                          /* raw loopback listener; 0 = disabled */
    uint32_t max_slots;
    uint32_t handshake_timeout_ms;
    uint32_t idle_timeout_ms;
    uint32_t pad_bucket;
} authd_config_t;

/* Fills `out` with the documented defaults for the optional keys. */
void authd_config_defaults(authd_config_t *out);

/* Parses `len` bytes. On success returns AUTHD_CFG_OK and `out` is fully
 * populated; on any failure `out` is left in the defaults state and, when
 * `err_line` is non-NULL, it receives the 1-based line number the failure was
 * attributed to (0 when the failure is not line-specific). Never allocates,
 * never reads outside [buf, buf+len), and requires no NUL terminator. */
authd_config_status_t authd_config_parse(const uint8_t *buf, size_t len,
                                         authd_config_t *out, size_t *err_line);

/* Reads a file (refusing one over AUTHD_CONFIG_MAX_BYTES) and parses it. */
authd_config_status_t authd_config_load(const char *path, authd_config_t *out, size_t *err_line);

const char *authd_config_status_name(authd_config_status_t st);

/* The checks authd_config_parse() cannot make, because it is a pure function
 * of the config's BYTES and these touch the filesystem:
 *
 *   - key_path and key_passphrase_file exist and are regular files;
 *   - the parent directory of store_path exists;
 *   - every configured socket path FITS sun_path.
 *
 * That last one is the reason this exists. AUTHD_PATH_MAX is 255 while
 * sun_path is 104 bytes on macOS and 108 on Linux, so a config with a long
 * socket path passes every byte-level check, --check-config reports "valid",
 * and the daemon then fails to bind at start-up. Catching it in the validator
 * is the difference between a clear refusal and a service that will not start.
 *
 * Called by BOTH binaries, deliberately: a second validator that drifts from
 * the first is worse than no second validator. `detail` (when non-NULL, at
 * least AUTHD_PATH_MAX + 64 bytes) receives a message naming the offending
 * key and value. */
#define AUTHD_CONFIG_DETAIL_MAX (AUTHD_PATH_MAX + 64u)
authd_config_status_t authd_config_check_paths(const authd_config_t *cfg, char *detail, size_t detail_cap);

#endif /* MLDSA_AUTHD_CONFIG_H */
