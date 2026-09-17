#ifndef MLDSA_AUTHD_CONFIG_H
#define MLDSA_AUTHD_CONFIG_H

#include <stddef.h>
#include <stdint.h>

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
    char     listen_unix[AUTHD_PATH_MAX + 1u];    /* proxy-facing Unix socket; "" = disabled */
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

#endif /* MLDSA_AUTHD_CONFIG_H */
