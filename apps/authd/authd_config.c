#include "authd_config.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "session.h"   /* SESSION_PAD_BUCKET_* for the bucket whitelist */

/* Keys. Required ones must appear; the rest have documented defaults. */
#define K_STORE      "store_path"
#define K_KEY        "key_path"
#define K_PASS       "key_passphrase_file"
#define K_SERVER_ID  "server_id"
#define K_UNIX       "listen_unix"
#define K_PORT       "listen_port"
#define K_SLOTS      "max_slots"
#define K_HS_MS      "handshake_timeout_ms"
#define K_IDLE_MS    "idle_timeout_ms"
#define K_BUCKET     "pad_bucket"
#define K_SITE_SOCK  "site_socket"
#define K_ADMIN_SOCK "admin_socket"
#define K_SITE_UIDS  "site_uids"
#define K_ADMIN_UIDS "admin_uids"
#define K_LOCAL_SLOTS "max_local_slots"

/* bit index per key, for duplicate and missing detection */
enum { B_STORE, B_KEY, B_PASS, B_SERVER_ID, B_UNIX, B_PORT, B_SLOTS, B_HS_MS, B_IDLE_MS, B_BUCKET,
       B_SITE_SOCK, B_ADMIN_SOCK, B_SITE_UIDS, B_ADMIN_UIDS, B_LOCAL_SLOTS, B_COUNT };

const char *authd_config_status_name(authd_config_status_t st)
{
    switch (st) {
    case AUTHD_CFG_OK:               return "ok";
    case AUTHD_CFG_ERR_IO:           return "io";
    case AUTHD_CFG_ERR_TOO_LARGE:    return "file-too-large";
    case AUTHD_CFG_ERR_LINE_LONG:    return "line-too-long";
    case AUTHD_CFG_ERR_SYNTAX:       return "syntax";
    case AUTHD_CFG_ERR_UNKNOWN_KEY:  return "unknown-key";
    case AUTHD_CFG_ERR_DUPLICATE_KEY:return "duplicate-key";
    case AUTHD_CFG_ERR_RANGE:        return "value-out-of-range";
    case AUTHD_CFG_ERR_VALUE:        return "malformed-value";
    case AUTHD_CFG_ERR_MISSING:      return "missing-required-key";
    default:                         return "unknown";
    }
}

void authd_config_defaults(authd_config_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof *out);
    out->max_slots = 256u;
    out->handshake_timeout_ms = 10000u;
    out->idle_timeout_ms = 60000u;
    out->pad_bucket = SESSION_PAD_BUCKET_DEFAULT;
    out->max_local_slots = 8u;
    /* The admin socket defaults to root only; the site socket has no default
     * allowlist, so a deployment must name the uid that may reach it. */
    out->admin_uids[0] = (uid_t)0;
    out->n_admin_uids = 1u;
    out->n_site_uids = 0u;
    out->listen_port = 0u;           /* raw listener disabled unless configured */
}

static int is_space(uint8_t c) { return c == ' ' || c == '\t' || c == '\r'; }

/* A printable, non-control ASCII byte. Config values are paths, ids and
 * numbers; anything else (a NUL, a newline smuggled via an escape, a UTF-8
 * blob) is refused rather than stored and later handed to open(). */
static int is_printable(uint8_t c) { return c >= 0x20u && c <= 0x7eu; }

/* Parses an unsigned decimal in [lo, hi]. Rejects empty, non-digits, leading
 * '+'/'-', and anything that would overflow -- no strtoul, whose error
 * reporting is easy to get subtly wrong. */
static authd_config_status_t parse_u32(const uint8_t *v, size_t n, uint32_t lo, uint32_t hi, uint32_t *out)
{
    if (n == 0u) {
        return AUTHD_CFG_ERR_VALUE;
    }
    if (n > 10u) {
        return AUTHD_CFG_ERR_RANGE;   /* any 11+ digit decimal exceeds uint32 */
    }
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return AUTHD_CFG_ERR_VALUE;
        }
        acc = acc * 10u + (uint64_t)(v[i] - '0');
        if (acc > 0xffffffffULL) {
            return AUTHD_CFG_ERR_RANGE;
        }
    }
    if (acc < (uint64_t)lo || acc > (uint64_t)hi) {
        return AUTHD_CFG_ERR_RANGE;
    }
    *out = (uint32_t)acc;
    return AUTHD_CFG_OK;
}

/* A comma-separated uid allowlist: "33,1001". Empty is refused -- a socket
 * with an empty allowlist would serve nobody, which is almost certainly a typo
 * rather than an intention. */
static authd_config_status_t parse_uids(const uint8_t *v, size_t n, uid_t *out, size_t *n_out)
{
    *n_out = 0u;
    if (n == 0u) {
        return AUTHD_CFG_ERR_VALUE;
    }
    size_t i = 0;
    while (i < n) {
        size_t start = i;
        while (i < n && v[i] != ',') {
            i++;
        }
        const size_t len = i - start;
        if (len == 0u || *n_out >= AUTHD_MAX_UIDS) {
            return (len == 0u) ? AUTHD_CFG_ERR_VALUE : AUTHD_CFG_ERR_RANGE;
        }
        uint32_t u = 0;
        const authd_config_status_t r = parse_u32(v + start, len, 0u, 0x7fffffffu, &u);
        if (r != AUTHD_CFG_OK) {
            return r;
        }
        out[*n_out] = (uid_t)u;
        (*n_out)++;
        if (i < n) { i++; }         /* step over the comma */
    }
    return AUTHD_CFG_OK;
}

static authd_config_status_t copy_str(const uint8_t *v, size_t n, char *dst, size_t cap)
{
    if (n == 0u || n >= cap) {
        return AUTHD_CFG_ERR_VALUE;
    }
    for (size_t i = 0; i < n; i++) {
        if (!is_printable(v[i])) {
            return AUTHD_CFG_ERR_VALUE;
        }
    }
    memcpy(dst, v, n);
    dst[n] = '\0';
    return AUTHD_CFG_OK;
}

static int key_is(const uint8_t *k, size_t kn, const char *name)
{
    size_t n = strlen(name);
    return kn == n && memcmp(k, name, n) == 0;
}

authd_config_status_t authd_config_parse(const uint8_t *buf, size_t len,
                                         authd_config_t *out, size_t *err_line)
{
    if (err_line != NULL) {
        *err_line = 0;
    }
    if (out == NULL || (buf == NULL && len != 0u)) {
        return AUTHD_CFG_ERR_SYNTAX;
    }
    authd_config_defaults(out);
    if (len > AUTHD_CONFIG_MAX_BYTES) {
        return AUTHD_CFG_ERR_TOO_LARGE;
    }

    /* Parsed into a LOCAL and committed to *out only once every check has
     * passed. An earlier version assigned straight into *out and reset it on
     * each error path -- which is exactly the shape that leaves a partially
     * applied config when a path forgets, and fuzz_authd_config caught three
     * such paths (unknown key, syntax, over-long line) on its first run.
     * Commit-on-success makes that class of bug unrepresentable. */
    authd_config_t cfg;
    authd_config_defaults(&cfg);

    uint32_t seen = 0u;
    size_t line_no = 0;
    size_t i = 0;

    while (i <= len) {
        /* find the end of this line */
        size_t start = i;
        while (i < len && buf[i] != '\n') {
            i++;
        }
        size_t end = i;              /* exclusive */
        int had_newline = (i < len);
        i++;                         /* step over the '\n' (or past len to stop) */

        if (start == len && !had_newline) {
            break;                   /* trailing content consumed exactly */
        }
        line_no++;

        if (end - start > AUTHD_CONFIG_MAX_LINE) {
            if (err_line != NULL) { *err_line = line_no; }
            return AUTHD_CFG_ERR_LINE_LONG;
        }

        /* trim leading/trailing space */
        while (start < end && is_space(buf[start])) { start++; }
        while (end > start && is_space(buf[end - 1u])) { end--; }

        if (start == end) {
            if (!had_newline) { break; }
            continue;                /* blank */
        }
        if (buf[start] == '#') {
            if (!had_newline) { break; }
            continue;                /* comment */
        }

        /* split on the first '=' */
        size_t eq = start;
        while (eq < end && buf[eq] != '=') { eq++; }
        if (eq == end) {
            if (err_line != NULL) { *err_line = line_no; }
            return AUTHD_CFG_ERR_SYNTAX;
        }
        size_t ks = start, ke = eq;
        while (ke > ks && is_space(buf[ke - 1u])) { ke--; }
        size_t vs = eq + 1u, ve = end;
        while (vs < ve && is_space(buf[vs])) { vs++; }

        const uint8_t *k = buf + ks;
        size_t kn = ke - ks;
        const uint8_t *v = buf + vs;
        size_t vn = ve - vs;

        if (kn == 0u) {
            if (err_line != NULL) { *err_line = line_no; }
            return AUTHD_CFG_ERR_SYNTAX;
        }

        /* 1. resolve the key */
        int bit = -1;
        if (key_is(k, kn, K_STORE))          { bit = B_STORE; }
        else if (key_is(k, kn, K_KEY))       { bit = B_KEY; }
        else if (key_is(k, kn, K_PASS))      { bit = B_PASS; }
        else if (key_is(k, kn, K_UNIX))      { bit = B_UNIX; }
        else if (key_is(k, kn, K_SERVER_ID)) { bit = B_SERVER_ID; }
        else if (key_is(k, kn, K_PORT))      { bit = B_PORT; }
        else if (key_is(k, kn, K_SLOTS))     { bit = B_SLOTS; }
        else if (key_is(k, kn, K_HS_MS))     { bit = B_HS_MS; }
        else if (key_is(k, kn, K_IDLE_MS))   { bit = B_IDLE_MS; }
        else if (key_is(k, kn, K_BUCKET))    { bit = B_BUCKET; }
        else if (key_is(k, kn, K_SITE_SOCK)) { bit = B_SITE_SOCK; }
        else if (key_is(k, kn, K_ADMIN_SOCK)){ bit = B_ADMIN_SOCK; }
        else if (key_is(k, kn, K_SITE_UIDS)) { bit = B_SITE_UIDS; }
        else if (key_is(k, kn, K_ADMIN_UIDS)){ bit = B_ADMIN_UIDS; }
        else if (key_is(k, kn, K_LOCAL_SLOTS)) { bit = B_LOCAL_SLOTS; }
        else {
            if (err_line != NULL) { *err_line = line_no; }
            return AUTHD_CFG_ERR_UNKNOWN_KEY;
        }

        /* 2. a repeated key is a structural error regardless of its value */
        if ((seen & (1u << bit)) != 0u) {
            if (err_line != NULL) { *err_line = line_no; }
            return AUTHD_CFG_ERR_DUPLICATE_KEY;
        }

        /* 3. only now is the value parsed */
        authd_config_status_t r = AUTHD_CFG_OK;
        uint32_t u = 0;

        if (bit == B_STORE) {
            r = copy_str(v, vn, cfg.store_path, sizeof cfg.store_path);
        } else if (bit == B_KEY) {
            r = copy_str(v, vn, cfg.key_path, sizeof cfg.key_path);
        } else if (bit == B_PASS) {
            r = copy_str(v, vn, cfg.key_passphrase_file, sizeof cfg.key_passphrase_file);
        } else if (bit == B_SITE_SOCK) {
            r = copy_str(v, vn, cfg.site_socket, sizeof cfg.site_socket);
        } else if (bit == B_ADMIN_SOCK) {
            r = copy_str(v, vn, cfg.admin_socket, sizeof cfg.admin_socket);
        } else if (bit == B_SITE_UIDS) {
            r = parse_uids(v, vn, cfg.site_uids, &cfg.n_site_uids);
        } else if (bit == B_ADMIN_UIDS) {
            r = parse_uids(v, vn, cfg.admin_uids, &cfg.n_admin_uids);
        } else if (bit == B_LOCAL_SLOTS) {
            r = parse_u32(v, vn, AUTHD_LOCAL_SLOTS_MIN, AUTHD_LOCAL_SLOTS_MAX, &cfg.max_local_slots);
        } else if (bit == B_UNIX) {
            r = copy_str(v, vn, cfg.listen_unix, sizeof cfg.listen_unix);
        } else if (bit == B_SERVER_ID) {
            if (vn == 0u || vn > AUTHD_ID_MAX) {
                r = AUTHD_CFG_ERR_VALUE;
            } else {
                for (size_t j = 0; j < vn && r == AUTHD_CFG_OK; j++) {
                    if (!is_printable(v[j])) { r = AUTHD_CFG_ERR_VALUE; }
                }
                if (r == AUTHD_CFG_OK) {
                    memcpy(cfg.server_id, v, vn);
                    cfg.server_id_len = vn;
                }
            }
        } else if (bit == B_PORT) {
            r = parse_u32(v, vn, 0u, 65535u, &u);
            if (r == AUTHD_CFG_OK) { cfg.listen_port = (uint16_t)u; }
        } else if (bit == B_SLOTS) {
            r = parse_u32(v, vn, AUTHD_SLOTS_MIN, AUTHD_SLOTS_MAX, &cfg.max_slots);
        } else if (bit == B_HS_MS) {
            r = parse_u32(v, vn, AUTHD_TIMEOUT_MS_MIN, AUTHD_TIMEOUT_MS_MAX, &cfg.handshake_timeout_ms);
        } else if (bit == B_IDLE_MS) {
            r = parse_u32(v, vn, AUTHD_TIMEOUT_MS_MIN, AUTHD_TIMEOUT_MS_MAX, &cfg.idle_timeout_ms);
        } else {
            r = parse_u32(v, vn, 1u, SESSION_PAD_BUCKET_MAX, &u);
            if (r == AUTHD_CFG_OK) {
                /* the same six the record layer accepts -- a range check alone
                 * would admit 32, which session_init would then reject at a
                 * much less helpful moment */
                if (u == 1u || u == 16u || u == 64u || u == 256u || u == 1024u || u == 4096u) {
                    cfg.pad_bucket = u;
                } else {
                    r = AUTHD_CFG_ERR_RANGE;
                }
            }
        }

        if (r != AUTHD_CFG_OK) {
            if (err_line != NULL) { *err_line = line_no; }
            return r;
        }
        seen |= (1u << bit);

        if (!had_newline) {
            break;
        }
    }

    /* required keys */
    const int required[] = { B_STORE, B_KEY, B_PASS, B_SERVER_ID };
    for (size_t j = 0; j < sizeof required / sizeof required[0]; j++) {
        if ((seen & (1u << required[j])) == 0u) {
            return AUTHD_CFG_ERR_MISSING;
        }
    }
    /* at least one listener must be configured, or the daemon can serve nobody */
    if (cfg.listen_port == 0u && cfg.listen_unix[0] == '\0') {
        return AUTHD_CFG_ERR_MISSING;
    }
    (void)B_COUNT;
    *out = cfg;                 /* the single commit point */
    return AUTHD_CFG_OK;
}

authd_config_status_t authd_config_load(const char *path, authd_config_t *out, size_t *err_line)
{
    if (path == NULL || out == NULL) {
        return AUTHD_CFG_ERR_IO;
    }
    authd_config_defaults(out);
    if (err_line != NULL) { *err_line = 0; }

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return AUTHD_CFG_ERR_IO;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)close(fd);
        return AUTHD_CFG_ERR_IO;
    }
    if (st.st_size < 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_CONFIG_MAX_BYTES) {
        (void)close(fd);
        return AUTHD_CFG_ERR_TOO_LARGE;
    }
    static uint8_t buf[AUTHD_CONFIG_MAX_BYTES];
    size_t total = 0;
    while (total < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + total, (size_t)st.st_size - total);
        if (n < 0) {
            (void)close(fd);
            return AUTHD_CFG_ERR_IO;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    (void)close(fd);
    return authd_config_parse(buf, total, out, err_line);
}
