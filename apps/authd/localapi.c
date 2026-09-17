#include "localapi.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "authd_conn.h"
#include "authd_log.h"
#include "conn_io.h"
#include "store.h"
#include "tokens.h"

/* ------------------------------------------------------------ the request */

typedef struct {
    const char *key;
    size_t      key_len;
    const char *val;
    size_t      val_len;
} kv_t;

typedef struct {
    char   cmd[24];
    kv_t   kv[LOCALAPI_MAX_KEYS];
    size_t n_kv;
} req_t;

/* Strict by construction: anything that is not exactly `CMD (SP key=value)*`
 * is refused. There is no tolerant mode, because the only client is a program
 * and a program that sends a malformed line has a bug worth surfacing. */
static int parse_request(const uint8_t *line, size_t len, req_t *r)
{
    memset(r, 0, sizeof *r);
    if (len == 0u) {
        return -1;
    }
    /* every byte must be printable ASCII: no NUL, no control smuggling */
    for (size_t i = 0; i < len; i++) {
        if (line[i] < 0x20u || line[i] > 0x7eu) {
            return -1;
        }
    }
    size_t i = 0;
    while (i < len && line[i] != ' ') {
        i++;
    }
    if (i == 0u || i >= sizeof r->cmd) {
        return -1;
    }
    memcpy(r->cmd, line, i);
    r->cmd[i] = '\0';

    while (i < len) {
        if (line[i] != ' ') {
            return -1;
        }
        while (i < len && line[i] == ' ') {
            i++;             /* tolerate runs of spaces between pairs */
        }
        if (i >= len) {
            break;
        }
        const size_t start = i;
        while (i < len && line[i] != ' ') {
            i++;
        }
        const size_t tok_len = i - start;
        const char *tok = (const char *)line + start;
        const char *eq = memchr(tok, '=', tok_len);
        if (eq == NULL || eq == tok) {
            return -1;                       /* no '=' or an empty key */
        }
        if (r->n_kv >= LOCALAPI_MAX_KEYS) {
            return -1;
        }
        const size_t klen = (size_t)(eq - tok);
        for (size_t j = 0; j < r->n_kv; j++) {
            if (r->kv[j].key_len == klen && memcmp(r->kv[j].key, tok, klen) == 0) {
                return -1;                   /* duplicate key */
            }
        }
        r->kv[r->n_kv].key = tok;
        r->kv[r->n_kv].key_len = klen;
        r->kv[r->n_kv].val = eq + 1;
        r->kv[r->n_kv].val_len = tok_len - klen - 1u;
        r->n_kv++;
    }
    return 0;
}

static const kv_t *kv_get(const req_t *r, const char *key)
{
    const size_t n = strlen(key);
    for (size_t i = 0; i < r->n_kv; i++) {
        if (r->kv[i].key_len == n && memcmp(r->kv[i].key, key, n) == 0) {
            return &r->kv[i];
        }
    }
    return NULL;
}

/* Rejects a request carrying a key this command does not define. Unknown keys
 * are malformed (spec 8) rather than ignored: silently dropping one would let
 * a caller believe an option took effect. */
static int keys_are_known(const req_t *r, const char *const *allowed, size_t n_allowed)
{
    for (size_t i = 0; i < r->n_kv; i++) {
        int ok = 0;
        for (size_t j = 0; j < n_allowed && !ok; j++) {
            const size_t n = strlen(allowed[j]);
            if (r->kv[i].key_len == n && memcmp(r->kv[i].key, allowed[j], n) == 0) {
                ok = 1;
            }
        }
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* Hex in, bytes out. `min_len == 0` allows an empty value, which exactly one
 * key needs: EXCHANGE's `state=`, because milestone A's tunnel listener binds
 * SHA-256("") (V4-8b decision 2). */
static int get_hex(const req_t *r, const char *key, uint8_t *out, size_t cap,
                   size_t *out_len, size_t min_len)
{
    const kv_t *kv = kv_get(r, key);
    if (kv == NULL) {
        return -1;
    }
    if (kv->val_len == 0u) {
        *out_len = 0u;
        return (min_len == 0u) ? 0 : -1;
    }
    if ((kv->val_len % 2u) != 0u || (kv->val_len / 2u) > cap) {
        return -1;
    }
    size_t bin_len = 0;
    if (sodium_hex2bin(out, cap, kv->val, kv->val_len, NULL, &bin_len, NULL) != 0) {
        return -1;
    }
    if (bin_len < min_len) {
        return -1;
    }
    *out_len = bin_len;
    return 0;
}

/* An identifier after hex-decoding: 1..64 bytes and printable, matching what
 * the log and the wire already accept. */
static int id_valid(const uint8_t *p, size_t n)
{
    if (n < 1u || n > STORE_ID_MAX) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (p[i] < 0x20u || p[i] > 0x7eu) {
            return 0;
        }
    }
    return 1;
}

/* ----------------------------------------------------------- the response */

typedef struct {
    char   buf[AUTHD_FRAME_MAX];
    size_t len;
    int    overflow;
} resp_t;

static void resp_init(resp_t *r) { r->len = 0u; r->overflow = 0; }

static void resp_add(resp_t *r, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static void resp_add(resp_t *r, const char *fmt, ...)
{
    if (r->overflow) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(r->buf + r->len, sizeof r->buf - r->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof r->buf - r->len) {
        r->overflow = 1;
        return;
    }
    r->len += (size_t)n;
}

static void resp_hex(resp_t *r, const uint8_t *p, size_t n)
{
    if (r->overflow) {
        return;
    }
    const size_t need = n * 2u + 1u;
    if (need > sizeof r->buf - r->len) {
        r->overflow = 1;
        return;
    }
    (void)sodium_bin2hex(r->buf + r->len, sizeof r->buf - r->len, p, n);
    r->len += n * 2u;
}

static ev_action_t send_resp(authd_slot_t *slot, resp_t *r)
{
    if (r->overflow || r->len == 0u) {
        static const char e[] = "ERR code=internal\n";
        (void)conn_io_queue(&slot->io, (const uint8_t *)e, sizeof e - 1u);
        return EV_ACTION_CONTINUE;
    }
    (void)conn_io_queue(&slot->io, (const uint8_t *)r->buf, r->len);
    return EV_ACTION_CONTINUE;
}

static ev_action_t send_err(authd_slot_t *slot, const char *code)
{
    resp_t r;
    resp_init(&r);
    resp_add(&r, "ERR code=%s\n", code);
    return send_resp(slot, &r);
}

/* ------------------------------------------------------------- handlers */

typedef ev_action_t (*handler_fn)(authd_app_t *app, authd_slot_t *slot, const req_t *req);

static ev_action_t h_ping(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "" };
    if (req->n_kv != 0u) { (void)allowed; return send_err(slot, "malformed"); }
    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK version=1 schema=%d uptime=%llu\n", STORE_SCHEMA_VERSION_PUBLIC,
             (unsigned long long)((app->now_ms - app->started_ms) / 1000u));
    return send_resp(slot, &r);
}

/* ENROLL / ENROLL-OPERATOR share everything but the role they create. */
static ev_action_t enroll_common(authd_app_t *app, authd_slot_t *slot, const req_t *req,
                                 store_role_t role)
{
    static const char *const allowed[] = { "user", "handle", "pk", "label", "via", "ticket" };
    if (!keys_are_known(req, allowed, sizeof allowed / sizeof allowed[0])) {
        return send_err(slot, "malformed");
    }
    uint8_t user[STORE_ID_MAX], handle[STORE_ID_MAX], pk[STORE_PK_BYTES], label[STORE_ID_MAX];
    size_t user_len = 0, handle_len = 0, pk_len = 0, label_len = 0;

    if (get_hex(req, "user", user, sizeof user, &user_len, 1u) != 0 || !id_valid(user, user_len) ||
        get_hex(req, "handle", handle, sizeof handle, &handle_len, 1u) != 0 || !id_valid(handle, handle_len) ||
        get_hex(req, "pk", pk, sizeof pk, &pk_len, STORE_PK_BYTES) != 0 || pk_len != STORE_PK_BYTES) {
        return send_err(slot, "malformed");
    }
    if (kv_get(req, "label") != NULL &&
        get_hex(req, "label", label, sizeof label, &label_len, 0u) != 0) {
        return send_err(slot, "malformed");
    }
    const kv_t *via = kv_get(req, "via");
    if (via == NULL) {
        return send_err(slot, "malformed");
    }
    if (via->val_len == 8u && memcmp(via->val, "recovery", 8) == 0) {
        /* V4-9c. Refusing is honest and mutation-visible; a stub that enrolled
         * without a valid ticket would be a hole. */
        return send_err(slot, "not-permitted");
    }
    if (!(via->val_len == 4u && memcmp(via->val, "site", 4) == 0)) {
        return send_err(slot, "malformed");
    }

    /* The user: created on first enrollment (the site is the trusted enroller,
     * spec 10.1), but never silently re-roled. */
    store_role_t existing = role;
    char status[16] = {0};
    const store_status_t us = store_get_user(app->store, user, user_len, &existing, status, sizeof status);
    if (us == STORE_ERR_NOT_FOUND) {
        if (store_add_user(app->store, user, user_len, role) != STORE_OK) {
            return send_err(slot, "internal");
        }
    } else if (us != STORE_OK) {
        return send_err(slot, "internal");
    } else {
        if (existing != role) {
            return send_err(slot, "role-mismatch");
        }
        if (strcmp(status, "active") != 0) {
            return send_err(slot, "user-disabled");
        }
    }

    /* Distinguish a byte-identical re-enrollment (idempotent) from the Req 7
     * case (a known handle presenting a DIFFERENT key) before touching the
     * store, because store_enroll_device reports both as a conflict. */
    int idempotent = 0;
    uint8_t cur[STORE_PK_BYTES];
    if (store_lookup_active(app->store, handle, handle_len, cur, NULL, 0, NULL, NULL) == STORE_OK) {
        if (sodium_memcmp(cur, pk, STORE_PK_BYTES) == 0) {
            idempotent = 1;
        } else {
            /* Req 7: rejected AND logged, with both fingerprints. */
            uint8_t fp_old[crypto_hash_sha256_BYTES], fp_new[crypto_hash_sha256_BYTES];
            crypto_hash_sha256(fp_old, cur, STORE_PK_BYTES);
            crypto_hash_sha256(fp_new, pk, STORE_PK_BYTES);
            authd_log_slot_id(AUTHD_LOG_WARN, "enroll-key-mismatch", slot->index, handle, handle_len);
            authd_log_fp(AUTHD_LOG_WARN, "enroll-key-mismatch-old", fp_old);
            authd_log_fp(AUTHD_LOG_WARN, "enroll-key-mismatch-new", fp_new);
            return send_err(slot, "exists-different-key");
        }
    }

    if (!idempotent) {
        const store_status_t es = store_enroll_device(app->store, handle, handle_len,
                                                      user, user_len, pk, "site", "local-api",
                                                      (label_len > 0u) ? label : NULL, label_len);
        if (es == STORE_ERR_CONFLICT) {
            return send_err(slot, "pk-in-use");
        }
        if (es != STORE_OK) {
            return send_err(slot, "internal");
        }
    }

    uint8_t fp[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(fp, pk, sizeof pk);
    authd_log_slot_id(AUTHD_LOG_INFO, idempotent ? "enroll-idempotent" : "enroll", slot->index,
                      handle, handle_len);
    authd_log_fp(AUTHD_LOG_INFO, "enroll-fp", fp);

    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK fp=");
    resp_hex(&r, fp, sizeof fp);
    if (idempotent) {
        resp_add(&r, " idempotent=1");
    }
    resp_add(&r, "\n");
    sodium_memzero(pk, sizeof pk);
    return send_resp(slot, &r);
}

static ev_action_t h_enroll(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    return enroll_common(app, slot, req, STORE_ROLE_USER);
}

static ev_action_t h_enroll_operator(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    return enroll_common(app, slot, req, STORE_ROLE_OPERATOR);
}

static ev_action_t h_exchange(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "code", "state" };
    if (!keys_are_known(req, allowed, 2u)) {
        return send_err(slot, "malformed");
    }
    uint8_t code[64], state[256];
    size_t code_len = 0, state_len = 0;
    if (get_hex(req, "code", code, sizeof code, &code_len, 32u) != 0 || code_len != 32u) {
        return send_err(slot, "malformed");
    }
    if (kv_get(req, "state") == NULL ||
        get_hex(req, "state", state, sizeof state, &state_len, 0u) != 0) {
        return send_err(slot, "malformed");
    }

    uint8_t code_hash[STORE_HASH_BYTES], state_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(code_hash, code, code_len);
    crypto_hash_sha256(state_hash, state, state_len);
    sodium_memzero(code, sizeof code);

    uint8_t user[STORE_ID_MAX], handle[STORE_ID_MAX];
    size_t user_len = 0, handle_len = 0;
    store_code_verdict_t v = STORE_CODE_UNKNOWN;
    if (store_consume_login_code_ex(app->store, code_hash, state_hash, app->now_unix, &v,
                                    user, sizeof user, &user_len,
                                    handle, sizeof handle, &handle_len) != STORE_OK) {
        sodium_memzero(code_hash, sizeof code_hash);
        return send_err(slot, "internal");
    }
    sodium_memzero(code_hash, sizeof code_hash);
    sodium_memzero(state_hash, sizeof state_hash);

    switch (v) {
    case STORE_CODE_OK:             break;
    case STORE_CODE_EXPIRED:        return send_err(slot, "expired");
    case STORE_CODE_USED:           return send_err(slot, "used");
    case STORE_CODE_STATE_MISMATCH: return send_err(slot, "state-mismatch");
    default:                        return send_err(slot, "unknown");
    }

    store_role_t role = STORE_ROLE_USER;
    (void)store_get_user(app->store, user, user_len, &role, NULL, 0u);

    uint8_t token[TOKEN_BYTES];
    int64_t issued = 0, expires = 0;
    if (tokens_issue(app->store, role, user, user_len, handle, handle_len, NULL, 0,
                     app->now_unix, token, &issued, &expires) != STORE_OK) {
        return send_err(slot, "internal");
    }

    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK token=");
    resp_hex(&r, token, sizeof token);
    sodium_memzero(token, sizeof token);      /* the plaintext lives only in the reply now */
    resp_add(&r, " user=");
    resp_hex(&r, user, user_len);
    resp_add(&r, " handle=");
    resp_hex(&r, handle, handle_len);
    resp_add(&r, " role=%s issued=%lld expires=%lld\n",
             (role == STORE_ROLE_OPERATOR) ? "operator" : "user",
             (long long)issued, (long long)expires);
    authd_log_slot_id(AUTHD_LOG_INFO, "exchange", slot->index, handle, handle_len);
    return send_resp(slot, &r);
}

static ev_action_t h_verify(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "token" };
    if (!keys_are_known(req, allowed, 1u)) {
        return send_err(slot, "malformed");
    }
    uint8_t token[64];
    size_t token_len = 0;
    if (get_hex(req, "token", token, sizeof token, &token_len, TOKEN_BYTES) != 0 ||
        token_len != TOKEN_BYTES) {
        return send_err(slot, "malformed");
    }
    uint8_t token_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(token_hash, token, token_len);
    sodium_memzero(token, sizeof token);

    /* Peek the role first so the idle window slides by the ROLE's interval. */
    store_token_verdict_t v = STORE_TOKEN_UNKNOWN;
    store_token_info_t info;
    if (store_verify_token(app->store, token_hash, app->now_unix, 0u, &v, &info) != STORE_OK) {
        sodium_memzero(token_hash, sizeof token_hash);
        return send_err(slot, "internal");
    }
    if (v == STORE_TOKEN_OK) {
        (void)store_verify_token(app->store, token_hash, app->now_unix,
                                 tokens_idle_ttl_s(info.role), &v, &info);
    }
    sodium_memzero(token_hash, sizeof token_hash);

    switch (v) {
    case STORE_TOKEN_OK:             break;
    case STORE_TOKEN_EXPIRED:        return send_err(slot, "expired");
    case STORE_TOKEN_IDLE_EXPIRED:   return send_err(slot, "idle-expired");
    case STORE_TOKEN_DEVICE_REVOKED: return send_err(slot, "device-revoked");
    case STORE_TOKEN_USER_DISABLED:  return send_err(slot, "user-disabled");
    default:                         return send_err(slot, "unknown");
    }

    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK user=");
    resp_hex(&r, info.user_id, info.user_id_len);
    resp_add(&r, " handle=");
    resp_hex(&r, info.handle, info.handle_len);
    resp_add(&r, " role=%s issued=%lld expires=%lld\n",
             (info.role == STORE_ROLE_OPERATOR) ? "operator" : "user",
             (long long)info.issued_at, (long long)info.expires_at);
    return send_resp(slot, &r);
}

static ev_action_t h_logout(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "token" };
    if (!keys_are_known(req, allowed, 1u)) {
        return send_err(slot, "malformed");
    }
    uint8_t token[64];
    size_t token_len = 0;
    if (get_hex(req, "token", token, sizeof token, &token_len, TOKEN_BYTES) != 0 ||
        token_len != TOKEN_BYTES) {
        return send_err(slot, "malformed");
    }
    uint8_t token_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(token_hash, token, token_len);
    sodium_memzero(token, sizeof token);

    size_t n = 0;
    const store_status_t s = store_delete_token(app->store, token_hash, &n);
    sodium_memzero(token_hash, sizeof token_hash);
    if (s != STORE_OK) {
        return send_err(slot, "internal");
    }
    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK deleted=%zu\n", n);
    return send_resp(slot, &r);
}

static ev_action_t h_revoke_tokens(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "user", "handle" };
    if (!keys_are_known(req, allowed, 2u)) {
        return send_err(slot, "malformed");
    }
    uint8_t user[STORE_ID_MAX], handle[STORE_ID_MAX];
    size_t user_len = 0, handle_len = 0;
    if (get_hex(req, "user", user, sizeof user, &user_len, 1u) != 0 || !id_valid(user, user_len)) {
        return send_err(slot, "malformed");
    }
    size_t n = 0;
    store_status_t s;
    if (kv_get(req, "handle") != NULL) {
        if (get_hex(req, "handle", handle, sizeof handle, &handle_len, 1u) != 0 ||
            !id_valid(handle, handle_len)) {
            return send_err(slot, "malformed");
        }
        s = store_delete_tokens_for_handle(app->store, handle, handle_len, &n);
    } else {
        s = store_delete_tokens_for_user(app->store, user, user_len, &n);
    }
    if (s != STORE_OK) {
        return send_err(slot, "internal");
    }
    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK count=%zu\n", n);
    return send_resp(slot, &r);
}

static ev_action_t h_revoke_device(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "handle", "reason" };
    if (!keys_are_known(req, allowed, 2u)) {
        return send_err(slot, "malformed");
    }
    uint8_t handle[STORE_ID_MAX], reason[256];
    size_t handle_len = 0, reason_len = 0;
    if (get_hex(req, "handle", handle, sizeof handle, &handle_len, 1u) != 0 ||
        !id_valid(handle, handle_len)) {
        return send_err(slot, "malformed");
    }
    if (kv_get(req, "reason") != NULL &&
        get_hex(req, "reason", reason, sizeof reason, &reason_len, 0u) != 0) {
        return send_err(slot, "malformed");
    }
    const store_status_t s = store_revoke_device(app->store, handle, handle_len, "local-api",
                                                 (reason_len > 0u) ? reason : NULL, reason_len);
    if (s == STORE_ERR_NOT_FOUND) {
        return send_err(slot, "unknown");
    }
    if (s != STORE_OK) {
        return send_err(slot, "internal");
    }
    /* Req 9: the live connections go too, not just the rows. */
    const size_t closed = authd_app_close_handle(app, handle, handle_len);
    authd_log_slot_id(AUTHD_LOG_WARN, "device-revoked", slot->index, handle, handle_len);
    authd_log_num(AUTHD_LOG_INFO, "device-revoked", "closed", (uint64_t)closed);

    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK\n");
    return send_resp(slot, &r);
}

static ev_action_t set_user_status(authd_app_t *app, authd_slot_t *slot, const req_t *req, int disable)
{
    static const char *const allowed[] = { "user", "reason" };
    if (!keys_are_known(req, allowed, disable ? 2u : 1u)) {
        return send_err(slot, "malformed");
    }
    uint8_t user[STORE_ID_MAX], reason[256];
    size_t user_len = 0, reason_len = 0;
    if (get_hex(req, "user", user, sizeof user, &user_len, 1u) != 0 || !id_valid(user, user_len)) {
        return send_err(slot, "malformed");
    }
    if (disable && kv_get(req, "reason") != NULL &&
        get_hex(req, "reason", reason, sizeof reason, &reason_len, 0u) != 0) {
        return send_err(slot, "malformed");
    }
    const store_status_t s = disable
        ? store_disable_user(app->store, user, user_len, "local-api",
                             (reason_len > 0u) ? reason : NULL, reason_len)
        : store_enable_user(app->store, user, user_len, "local-api");
    if (s == STORE_ERR_NOT_FOUND) {
        return send_err(slot, "unknown");
    }
    if (s != STORE_OK) {
        return send_err(slot, "internal");
    }
    if (disable) {
        const size_t closed = authd_app_close_user(app, user, user_len);
        authd_log_num(AUTHD_LOG_WARN, "user-disabled", "closed", (uint64_t)closed);
    }
    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK\n");
    return send_resp(slot, &r);
}

static ev_action_t h_disable_user(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{ return set_user_status(app, slot, req, 1); }
static ev_action_t h_enable_user(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{ return set_user_status(app, slot, req, 0); }

/* --- list responses ------------------------------------------------------ */

typedef struct {
    resp_t *r;
    size_t  n;
    int     too_many;
} list_ctx_t;

static int on_device(void *ctx, const uint8_t *handle, size_t handle_len,
                     const uint8_t *label, size_t label_len, const char *status,
                     int64_t enrolled_at, int64_t last_seen,
                     const uint8_t *pk_fp, size_t pk_fp_len)
{
    list_ctx_t *c = (list_ctx_t *)ctx;
    if (c->n >= AUTHD_LIST_MAX) { c->too_many = 1; return 1; }
    resp_add(c->r, "DEVICE handle=");
    resp_hex(c->r, handle, handle_len);
    resp_add(c->r, " label=");
    resp_hex(c->r, label, label_len);
    resp_add(c->r, " status=%s enrolled=%lld last_seen=%lld fp=",
             (status != NULL) ? status : "?", (long long)enrolled_at, (long long)last_seen);
    resp_hex(c->r, pk_fp, pk_fp_len);
    resp_add(c->r, "\n");
    c->n++;
    return c->r->overflow ? 1 : 0;
}

static int on_user(void *ctx, const uint8_t *user_id, size_t user_id_len,
                   store_role_t role, const char *status, int64_t created_at)
{
    list_ctx_t *c = (list_ctx_t *)ctx;
    if (c->n >= AUTHD_LIST_MAX) { c->too_many = 1; return 1; }
    resp_add(c->r, "USER user=");
    resp_hex(c->r, user_id, user_id_len);
    resp_add(c->r, " role=%s status=%s created=%lld\n",
             (role == STORE_ROLE_OPERATOR) ? "operator" : "user",
             (status != NULL) ? status : "?", (long long)created_at);
    c->n++;
    return c->r->overflow ? 1 : 0;
}

static int on_audit(void *ctx, int64_t seq, int64_t at, const char *event,
                    const uint8_t *user_id, size_t user_id_len,
                    const uint8_t *handle, size_t handle_len, const char *detail)
{
    list_ctx_t *c = (list_ctx_t *)ctx;
    if (c->n >= AUTHD_LIST_MAX) { c->too_many = 1; return 1; }
    resp_add(c->r, "AUDIT seq=%lld at=%lld event=%s user=", (long long)seq, (long long)at,
             (event != NULL) ? event : "?");
    resp_hex(c->r, user_id, user_id_len);
    resp_add(c->r, " handle=");
    resp_hex(c->r, handle, handle_len);
    resp_add(c->r, " detail=%s\n", (detail != NULL) ? detail : "");
    c->n++;
    return c->r->overflow ? 1 : 0;
}

/* A list is built into one buffer and sent as one reply, so the item body is
 * built first and the `OK count=` header prepended once the count is known. */
static ev_action_t finish_list(authd_slot_t *slot, resp_t *body, list_ctx_t *c)
{
    if (c->too_many) {
        return send_err(slot, "too-many");
    }
    resp_t out;
    resp_init(&out);
    resp_add(&out, "OK count=%zu\n", c->n);
    if (out.overflow || body->overflow || body->len > sizeof out.buf - out.len - 5u) {
        return send_err(slot, "too-many");
    }
    memcpy(out.buf + out.len, body->buf, body->len);
    out.len += body->len;
    resp_add(&out, "END\n");
    return send_resp(slot, &out);
}

static ev_action_t h_list_devices(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "user" };
    if (!keys_are_known(req, allowed, 1u)) {
        return send_err(slot, "malformed");
    }
    uint8_t user[STORE_ID_MAX];
    size_t user_len = 0;
    if (get_hex(req, "user", user, sizeof user, &user_len, 1u) != 0 || !id_valid(user, user_len)) {
        return send_err(slot, "malformed");
    }
    resp_t body;
    resp_init(&body);
    list_ctx_t c = { &body, 0u, 0 };
    if (store_list_devices(app->store, user, user_len, on_device, &c) != STORE_OK) {
        return send_err(slot, "internal");
    }
    return finish_list(slot, &body, &c);
}

static ev_action_t h_list_users(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    if (req->n_kv != 0u) {
        return send_err(slot, "malformed");
    }
    resp_t body;
    resp_init(&body);
    list_ctx_t c = { &body, 0u, 0 };
    if (store_list_users(app->store, on_user, &c) != STORE_OK) {
        return send_err(slot, "internal");
    }
    return finish_list(slot, &body, &c);
}

static ev_action_t h_audit_tail(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "n" };
    if (!keys_are_known(req, allowed, 1u)) {
        return send_err(slot, "malformed");
    }
    const kv_t *kv = kv_get(req, "n");
    if (kv == NULL || kv->val_len == 0u || kv->val_len > 4u) {
        return send_err(slot, "malformed");
    }
    size_t n = 0;
    for (size_t i = 0; i < kv->val_len; i++) {
        if (kv->val[i] < '0' || kv->val[i] > '9') {
            return send_err(slot, "malformed");
        }
        n = n * 10u + (size_t)(kv->val[i] - '0');
    }
    if (n == 0u || n > AUTHD_LIST_MAX) {
        return send_err(slot, "malformed");
    }
    resp_t body;
    resp_init(&body);
    list_ctx_t c = { &body, 0u, 0 };
    if (store_audit_tail(app->store, n, on_audit, &c) != STORE_OK) {
        return send_err(slot, "internal");
    }
    return finish_list(slot, &body, &c);
}

static ev_action_t h_backup(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    static const char *const allowed[] = { "path" };
    if (!keys_are_known(req, allowed, 1u)) {
        return send_err(slot, "malformed");
    }
    uint8_t path[512];
    size_t path_len = 0;
    if (get_hex(req, "path", path, sizeof path - 1u, &path_len, 1u) != 0) {
        return send_err(slot, "malformed");
    }
    for (size_t i = 0; i < path_len; i++) {
        if (path[i] < 0x20u || path[i] > 0x7eu) {
            return send_err(slot, "malformed");
        }
    }
    path[path_len] = 0;
    if (store_backup(app->store, (const char *)path) != STORE_OK) {
        return send_err(slot, "internal");
    }
    resp_t r;
    resp_init(&r);
    resp_add(&r, "OK\n");
    return send_resp(slot, &r);
}

static ev_action_t h_recovery_later(authd_app_t *app, authd_slot_t *slot, const req_t *req)
{
    (void)app; (void)req;
    return send_err(slot, "not-permitted");   /* V4-9c */
}

/* --------------------------------------------------------------- dispatch */

typedef struct {
    const char *cmd;
    handler_fn  fn;
} entry_t;

/* Two tables. An admin command is ABSENT from the site table, not refused by
 * a flag inside a shared one -- Req 11 by construction (spec 8). */
static const entry_t SITE_TABLE[] = {
    { "PING",            h_ping },
    { "ENROLL",          h_enroll },
    { "EXCHANGE",        h_exchange },
    { "VERIFY",          h_verify },
    { "LOGOUT",          h_logout },
    { "REVOKE-TOKENS",   h_revoke_tokens },
    { "REVOKE-DEVICE",   h_revoke_device },
    { "LIST-DEVICES",    h_list_devices },
    { "RECOVERY-ISSUE",  h_recovery_later },
    { "RECOVERY-USE",    h_recovery_later },
};

static const entry_t ADMIN_TABLE[] = {
    { "PING",            h_ping },
    { "ENROLL",          h_enroll },
    { "EXCHANGE",        h_exchange },
    { "VERIFY",          h_verify },
    { "LOGOUT",          h_logout },
    { "REVOKE-TOKENS",   h_revoke_tokens },
    { "REVOKE-DEVICE",   h_revoke_device },
    { "LIST-DEVICES",    h_list_devices },
    { "RECOVERY-ISSUE",  h_recovery_later },
    { "RECOVERY-USE",    h_recovery_later },
    { "ENROLL-OPERATOR", h_enroll_operator },
    { "DISABLE-USER",    h_disable_user },
    { "ENABLE-USER",     h_enable_user },
    { "LIST-USERS",      h_list_users },
    { "AUDIT-TAIL",      h_audit_tail },
    { "BACKUP",          h_backup },
};

ev_action_t localapi_on_line(void *user, authd_slot_t *slot, const uint8_t *line, size_t len)
{
    authd_app_t *app = (authd_app_t *)user;
    if (app == NULL || slot == NULL || line == NULL) {
        return EV_ACTION_CLOSE;
    }

    req_t req;
    if (parse_request(line, len, &req) != 0) {
        /* The COMMAND is not logged here: a malformed line is attacker-shaped
         * and echoing any of it into the journal is how log injection starts. */
        authd_log_local(AUTHD_LOG_WARN, "local-request", "?", slot->peer.uid, slot->peer.pid, "malformed");
        return send_err(slot, "malformed");
    }

    const entry_t *table = slot->is_admin ? ADMIN_TABLE : SITE_TABLE;
    const size_t n = slot->is_admin ? (sizeof ADMIN_TABLE / sizeof ADMIN_TABLE[0])
                                    : (sizeof SITE_TABLE / sizeof SITE_TABLE[0]);

    /* Spec 8: every request is logged with the peer's uid and pid. The VALUES
     * never are -- a token or a login code would reach the journal. */
    authd_log_local(AUTHD_LOG_INFO, "local-request", req.cmd, slot->peer.uid, slot->peer.pid,
                    slot->is_admin ? "admin" : "site");

    for (size_t i = 0; i < n; i++) {
        if (strcmp(req.cmd, table[i].cmd) == 0) {
            return table[i].fn(app, slot, &req);
        }
    }
    /* Either genuinely unknown, or an admin command on the site socket. Both
     * answer the same thing, so the site socket does not become an oracle for
     * which administrative commands exist. */
    return send_err(slot, "not-permitted");
}
