#include "authd_conn.h"

#include <string.h>

#include <sodium.h>

#include "authd_log.h"
#include "authmsg.h"
#include "conn_io.h"
#include "transcript.h"

const char *authd_conn_stage_name(conn_stage_t s)
{
    switch (s) {
    case CONN_STAGE_FREE:     return "free";
    case CONN_STAGE_AWAIT_CH: return "await-client-hello";
    case CONN_STAGE_AWAIT_CA: return "await-client-auth";
    case CONN_STAGE_SERVING:  return "serving";
    case CONN_STAGE_CLOSING:  return "closing";
    default:                  return "unknown";
    }
}

uint64_t authd_app_clock(void *ctx)
{
    const authd_app_t *app = (const authd_app_t *)ctx;
    return (app != NULL) ? app->now_ms : 0u;
}

static authd_conn_t *conn_of(authd_app_t *app, authd_slot_t *slot)
{
    if (app == NULL || slot == NULL || slot->index >= app->n_conns) {
        return NULL;
    }
    return &app->conns[slot->index];
}

/* Wipes every secret a connection can be holding. Ordered so nothing is
 * observable afterwards: the session first (it owns the traffic keys), then
 * the handshake (which cancels a still-live ledger entry -- see
 * handshake_ctx_wipe's contract), then the scratch pin and the identifiers. */
static void conn_reset(authd_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    session_wipe(&c->sess);
    if (c->hs_live) {
        handshake_ctx_wipe(&c->hs);
        c->hs_live = 0;
    }
    keystore_wipe(&c->ks);
    sodium_memzero(c->handle, sizeof c->handle);
    sodium_memzero(c->user_id, sizeof c->user_id);
    c->handle_len = 0;
    c->user_id_len = 0;
    c->decoy = 0;
    c->stage = CONN_STAGE_FREE;
}

void authd_conn_bind(authd_app_t *app, authd_slot_t *slot)
{
    authd_conn_t *c = conn_of(app, slot);
    if (c == NULL) {
        return;
    }
    conn_reset(c);
    memset(&c->sess, 0, sizeof c->sess);
    keystore_init(&c->ks);
    c->stage = CONN_STAGE_AWAIT_CH;
    slot->user = c;
}

void authd_conn_on_close(void *user, authd_slot_t *slot)
{
    authd_app_t *app = (authd_app_t *)user;
    authd_conn_t *c = conn_of(app, slot);
    if (c != NULL) {
        conn_reset(c);
    }
    if (slot != NULL) {
        slot->user = NULL;
    }
}

/* Seals `content` into one record and queues it as this slot's reply.
 * Returns 0 on success. The record buffer is a local, not per-slot state:
 * it exists only for the duration of the call. */
static int queue_sealed(authd_slot_t *slot, session_t *sess, const uint8_t *content, size_t content_len)
{
    uint8_t rec[AUTHD_MAX_RECORD];
    size_t rec_len = 0;
    const session_status_t ss = session_seal(sess, content, content_len, rec, sizeof rec, &rec_len);
    if (ss != SESSION_OK) {
        sodium_memzero(rec, sizeof rec);
        return -1;
    }
    const conn_io_status_t cs = conn_io_queue(&slot->io, rec, rec_len);
    sodium_memzero(rec, sizeof rec);
    return (cs == CONN_IO_OK) ? 0 : -1;
}

/* Seals an ERROR and asks the loop to close once it has gone out. */
static ev_action_t fail_with_error(authd_slot_t *slot, authd_conn_t *c, uint8_t code, const char *why)
{
    uint8_t content[AUTHMSG_ERROR_CONTENT_LEN];
    size_t n = 0;
    if (authmsg_encode_error(content, sizeof content, &n, code) == AUTHMSG_OK) {
        (void)queue_sealed(slot, &c->sess, content, n);
    }
    authd_log_slot_detail(AUTHD_LOG_INFO, "record-refused", slot->index, why);
    c->stage = CONN_STAGE_CLOSING;
    return EV_ACTION_CLOSE;
}

/* --- AWAIT_CH ------------------------------------------------------------ */

static ev_action_t on_client_hello(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c,
                                   const uint8_t *payload, size_t len)
{
    /* Peek the claimed identity. This decode is advisory: the library decodes
     * the same bytes again, strictly, inside accept_client_hello(). */
    client_hello_t ch;
    size_t consumed = 0;
    if (decode_client_hello(payload, len, &ch, &consumed) != 0) {
        authd_log_slot(AUTHD_LOG_INFO, "client-hello-malformed", slot->index);
        app->handshakes_failed++;
        return EV_ACTION_CLOSE;   /* no session exists yet: nothing to reply with */
    }

    /* Resolve the pin. Every not-active outcome -- unknown, revoked,
     * superseded, disabled -- lands in the same branch and gets the decoy. */
    uint8_t pk[STORE_PK_BYTES];
    store_status_t st = store_lookup_active(app->store, ch.id, ch.id_len, pk,
                                            c->user_id, sizeof c->user_id, &c->user_id_len, NULL);
    if (st == STORE_OK) {
        c->decoy = 0;
    } else {
        if (store_get_decoy_pk(app->store, pk) != STORE_OK) {
            authd_log_slot(AUTHD_LOG_ERROR, "decoy-unavailable", slot->index);
            return EV_ACTION_CLOSE;
        }
        c->decoy = 1;
        c->user_id_len = 0;
        app->decoy_pins++;
    }
    memcpy(c->handle, ch.id, ch.id_len);
    c->handle_len = ch.id_len;
    /* Identities are logged (they are not secret); the field is escaped and
     * truncated by authd_log_slot_id. The decoy branch is NOT distinguished
     * in the log -- that would reopen the channel this whole flow closes. */
    authd_log_slot_id(AUTHD_LOG_INFO, "client-hello", slot->index, ch.id, ch.id_len);
    sodium_memzero(&ch, sizeof ch);

    keystore_init(&c->ks);
    if (keystore_add(&c->ks, c->handle, c->handle_len, pk) != KEYSTORE_OK) {
        sodium_memzero(pk, sizeof pk);
        authd_log_slot(AUTHD_LOG_ERROR, "pin-failed", slot->index);
        return EV_ACTION_CLOSE;
    }
    sodium_memzero(pk, sizeof pk);

    if (handshake_responder_init(&c->hs, app->server_id, app->server_id_len,
                                 app->server_kp, &c->ks, app->pending) != HANDSHAKE_OK) {
        authd_log_slot(AUTHD_LOG_ERROR, "responder-init-failed", slot->index);
        return EV_ACTION_CLOSE;
    }
    c->hs_live = 1;

    handshake_status_t hst = handshake_responder_accept_client_hello(&c->hs, payload, len);
    if (hst != HANDSHAKE_OK) {
        /* With the decoy pinned this can no longer be UNKNOWN_IDENTITY. */
        authd_log_slot(AUTHD_LOG_INFO, "client-hello-rejected", slot->index);
        app->handshakes_failed++;
        return EV_ACTION_CLOSE;
    }

    uint8_t sh[AUTHD_FRAME_MAX];
    size_t sh_len = 0;
    hst = handshake_responder_create_server_hello(&c->hs, sh, sizeof sh, &sh_len);
    if (hst != HANDSHAKE_OK) {
        sodium_memzero(sh, sizeof sh);
        /* RESOURCE_EXHAUSTED here is the pending ledger at capacity -- a real
         * operating condition, not a peer error, so it is logged as such. */
        authd_log_slot_detail(AUTHD_LOG_WARN, "server-hello-failed", slot->index,
                              (hst == HANDSHAKE_ERR_RESOURCE_EXHAUSTED) ? "ledger-full" : "kex");
        app->handshakes_failed++;
        return EV_ACTION_CLOSE;
    }
    const conn_io_status_t cs = conn_io_queue(&slot->io, sh, sh_len);
    sodium_memzero(sh, sizeof sh);
    if (cs != CONN_IO_OK) {
        return EV_ACTION_CLOSE;
    }
    c->stage = CONN_STAGE_AWAIT_CA;
    return EV_ACTION_CONTINUE;
}

/* --- AWAIT_CA ------------------------------------------------------------ */

/* Issues the login code as the session's FIRST record. spec-v2 6.4.4 allows
 * the responder's confirmation record to carry content, and spec 6.2 makes it
 * this message -- so confirmation and the login code are one record, not two. */
static int issue_login_code(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c)
{
    uint8_t hsid[WIRE_HANDSHAKE_ID_LEN];
    if (handshake_get_handshake_id(&c->hs, hsid) != HANDSHAKE_OK) {
        return -1;
    }

    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = app->pad_bucket;
    if (session_init_from_handshake(&c->sess, &c->hs, &lim, authd_app_clock, app) != SESSION_OK) {
        sodium_memzero(hsid, sizeof hsid);
        return -1;
    }
    /* session_init consumed (wiped) the handshake context. */
    c->hs_live = 0;

    authmsg_login_code_t m;
    memset(&m, 0, sizeof m);
    m.flags = 0u;                                   /* rotation_due is V4-9 policy */
    randombytes_buf(m.code, sizeof m.code);
    m.code_expires = (uint64_t)(app->now_unix + (int64_t)app->code_ttl_s);

    /* Req 4: the store never sees the code, only its SHA-256. Req 5: it is
     * bound to {user, handle, handshake_id, SHA-256(state)}. On the raw
     * listener `state` is the empty string (V4-8b decision 2); V4-10 gives
     * the WebSocket listener a real one from the URL. */
    uint8_t code_hash[STORE_HASH_BYTES];
    uint8_t state_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(code_hash, m.code, sizeof m.code);
    crypto_hash_sha256(state_hash, (const uint8_t *)"", 0u);

    int rc = -1;
    if (store_add_login_code(app->store, code_hash,
                             c->user_id, c->user_id_len,
                             c->handle, c->handle_len,
                             hsid, sizeof hsid,
                             state_hash,
                             app->now_unix, (int64_t)m.code_expires) == STORE_OK) {
        uint8_t content[AUTHMSG_LOGIN_CODE_CONTENT_LEN];
        size_t n = 0;
        if (authmsg_encode_login_code(content, sizeof content, &n, &m) == AUTHMSG_OK &&
            queue_sealed(slot, &c->sess, content, n) == 0) {
            rc = 0;
        }
        sodium_memzero(content, sizeof content);
    }

    sodium_memzero(&m, sizeof m);          /* the code exists nowhere else now */
    sodium_memzero(code_hash, sizeof code_hash);
    sodium_memzero(state_hash, sizeof state_hash);
    sodium_memzero(hsid, sizeof hsid);
    return rc;
}

static ev_action_t on_client_auth(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c,
                                  const uint8_t *payload, size_t len)
{
    const handshake_status_t hst = handshake_responder_verify_client_auth(&c->hs, payload, len);

    if (hst != HANDSHAKE_OK) {
        /* The library's retry semantics, honoured rather than reinterpreted:
         * these three leave the context and the ledger entry usable, so the
         * handshake is still live and the peer may try again. Everything else
         * is terminal. A decoy connection always ends here, which is exactly
         * what makes it indistinguishable from a wrong signature. */
        const int retryable = (hst == HANDSHAKE_ERR_MALFORMED ||
                               hst == HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH ||
                               hst == HANDSHAKE_ERR_SIGNATURE);
        if (retryable) {
            authd_log_slot(AUTHD_LOG_INFO, "client-auth-retryable", slot->index);
            return EV_ACTION_CONTINUE;
        }
        authd_log_slot(AUTHD_LOG_INFO, "client-auth-failed", slot->index);
        app->handshakes_failed++;
        return EV_ACTION_CLOSE;
    }

    if (handshake_responder_finish(&c->hs) != HANDSHAKE_OK || !handshake_is_peer_confirmed(&c->hs)) {
        app->handshakes_failed++;
        return EV_ACTION_CLOSE;
    }

    /* Defence in depth: a decoy connection cannot reach here (its secret was
     * discarded, so no valid sig_A exists), but if it ever did, no code. */
    if (c->decoy || c->user_id_len == 0u) {
        authd_log_slot(AUTHD_LOG_ERROR, "authenticated-without-identity", slot->index);
        return EV_ACTION_CLOSE;
    }

    if (issue_login_code(app, slot, c) != 0) {
        authd_log_slot(AUTHD_LOG_ERROR, "login-code-failed", slot->index);
        return EV_ACTION_CLOSE;
    }
    (void)store_touch_last_seen(app->store, c->handle, c->handle_len);

    app->logins_issued++;
    authd_log_slot_id(AUTHD_LOG_INFO, "login-code-issued", slot->index, c->handle, c->handle_len);
    c->stage = CONN_STAGE_SERVING;
    return EV_ACTION_CONTINUE;
}

/* --- SERVING -------------------------------------------------------------- */

static ev_action_t on_record(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c,
                             const uint8_t *payload, size_t len)
{
    (void)app;
    if (len > AUTHD_MAX_RECORD) {
        return fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "record-over-cap");
    }
    uint8_t pt[AUTHD_MAX_RECORD];
    size_t pt_len = 0;
    const session_status_t ss = session_open(&c->sess, payload, len, pt, sizeof pt, &pt_len);
    if (ss != SESSION_OK) {
        /* Every session_open failure worth naming is terminal, and the session
         * is already dead -- so there is nothing left to seal an ERROR with. */
        sodium_memzero(pt, sizeof pt);
        authd_log_slot(AUTHD_LOG_INFO, "record-rejected", slot->index);
        c->stage = CONN_STAGE_CLOSING;
        return EV_ACTION_CLOSE;
    }

    uint8_t op = 0;
    const authmsg_status_t as = authmsg_peek_op(pt, pt_len, &op);
    sodium_memzero(pt, sizeof pt);
    if (as != AUTHMSG_OK) {
        return fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "empty-content");
    }
    if (op == AUTHMSG_OP_BYE) {
        if (pt_len != AUTHMSG_BYE_CONTENT_LEN) {
            return fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "bye-bad-length");
        }
        authd_log_slot(AUTHD_LOG_INFO, "bye", slot->index);
        c->stage = CONN_STAGE_CLOSING;
        return EV_ACTION_CLOSE;
    }
    /* ROTATE is V4-9's. Refusing it as "not permitted in this state" is the
     * honest answer; serving a half-implemented rotation would be worse. */
    return fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED,
                           (op == AUTHMSG_OP_ROTATE) ? "rotate-not-implemented" : "op-not-permitted");
}

/* --- dispatch ------------------------------------------------------------- */

ev_action_t authd_conn_on_frame(void *user, authd_slot_t *slot, const uint8_t *payload, size_t len)
{
    authd_app_t *app = (authd_app_t *)user;
    authd_conn_t *c = conn_of(app, slot);
    if (c == NULL || payload == NULL) {
        return EV_ACTION_CLOSE;
    }
    if (slot->user != c || c->stage == CONN_STAGE_FREE) {
        authd_conn_bind(app, slot);   /* first frame on a freshly accepted slot */
    }

    switch (c->stage) {
    case CONN_STAGE_AWAIT_CH: return on_client_hello(app, slot, c, payload, len);
    case CONN_STAGE_AWAIT_CA: return on_client_auth(app, slot, c, payload, len);
    case CONN_STAGE_SERVING:  return on_record(app, slot, c, payload, len);
    default:                  return EV_ACTION_CLOSE;
    }
}
