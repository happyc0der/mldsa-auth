#include "authd_conn.h"

#include <string.h>

#include <sodium.h>

#include "authd_log.h"
#include "authmsg.h"
#include "conn_io.h"
#include "transcript.h"
#include "tokens.h"

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
    sodium_memzero(c->handshake_id, sizeof c->handshake_id);
    c->handle_len = 0;
    c->user_id_len = 0;
    c->hsid_set = 0;
    c->decoy = 0;
    c->rotated = 0;
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

/* --- the client address, and what it is allowed to do (V4-10b) ----------- */

ev_action_t authd_conn_on_addr(void *user, authd_slot_t *slot)
{
    authd_app_t *app = (authd_app_t *)user;
    if (app == NULL || slot == NULL) {
        return EV_ACTION_CLOSE;
    }
    const authd_addr_t *addr = conn_io_client_addr(&slot->io);

    /* Req 12, and the only implementable reading of §7.2's "fails closed":
     * close the connection. Nothing can be SAID here that carries meaning --
     * spec §6.5's ERROR is a sealed record and no session exists -- and the
     * one thing that could be said, an HTTP status, would tell a prober that
     * its preamble was structurally fine. A well-formed preamble with no
     * client in it (a LOCAL health check, or AF_UNIX) is the normal way this
     * happens, so the log says which rather than shouting "malformed". */
    if (addr->family == 0u) {
        app->refused_no_address++;
        authd_log_slot_addr(AUTHD_LOG_WARN, "refused-no-client-address", slot->index,
                            addr, "fail-closed");
        conn_io_ws_silence(&slot->io);
        return EV_ACTION_CLOSE;
    }

    if (app->rl == NULL) {
        authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", slot->index, addr, "unlimited");
        return EV_ACTION_CONTINUE;
    }

    const ratelimit_verdict_t v = ratelimit_admit(app->rl, addr, app->now_ms);
    if (v != RATELIMIT_ALLOW) {
        app->refused_rate++;
        authd_log_slot_addr(AUTHD_LOG_WARN, "refused-rate-limited", slot->index,
                            addr, ratelimit_verdict_name(v));
        /* 429 for "you, slow down"; 503 for "we have run out of room to track
         * addresses", which is our capacity problem and not the caller's rate. */
        (void)conn_io_ws_refuse(&slot->io, (v == RATELIMIT_DENY_TABLE) ? 503u : 429u);
        return EV_ACTION_CLOSE;
    }
    slot->addr_admitted = 1;
    authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", slot->index, addr, "admitted");
    return EV_ACTION_CONTINUE;
}

void authd_conn_on_close(void *user, authd_slot_t *slot)
{
    authd_app_t *app = (authd_app_t *)user;
    authd_conn_t *c = conn_of(app, slot);
    if (c != NULL) {
        conn_reset(c);
    }
    if (slot != NULL) {
        /* Give back exactly what admission counted. The loop calls this before
         * it resets the slot or the connection's buffers, so both the flag and
         * the address are still readable here -- and a slot that was never
         * admitted (refused, or a listener with no preamble at all) has
         * nothing to give back, which is why the flag exists rather than an
         * unconditional release. */
        if (slot->addr_admitted && app != NULL && app->rl != NULL) {
            ratelimit_release(app->rl, conn_io_client_addr(&slot->io));
            slot->addr_admitted = 0;
        }
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

/* Is this device's active key older than the configured cadence?
 *
 * The threshold is CONFIG, not a constant: spec 6.2 defines the flag but
 * neither 10.2 nor 17 defines a cadence, so rather than invent a number and
 * bury it in a comment the daemon takes one from the operator, with 0 meaning
 * "never hint". The read happens here, AFTER authentication -- not in
 * store_lookup_active, which runs on an unauthenticated ClientHello on the
 * path whose whole job (7.3, Req 6) is to look identical for a real and a
 * decoy identity. */
static int rotation_due(const authd_app_t *app, const authd_conn_t *c)
{
    if (app->rotation_due_age_s == 0u) {
        return 0;
    }
    int64_t valid_from = 0;
    if (store_active_key_age(app->store, c->handle, c->handle_len, &valid_from) != STORE_OK) {
        return 0;
    }
    return (app->now_unix - valid_from) >= (int64_t)app->rotation_due_age_s;
}

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
    /* Kept for ROTATE's digest: after this point the handshake context is gone
     * and session_t's copy is private to session.c. */
    memcpy(c->handshake_id, hsid, sizeof c->handshake_id);
    c->hsid_set = 1;

    authmsg_login_code_t m;
    memset(&m, 0, sizeof m);
    m.flags = rotation_due(app, c) ? AUTHMSG_FLAG_ROTATION_DUE : 0u;
    randombytes_buf(m.code, sizeof m.code);
    m.code_expires = (uint64_t)(app->now_unix + (int64_t)app->code_ttl_s);

    /* Req 4: the store never sees the code, only its SHA-256. Req 5: it is
     * bound to {user, handle, handshake_id, SHA-256(state)}.
     *
     * The `state` comes from the WebSocket URL (§7.1) and lives in the slot's
     * conn_io, which is where the upgrade parser put it -- so there is no
     * second copy to keep in step and nothing extra to wipe: conn_io_reset
     * already zeroes it when the slot is released. On the raw/tunnel listener
     * there is no URL and the value is the empty string, exactly as V4-8b
     * fixed it; that is now a property of the slot's MODE rather than of the
     * whole daemon. */
    const uint8_t *state = (const uint8_t *)"";
    size_t state_len = 0u;
    if (slot->io.mode == CONN_IO_MODE_WS) {
        state = slot->io.ws.state;
        state_len = slot->io.ws.state_len;
    }

    uint8_t code_hash[STORE_HASH_BYTES];
    uint8_t state_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(code_hash, m.code, sizeof m.code);
    crypto_hash_sha256(state_hash, state, state_len);

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

/* --- ROTATE (spec 6.3) ---------------------------------------------------- */

/* Handles one ROTATE, already decrypted into `pt`.
 *
 * ACCEPTANCE ORDER is the spec's, first failure wins, nothing written until
 * all of it passes. What the PEER learns is one bit: it failed. Every
 * rejection below answers ERROR(0x03 REJECTED) -- handle mismatch, key in use,
 * either signature, the store's refusals -- because a distinct code for "that
 * public key is already enrolled" would hand any authenticated user an oracle
 * for the whole deployment's key set: the cross-device twin of the enumeration
 * 7.3's decoy flow exists to close. The fine-grained reason goes to the
 * operator's journal through `why`, which never reaches the wire.
 *
 * Known residual, recorded in docs/v4/audit.md rather than silently deviated
 * from: 6.3 orders the cheap store query BEFORE the ~100 us signature
 * verification, so "in use" is still distinguishable by TIMING even with a
 * uniform code. Reordering would contradict the spec. */
static ev_action_t on_rotate(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c,
                             const uint8_t *pt, size_t pt_len)
{
    const char *why = "rotate-rejected";
    uint8_t code = AUTHMSG_ERR_REJECTED;

    /* One ROTATE per session. The spec does not say so, and without it the
     * holder of the key being rotated AWAY from can keep rotating: sig_old is
     * still valid because the slot still pins that key. Recorded as errata. */
    if (c->rotated) {
        return fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED, "rotate-already-done");
    }
    if (!c->hsid_set || c->decoy) {
        return fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED, "rotate-no-session-binding");
    }

    authmsg_rotate_t m;
    const authmsg_status_t ds = authmsg_decode_rotate(pt, pt_len, &m);
    if (ds != AUTHMSG_OK) {
        return fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "rotate-malformed");
    }

    /* The pinned key that authenticated this session IS pk_old: it is what
     * sig_old must verify under, and what the digest binds to. Taking it from
     * the store instead would let a rotation that happened underneath this
     * session be signed by a key that is no longer current. */
    const uint8_t *pk_old = NULL;
    if (keystore_lookup(&c->ks, c->handle, c->handle_len, &pk_old) != KEYSTORE_OK ||
        pk_old == NULL) {
        return fail_with_error(slot, c, AUTHMSG_ERR_INTERNAL, "rotate-no-pin");
    }

    ev_action_t act;
    uint8_t digest[crypto_hash_sha256_BYTES];
    uint8_t fp[crypto_hash_sha256_BYTES];
    int64_t rotated_at = 0;
    size_t dropped = 0;

    if (m.handle_len != c->handle_len ||
        sodium_memcmp(m.handle, c->handle, c->handle_len) != 0) {
        why = "rotate-wrong-handle";
        goto reject;
    }
    /* sig_old under the OLD label, against the session's pinned key. */
    if (authmsg_rotate_digest(digest, AUTHMSG_LABEL_ROTATE_OLD, c->handshake_id, m.flags,
                              c->handle, c->handle_len, pk_old, m.pk_new) != AUTHMSG_OK) {
        why = "rotate-digest";
        goto reject;
    }
    if (mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, pk_old) != 0) {
        why = "rotate-sig-old";
        goto reject;
    }
    /* sig_new under the NEW label, against the INCOMING key -- proof the peer
     * holds the private half of what it is asking us to trust. */
    if (authmsg_rotate_digest(digest, AUTHMSG_LABEL_ROTATE_NEW, c->handshake_id, m.flags,
                              c->handle, c->handle_len, pk_old, m.pk_new) != AUTHMSG_OK) {
        why = "rotate-digest";
        goto reject;
    }
    if (mldsa_verify(digest, sizeof digest, m.sig_new, m.sig_new_len, m.pk_new) != 0) {
        why = "rotate-sig-new";
        goto reject;
    }

    /* store_rotate_key re-reads device and user status INSIDE its transaction
     * and rejects a duplicate or unchanged key there, so the daemon does not
     * duplicate either check: a second copy here would be a branch no test
     * could distinguish, and a pre-check would be a race with authd_admin. */
    {
        const int drop = (m.flags & AUTHMSG_FLAG_ROTATE_DROP_TOKENS) != 0;
        /* pk_old is pinned: the store commits only if the handle's active key
         * is still the one this session authenticated with and signed over. */
        const store_status_t rs = store_rotate_key(app->store, c->handle, c->handle_len,
                                                   m.pk_new, pk_old, c->handshake_id,
                                                   sizeof c->handshake_id, drop,
                                                   app->now_unix, &rotated_at, &dropped);
        if (rs != STORE_OK) {
            why = (rs == STORE_ERR_DB) ? "rotate-store-error" : "rotate-store-refused";
            if (rs == STORE_ERR_DB) { code = AUTHMSG_ERR_INTERNAL; }
            goto reject;
        }
    }

    /* Spec 15: every rotation is logged, with the handle and both
     * fingerprints. The handshake_id 15 also asks for has no carrier in
     * authd_log.h -- recorded as errata rather than widened here, because the
     * never-list is a property of that API's shape. */
    crypto_hash_sha256(fp, pk_old, MLDSA_PUBLIC_KEY_BYTES);
    authd_log_fp(AUTHD_LOG_INFO, "rotate-fp-old", fp);
    crypto_hash_sha256(fp, m.pk_new, MLDSA_PUBLIC_KEY_BYTES);
    authd_log_fp(AUTHD_LOG_INFO, "rotate-fp-new", fp);
    authd_log_slot_id(AUTHD_LOG_INFO, "rotate", slot->index, c->handle, c->handle_len);
    if (dropped > 0u) {
        authd_log_num(AUTHD_LOG_INFO, "rotate-tokens-dropped", "count", (uint64_t)dropped);
    }

    {
        uint8_t ack[AUTHMSG_ROTATE_ACK_CONTENT_LEN(STORE_ID_MAX)];
        size_t n = 0;
        if (authmsg_encode_rotate_ack(ack, sizeof ack, &n, c->handle, c->handle_len, fp,
                                      (uint64_t)rotated_at) != AUTHMSG_OK ||
            queue_sealed(slot, &c->sess, ack, n) != 0) {
            sodium_memzero(ack, sizeof ack);
            act = fail_with_error(slot, c, AUTHMSG_ERR_INTERNAL, "rotate-ack-failed");
            goto done;
        }
        sodium_memzero(ack, sizeof ack);
    }
    c->rotated = 1;
    app->rotations++;
    act = EV_ACTION_CONTINUE;
    goto done;

reject:
    act = fail_with_error(slot, c, code, why);
done:
    sodium_memzero(digest, sizeof digest);
    sodium_memzero(&m, sizeof m);
    return act;
}

static ev_action_t on_record(authd_app_t *app, authd_slot_t *slot, authd_conn_t *c,
                             const uint8_t *payload, size_t len)
{
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

    /* ONE exit, ONE wipe. The ROTATE handler has eight rejection paths; if each
     * returned directly, each would be a separate place to forget this
     * memzero, and a mutation deleting one of them would be unkillable by any
     * test and invisible to a sanitizer. */
    ev_action_t act;
    uint8_t op = 0;
    const authmsg_status_t as = authmsg_peek_op(pt, pt_len, &op);
    if (as != AUTHMSG_OK) {
        act = fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "empty-content");
    } else if (op == AUTHMSG_OP_BYE) {
        if (pt_len != AUTHMSG_BYE_CONTENT_LEN) {
            act = fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, "bye-bad-length");
        } else {
            authd_log_slot(AUTHD_LOG_INFO, "bye", slot->index);
            c->stage = CONN_STAGE_CLOSING;
            act = EV_ACTION_CLOSE;
        }
    } else if (op == AUTHMSG_OP_ROTATE) {
        act = on_rotate(app, slot, c, pt, pt_len);
    } else {
        act = fail_with_error(slot, c, AUTHMSG_ERR_NOT_PERMITTED, "op-not-permitted");
    }
    sodium_memzero(pt, sizeof pt);
    return act;
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

/* --- revocation reaches live sessions, not just rows --------------------- */

static size_t close_matching(authd_app_t *app, const uint8_t *id, size_t id_len, int by_user)
{
    if (app == NULL || app->ev == NULL || id == NULL || id_len == 0u) {
        return 0u;
    }
    size_t closed = 0u;
    for (size_t i = 0; i < app->n_conns && i < app->ev->n_slots; i++) {
        authd_conn_t *c = &app->conns[i];
        if (c->stage == CONN_STAGE_FREE) {
            continue;
        }
        const uint8_t *have = by_user ? c->user_id : c->handle;
        const size_t have_len = by_user ? c->user_id_len : c->handle_len;
        if (have_len != id_len || sodium_memcmp(have, id, id_len) != 0) {
            continue;
        }
        evloop_close_slot(app->ev, &app->ev->slots[i]);
        closed++;
    }
    return closed;
}

size_t authd_app_close_handle(authd_app_t *app, const uint8_t *handle, size_t handle_len)
{
    return close_matching(app, handle, handle_len, 0);
}

size_t authd_app_close_user(authd_app_t *app, const uint8_t *user_id, size_t user_id_len)
{
    return close_matching(app, user_id, user_id_len, 1);
}

void authd_app_maybe_sweep(authd_app_t *app)
{
    if (app == NULL || app->store == NULL) {
        return;
    }
    if (app->next_sweep_ms != 0u && app->now_ms < app->next_sweep_ms) {
        return;
    }
    app->next_sweep_ms = app->now_ms + (uint64_t)TOKEN_SWEEP_INTERVAL_MS;

    store_sweep_counts_t sc;
    if (store_sweep(app->store, app->now_unix, &sc) != STORE_OK) {
        authd_log_event(AUTHD_LOG_WARN, "sweep-failed");
        return;
    }
    app->swept_tokens += sc.tokens;
    app->swept_codes += sc.login_codes;
    app->swept_tickets += sc.tickets;
    if (sc.tokens != 0u || sc.login_codes != 0u || sc.tickets != 0u) {
        /* spec 15: the sweep counts are logged. */
        authd_log_num(AUTHD_LOG_INFO, "swept", "tokens", (uint64_t)sc.tokens);
        authd_log_num(AUTHD_LOG_INFO, "swept", "codes", (uint64_t)sc.login_codes);
        authd_log_num(AUTHD_LOG_INFO, "swept", "tickets", (uint64_t)sc.tickets);
    }
}
