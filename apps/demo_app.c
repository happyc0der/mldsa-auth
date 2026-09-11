#include "demo_app.h"

#include "demo_keys.h"

#include <sodium.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

_Static_assert(DEMO_MAX_MESSAGE_BYTES + 1u == SESSION_MAX_PLAINTEXT_BYTES,
               "op byte + largest message = largest record plaintext");

#define ID_TEXT_MAX (4u * WIRE_ID_MAX_LEN + 1u)

/* ---- logging (fixed text, names, counts and ids ONLY) ------------------- */

static void emit(const demo_config_t *cfg, const char *role, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void emit(const demo_config_t *cfg, const char *role, const char *fmt, ...) {
    char line[DEMO_LOG_LINE_MAX];
    int n = snprintf(line, sizeof(line), "%s: ", role);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (cfg != NULL && cfg->log.fn != NULL) {
        cfg->log.fn(cfg->log.ctx, line);
    } else {
        fprintf(stderr, "%s\n", line);
    }
}

/* Identities are opaque public labels: printable bytes as-is, others \xHH. */
static void format_id(char out[ID_TEXT_MAX], const uint8_t *id, size_t len) {
    size_t o = 0;
    for (size_t i = 0; i < len && i < WIRE_ID_MAX_LEN; i++) {
        const uint8_t c = id[i];
        if (c > 0x20u && c < 0x7fu && c != '\\') {
            out[o++] = (char)c;
        } else {
            (void)snprintf(out + o, ID_TEXT_MAX - o, "\\x%02x", c);
            o += 4;
        }
    }
    out[o] = '\0';
}

const char *demo_status_name(demo_status_t st) {
    switch (st) {
    case DEMO_OK: return "ok";
    case DEMO_ERR_CONFIG: return "config-error";
    case DEMO_ERR_IO: return "io-error";
    case DEMO_ERR_TIMEOUT: return "timeout";
    case DEMO_ERR_PEER_CLOSED: return "peer-closed-without-goodbye";
    case DEMO_ERR_TRUNCATED: return "truncated";
    case DEMO_ERR_FRAME_SIZE: return "frame-size";
    case DEMO_ERR_HANDSHAKE: return "handshake-failed";
    case DEMO_ERR_SESSION: return "session-failed";
    case DEMO_ERR_NOT_CONFIRMED: return "not-confirmed";
    case DEMO_ERR_APP_PROTOCOL: return "app-protocol-error";
    case DEMO_ERR_RESOURCE: return "resource-error";
    }
    return "unknown";
}

const char *demo_stage_name(demo_stage_t st) {
    switch (st) {
    case DEMO_STAGE_CONNECT: return "connect";
    case DEMO_STAGE_CLIENT_HELLO: return "client-hello";
    case DEMO_STAGE_SERVER_HELLO: return "server-hello";
    case DEMO_STAGE_CLIENT_AUTH: return "client-auth";
    case DEMO_STAGE_CONFIRM: return "confirm";
    case DEMO_STAGE_SESSION: return "session";
    case DEMO_STAGE_GOODBYE: return "goodbye";
    }
    return "unknown";
}

/* ---- failure recording ---------------------------------------------------- */

static void frame_fail(demo_result_t *r, frame_status_t fs) {
    r->frame_status = fs;
    switch (fs) {
    case FRAME_EOF: r->status = DEMO_ERR_PEER_CLOSED; break;
    case FRAME_TRUNCATED: r->status = DEMO_ERR_TRUNCATED; break;
    case FRAME_TIMEOUT: r->status = DEMO_ERR_TIMEOUT; break;
    case FRAME_IO: r->status = DEMO_ERR_IO; break;
    case FRAME_BAD_LENGTH: r->status = DEMO_ERR_FRAME_SIZE; break;
    case FRAME_OK:
    case FRAME_INVALID_ARG: r->status = DEMO_ERR_CONFIG; break;
    }
}

static void hs_fail(demo_result_t *r, handshake_status_t st) {
    r->hs_status = st;
    r->status = (st == HANDSHAKE_ERR_RESOURCE_EXHAUSTED) ? DEMO_ERR_RESOURCE : DEMO_ERR_HANDSHAKE;
}

static void sess_fail(demo_result_t *r, session_status_t st) {
    r->sess_status = st;
    r->status = DEMO_ERR_SESSION;
}

static bool config_valid(const demo_config_t *c, bool client) {
    return c != NULL && c->local_id != NULL && c->local_id_len >= WIRE_ID_MIN_LEN &&
           c->local_id_len <= WIRE_ID_MAX_LEN && c->local_kp != NULL && c->local_kp->secret_key != NULL &&
           c->pins != NULL && c->handshake_timeout_ms >= 1u && c->idle_timeout_ms >= 1u &&
           (!client || (c->peer_id != NULL && c->peer_id_len >= WIRE_ID_MIN_LEN &&
                        c->peer_id_len <= WIRE_ID_MAX_LEN));
}

/* ---- application records -------------------------------------------------- */

static demo_status_t send_app(session_t *s, net_conn_t *conn, demo_buffers_t *buf, uint8_t op,
                              const uint8_t *body, size_t body_len, uint64_t deadline_ms, demo_result_t *r) {
    if (s == NULL || conn == NULL || buf == NULL || (body == NULL && body_len != 0) ||
        body_len > DEMO_MAX_MESSAGE_BYTES) {
        r->status = DEMO_ERR_CONFIG;
        return r->status;
    }
    /* Confirmation gate: nothing is sealed or written before the peer is
     * cryptographically confirmed (spec §6.4.4). */
    if (!session_is_peer_confirmed(s)) {
        r->status = DEMO_ERR_NOT_CONFIRMED;
        return r->status;
    }
    if (body_len != 0) {
        memmove(buf->pt + 1, body, body_len);
    }
    buf->pt[0] = op;
    size_t rec_len = 0;
    const session_status_t sst = session_seal(s, buf->pt, body_len + 1u, buf->tx + FRAME_HEADER_BYTES,
                                              FRAME_MAX_PAYLOAD, &rec_len);
    sodium_memzero(buf->pt, body_len + 1u);
    if (sst != SESSION_OK) {
        sess_fail(r, sst);
        return r->status;
    }
    const frame_status_t fs = frame_send(conn, buf->tx, rec_len, deadline_ms);
    if (fs != FRAME_OK) {
        frame_fail(r, fs);
        return r->status;
    }
    return DEMO_OK;
}

demo_status_t demo_send_app(session_t *s, net_conn_t *conn, demo_buffers_t *buf, uint8_t op,
                            const uint8_t *body, size_t body_len, uint64_t deadline_ms) {
    demo_result_t scratch;
    memset(&scratch, 0, sizeof(scratch));
    return send_app(s, conn, buf, op, body, body_len, deadline_ms, &scratch);
}

/* Receives and opens one session record into buf->pt. */
static demo_status_t recv_record(session_t *s, net_conn_t *conn, demo_buffers_t *buf, size_t min_len,
                                 size_t max_len, uint64_t deadline_ms, size_t *pt_len, demo_result_t *r) {
    size_t len = 0;
    *pt_len = 0;
    const frame_status_t fs = frame_recv(conn, buf->rx, min_len, max_len, &len, deadline_ms);
    if (fs != FRAME_OK) {
        frame_fail(r, fs);
        return r->status;
    }
    const session_status_t sst =
        session_open(s, buf->rx + FRAME_HEADER_BYTES, len, buf->pt, sizeof(buf->pt), pt_len);
    if (sst != SESSION_OK) {
        sess_fail(r, sst);
        return r->status;
    }
    return DEMO_OK;
}

/* ---- server ----------------------------------------------------------------- */

demo_status_t demo_server_handle_connection(const demo_config_t *cfg, handshake_pending_store_t *store,
                                            net_conn_t *conn, demo_buffers_t *buf, demo_result_t *res) {
    static const char role[] = "server";
    demo_result_t r;
    handshake_ctx_t hs;
    session_t sess;
    client_hello_t ch;
    char idtext[ID_TEXT_MAX];
    size_t len = 0;
    size_t out_len = 0;
    size_t pt_len = 0;
    size_t consumed = 0;
    uint64_t hs_deadline = 0;
    handshake_status_t hst;
    session_status_t sst;
    frame_status_t fs;

    memset(&r, 0, sizeof(r));
    memset(&hs, 0, sizeof(hs));
    memset(&sess, 0, sizeof(sess));
    r.status = DEMO_ERR_CONFIG;
    r.stage = DEMO_STAGE_CLIENT_HELLO;

    if (!config_valid(cfg, false) || store == NULL || conn == NULL || conn->fd < 0 || buf == NULL ||
        cfg->handshake_timeout_ms > store->ttl_ms) {
        goto done;
    }
    hs_deadline = net_deadline_in(cfg->handshake_timeout_ms);

    hst = handshake_responder_init(&hs, cfg->local_id, cfg->local_id_len, cfg->local_kp, cfg->pins, store);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    emit(cfg, role, "connection accepted; awaiting ClientHello");

    /* 1. ClientHello */
    fs = frame_recv(conn, buf->rx, 1u, FRAME_MAX_CLIENT_HELLO, &len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    hst = handshake_responder_accept_client_hello(&hs, buf->rx + FRAME_HEADER_BYTES, len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        emit(cfg, role, "ClientHello rejected (handshake status %d)", (int)hst);
        goto done;
    }
    /* The library already validated it; decoded again only to name the peer. */
    if (decode_client_hello(buf->rx + FRAME_HEADER_BYTES, len, &ch, &consumed) == 0) {
        format_id(idtext, ch.id, ch.id_len);
        emit(cfg, role, "ClientHello accepted from pinned identity '%s'", idtext);
    }

    /* 2. ServerHello */
    r.stage = DEMO_STAGE_SERVER_HELLO;
    hst = handshake_responder_create_server_hello(&hs, buf->tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD,
                                                  &out_len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    fs = frame_send(conn, buf->tx, out_len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    emit(cfg, role, "ServerHello sent (%zu bytes)", out_len);

    /* 3. ClientAuth -- any failure ends the connection (reference transport
     *    policy, spec §6.5: no second ClientAuth on the same stream). */
    r.stage = DEMO_STAGE_CLIENT_AUTH;
    fs = frame_recv(conn, buf->rx, 1u, FRAME_MAX_CLIENT_AUTH, &len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    hst = handshake_responder_verify_client_auth(&hs, buf->rx + FRAME_HEADER_BYTES, len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        emit(cfg, role, "ClientAuth rejected (handshake status %d); closing the connection", (int)hst);
        goto done;
    }
    hst = handshake_responder_finish(&hs);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    sst = session_init_from_handshake(&sess, &hs, NULL, NULL, NULL);
    if (sst != SESSION_OK) {
        sess_fail(&r, sst);
        goto done;
    }
    emit(cfg, role, "client authenticated (ML-DSA-65 signature verified against the pinned key); "
                    "session established");

    /* 4. Immediate empty confirmation record (spec §6.4.4). */
    r.stage = DEMO_STAGE_CONFIRM;
    sst = session_seal(&sess, NULL, 0, buf->tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD, &out_len);
    if (sst != SESSION_OK) {
        sess_fail(&r, sst);
        goto done;
    }
    fs = frame_send(conn, buf->tx, out_len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    emit(cfg, role, "sent empty confirmation record");

    /* 5. Application records. */
    r.stage = DEMO_STAGE_SESSION;
    for (;;) {
        const uint64_t idle = net_deadline_in(cfg->idle_timeout_ms);
        if (recv_record(&sess, conn, buf, FRAME_MIN_RECORD, FRAME_MAX_RECORD, idle, &pt_len, &r) != DEMO_OK) {
            if (r.status == DEMO_ERR_PEER_CLOSED) {
                emit(cfg, role, "peer closed without GOODBYE (possible truncation)");
            } else if (r.status == DEMO_ERR_SESSION) {
                emit(cfg, role, "record rejected (session status %d); closing", (int)r.sess_status);
            }
            goto done;
        }
        if (pt_len >= 1u && buf->pt[0] == DEMO_OP_MSG) {
            if (send_app(&sess, conn, buf, DEMO_OP_ECHO, buf->pt + 1, pt_len - 1u, idle, &r) != DEMO_OK) {
                goto done;
            }
            r.messages_echoed++;
            emit(cfg, role, "echoed message %u (%zu bytes)", (unsigned)r.messages_echoed, pt_len - 1u);
        } else if (pt_len == 1u && buf->pt[0] == DEMO_OP_GOODBYE) {
            sodium_memzero(buf->pt, pt_len);
            r.stage = DEMO_STAGE_GOODBYE;
            if (send_app(&sess, conn, buf, DEMO_OP_GOODBYE, NULL, 0, idle, &r) != DEMO_OK) {
                goto done;
            }
            r.status = DEMO_OK;
            emit(cfg, role, "GOODBYE exchanged; closing");
            goto done;
        } else {
            sodium_memzero(buf->pt, pt_len);
            r.status = DEMO_ERR_APP_PROTOCOL;
            emit(cfg, role, "unexpected application record; closing");
            goto done;
        }
        if (session_rekey_due(&sess)) {
            /* Rekey orchestration is out of scope for Step 6: close cleanly. */
            r.stage = DEMO_STAGE_GOODBYE;
            if (send_app(&sess, conn, buf, DEMO_OP_GOODBYE, NULL, 0, idle, &r) == DEMO_OK) {
                r.status = DEMO_OK;
            }
            emit(cfg, role, "rekey due; sent GOODBYE and closing");
            goto done;
        }
    }

done:
    session_wipe(&sess);
    handshake_ctx_wipe(&hs); /* cancels a still-active ledger entry */
    if (buf != NULL) {
        sodium_memzero(buf, sizeof(*buf));
    }
    if (conn != NULL) {
        r.net = conn->stats;
        net_close(conn);
    }
    r.pending_active_after = (store != NULL) ? handshake_pending_active_count(store) : 0;
    emit(cfg, role, "connection finished: status=%s stage=%s messages=%u", demo_status_name(r.status),
         demo_stage_name(r.stage), (unsigned)r.messages_echoed);
    if (res != NULL) {
        *res = r;
    }
    return r.status;
}

/* ---- client ----------------------------------------------------------------- */

demo_status_t demo_client_run(const demo_config_t *cfg, net_conn_t *conn, const demo_message_t *msgs,
                              size_t n_msgs, demo_buffers_t *buf, demo_result_t *res) {
    static const char role[] = "client";
    demo_result_t r;
    handshake_ctx_t hs;
    session_t sess;
    char idtext[ID_TEXT_MAX];
    size_t len = 0;
    size_t out_len = 0;
    size_t pt_len = 0;
    uint64_t hs_deadline = 0;
    handshake_status_t hst;
    session_status_t sst;
    frame_status_t fs;
    bool msgs_ok = (n_msgs == 0) || (msgs != NULL);

    memset(&r, 0, sizeof(r));
    memset(&hs, 0, sizeof(hs));
    memset(&sess, 0, sizeof(sess));
    r.status = DEMO_ERR_CONFIG;
    r.stage = DEMO_STAGE_CLIENT_HELLO;

    for (size_t i = 0; msgs_ok && i < n_msgs; i++) {
        msgs_ok = msgs[i].data != NULL && msgs[i].len >= 1u && msgs[i].len <= DEMO_MAX_MESSAGE_BYTES;
    }
    if (!config_valid(cfg, true) || !msgs_ok || conn == NULL || conn->fd < 0 || buf == NULL) {
        goto done;
    }
    hs_deadline = net_deadline_in(cfg->handshake_timeout_ms);
    format_id(idtext, cfg->peer_id, cfg->peer_id_len);

    hst = handshake_initiator_init(&hs, cfg->local_id, cfg->local_id_len, cfg->local_kp, cfg->pins,
                                   cfg->peer_id, cfg->peer_id_len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }

    /* 1. ClientHello */
    hst = handshake_initiator_create_client_hello(&hs, buf->tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD, &out_len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    fs = frame_send(conn, buf->tx, out_len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    emit(cfg, role, "ClientHello sent to '%s'", idtext);

    /* 2. ServerHello */
    r.stage = DEMO_STAGE_SERVER_HELLO;
    fs = frame_recv(conn, buf->rx, 1u, FRAME_MAX_SERVER_HELLO, &len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    hst = handshake_initiator_verify_server_hello(&hs, buf->rx + FRAME_HEADER_BYTES, len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        emit(cfg, role, "ServerHello rejected (handshake status %d)", (int)hst);
        goto done;
    }
    emit(cfg, role, "server '%s' authenticated (ML-DSA-65 signature verified against the pinned key)", idtext);

    /* 3. ClientAuth, then the (optimistic) initiator session. */
    r.stage = DEMO_STAGE_CLIENT_AUTH;
    hst = handshake_initiator_create_client_auth(&hs, buf->tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD, &out_len);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    fs = frame_send(conn, buf->tx, out_len, hs_deadline);
    if (fs != FRAME_OK) {
        frame_fail(&r, fs);
        goto done;
    }
    hst = handshake_initiator_finish(&hs);
    if (hst != HANDSHAKE_OK) {
        hs_fail(&r, hst);
        goto done;
    }
    sst = session_init_from_handshake(&sess, &hs, NULL, NULL, NULL);
    if (sst != SESSION_OK) {
        sess_fail(&r, sst);
        goto done;
    }
    emit(cfg, role, "ClientAuth sent; waiting for the responder's confirmation record");

    /* 4. Exactly one empty record must arrive and authenticate before the
     *    peer is treated as confirmed and before any application data. */
    r.stage = DEMO_STAGE_CONFIRM;
    if (recv_record(&sess, conn, buf, FRAME_CONFIRM_LEN, FRAME_CONFIRM_LEN, hs_deadline, &pt_len, &r) != DEMO_OK) {
        goto done;
    }
    if (pt_len != 0) {
        sodium_memzero(buf->pt, pt_len);
        r.status = DEMO_ERR_APP_PROTOCOL;
        goto done;
    }
    if (!session_is_peer_confirmed(&sess)) {
        r.status = DEMO_ERR_NOT_CONFIRMED;
        goto done;
    }
    emit(cfg, role, "responder confirmed (empty authenticated record received)");

    /* 5. Messages, each answered by an authenticated echo. */
    r.stage = DEMO_STAGE_SESSION;
    for (size_t i = 0; i < n_msgs; i++) {
        const uint64_t idle = net_deadline_in(cfg->idle_timeout_ms);
        if (send_app(&sess, conn, buf, DEMO_OP_MSG, msgs[i].data, msgs[i].len, idle, &r) != DEMO_OK ||
            recv_record(&sess, conn, buf, FRAME_MIN_RECORD, FRAME_MAX_RECORD, idle, &pt_len, &r) != DEMO_OK) {
            goto done;
        }
        const bool echo_ok = pt_len == msgs[i].len + 1u && buf->pt[0] == DEMO_OP_ECHO &&
                             memcmp(buf->pt + 1, msgs[i].data, msgs[i].len) == 0;
        sodium_memzero(buf->pt, pt_len);
        if (!echo_ok) {
            r.status = DEMO_ERR_APP_PROTOCOL;
            emit(cfg, role, "message %zu: echo did not match; closing", i + 1u);
            goto done;
        }
        r.messages_echoed++;
        emit(cfg, role, "message %zu: authenticated echo verified (%zu bytes)", i + 1u, msgs[i].len);
    }

    /* 6. Authenticated close. */
    r.stage = DEMO_STAGE_GOODBYE;
    {
        const uint64_t idle = net_deadline_in(cfg->idle_timeout_ms);
        if (send_app(&sess, conn, buf, DEMO_OP_GOODBYE, NULL, 0, idle, &r) != DEMO_OK ||
            recv_record(&sess, conn, buf, FRAME_MIN_RECORD, FRAME_MAX_RECORD, idle, &pt_len, &r) != DEMO_OK) {
            goto done;
        }
        const bool bye = (pt_len == 1u && buf->pt[0] == DEMO_OP_GOODBYE);
        sodium_memzero(buf->pt, pt_len);
        if (!bye) {
            r.status = DEMO_ERR_APP_PROTOCOL;
            goto done;
        }
    }
    r.status = DEMO_OK;
    emit(cfg, role, "GOODBYE exchanged; closing");

done:
    session_wipe(&sess);
    handshake_ctx_wipe(&hs);
    if (buf != NULL) {
        sodium_memzero(buf, sizeof(*buf));
    }
    if (conn != NULL) {
        r.net = conn->stats;
        net_close(conn);
    }
    emit(cfg, role, "connection finished: status=%s stage=%s messages=%u", demo_status_name(r.status),
         demo_stage_name(r.stage), (unsigned)r.messages_echoed);
    if (res != NULL) {
        *res = r;
    }
    return r.status;
}

/* ---- CLI helpers ------------------------------------------------------------ */

int demo_parse_u64(const char *s, uint64_t min, uint64_t max, uint64_t *out) {
    if (s == NULL || out == NULL || s[0] < '0' || s[0] > '9') {
        return -1; /* no sign, no whitespace, no empty string */
    }
    errno = 0;
    char *end = NULL;
    const unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || (uint64_t)v < min || (uint64_t)v > max) {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static bool id_chars_ok(const char *s, size_t len) {
    return demo_keys_id_filename_safe((const uint8_t *)s, len) != 0;
}

int demo_parse_id(const char *s, const uint8_t **id, size_t *id_len) {
    if (s == NULL || id == NULL || id_len == NULL) {
        return -1;
    }
    const size_t len = strnlen(s, WIRE_ID_MAX_LEN + 1u);
    if (!id_chars_ok(s, len)) {
        return -1;
    }
    *id = (const uint8_t *)s;
    *id_len = len;
    return 0;
}

int demo_split_pin(const char *arg, const uint8_t **id, size_t *id_len, const char **path) {
    if (arg == NULL || id == NULL || id_len == NULL || path == NULL) {
        return -1;
    }
    const char *eq = strchr(arg, '=');
    if (eq == NULL || eq[1] == '\0' || !id_chars_ok(arg, (size_t)(eq - arg))) {
        return -1;
    }
    *id = (const uint8_t *)arg;
    *id_len = (size_t)(eq - arg);
    *path = eq + 1;
    return 0;
}

int demo_cli_keygen(int argc, char **argv, int first, const char *prog) {
    const char *id_s = NULL;
    const char *dir = NULL;
    for (int i = first; i < argc; i++) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            id_s = argv[++i];
        } else if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) {
            dir = argv[++i];
        } else {
            fprintf(stderr, "%s keygen: unexpected argument '%s'\n", prog, argv[i]);
            return 2;
        }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (id_s == NULL || dir == NULL || demo_parse_id(id_s, &id, &id_len) != 0) {
        fprintf(stderr, "usage: %s keygen --id ID --dir DIR   (ID: 1-64 of [A-Za-z0-9._-])\n", prog);
        return 2;
    }
    const demo_keys_status_t st = demo_keys_generate_files(dir, id, id_len);
    if (st != DEMO_KEYS_OK) {
        fprintf(stderr, "%s keygen: failed: %s\n", prog, demo_keys_status_name(st));
        return 1;
    }
    printf("%s keygen: wrote %s/%s.sk (mode 0600; DEMO ONLY, unencrypted) and %s/%s.pub\n", prog, dir, id_s,
           dir, id_s);
    return 0;
}

int demo_publish_port_file(const char *path, uint16_t port) {
    char tmp[PATH_MAX];
    char line[16];
    if (path == NULL || port == 0) {
        return -1;
    }
    const int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    const int ln = snprintf(line, sizeof(line), "%u\n", (unsigned)port);
    if (tn < 0 || (size_t)tn >= sizeof(tmp) || ln < 0 || (size_t)ln >= sizeof(line)) {
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    while (off < (size_t)ln) {
        const ssize_t w = write(fd, line + off, (size_t)ln - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            (void)close(fd);
            (void)unlink(tmp);
            return -1;
        }
        off += (size_t)w;
    }
    const int synced = fsync(fd);
    const int closed = close(fd); /* closed before any reader can see it */
    /* link() publishes atomically and refuses to clobber an existing path. */
    if (synced != 0 || closed != 0 || link(tmp, path) != 0) {
        (void)unlink(tmp);
        return -1;
    }
    (void)unlink(tmp);
    return 0;
}
