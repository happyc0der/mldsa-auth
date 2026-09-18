#ifndef MLDSA_AUTHD_TEST_HARNESS_H
#define MLDSA_AUTHD_TEST_HARNESS_H

/*
 * The daemon, in-process, for tests (V4-9a).
 *
 * Extracted from test_authd_conn.c so the connection tests and the local-API
 * tests drive the SAME daemon rather than two divergent approximations of it.
 * The daemon is assembled exactly as authd_main.c assembles it -- same evloop,
 * same store, same callbacks -- but the test owns its clock, so every deadline,
 * expiry and sweep is exact instead of wall-clock flaky.
 *
 * Everything here is `static inline`: a header-only harness keeps each test a
 * single translation unit and avoids a library that only tests link.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include <sodium.h>

#include "authd_conn.h"
#include "authd_log.h"
#include "conn_io.h"
#include "evloop.h"
#include "listener.h"
#include "localapi.h"
#include "recovery.h"
#include "localcli.h"
#include "store.h"
#include "handshake.h"
#include "keystore.h"
#include "session.h"
#include "tokens.h"

#define H_MAX_SLOTS 8u
#define H_MAX_LOCAL 4u

typedef struct {
    evloop_t                  ev;
    authd_app_t               app;
    authd_slot_t              slots[H_MAX_SLOTS];
    authd_conn_t              conns[H_MAX_SLOTS];
    authd_slot_t              local_slots[H_MAX_LOCAL];
    handshake_pending_store_t pending;
    store_t                  *store;
    mldsa_keypair_t           server_kp;
    int                       lfd;        /* protocol listener */
    int                       site_fd;
    int                       admin_fd;
    uint16_t                  port;
    size_t                    nslots;
    char                      dir[256];
    char                      site_path[320];
    char                      admin_path[320];
} h_daemon_t;

static const uint8_t H_SERVER_ID[] = { 'a','u','t','h','d' };
static const uint8_t H_KEK[32] = {
    1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 17,18,19,20,21,22,23,24, 25,26,27,28,29,30,31,32 };

/* Starts a daemon with a protocol listener and, when `with_local`, a site and
 * an admin socket whose allowlist is this process's own uid -- the only uid a
 * test can prove anything about. */
static inline int h_start(h_daemon_t *d, const char *dir, const char *dbname, int with_local)
{
    memset(d, 0, sizeof *d);
    d->lfd = d->site_fd = d->admin_fd = -1;
    d->nslots = H_MAX_SLOTS;
    snprintf(d->dir, sizeof d->dir, "%s", dir);

    if (mldsa_keypair_generate(&d->server_kp) != 0) { return -1; }

    char db[512];
    snprintf(db, sizeof db, "%s/%s", dir, dbname);
    (void)unlink(db);
    if (store_open(db, H_KEK, &d->store) != STORE_OK) { return -1; }

    d->app.conns = d->conns;
    d->app.n_conns = d->nslots;
    d->app.store = d->store;
    d->app.server_kp = &d->server_kp;
    d->app.server_id = H_SERVER_ID;
    d->app.server_id_len = sizeof H_SERVER_ID;
    d->app.pad_bucket = 256u;
    d->app.code_ttl_s = AUTHD_LOGIN_CODE_TTL_S;
    /* The KDF is lowered to libsodium's MINIMUM here and ONLY here. At the
     * spec's 2/64MiB a single RECOVERY-ISSUE of 16 codes costs over a second,
     * which would make this suite unusably slow while proving nothing
     * extra: every property under test is about WHICH code matches and what
     * the store does, not about how expensive the hash is. The daemon's real
     * parameters are asserted by tools/audit/check_spec_constants.sh. */
    d->app.recovery_ops = crypto_pwhash_OPSLIMIT_MIN;
    d->app.recovery_mem = crypto_pwhash_MEMLIMIT_MIN;
    d->app.recovery_lock_threshold = RECOVERY_LOCK_THRESHOLD;
    d->app.recovery_lock_seconds = RECOVERY_LOCK_SECONDS;
    d->app.ticket_ttl_s = RECOVERY_TICKET_TTL_S;

    d->app.now_ms = 1000u;
    d->app.now_unix = 1700000000;
    d->app.started_ms = 1000u;

    if (handshake_pending_store_init(&d->pending, d->nslots, 10000u,
                                     authd_app_clock, &d->app) != PENDING_OK) { return -1; }
    d->app.pending = &d->pending;

    if (evloop_init(&d->ev, d->slots, d->nslots, 10000u, 60000u,
                    authd_conn_on_frame, authd_conn_on_close, &d->app) != 0) { return -1; }
    d->app.ev = &d->ev;

    if (listener_open_loopback(0, 16, &d->lfd, &d->port) != LISTENER_OK) { return -1; }
    if (evloop_add_listener(&d->ev, d->lfd, (uid_t)-1) != 0) { return -1; }

    if (with_local) {
        if (evloop_set_local(&d->ev, d->local_slots, H_MAX_LOCAL, localapi_on_line) != 0) { return -1; }
        const uid_t me[1] = { getuid() };
        snprintf(d->site_path, sizeof d->site_path, "%s/site.sock", dir);
        snprintf(d->admin_path, sizeof d->admin_path, "%s/admin.sock", dir);
        if (listener_open_unix(d->site_path, 8, LISTENER_MODE_GROUP, &d->site_fd) != LISTENER_OK) { return -1; }
        if (evloop_add_local_listener(&d->ev, d->site_fd, me, 1u, 0) != 0) { return -1; }
        if (listener_open_unix(d->admin_path, 8, LISTENER_MODE_PRIVATE, &d->admin_fd) != LISTENER_OK) { return -1; }
        if (evloop_add_local_listener(&d->ev, d->admin_fd, me, 1u, 1) != 0) { return -1; }
    }
    return 0;
}

static inline void h_stop(h_daemon_t *d)
{
    evloop_close_all(&d->ev);
    listener_close(&d->lfd, NULL);
    listener_close(&d->site_fd, d->site_path[0] ? d->site_path : NULL);
    listener_close(&d->admin_fd, d->admin_path[0] ? d->admin_path : NULL);
    handshake_pending_store_wipe(&d->pending);
    if (d->store != NULL) { store_close(d->store); d->store = NULL; }
    mldsa_keypair_free(&d->server_kp);
}

static inline void h_tick(h_daemon_t *d) { (void)evloop_run_once(&d->ev, 5, d->app.now_ms); }

/* Ticks until `pred` holds or the ceiling is reached; 1 if it held. Never a
 * fixed iteration count (memory: evloop-test-timing-risk). */
#define H_PUMP_UNTIL(d, pred) ({ int _ok = 0; for (int _i = 0; _i < 3000; _i++) { \
    if (pred) { _ok = 1; break; } h_tick(d); } _ok; })

/* ------------------------------------------------------------- framed I/O */

static inline void h_put_be32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static inline uint32_t h_get_be32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

static inline int h_dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) { (void)close(fd); return -1; }
    return fd;
}

static inline int h_dial_unix(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    /* An explicit bound rather than snprintf's silent truncation. gcc at -O2
     * refuses the snprintf outright (-Werror=format-truncation), and it is
     * right to: a truncated sun_path connects to a DIFFERENT socket. */
    const size_t plen = strlen(path);
    if (plen >= sizeof a.sun_path) { (void)close(fd); return -1; }
    memcpy(a.sun_path, path, plen + 1u);
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) { (void)close(fd); return -1; }
    /* NON-BLOCKING, and it matters: the daemon runs in THIS thread, so a
     * blocking write that fills the socket buffer would deadlock -- nothing
     * would ever drain it. A request near the 8192-byte line cap is larger
     * than a default Unix socket buffer, so this is not hypothetical: it hung
     * the first run of the over-cap test. */
    const int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) { (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK); }
    return fd;
}

/* Writes every byte, ticking the daemon whenever the socket is full so the
 * reader on the other side of this thread can make room. */
static inline int h_write_all(h_daemon_t *d, int fd, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t off = 0;
    for (int i = 0; i < 20000 && off < n; i++) {
        const ssize_t w = write(fd, b + off, n - off);
        if (w > 0) {
            off += (size_t)w;
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            h_tick(d);
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return (off == n) ? 0 : -1;
}

static inline int h_send_frame(int fd, const uint8_t *p, size_t n)
{
    uint8_t hdr[4]; h_put_be32(hdr, (uint32_t)n);
    if (write(fd, hdr, 4) != 4) { return -1; }
    return (write(fd, p, n) == (ssize_t)n) ? 0 : -1;
}

static inline int h_recv_frame(h_daemon_t *d, int fd, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t hdr[4];
    size_t got = 0;
    for (int i = 0; i < 3000 && got < 4u; i++) {
        h_tick(d);
        const ssize_t n = recv(fd, hdr + got, 4u - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; } else if (n == 0) { return -1; }
    }
    if (got != 4u) { return -1; }
    const uint32_t len = h_get_be32(hdr);
    if (len == 0u || (size_t)len > cap) { return -1; }
    got = 0;
    for (int i = 0; i < 5000 && got < (size_t)len; i++) {
        h_tick(d);
        const ssize_t n = recv(fd, out + got, (size_t)len - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; } else if (n == 0) { return -1; }
    }
    if (got != (size_t)len) { return -1; }
    *out_len = got;
    return 0;
}

/* --------------------------------------------------------- local-API I/O */

/* Sends one request line and collects the whole response: a single line, or
 * everything up to and including the "END" line for a list. */
/* True when `buf` holds a complete response: an ERR line always terminates,
 * a list ends at a line that is exactly "END", anything else is one line. */
static inline int h_reply_complete(const char *buf, size_t len, int is_list)
{
    const char *nl = memchr(buf, '\n', len);
    if (nl == NULL) { return 0; }
    if (strncmp(buf, "ERR ", 4) == 0 || !is_list) { return 1; }
    const char *line = nl + 1;
    const char *end = buf + len;
    while (line < end) {
        const char *e = memchr(line, '\n', (size_t)(end - line));
        if (e == NULL) { return 0; }
        if ((size_t)(e - line) == 3u && memcmp(line, "END", 3) == 0) { return 1; }
        line = e + 1;
    }
    return 0;
}

static inline int h_local_cmd(h_daemon_t *d, int fd, const char *req, char *out, size_t cap)
{
    /* The CALLER's command decides, never the reply's prefix. */
    char cmd[32];
    size_t ci = 0;
    while (req[ci] != '\0' && req[ci] != ' ' && ci + 1u < sizeof cmd) { cmd[ci] = req[ci]; ci++; }
    cmd[ci] = '\0';
    const int h_expects_list = localcli_is_list_command(cmd);
    const size_t n = strlen(req);
    if (h_write_all(d, fd, req, n) != 0 || h_write_all(d, fd, "\n", 1) != 0) { return -1; }
    size_t got = 0;
    out[0] = '\0';
    for (int i = 0; i < 5000; i++) {
        h_tick(d);
        char buf[1024];
        const ssize_t r = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (r > 0) {
            if (got + (size_t)r >= cap) { return -1; }
            memcpy(out + got, buf, (size_t)r);
            got += (size_t)r;
            out[got] = '\0';
            /* complete when a list has ended, or a single line has arrived */
            /* THE framing rule lives in ONE place: localcli_is_list_command().
             * This used to classify any "OK count=" reply as a list, which is
             * wrong -- REVOKE-TOKENS answers OK count=N on a single line -- and
             * it survived only because no test sent that command through here.
             * A second copy of a subtle rule is a second rule. */
            if (h_reply_complete(out, got, h_expects_list)) { return 0; }
        } else if (r == 0) {
            return (got > 0) ? 0 : -1;
        }
    }
    return (got > 0) ? 0 : -1;
}

/* Sends a request and pumps a FIXED number of ticks, returning whatever
 * arrived, with no completion heuristic at all.
 *
 * It exists so a test can measure what shape a command's reply actually has
 * WITHOUT consulting localcli_is_list_command() -- which is the table under
 * test. Using h_local_cmd() there would compare the table against itself. */
static inline int h_local_drain(h_daemon_t *d, int fd, const char *req, char *out, size_t cap)
{
    const size_t n = strlen(req);
    if (h_write_all(d, fd, req, n) != 0 || h_write_all(d, fd, "\n", 1) != 0) { return -1; }
    size_t got = 0;
    out[0] = '\0';
    for (int i = 0; i < 800; i++) {
        h_tick(d);
        char buf[1024];
        const ssize_t r = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (r > 0) {
            if (got + (size_t)r >= cap) { return -1; }
            memcpy(out + got, buf, (size_t)r);
            got += (size_t)r;
            out[got] = '\0';
        }
    }
    return (got > 0) ? 0 : -1;
}

/* ------------------------------------------------------------- the client */

typedef struct {
    int             fd;
    handshake_ctx_t hs;
    session_t       sess;
    keystore_t      pins;
} h_client_t;

/* The real library initiator over a real socket. Returns 0 when the client
 * side completed (optimistically -- the server may still reject sig_A). */
static inline int h_login(h_daemon_t *d, h_client_t *c, const uint8_t *handle, size_t handle_len,
                          const mldsa_keypair_t *kp)
{
    memset(c, 0, sizeof *c);
    keystore_init(&c->pins);
    if (keystore_add(&c->pins, H_SERVER_ID, sizeof H_SERVER_ID, d->server_kp.public_key) != KEYSTORE_OK) {
        return -1;
    }
    c->fd = h_dial(d->port);
    if (c->fd < 0) { return -1; }
    if (!H_PUMP_UNTIL(d, evloop_active(&d->ev) >= 1u)) { return -1; }

    if (handshake_initiator_init(&c->hs, handle, handle_len, kp, &c->pins,
                                 H_SERVER_ID, sizeof H_SERVER_ID) != HANDSHAKE_OK) { return -1; }
    uint8_t buf[AUTHD_FRAME_MAX];
    size_t n = 0;
    if (handshake_initiator_create_client_hello(&c->hs, buf, sizeof buf, &n) != HANDSHAKE_OK) { return -1; }
    if (h_send_frame(c->fd, buf, n) != 0) { return -1; }
    size_t sh = 0;
    if (h_recv_frame(d, c->fd, buf, sizeof buf, &sh) != 0) { return -1; }
    if (handshake_initiator_verify_server_hello(&c->hs, buf, sh) != HANDSHAKE_OK) { return -2; }
    if (handshake_initiator_create_client_auth(&c->hs, buf, sizeof buf, &n) != HANDSHAKE_OK) { return -1; }
    if (h_send_frame(c->fd, buf, n) != 0) { return -1; }
    if (handshake_initiator_finish(&c->hs) != HANDSHAKE_OK) { return -1; }

    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = 256u;
    if (session_init_from_handshake(&c->sess, &c->hs, &lim, NULL, NULL) != SESSION_OK) { return -1; }
    return 0;
}

static inline void h_client_close(h_client_t *c)
{
    if (c->fd >= 0) { (void)close(c->fd); c->fd = -1; }
    session_wipe(&c->sess);
    handshake_ctx_wipe(&c->hs);
    keystore_wipe(&c->pins);
}

/* Completes a login and returns the 32-byte login code from the first record. */
static inline int h_get_login_code(h_daemon_t *d, h_client_t *c, uint8_t code_out[32])
{
    uint8_t rec[AUTHD_MAX_RECORD], pt[AUTHD_MAX_RECORD];
    size_t rec_len = 0, pt_len = 0;
    if (h_recv_frame(d, c->fd, rec, sizeof rec, &rec_len) != 0) { return -1; }
    if (session_open(&c->sess, rec, rec_len, pt, sizeof pt, &pt_len) != SESSION_OK) { return -1; }
    if (pt_len != 43u || pt[0] != 0x10u) { return -1; }
    memcpy(code_out, pt + 3, 32u);
    sodium_memzero(pt, sizeof pt);
    return 0;
}

static inline void h_hex(char *out, size_t cap, const uint8_t *p, size_t n)
{
    (void)sodium_bin2hex(out, cap, p, n);
}

#endif /* MLDSA_AUTHD_TEST_HARNESS_H */
