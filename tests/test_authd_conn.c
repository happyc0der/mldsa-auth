/*
 * V4-8b: the daemon's connection state machine -- the first step at which the
 * daemon actually serves a login.
 *
 * The daemon runs IN-PROCESS here (the same evloop + authd_app the binary
 * builds) rather than as a subprocess, so the test controls its clock exactly
 * and can read its counters and slot state directly. The client is the real
 * library initiator over a real loopback socket, so nothing about the
 * handshake is simulated.
 *
 * Two habits carried forward deliberately:
 *  - pump-until-condition, never a fixed iteration count. V4-8a's fixed pumps
 *    are the one timing risk on record (memory: evloop-test-timing-risk);
 *    this file does not repeat them.
 *  - present canaries. Every "X is absent" check is preceded by proof that X
 *    was observable in the first place.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <sodium.h>

#include "authd_conn.h"
#include "authd_log.h"
#include "authmsg.h"
#include "conn_io.h"
#include "evloop.h"
#include "listener.h"
#include "store.h"
#include "handshake.h"
#include "keystore.h"
#include "session.h"
#include "transcript.h"

static int g_fail = 0;
static int g_checks = 0;
static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) { printf("FAIL: %s\n", what); g_fail = 1; }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

static char g_dir[256];

static const uint8_t SERVER_ID[] = { 'a','u','t','h','d' };
static const uint8_t USER1[]     = { 'u','1' };
static const uint8_t HANDLE1[]   = { 'd','1','a','a' };
static const uint8_t HANDLE_UNK[]= { 'd','1','z','z' };
static const uint8_t KEK[32] = {
    1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 17,18,19,20,21,22,23,24, 25,26,27,28,29,30,31,32 };

/* ----------------------------------------------------------- the daemon */

typedef struct {
    evloop_t                  ev;
    authd_app_t               app;
    authd_slot_t             *slots;
    authd_conn_t             *conns;
    handshake_pending_store_t pending;
    store_t                  *store;
    mldsa_keypair_t           server_kp;
    int                       lfd;
    uint16_t                  port;
    size_t                    nslots;
} daemon_t;

static int daemon_start(daemon_t *d, size_t nslots, const char *dbname)
{
    memset(d, 0, sizeof *d);
    d->nslots = nslots;
    d->lfd = -1;
    if (mldsa_keypair_generate(&d->server_kp) != 0) { return -1; }

    char db[512];
    snprintf(db, sizeof db, "%s/%s", g_dir, dbname);
    (void)unlink(db);
    if (store_open(db, KEK, &d->store) != STORE_OK) { return -1; }

    d->slots = calloc(nslots, sizeof *d->slots);
    d->conns = calloc(nslots, sizeof *d->conns);
    if (d->slots == NULL || d->conns == NULL) { return -1; }

    d->app.conns = d->conns;
    d->app.n_conns = nslots;
    d->app.store = d->store;
    d->app.server_kp = &d->server_kp;
    d->app.server_id = SERVER_ID;
    d->app.server_id_len = sizeof SERVER_ID;
    d->app.pad_bucket = 256u;
    d->app.code_ttl_s = AUTHD_LOGIN_CODE_TTL_S;
    d->app.now_ms = 1000u;
    d->app.now_unix = 1700000000;

    if (handshake_pending_store_init(&d->pending, nslots < 256u ? nslots : 256u,
                                     10000u, authd_app_clock, &d->app) != PENDING_OK) { return -1; }
    d->app.pending = &d->pending;

    if (evloop_init(&d->ev, d->slots, nslots, 10000u, 60000u,
                    authd_conn_on_frame, authd_conn_on_close, &d->app) != 0) { return -1; }
    if (listener_open_loopback(0, 16, &d->lfd, &d->port) != LISTENER_OK) { return -1; }
    if (evloop_add_listener(&d->ev, d->lfd, (uid_t)-1) != 0) { return -1; }
    return 0;
}

static void daemon_stop(daemon_t *d)
{
    evloop_close_all(&d->ev);
    listener_close(&d->lfd, NULL);
    handshake_pending_store_wipe(&d->pending);
    if (d->store != NULL) { store_close(d->store); }
    mldsa_keypair_free(&d->server_kp);
    free(d->slots);
    free(d->conns);
}

static void daemon_tick(daemon_t *d) { (void)evloop_run_once(&d->ev, 5, d->app.now_ms); }

/* ---------------------------------------------------- framed client I/O */

static void put_be32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static uint32_t get_be32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

static int dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) { (void)close(fd); return -1; }
    return fd;
}

static int send_frame(int fd, const uint8_t *p, size_t n)
{
    uint8_t hdr[4]; put_be32(hdr, (uint32_t)n);
    if (write(fd, hdr, 4) != 4) { return -1; }
    return (write(fd, p, n) == (ssize_t)n) ? 0 : -1;
}

/* Reads one frame, ticking the daemon until the bytes appear. Bounded by a
 * generous ceiling so a genuine hang still fails rather than spinning. */
static int recv_frame(daemon_t *d, int fd, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t hdr[4];
    size_t got = 0;
    for (int i = 0; i < 2000 && got < 4u; i++) {
        daemon_tick(d);
        const ssize_t n = recv(fd, hdr + got, 4u - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; }
        else if (n == 0) { return -1; }
    }
    if (got != 4u) { return -1; }
    const uint32_t len = get_be32(hdr);
    if (len == 0u || (size_t)len > cap) { return -1; }
    got = 0;
    for (int i = 0; i < 4000 && got < (size_t)len; i++) {
        daemon_tick(d);
        const ssize_t n = recv(fd, out + got, (size_t)len - got, MSG_DONTWAIT);
        if (n > 0) { got += (size_t)n; }
        else if (n == 0) { return -1; }
    }
    if (got != (size_t)len) { return -1; }
    *out_len = got;
    return 0;
}

/* Ticks until `pred` or the ceiling; returns 1 if the predicate held. */
#define PUMP_UNTIL(d, pred) ({ int _ok = 0; for (int _i = 0; _i < 2000; _i++) { \
    if (pred) { _ok = 1; break; } daemon_tick(d); } _ok; })

/* --------------------------------------------------------- the client */

typedef struct {
    int             fd;
    handshake_ctx_t hs;
    session_t       sess;
    keystore_t      pins;
    int             established;
} client_t;

/* Runs the handshake as the real library initiator. `kp` is the device key it
 * signs with -- pass a key the daemon does not know to exercise the decoy and
 * wrong-key paths. Returns 0 if the handshake completed on the client side
 * (which, per spec-v2, is OPTIMISTIC: the server may still reject sig_A). */
static int client_handshake(daemon_t *d, client_t *c, const uint8_t *handle, size_t handle_len,
                            const mldsa_keypair_t *kp)
{
    memset(c, 0, sizeof *c);
    keystore_init(&c->pins);
    if (keystore_add(&c->pins, SERVER_ID, sizeof SERVER_ID, d->server_kp.public_key) != KEYSTORE_OK) {
        return -1;
    }
    c->fd = dial(d->port);
    if (c->fd < 0) { return -1; }
    if (!PUMP_UNTIL(d, evloop_active(&d->ev) >= 1u)) { return -1; }

    if (handshake_initiator_init(&c->hs, handle, handle_len, kp, &c->pins,
                                 SERVER_ID, sizeof SERVER_ID) != HANDSHAKE_OK) { return -1; }

    uint8_t buf[AUTHD_FRAME_MAX];
    size_t n = 0;
    if (handshake_initiator_create_client_hello(&c->hs, buf, sizeof buf, &n) != HANDSHAKE_OK) { return -1; }
    if (send_frame(c->fd, buf, n) != 0) { return -1; }

    size_t sh_len = 0;
    if (recv_frame(d, c->fd, buf, sizeof buf, &sh_len) != 0) { return -1; }
    if (handshake_initiator_verify_server_hello(&c->hs, buf, sh_len) != HANDSHAKE_OK) { return -2; }

    if (handshake_initiator_create_client_auth(&c->hs, buf, sizeof buf, &n) != HANDSHAKE_OK) { return -1; }
    if (send_frame(c->fd, buf, n) != 0) { return -1; }
    if (handshake_initiator_finish(&c->hs) != HANDSHAKE_OK) { return -1; }

    session_limits_t lim;
    session_default_limits(&lim);
    lim.pad_bucket = 256u;
    if (session_init_from_handshake(&c->sess, &c->hs, &lim, NULL, NULL) != SESSION_OK) { return -1; }
    c->established = 1;
    return 0;
}

static void client_close(client_t *c)
{
    if (c->fd >= 0) { (void)close(c->fd); c->fd = -1; }
    session_wipe(&c->sess);
    handshake_ctx_wipe(&c->hs);
    keystore_wipe(&c->pins);
}

/* --------------------------------------------------------------- tests */

static void enroll(daemon_t *d, const uint8_t *handle, size_t hl, const mldsa_keypair_t *kp)
{
    (void)store_add_user(d->store, USER1, sizeof USER1, STORE_ROLE_USER);
    CHECK(store_enroll_device(d->store, handle, hl, USER1, sizeof USER1,
                              kp->public_key, "site", "test", NULL, 0) == STORE_OK, "fixture: enroll");
}

/* The happy path, and everything the login code must satisfy. */
static void test_login(void)
{
    daemon_t d; client_t c;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 4, "login.sqlite3") == 0, "login: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "login: device key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);

    CHECK(client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "login: handshake completes");

    uint8_t rec[AUTHD_MAX_RECORD];
    size_t rec_len = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &rec_len) == 0, "login: first record arrives");
    CHECK(rec_len == 281u, "login: the first record is 281 bytes (spec 6.2 at bucket 256)");

    uint8_t pt[AUTHD_MAX_RECORD];
    size_t pt_len = 0;
    CHECK(session_open(&c.sess, rec, rec_len, pt, sizeof pt, &pt_len) == SESSION_OK,
          "login: the first record authenticates");
    CHECK(pt_len == AUTHMSG_LOGIN_CODE_CONTENT_LEN, "login: content is 43 bytes");
    CHECK(pt_len > 0 && pt[0] == AUTHMSG_OP_LOGIN_CODE, "login: the first record is LOGIN_CODE (0x10)");

    authmsg_login_code_t m;
    CHECK(authmsg_decode_login_code(pt, pt_len, &m) == AUTHMSG_OK, "login: LOGIN_CODE decodes");
    CHECK(m.flags == 0u, "login: rotation_due is clear (V4-9 policy)");
    CHECK(m.code_expires > (uint64_t)d.app.now_unix &&
          m.code_expires - (uint64_t)d.app.now_unix <= 60u,
          "login: the code expires in at most 60 s (Req 5)");
    { int nz = 0; for (size_t i = 0; i < sizeof m.code; i++) { if (m.code[i]) nz = 1; }
      CHECK(nz, "login: the code is not all-zero"); }
    CHECK(d.app.logins_issued == 1u, "login: one login counted");
    CHECK(d.app.decoy_pins == 0u, "login: a known identity did NOT get the decoy");

    /* Req 4 + Req 5: the store holds SHA-256(code), bound to this handshake
     * and to SHA-256(state). Consuming proves both halves. */
    uint8_t code_hash[STORE_HASH_BYTES], state_ok[STORE_HASH_BYTES], state_bad[STORE_HASH_BYTES];
    crypto_hash_sha256(code_hash, m.code, sizeof m.code);
    crypto_hash_sha256(state_ok, (const uint8_t *)"", 0u);
    crypto_hash_sha256(state_bad, (const uint8_t *)"other", 5u);

    uint8_t uid[STORE_ID_MAX], hnd[STORE_ID_MAX];
    size_t uidl = 0, hndl = 0;
    CHECK(store_consume_login_code(d.store, code_hash, state_bad, d.app.now_unix,
                                   uid, sizeof uid, &uidl, hnd, sizeof hnd, &hndl) == STORE_ERR_CONFLICT,
          "login: the code is REFUSED against a different state (login-CSRF binding)");
    CHECK(store_consume_login_code(d.store, code_hash, state_ok, d.app.now_unix,
                                   uid, sizeof uid, &uidl, hnd, sizeof hnd, &hndl) == STORE_OK &&
          uidl == sizeof USER1 && memcmp(uid, USER1, uidl) == 0 &&
          hndl == sizeof HANDLE1 && memcmp(hnd, HANDLE1, hndl) == 0,
          "login: the code is bound to the right user and handle");
    CHECK(store_consume_login_code(d.store, code_hash, state_ok, d.app.now_unix,
                                   NULL, 0, NULL, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
          "login: the code is single-use (Req 5)");

    /* BYE closes cleanly. */
    uint8_t bye[AUTHMSG_BYE_CONTENT_LEN]; size_t bl = 0;
    CHECK(authmsg_encode_bye(bye, sizeof bye, &bl) == AUTHMSG_OK, "login: encode BYE");
    size_t out_len = 0;
    CHECK(session_seal(&c.sess, bye, bl, rec, sizeof rec, &out_len) == SESSION_OK, "login: seal BYE");
    CHECK(send_frame(c.fd, rec, out_len) == 0, "login: send BYE");
    CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "login: the daemon closes the connection on BYE");

    sodium_memzero(&m, sizeof m);
    client_close(&c);
    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

/* Req 6: unknown / revoked identities are indistinguishable from a known
 * identity whose signature is wrong. */
static void test_uniform_responder(void)
{
    daemon_t d;
    mldsa_keypair_t good, other;
    CHECK(daemon_start(&d, 4, "decoy.sqlite3") == 0, "decoy: daemon starts");
    CHECK(mldsa_keypair_generate(&good) == 0 && mldsa_keypair_generate(&other) == 0, "decoy: keys");
    enroll(&d, HANDLE1, sizeof HANDLE1, &good);

    size_t sh_known = 0, sh_unknown = 0;
    int rc_known = 0, rc_unknown = 0;

    /* (a) a KNOWN handle signing with the WRONG key */
    {
        client_t c;
        rc_known = client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &other);
        sh_known = 1;   /* the handshake got far enough to verify a ServerHello */
        uint8_t rec[AUTHD_MAX_RECORD]; size_t n = 0;
        CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) != 0,
              "decoy: a wrong-key client receives NO record");
        client_close(&c);
        CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "decoy: wrong-key connection closed");
    }
    /* (b) an UNKNOWN handle */
    {
        client_t c;
        rc_unknown = client_handshake(&d, &c, HANDLE_UNK, sizeof HANDLE_UNK, &other);
        sh_unknown = 1;
        uint8_t rec[AUTHD_MAX_RECORD]; size_t n = 0;
        CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) != 0,
              "decoy: an unknown-handle client receives NO record");
        client_close(&c);
        CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "decoy: unknown-handle connection closed");
    }

    CHECK(rc_known == rc_unknown && sh_known == sh_unknown,
          "decoy: known-wrong-key and unknown-handle reach the SAME client-side outcome");
    CHECK(d.app.decoy_pins == 1u, "decoy: exactly the unknown handle got the decoy pin");
    CHECK(d.app.logins_issued == 0u, "decoy: neither connection was issued a login code");

    /* Present canary: the decoy path really did produce a full, verifiable
     * ServerHello -- otherwise "indistinguishable" would be trivially true
     * because neither side got anything. */
    CHECK(rc_unknown == 0, "decoy: the unknown handle still got a VERIFIABLE ServerHello (canary)");

    mldsa_keypair_free(&good); mldsa_keypair_free(&other);
    daemon_stop(&d);
}

/* Req 9's "next handshake" half: a revoked device fails exactly like unknown. */
static void test_revoked(void)
{
    daemon_t d; client_t c;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 4, "revoked.sqlite3") == 0, "revoked: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "revoked: key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);

    CHECK(client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "revoked: first login works");
    uint8_t rec[AUTHD_MAX_RECORD]; size_t n = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) == 0, "revoked: code issued before revocation (canary)");
    client_close(&c);
    (void)PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u);

    CHECK(store_revoke_device(d.store, HANDLE1, sizeof HANDLE1, "test", NULL, 0) == STORE_OK,
          "revoked: revoke the device");

    const uint64_t decoys_before = d.app.decoy_pins;
    client_t c2;
    (void)client_handshake(&d, &c2, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(recv_frame(&d, c2.fd, rec, sizeof rec, &n) != 0,
          "revoked: after revocation the SAME key gets no login code");
    CHECK(d.app.decoy_pins == decoys_before + 1u,
          "revoked: a revoked device is served the decoy, exactly like an unknown one");
    CHECK(d.app.logins_issued == 1u, "revoked: still only the pre-revocation login");
    client_close(&c2);
    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

/* After LOGIN_CODE only BYE is permitted; ROTATE is V4-9's and is refused. */
static void test_not_permitted(void)
{
    daemon_t d; client_t c;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 4, "notperm.sqlite3") == 0, "notperm: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "notperm: key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "notperm: handshake");

    uint8_t rec[AUTHD_MAX_RECORD]; size_t n = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) == 0, "notperm: login code received");
    uint8_t pt[AUTHD_MAX_RECORD]; size_t pl = 0;
    CHECK(session_open(&c.sess, rec, n, pt, sizeof pt, &pl) == SESSION_OK, "notperm: open it");

    /* a syntactically plausible ROTATE */
    uint8_t rot[8]; rot[0] = AUTHMSG_OP_ROTATE; rot[1] = 0x01u; memset(rot + 2, 0, 6);
    size_t out_len = 0;
    CHECK(session_seal(&c.sess, rot, sizeof rot, rec, sizeof rec, &out_len) == SESSION_OK, "notperm: seal ROTATE");
    CHECK(send_frame(c.fd, rec, out_len) == 0, "notperm: send ROTATE");

    size_t er = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &er) == 0, "notperm: the daemon replies");
    CHECK(session_open(&c.sess, rec, er, pt, sizeof pt, &pl) == SESSION_OK, "notperm: the reply authenticates");
    uint8_t code = 0;
    CHECK(authmsg_decode_error(pt, pl, &code) == AUTHMSG_OK && code == AUTHMSG_ERR_NOT_PERMITTED,
          "notperm: ROTATE is refused with ERROR(0x02 not permitted), not served");
    CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "notperm: the connection is closed after ERROR");

    client_close(&c);
    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

/* Secrets do not outlive the connection. */
static void test_wipe_on_close(void)
{
    daemon_t d; client_t c;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 2, "wipe.sqlite3") == 0, "wipe: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "wipe: key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "wipe: handshake");
    uint8_t rec[AUTHD_MAX_RECORD]; size_t n = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) == 0, "wipe: login code received");

    /* present canary: the connection really is holding live state */
    int live = 0;
    for (size_t i = 0; i < d.nslots; i++) {
        if (d.conns[i].stage == CONN_STAGE_SERVING &&
            session_get_state(&d.conns[i].sess) == SESSION_STATE_ACTIVE &&
            d.conns[i].handle_len == sizeof HANDLE1) { live = 1; }
    }
    CHECK(live, "wipe: a serving connection holds an ACTIVE session and its handle (canary)");

    client_close(&c);
    (void)PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u);
    evloop_close_all(&d.ev);

    int residue = 0;
    for (size_t i = 0; i < d.nslots; i++) {
        if (d.conns[i].stage != CONN_STAGE_FREE) { residue = 1; }
        if (d.conns[i].handle_len != 0u || d.conns[i].user_id_len != 0u) { residue = 1; }
        if (session_get_state(&d.conns[i].sess) != SESSION_STATE_EMPTY) { residue = 1; }
        if (memmem(d.conns[i].handle, sizeof d.conns[i].handle, HANDLE1, sizeof HANDLE1) != NULL) { residue = 1; }
    }
    CHECK(!residue, "wipe: closing a connection clears its session, handle and identity");

    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

/* The wipe above runs on a SUCCESSFUL connection -- where
 * session_init_from_handshake has already consumed the handshake context, so
 * conn_reset's handshake_ctx_wipe is a no-op and cannot be distinguished.
 * The path where it matters is a connection abandoned MID-HANDSHAKE: the
 * context is still live, and wiping it is what CANCELS its pending-ledger
 * entry (handshake_ctx_wipe's documented cancellation behaviour). Without
 * that, an abandoned handshake holds ledger capacity until its TTL -- which
 * at 256 entries is a denial-of-service lever, not a tidiness question. */
static void test_abandoned_handshake_frees_ledger(void)
{
    daemon_t d;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 4, "abandon.sqlite3") == 0, "abandon: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "abandon: key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);

    CHECK(handshake_pending_active_count(&d.pending) == 0u, "abandon: ledger starts empty");

    /* Send ONLY the ClientHello, then walk away. */
    client_t c;
    memset(&c, 0, sizeof c);
    keystore_init(&c.pins);
    CHECK(keystore_add(&c.pins, SERVER_ID, sizeof SERVER_ID, d.server_kp.public_key) == KEYSTORE_OK,
          "abandon: pin the server");
    c.fd = dial(d.port);
    CHECK(c.fd >= 0, "abandon: connect");
    CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) >= 1u), "abandon: accepted");
    CHECK(handshake_initiator_init(&c.hs, HANDLE1, sizeof HANDLE1, &kp, &c.pins,
                                   SERVER_ID, sizeof SERVER_ID) == HANDSHAKE_OK, "abandon: init");
    uint8_t buf[AUTHD_FRAME_MAX];
    size_t n = 0;
    CHECK(handshake_initiator_create_client_hello(&c.hs, buf, sizeof buf, &n) == HANDSHAKE_OK,
          "abandon: build ClientHello");
    CHECK(send_frame(c.fd, buf, n) == 0, "abandon: send ClientHello");

    /* The ServerHello comes back, which means the entry is in the ledger. */
    size_t sh = 0;
    CHECK(recv_frame(&d, c.fd, buf, sizeof buf, &sh) == 0, "abandon: ServerHello received");
    CHECK(handshake_pending_active_count(&d.pending) == 1u,
          "abandon: the handshake occupies one ledger entry (canary)");

    /* Now abandon it. */
    client_close(&c);
    CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "abandon: the daemon closes the connection");
    CHECK(handshake_pending_active_count(&d.pending) == 0u,
          "abandon: closing mid-handshake RELEASES the ledger entry immediately");

    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

int main(void)
{
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);   /* keep daemon chatter out of the output */
    snprintf(g_dir, sizeof g_dir, "authd-conn-%ld", (long)getpid());
    if (mkdir(g_dir, 0700) != 0) { printf("FAIL: mkdir\n"); return 1; }

    test_login();
    test_uniform_responder();
    test_revoked();
    test_not_permitted();
    test_wipe_on_close();
    test_abandoned_handshake_frees_ledger();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      /* Best-effort cleanup. The result IS consumed: gcc declares system()
       * warn_unused_result and a (void) cast does not silence it -- the same
       * portability trap V4-5 fixed for symlink() (audit finding F0). */
      if (system(cmd) != 0) { /* the scratch dir outlives the run; harmless */ } }
    printf("%s: test_authd_conn (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
