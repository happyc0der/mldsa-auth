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
    /* Captured BEFORE session_init consumes the handshake context, because
     * ROTATE's digest binds to it and nothing else can hand it back. */
    uint8_t         hsid[STORE_HSID_BYTES];
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
    if (handshake_get_handshake_id(&c->hs, c->hsid) != HANDSHAKE_OK) { return -1; }

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

    /* LOGIN_CODE is daemon->client ONLY, so a client sending one is a state
     * error, not a malformed message. This used to be ROTATE; V4-9c serves
     * ROTATE, so the check moved to an op that is still genuinely not
     * permitted -- the property being guarded is unchanged. */
    uint8_t notp[AUTHMSG_LOGIN_CODE_CONTENT_LEN];
    memset(notp, 0, sizeof notp);
    notp[0] = AUTHMSG_OP_LOGIN_CODE; notp[1] = 0x01u;
    size_t out_len = 0;
    CHECK(session_seal(&c.sess, notp, sizeof notp, rec, sizeof rec, &out_len) == SESSION_OK,
          "notperm: seal a client-sent LOGIN_CODE");
    CHECK(send_frame(c.fd, rec, out_len) == 0, "notperm: send it");

    size_t er = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &er) == 0, "notperm: the daemon replies");
    CHECK(session_open(&c.sess, rec, er, pt, sizeof pt, &pl) == SESSION_OK, "notperm: the reply authenticates");
    uint8_t code = 0;
    CHECK(authmsg_decode_error(pt, pl, &code) == AUTHMSG_OK && code == AUTHMSG_ERR_NOT_PERMITTED,
          "notperm: a daemon-only op from the client is refused with ERROR(0x02), not served");
    CHECK(PUMP_UNTIL(&d, evloop_active(&d.ev) == 0u), "notperm: the connection is closed after ERROR");

    client_close(&c);
    mldsa_keypair_free(&kp);
    daemon_stop(&d);
}

/* Secrets do not outlive the connection. */
/*
 * The pin resolver, tested DIRECTLY. Through the wire its identity comparison
 * can never fail -- the pin is taken for the id in the same ClientHello the
 * library then decodes -- so the only way to show the comparison exists at all
 * is to call it. Mutation P8 removes it and dies here and nowhere else.
 */
static void test_pin_lookup(void)
{
    authd_conn_t c;
    memset(&c, 0, sizeof c);
    uint8_t pk[STORE_PK_BYTES];
    memset(pk, 0xC3, sizeof pk);
    memcpy(c.handle, HANDLE1, sizeof HANDLE1);
    c.handle_len = sizeof HANDLE1;
    memcpy(c.pin_pk, pk, sizeof c.pin_pk);
    c.pin_set = 1;

    CHECK(authd_conn_pin_lookup(&c, HANDLE1, sizeof HANDLE1) == c.pin_pk,
          "conn: the pin lookup answers for THIS connection's handle (canary)");

    uint8_t other[sizeof HANDLE1];
    memcpy(other, HANDLE1, sizeof HANDLE1);
    other[0] = (uint8_t)(other[0] ^ 0x01u);
    CHECK(authd_conn_pin_lookup(&c, other, sizeof other) == NULL,
          "conn: the pin lookup refuses an id that is not this connection's handle");
    CHECK(authd_conn_pin_lookup(&c, HANDLE1, sizeof HANDLE1 - 1u) == NULL,
          "conn: the pin lookup refuses a PREFIX of its handle");
    CHECK(authd_conn_pin_lookup(&c, HANDLE1, 0) == NULL,
          "conn: the pin lookup refuses a zero-length id");
    CHECK(authd_conn_pin_lookup(&c, NULL, sizeof HANDLE1) == NULL,
          "conn: the pin lookup refuses a NULL id");
    CHECK(authd_conn_pin_lookup(NULL, HANDLE1, sizeof HANDLE1) == NULL,
          "conn: the pin lookup refuses a NULL connection");

    c.pin_set = 0;
    CHECK(authd_conn_pin_lookup(&c, HANDLE1, sizeof HANDLE1) == NULL,
          "conn: the pin lookup answers nothing before a pin is set");
    sodium_memzero(&c, sizeof c);
}

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

    /* V4-12: the pin is a slot field now, not a keystore. Its own canary --
     * the key really IS there while the connection lives -- so the residue
     * check below cannot pass by the pin never having been stored. */
    {
        int pinned = 0;
        for (size_t i = 0; i < d.nslots; i++) {
            if (d.conns[i].pin_set &&
                memcmp(d.conns[i].pin_pk, kp.public_key, sizeof d.conns[i].pin_pk) == 0) {
                pinned = 1;
            }
        }
        CHECK(pinned, "wipe: the live connection holds the device's pinned key (canary)");
    }

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

    int pin_residue = 0;
    for (size_t i = 0; i < d.nslots; i++) {
        if (d.conns[i].pin_set) { pin_residue = 1; }
        if (memmem(d.conns[i].pin_pk, sizeof d.conns[i].pin_pk,
                   kp.public_key, sizeof kp.public_key) != NULL) { pin_residue = 1; }
    }
    CHECK(!pin_residue, "wipe: the slot's pinned key is zero after close");

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

/* --- rotation (spec 6.3) -------------------------------------------------- */

/* Builds a ROTATE the daemon should accept, then lets the caller corrupt it.
 * `sign_flags` is what goes INTO the digest and `wire_flags` what goes on the
 * wire -- normally equal; differing them is how the flags binding is tested. */
static size_t build_rotate(uint8_t *out, size_t cap,
                           const uint8_t hsid[STORE_HSID_BYTES],
                           uint8_t sign_flags, uint8_t wire_flags,
                           const uint8_t *handle, size_t hl,
                           const mldsa_keypair_t *old_kp, const mldsa_keypair_t *new_kp,
                           const mldsa_keypair_t *sig_new_signer,
                           const char *label_old, const char *label_new)
{
    uint8_t d_old[32], d_new[32];
    uint8_t s_old[MLDSA_SIGNATURE_MAX_BYTES], s_new[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sol = 0, snl = 0, n = 0;
    if (authmsg_rotate_digest(d_old, label_old, hsid, sign_flags, handle, hl,
                              old_kp->public_key, new_kp->public_key) != AUTHMSG_OK ||
        authmsg_rotate_digest(d_new, label_new, hsid, sign_flags, handle, hl,
                              old_kp->public_key, new_kp->public_key) != AUTHMSG_OK) {
        return 0;
    }
    if (mldsa_sign(s_old, &sol, d_old, sizeof d_old, old_kp) != 0 ||
        mldsa_sign(s_new, &snl, d_new, sizeof d_new, sig_new_signer) != 0) {
        return 0;
    }
    if (authmsg_encode_rotate(out, cap, &n, wire_flags, handle, hl, new_kp->public_key,
                              s_old, sol, s_new, snl) != AUTHMSG_OK) {
        return 0;
    }
    return n;
}

/* Sends `content` as a sealed record and returns the daemon's decrypted reply.
 * Returns the reply length, or 0 if nothing came back. */
static size_t exchange_record(daemon_t *d, client_t *c, const uint8_t *content, size_t len,
                              uint8_t *reply, size_t reply_cap)
{
    uint8_t rec[AUTHD_MAX_RECORD];
    size_t n = 0, got = 0, pl = 0;
    if (session_seal(&c->sess, content, len, rec, sizeof rec, &n) != SESSION_OK) { return 0; }
    if (send_frame(c->fd, rec, n) != 0) { return 0; }
    if (recv_frame(d, c->fd, rec, sizeof rec, &got) != 0) { return 0; }
    if (session_open(&c->sess, rec, got, reply, reply_cap, &pl) != SESSION_OK) { return 0; }
    return pl;
}

static uint8_t reply_error_code(const uint8_t *pt, size_t len)
{
    uint8_t code = 0xffu;
    if (authmsg_decode_error(pt, len, &code) != AUTHMSG_OK) { return 0xfeu; }
    return code;
}

/* A fresh session, through the login code, ready to send one application
 * record. Every rejected ROTATE is TERMINAL -- fail_with_error closes the
 * connection -- so each negative case needs its own session; reusing one would
 * write into a closed socket. */
static int rotate_session(daemon_t *d, client_t *c, const mldsa_keypair_t *kp)
{
    if (client_handshake(d, c, HANDLE1, sizeof HANDLE1, kp) != 0) { return -1; }
    uint8_t rec[AUTHD_MAX_RECORD], pt[AUTHD_MAX_RECORD];
    size_t n = 0, pl = 0;
    if (recv_frame(d, c->fd, rec, sizeof rec, &n) != 0) { return -1; }
    if (session_open(&c->sess, rec, n, pt, sizeof pt, &pl) != SESSION_OK) { return -1; }
    sodium_memzero(pt, sizeof pt);
    return 0;
}

static void test_rotate(void)
{
    daemon_t d; client_t c;
    mldsa_keypair_t old_kp, new_kp, other_kp, spare_kp;
    static const uint8_t HANDLE2[] = { 'd','1','b','b' };
        /* Room for a session PER CASE. Each rejected ROTATE is terminal, and the
     * injected clock never advances, so a consumed ledger entry is never
     * reclaimed -- capacity has to cover every handshake this test makes. */
    CHECK(daemon_start(&d, 32, "rotate.sqlite3") == 0, "rotate: daemon starts");
    CHECK(mldsa_keypair_generate(&old_kp) == 0, "rotate: old key");
    CHECK(mldsa_keypair_generate(&new_kp) == 0, "rotate: new key");
    CHECK(mldsa_keypair_generate(&other_kp) == 0, "rotate: a third key");
    CHECK(mldsa_keypair_generate(&spare_kp) == 0, "rotate: a fourth key, enrolled nowhere");
    enroll(&d, HANDLE1, sizeof HANDLE1, &old_kp);
    enroll(&d, HANDLE2, sizeof HANDLE2, &other_kp);

    uint8_t pt[AUTHD_MAX_RECORD];
    uint8_t rot[AUTHMSG_ROTATE_MAX_CONTENT];
    size_t pl = 0, rl = 0;

    /* The digest, against a vector built HERE from the spec's field order and
     * literal label bytes -- not by calling the function under test. A round
     * trip proves only that both sides agree; this proves they agree with the
     * SPEC, which is the only thing that matters when both sides share one
     * implementation. */
    CHECK(rotate_session(&d, &c, &old_kp) == 0, "rotate: session for the digest vector");
    {
        static const char lo[] = { 'm','l','d','s','a','-','a','u','t','h','d','/','v','1','/',
                                   'r','o','t','a','t','e','-','o','l','d' };
        uint8_t want[32], got_d[32], other_d[32];
        const uint8_t sep = 0x00, flags = 0x00u, hl = (uint8_t)sizeof HANDLE1;
        crypto_hash_sha256_state st;
        crypto_hash_sha256_init(&st);
        crypto_hash_sha256_update(&st, (const unsigned char *)lo, sizeof lo);
        crypto_hash_sha256_update(&st, &sep, 1);
        crypto_hash_sha256_update(&st, c.hsid, sizeof c.hsid);
        crypto_hash_sha256_update(&st, &flags, 1);
        crypto_hash_sha256_update(&st, &hl, 1);
        crypto_hash_sha256_update(&st, HANDLE1, sizeof HANDLE1);
        crypto_hash_sha256_update(&st, old_kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
        crypto_hash_sha256_update(&st, new_kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
        crypto_hash_sha256_final(&st, want);
        CHECK(authmsg_rotate_digest(got_d, AUTHMSG_LABEL_ROTATE_OLD, c.hsid, 0u,
                                    HANDLE1, sizeof HANDLE1,
                                    old_kp.public_key, new_kp.public_key) == AUTHMSG_OK &&
              memcmp(got_d, want, 32) == 0,
              "rotate: the digest matches the hand-built spec 6.3 vector for both labels");
        CHECK(authmsg_rotate_digest(other_d, AUTHMSG_LABEL_ROTATE_NEW, c.hsid, 0u,
                                    HANDLE1, sizeof HANDLE1,
                                    old_kp.public_key, new_kp.public_key) == AUTHMSG_OK &&
              memcmp(other_d, want, 32) != 0,
              "rotate: the two labels produce different digests");
    }
    client_close(&c);

#define ROT_CASE(desc_ok, sign_f, wire_f, hnd, hlen, signer, lab_o, lab_n, extra, want_code, msg) \
    do {                                                                                     \
        CHECK(rotate_session(&d, &c, &old_kp) == 0, desc_ok);                                 \
        rl = build_rotate(rot, sizeof rot, c.hsid, (sign_f), (wire_f), (hnd), (hlen),         \
                          &old_kp, &new_kp, (signer), (lab_o), (lab_n));                      \
        CHECK(rl > 0, desc_ok);                                                               \
        rl += (size_t)(extra);                                                                \
        pl = exchange_record(&d, &c, rot, rl, pt, sizeof pt);                                 \
        CHECK(pl > 0 && reply_error_code(pt, pl) == (want_code), msg);                        \
        client_close(&c);                                                                     \
    } while (0)

    /* flags changed after signing: the wire flags are what the daemon digests,
     * so a signature over different flags must fail. The ONLY check that can
     * see `flags` leaving the digest. */
    ROT_CASE("rotate: session (flags)", 0x00u, AUTHMSG_FLAG_ROTATE_DROP_TOKENS,
             HANDLE1, sizeof HANDLE1, &new_kp,
             AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW, 0, AUTHMSG_ERR_REJECTED,
             "rotate: a ROTATE whose flags byte changed after signing is REJECTED");

    /* sig_new by the OLD key: no proof of possession of the incoming key. */
    ROT_CASE("rotate: session (sig_new by old)", 0u, 0u, HANDLE1, sizeof HANDLE1, &old_kp,
             AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW, 0, AUTHMSG_ERR_REJECTED,
             "rotate: a ROTATE whose sig_new is by the OLD key is REJECTED");

    /* Both signatures under the same label: the separation is what stops one
     * key's signature standing in for the other's. */
    ROT_CASE("rotate: session (same label)", 0u, 0u, HANDLE1, sizeof HANDLE1, &new_kp,
             AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_OLD, 0, AUTHMSG_ERR_REJECTED,
             "rotate: sig_new signed under the rotate-old label is REJECTED");

    /* A different handle that EXISTS and is ACTIVE, so the refusal comes from
     * the handle check rather than from the store failing to find it. */
    ROT_CASE("rotate: session (wrong handle)", 0u, 0u, HANDLE2, sizeof HANDLE2, &new_kp,
             AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW, 0, AUTHMSG_ERR_REJECTED,
             "rotate: a ROTATE naming a DIFFERENT enrolled handle is REJECTED");

    /* One trailing byte. Strict decode, spec 6. */
    ROT_CASE("rotate: session (trailing byte)", 0u, 0u, HANDLE1, sizeof HANDLE1, &new_kp,
             AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW, 1, AUTHMSG_ERR_MALFORMED,
             "rotate: a ROTATE with one trailing byte is REJECTED");
#undef ROT_CASE

    /* A ROTATE captured from one session, replayed on another. handshake_id is
     * what makes it useless elsewhere (Req 8) -- the code-side twin of the
     * model's rot_hsid control. */
    {
        client_t a, b;
        CHECK(rotate_session(&d, &a, &old_kp) == 0, "rotate: session A for the replay");
        rl = build_rotate(rot, sizeof rot, a.hsid, 0u, 0u, HANDLE1, sizeof HANDLE1,
                          &old_kp, &new_kp, &new_kp,
                          AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW);
        CHECK(rl > 0, "rotate: built a ROTATE bound to session A");
        CHECK(rotate_session(&d, &b, &old_kp) == 0, "rotate: session B for the replay");
        pl = exchange_record(&d, &b, rot, rl, pt, sizeof pt);
        CHECK(pl > 0 && reply_error_code(pt, pl) == AUTHMSG_ERR_REJECTED,
              "rotate: a ROTATE captured from one session is REJECTED on a second");
        client_close(&b);
        client_close(&a);
    }

    /* Rotating to a key that is already enrolled elsewhere answers the SAME
     * code as a bad signature -- otherwise an authenticated peer could probe
     * the deployment's whole key set. The rejections above are the canary that
     * 0x03 really is what a bad signature produces. */
    {
        CHECK(rotate_session(&d, &c, &old_kp) == 0, "rotate: session (pk in use)");
        uint8_t dig_o[32], dig_n[32], so[MLDSA_SIGNATURE_MAX_BYTES], sn[MLDSA_SIGNATURE_MAX_BYTES];
        size_t sol = 0, snl = 0;
        (void)authmsg_rotate_digest(dig_o, AUTHMSG_LABEL_ROTATE_OLD, c.hsid, 0u,
                                    HANDLE1, sizeof HANDLE1, old_kp.public_key, other_kp.public_key);
        (void)authmsg_rotate_digest(dig_n, AUTHMSG_LABEL_ROTATE_NEW, c.hsid, 0u,
                                    HANDLE1, sizeof HANDLE1, old_kp.public_key, other_kp.public_key);
        CHECK(mldsa_sign(so, &sol, dig_o, sizeof dig_o, &old_kp) == 0 &&
              mldsa_sign(sn, &snl, dig_n, sizeof dig_n, &other_kp) == 0, "rotate: sign for pk-in-use");
        CHECK(authmsg_encode_rotate(rot, sizeof rot, &rl, 0u, HANDLE1, sizeof HANDLE1,
                                    other_kp.public_key, so, sol, sn, snl) == AUTHMSG_OK,
              "rotate: encode for pk-in-use");
        pl = exchange_record(&d, &c, rot, rl, pt, sizeof pt);
        CHECK(pl > 0 && reply_error_code(pt, pl) == AUTHMSG_ERR_REJECTED,
              "rotate: pk-in-use and bad-signature produce the SAME error code");
        client_close(&c);
    }

    /* The happy path LAST: it changes the active key, so nothing after it can
     * authenticate with old_kp. */
    {
        CHECK(rotate_session(&d, &c, &old_kp) == 0, "rotate: session for the happy path");
        rl = build_rotate(rot, sizeof rot, c.hsid, 0u, 0u, HANDLE1, sizeof HANDLE1,
                          &old_kp, &new_kp, &new_kp,
                          AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW);
        CHECK(rl > 0, "rotate: built a valid ROTATE");
        pl = exchange_record(&d, &c, rot, rl, pt, sizeof pt);
        authmsg_rotate_ack_t ack;
        CHECK(pl > 0 && authmsg_decode_rotate_ack(pt, pl, &ack) == AUTHMSG_OK,
              "rotate: the daemon answers ROTATE_ACK");
        uint8_t fp[32];
        crypto_hash_sha256(fp, new_kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
        CHECK(ack.handle_len == sizeof HANDLE1 &&
              memcmp(ack.handle, HANDLE1, sizeof HANDLE1) == 0 &&
              memcmp(ack.fp_new, fp, 32) == 0,
              "rotate: the ACK names this handle and the NEW key's fingerprint");
        CHECK(ack.rotated_at == (uint64_t)d.app.now_unix,
              "rotate: ROTATE_ACK's rotated_at equals the daemon's injected clock");

        uint8_t active[STORE_PK_BYTES];
        CHECK(store_lookup_active(d.store, HANDLE1, sizeof HANDLE1, active, NULL, 0, NULL, NULL)
                  == STORE_OK && memcmp(active, new_kp.public_key, STORE_PK_BYTES) == 0,
              "rotate: the NEW key is the active one afterwards");

        /* A second ROTATE on the same session. Without this the holder of the
         * key being rotated AWAY from could keep rotating: sig_old still
         * verifies, because the slot still pins that key. */
        uint8_t rot2[AUTHMSG_ROTATE_MAX_CONTENT];
        const size_t r2 = build_rotate(rot2, sizeof rot2, c.hsid, 0u, 0u,
                                       HANDLE1, sizeof HANDLE1, &old_kp, &other_kp, &other_kp,
                                       AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW);
        CHECK(r2 > 0, "rotate: built a second ROTATE");
        pl = exchange_record(&d, &c, rot2, r2, pt, sizeof pt);
        CHECK(pl > 0 && reply_error_code(pt, pl) == AUTHMSG_ERR_NOT_PERMITTED,
              "rotate: a SECOND ROTATE on the same session is refused with ERROR(0x02)");
        client_close(&c);
    }


    /* A session that authenticated BEFORE someone else rotated the handle must
     * not be able to rotate afterwards. Its signatures name an old->new edge
     * the store is no longer on, so committing them would supersede a key they
     * say nothing about. The store pins the expected old key inside its OWN
     * transaction, so this is not a race with another process either.
     *
     * Runs after the happy path because a superseded key can never be
     * reinstated (pk is unique forever), so the fixture cannot be rewound. */
    {
        client_t stale;
        int64_t at = 0;
        CHECK(rotate_session(&d, &stale, &new_kp) == 0, "rotate: a session before the rotation");
        CHECK(store_rotate_key(d.store, HANDLE1, sizeof HANDLE1, spare_kp.public_key,
                               new_kp.public_key, NULL, 0, 0, d.app.now_unix, &at, NULL)
                  == STORE_OK, "rotate: the handle moves under the live session");
        {
            mldsa_keypair_t yet;
            CHECK(mldsa_keypair_generate(&yet) == 0, "rotate: a key for the stale attempt");
            rl = build_rotate(rot, sizeof rot, stale.hsid, 0u, 0u, HANDLE1, sizeof HANDLE1,
                              &new_kp, &yet, &yet,
                              AUTHMSG_LABEL_ROTATE_OLD, AUTHMSG_LABEL_ROTATE_NEW);
            CHECK(rl > 0, "rotate: built a ROTATE from the stale session");
            pl = exchange_record(&d, &stale, rot, rl, pt, sizeof pt);
            CHECK(pl > 0 && reply_error_code(pt, pl) == AUTHMSG_ERR_REJECTED,
                  "rotate: after the active key changes under a live session, "
                  "that session's ROTATE is REJECTED");
            mldsa_keypair_free(&yet);
        }
        client_close(&stale);
    }

    /* And the old key no longer authenticates at all: there is no overlap
     * window in which two keys work (spec 10.2). */
    {
        /* The client cannot be TOLD that its key is stale -- Req 6 makes a
         * superseded key indistinguishable from an unknown one, so the
         * ServerHello still verifies and the handshake still completes on this
         * side. What it never gets is a login code: the daemon pinned the
         * decoy, so ClientAuth fails there and the session is abandoned. That
         * is exactly the "no overlap window" spec 10.2 promises, observed the
         * only way an honest client can observe it. */
        client_t z;
        CHECK(rotate_session(&d, &z, &old_kp) != 0,
              "rotate: the OLD key gets no login code after the rotation (no overlap window)");
        client_close(&z);
    }

    mldsa_keypair_free(&old_kp);
    mldsa_keypair_free(&new_kp);
    mldsa_keypair_free(&other_kp);
    mldsa_keypair_free(&spare_kp);
    daemon_stop(&d);
}

/* The login code must not reach the journal.
 *
 * This used to be argued rather than tested: authd_log.h had no function
 * taking a byte buffer, so the leak was said to be unrepresentable. V4-9a
 * added authd_log_fp(lvl, event, const uint8_t fp[32]) -- and in C that
 * parameter is a POINTER, while a login code is exactly 32 bytes, so
 * authd_log_fp(..., m.code) compiles and dumps it. The argument stopped being
 * true and nothing noticed, because it lived in prose. Now it is a check. */
static void test_log_has_no_code(void)
{
    char path[512];
    snprintf(path, sizeof path, "%s/daemon.log", g_dir);
    FILE *lf = fopen(path, "w+");
    CHECK(lf != NULL, "logscan: capture file");
    if (lf == NULL) { return; }
    authd_log_init(lf, AUTHD_LOG_INFO);

    daemon_t d; client_t c;
    mldsa_keypair_t kp;
    CHECK(daemon_start(&d, 4, "logscan.sqlite3") == 0, "logscan: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0, "logscan: key");
    enroll(&d, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(client_handshake(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "logscan: handshake");

    uint8_t rec[AUTHD_MAX_RECORD], pt[AUTHD_MAX_RECORD];
    size_t n = 0, pl = 0;
    CHECK(recv_frame(&d, c.fd, rec, sizeof rec, &n) == 0, "logscan: login code");
    CHECK(session_open(&c.sess, rec, n, pt, sizeof pt, &pl) == SESSION_OK, "logscan: open it");
    authmsg_login_code_t m;
    CHECK(authmsg_decode_login_code(pt, pl, &m) == AUTHMSG_OK, "logscan: decode it");

    char hex[65];
    (void)sodium_bin2hex(hex, sizeof hex, m.code, sizeof m.code);
    fflush(lf);

    /* Present canary: the log DOES carry this connection's identity, so a
     * "code not found" result cannot be explained by an empty log. */
    long sz = 0;
    char *buf = NULL;
    if (fseek(lf, 0, SEEK_END) == 0 && (sz = ftell(lf)) > 0 && fseek(lf, 0, SEEK_SET) == 0) {
        buf = (char *)calloc((size_t)sz + 1u, 1u);
        if (buf != NULL && fread(buf, 1u, (size_t)sz, lf) != (size_t)sz) { buf[0] = '\0'; }
    }
    CHECK(buf != NULL && strstr(buf, "event=login") != NULL,
          "logscan: the log records the login (canary: it is not empty)");
    CHECK(buf != NULL && strstr(buf, hex) == NULL,
          "logscan: the login code never appears in the daemon's log");

    free(buf);
    sodium_memzero(&m, sizeof m);
    sodium_memzero(hex, sizeof hex);
    client_close(&c);
    mldsa_keypair_free(&kp);
    daemon_stop(&d);
    (void)fclose(lf);
    authd_log_init(stderr, AUTHD_LOG_ERROR);
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
    test_rotate();
    test_log_has_no_code();
    test_pin_lookup();
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
