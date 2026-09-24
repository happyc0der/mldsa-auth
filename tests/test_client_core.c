/*
 * V4-13a: the client core (apps/authd/client_core.c) -- the whole client as
 * bytes in, bytes out, which the CLI and (13b) the browser both run.
 *
 * AGAINST THE REAL DAEMON (tests/authd_harness.h, in-process, both transports):
 * a login whose code the site socket EXCHANGEs for a token; a ServerHello not
 * signed by the pinned key refused with no ClientAuth produced (spec 4 --
 * phishing resistance); a rotation the daemon acknowledges, after which only
 * the new key logs in.
 *
 * AGAINST A FAKE SERVER (tests/cc_fake_server.h), for what the daemon never
 * sends and a hostile server would: a first record that is not LOGIN_CODE; a
 * ROTATE_ACK naming a different key, or a different handle of the same length.
 *
 * And, without a network: the secret key's lifetime (freed or dropped the
 * moment ClientAuth is built, and on refusal); frames whose length header
 * disagrees with their size; the injected clock governing the session; every
 * later call refused once the core has failed; the browser's KDF parameters;
 * the envelope and MLDSAPK1 paths the browser will use.
 *
 * White-box where the property IS the private state: "the key is freed" is
 * asserted by reading cc_t's key fields, because no public call can observe
 * an absence that is the whole point.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "authd_harness.h"
#include "cc_fake_server.h"
#include "client_core.h"
#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { printf("PASS: %s\n", msg); } \
    else { printf("FAIL: %s\n", msg); g_fail = 1; } } while (0)

static char g_dir[256];
static const uint8_t U1[] = { 'u', '1' };
static const char PASS[] = "correct horse battery staple";
#define OPS 1u
#define MEM (8u * 1024u * 1024u)

static uint8_t g_out[FRAME_BUF_BYTES];
static uint8_t g_in[FRAME_BUF_BYTES];
static cc_t g_cc;     /* ~135 KB: static, not on the stack */

/* ---- transport over the harness daemon ---------------------------------- */

static int t_send(h_daemon_t *d, int fd, int ws, const uint8_t *msg, size_t len)
{
    if (!ws) {
        return h_write_all(d, fd, msg, len);
    }
    static uint8_t wire[WS_SRV_HDR_MAX + 4u + FRAME_BUF_BYTES];
    uint8_t mask[4];
    randombytes_buf(mask, sizeof mask);
    const size_t w = ws_client_frame(wire, sizeof wire, msg, len, mask);
    return (w == 0u) ? -1 : h_write_all(d, fd, wire, w);
}

/* Returns one whole frame, header included, as the core consumes it. */
static int t_recv(h_daemon_t *d, int fd, int ws, uint8_t *msg, size_t cap, size_t *len)
{
    if (!ws) {
        size_t pl = 0;
        if (h_recv_frame(d, fd, msg + 4, cap - 4u, &pl) != 0) { return -1; }
        fs_put_len(msg, pl);
        *len = 4u + pl;
        return 0;
    }
    h_ws_rd_t ctx = { d, fd };
    return (ws_client_read_message(h_ws_read, &ctx, msg, cap, len) == WS_CLIENT_OK) ? 0 : -1;
}

typedef struct { uint64_t now; } tclock_t;
static uint64_t t_clock(void *ctx) { return ((tclock_t *)ctx)->now; }

/* A device: handle, sealed envelope, public key -- made by the core itself. */
typedef struct {
    char hid[CC_HANDLE_BUF];
    uint8_t ek[8192];
    size_t ek_len;
    uint8_t pub[4096];
    size_t pub_len;
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
} device_t;

static int make_device(device_t *dv)
{
    cc_new_handle(dv->hid);
    return cc_seal_new_identity((const uint8_t *)dv->hid, CC_HANDLE_LEN, PASS, strlen(PASS), OPS, MEM,
                                dv->ek, sizeof dv->ek, &dv->ek_len, dv->pub, sizeof dv->pub, &dv->pub_len,
                                dv->pk, NULL) == CC_OK ? 0 : -1;
}

/* Logs in over `ws` or raw; returns the core's status, the code and the fd. */
static cc_status_t login_daemon(h_daemon_t *d, cc_t *cc, tclock_t *clk, int ws, const device_t *dv,
                                unsigned flags, const uint8_t *pin_pk, authmsg_login_code_t *code, int *fd_out)
{
    size_t n = 0, m = 0;
    cc_init(cc, clk != NULL ? t_clock : NULL, clk);
    if (cc_pin_server(cc, H_SERVER_ID, sizeof H_SERVER_ID, pin_pk) != CC_OK) { return CC_ERR_ARG; }
    const int fd = ws ? h_ws_connect(d, "st8") : h_dial(d->port);
    *fd_out = fd;
    if (fd < 0) { return CC_ERR_ARG; }
    cc_status_t st = cc_login_begin_sealed(cc, (const uint8_t *)dv->hid, CC_HANDLE_LEN, dv->ek, dv->ek_len,
                                           PASS, strlen(PASS), flags, g_out, sizeof g_out, &n);
    if (st != CC_OK) { return st; }
    if (t_send(d, fd, ws, g_out, n) != 0 || t_recv(d, fd, ws, g_in, sizeof g_in, &m) != 0) { return CC_ERR_ARG; }
    st = cc_login_on_server_hello(cc, g_in, m, g_out, sizeof g_out, &n);
    if (st != CC_OK) { return st; }
    if (t_send(d, fd, ws, g_out, n) != 0) { return CC_ERR_ARG; }
    if (t_recv(d, fd, ws, g_in, sizeof g_in, &m) != 0) { return CC_ERR_SESSION; }
    return cc_login_on_record(cc, g_in, m, code);
}

static void bye_close(h_daemon_t *d, cc_t *cc, int fd, int ws)
{
    size_t n = 0;
    if (cc_bye(cc, g_out, sizeof g_out, &n) == CC_OK) { (void)t_send(d, fd, ws, g_out, n); }
    cc_wipe(cc);
    if (fd >= 0) { (void)close(fd); }
}

static int exchange(h_daemon_t *d, const uint8_t code[32], const char *state_hex, char *resp, size_t cap)
{
    const int site = h_dial_unix(d->site_path);
    if (site < 0) { return -1; }
    char hex[80], req[256];
    h_hex(hex, sizeof hex, code, 32u);
    snprintf(req, sizeof req, "EXCHANGE code=%s state=%s", hex, state_hex);
    const int r = h_local_cmd(d, site, req, resp, cap);
    (void)close(site);
    return r;
}

/* ---- against the real daemon -------------------------------------------- */

static void test_daemon(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "cc.sqlite3", 1) == 0, "daemon: starts");
    device_t dv;
    CHECK(make_device(&dv) == 0, "daemon: the core makes a device (handle, envelope, public key)");
    (void)store_add_user(d.store, U1, sizeof U1, STORE_ROLE_USER);
    CHECK(store_enroll_device(d.store, (const uint8_t *)dv.hid, CC_HANDLE_LEN, U1, sizeof U1, dv.pk,
                              "site", "test", NULL, 0) == STORE_OK, "daemon: the device is enrolled");

    /* The server's MLDSAPK1, parsed the way the browser will parse it. */
    uint8_t spub[4096], spk[MLDSA_PUBLIC_KEY_BYTES];
    const size_t spl = demo_keys_public_image_len(sizeof H_SERVER_ID);
    CHECK(demo_keys_build_public_image(spub, sizeof spub, H_SERVER_ID, sizeof H_SERVER_ID,
                                       d.server_kp.public_key) == DEMO_KEYS_OK &&
          cc_parse_server_pub(spub, spl, H_SERVER_ID, sizeof H_SERVER_ID, spk, NULL) == CC_OK &&
          memcmp(spk, d.server_kp.public_key, sizeof spk) == 0,
          "daemon: the server's MLDSAPK1 parses to its key");

    for (int ws = 0; ws <= 1; ws++) {
        const char *tp = ws ? "ws" : "raw";
        char msg[160], resp[4096];
        authmsg_login_code_t code;
        int fd = -1;
        const cc_status_t st = login_daemon(&d, &g_cc, NULL, ws, &dv, 0u, spk, &code, &fd);
        snprintf(msg, sizeof msg, "daemon/%s: login completes and yields a LOGIN_CODE", tp);
        CHECK(st == CC_OK && cc_state(&g_cc) == CC_STATE_LIVE, msg);
        snprintf(msg, sizeof msg, "daemon/%s: the owned key was freed when ClientAuth was built", tp);
        CHECK(g_cc.kp == NULL && g_cc.own_kp.secret_key == NULL, msg);
        uint8_t raw[32];
        memcpy(raw, code.code, sizeof raw);
        bye_close(&d, &g_cc, fd, ws);
        snprintf(msg, sizeof msg, "daemon/%s: the site socket EXCHANGEs the code for a token", tp);
        char sh[16];
        h_hex(sh, sizeof sh, (const uint8_t *)"st8", 3u);
        CHECK(exchange(&d, raw, ws ? sh : "", resp, sizeof resp) == 0 && strncmp(resp, "OK token=", 9) == 0, msg);
    }

    /* Spec 4: pin a DIFFERENT key for the same server id. The daemon's genuine
     * ServerHello must be refused, and no ClientAuth may exist afterwards. */
    {
        mldsa_keypair_t other;
        CHECK(mldsa_keypair_generate(&other) == 0, "phish: a second server key");
        authmsg_login_code_t code;
        int fd = -1;
        size_t n = 0, m = 0;
        cc_init(&g_cc, NULL, NULL);
        (void)cc_pin_server(&g_cc, H_SERVER_ID, sizeof H_SERVER_ID, other.public_key);
        fd = h_dial(d.port);
        (void)cc_login_begin_sealed(&g_cc, (const uint8_t *)dv.hid, CC_HANDLE_LEN, dv.ek, dv.ek_len, PASS,
                                    strlen(PASS), 0u, g_out, sizeof g_out, &n);
        (void)t_send(&d, fd, 0, g_out, n);
        CHECK(t_recv(&d, fd, 0, g_in, sizeof g_in, &m) == 0, "phish: the daemon's ServerHello arrives");
        memset(g_out, 0xA5, sizeof g_out);
        n = 12345u;
        const cc_status_t st = cc_login_on_server_hello(&g_cc, g_in, m, g_out, sizeof g_out, &n);
        CHECK(st == CC_ERR_HANDSHAKE && cc_state(&g_cc) == CC_STATE_FAILED,
              "phish: a ServerHello not signed by the pinned key is refused (spec 4)");
        { int untouched = 1; for (size_t i = 0; i < 8192u; i++) { if (g_out[i] != 0xA5u) { untouched = 0; } }
          CHECK(n == 0u && untouched, "phish: no ClientAuth is produced -- not a byte of the output is written"); }
        CHECK(g_cc.kp == NULL && g_cc.own_kp.secret_key == NULL, "phish: the owned key is freed on refusal");
        const cc_diag_t *dg = cc_diag(&g_cc);
        CHECK(dg->kind == CC_DIAG_HANDSHAKE && strcmp(dg->stage, "server-hello") == 0 && dg->detail != NULL,
              "phish: the refusal is named as a handshake failure at server-hello");
        CHECK(cc_login_on_record(&g_cc, g_in, m, &code) == CC_ERR_STATE &&
              cc_bye(&g_cc, g_out, sizeof g_out, &n) == CC_ERR_STATE,
              "phish: every later call is refused once the core has failed");
        cc_wipe(&g_cc);
        (void)close(fd);
        mldsa_keypair_free(&other);
    }

    /* Rotation, acknowledged by the real daemon. */
    {
        authmsg_login_code_t code;
        int fd = -1;
        size_t n = 0, m = 0;
        cc_status_t st = login_daemon(&d, &g_cc, NULL, 1, &dv, CC_KEEP_FOR_ROTATE, spk, &code, &fd);
        CHECK(st == CC_OK && g_cc.own_kp.secret_key != NULL,
              "rotate: CC_KEEP_FOR_ROTATE keeps the old key past ClientAuth");
        device_t nx;
        memcpy(nx.hid, dv.hid, sizeof nx.hid);
        CHECK(cc_seal_new_identity((const uint8_t *)nx.hid, CC_HANDLE_LEN, PASS, strlen(PASS), OPS, MEM,
                                   nx.ek, sizeof nx.ek, &nx.ek_len, nx.pub, sizeof nx.pub, &nx.pub_len,
                                   nx.pk, NULL) == CC_OK, "rotate: the new key is sealed first");
        mldsa_keypair_t nkp;
        CHECK(cc_open_sealed(nx.ek, nx.ek_len, (const uint8_t *)nx.hid, CC_HANDLE_LEN, PASS, strlen(PASS), &nkp,
                             NULL) == CC_OK, "rotate: and opens");
        st = cc_rotate_build(&g_cc, &nkp, 0u, g_out, sizeof g_out, &n);
        CHECK(st == CC_OK && g_cc.kp == NULL && g_cc.own_kp.secret_key == NULL,
              "rotate: ROTATE is built and the old key is freed with it");
        CHECK(t_send(&d, fd, 1, g_out, n) == 0 && t_recv(&d, fd, 1, g_in, sizeof g_in, &m) == 0,
              "rotate: the daemon answers");
        uint8_t ec = 0xEE;
        st = cc_rotate_on_reply(&g_cc, g_in, m, &ec);
        CHECK(st == CC_OK && cc_state(&g_cc) == CC_STATE_LIVE, "rotate: the daemon's ROTATE_ACK is accepted");
        bye_close(&d, &g_cc, fd, 1);
        mldsa_keypair_free(&nkp);

        fd = -1;
        st = login_daemon(&d, &g_cc, NULL, 0, &dv, 0u, spk, &code, &fd);
        CHECK(st != CC_OK, "rotate: the superseded key no longer logs in");
        cc_wipe(&g_cc);
        if (fd >= 0) { (void)close(fd); }
        fd = -1;
        st = login_daemon(&d, &g_cc, NULL, 0, &nx, 0u, spk, &code, &fd);
        CHECK(st == CC_OK, "rotate: the new key logs in");
        bye_close(&d, &g_cc, fd, 0);
    }

    /* The injected clock governs the session: jump it past the hard limit and
     * the core can no longer seal. The control run with the clock held still
     * shows it is the clock, not the login, that decides. */
    {
        device_t dv2;
        CHECK(make_device(&dv2) == 0 &&
              store_enroll_device(d.store, (const uint8_t *)dv2.hid, CC_HANDLE_LEN, U1, sizeof U1, dv2.pk,
                                  "site", "test", NULL, 0) == STORE_OK, "clock: a second device");
        for (int jump = 0; jump <= 1; jump++) {
            tclock_t clk = { 5000u };
            authmsg_login_code_t code;
            int fd = -1;
            size_t n = 0;
            const cc_status_t st = login_daemon(&d, &g_cc, &clk, 0, &dv2, 0u, spk, &code, &fd);
            if (jump) { clk.now += SESSION_REJECT_AFTER_MS + 1u; }
            const cc_status_t bs = cc_bye(&g_cc, g_out, sizeof g_out, &n);
            if (jump) {
                CHECK(st == CC_OK && bs == CC_ERR_SESSION,
                      "clock: past the injected clock's hard limit the session refuses to seal");
            } else {
                CHECK(st == CC_OK && bs == CC_OK, "clock: control -- with the clock held, the same seal succeeds");
                (void)t_send(&d, fd, 0, g_out, n);
            }
            cc_wipe(&g_cc);
            if (fd >= 0) { (void)close(fd); }
        }
    }
    h_stop(&d);
}

/* ---- against the fake server -------------------------------------------- */

static const uint8_t SID[] = { 'a', 'u', 't', 'h', 'd' };

/* Logs the core in against `fs` up to (not including) the first record. */
static int fake_login(fs_t *fs, cc_t *cc, const uint8_t *hid, size_t hid_len, const mldsa_keypair_t *kp,
                      unsigned flags)
{
    size_t n = 0, m = 0;
    cc_init(cc, NULL, NULL);
    if (cc_pin_server(cc, SID, sizeof SID, fs->kp.public_key) != CC_OK ||
        cc_login_begin(cc, hid, hid_len, kp, flags, g_out, sizeof g_out, &n) != CC_OK ||
        fs_on_client_hello(fs, g_out, n, g_in, sizeof g_in, &m) != 0 ||
        cc_login_on_server_hello(cc, g_in, m, g_out, sizeof g_out, &n) != CC_OK ||
        fs_on_client_auth(fs, g_out, n) != 0) {
        return -1;
    }
    return 0;
}

static void test_fake(void)
{
    const uint8_t hid[] = "d1fake0000000000000000000000000000";
    const size_t hl = CC_HANDLE_LEN;
    mldsa_keypair_t kp;
    CHECK(mldsa_keypair_generate(&kp) == 0, "fake: a client key");
    authmsg_login_code_t code;
    size_t n = 0, m = 0;

    /* control: a genuine LOGIN_CODE from the fake is accepted */
    { fs_t fs;
      CHECK(fs_init(&fs, SID, sizeof SID, hid, hl, kp.public_key) == 0 && fake_login(&fs, &g_cc, hid, hl, &kp, 0u) == 0,
            "fake: the core logs in against the fake server");
      CHECK(g_cc.kp == NULL && kp.secret_key != NULL,
            "fake: a LENT key's pointer is dropped at ClientAuth, and the caller's key is left intact");
      CHECK(fs_send_login_code(&fs, 0u, 0x42, 1700000060u, g_in, sizeof g_in, &m) == 0 &&
            cc_login_on_record(&g_cc, g_in, m, &code) == CC_OK && code.code[0] == 0x42 && code.code[31] == 0x42,
            "fake: control -- a LOGIN_CODE first record is accepted");
      cc_wipe(&g_cc); fs_wipe(&fs); }

    /* the first record must be LOGIN_CODE */
    const uint8_t bye[1] = { AUTHMSG_OP_BYE };
    uint8_t err[AUTHMSG_ERROR_CONTENT_LEN];
    size_t el = 0;
    (void)authmsg_encode_error(err, sizeof err, &el, AUTHMSG_ERR_REJECTED);
    const struct { const uint8_t *b; size_t l; const char *name; } firsts[] = {
        { bye, sizeof bye, "fake: a BYE as the first record is refused, not skipped" },
        { err, el,         "fake: an ERROR as the first record is refused" },
    };
    for (size_t i = 0; i < sizeof firsts / sizeof firsts[0]; i++) {
        fs_t fs;
        (void)fs_init(&fs, SID, sizeof SID, hid, hl, kp.public_key);
        (void)fake_login(&fs, &g_cc, hid, hl, &kp, 0u);
        memset(&code, 0xA5, sizeof code);
        const cc_status_t st = (fs_send(&fs, firsts[i].b, firsts[i].l, g_in, sizeof g_in, &m) == 0)
                                   ? cc_login_on_record(&g_cc, g_in, m, &code) : CC_OK;
        CHECK(st == CC_ERR_MESSAGE && cc_state(&g_cc) == CC_STATE_FAILED && sodium_is_zero(code.code, 32),
              firsts[i].name);
        cc_wipe(&g_cc); fs_wipe(&fs);
    }

    /* ROTATE_ACK must name THIS handle and THIS new key */
    mldsa_keypair_t nkp, other;
    CHECK(mldsa_keypair_generate(&nkp) == 0 && mldsa_keypair_generate(&other) == 0, "fake: new and other keys");
    uint8_t wrong_hid[CC_HANDLE_LEN];
    memcpy(wrong_hid, hid, hl);
    wrong_hid[hl - 1u] = (uint8_t)(wrong_hid[hl - 1u] == '0' ? '1' : '0');
    enum { ACK_OK, ACK_OTHER_KEY, ACK_OTHER_HANDLE, ACK_SHORT_HANDLE, ACK_ERROR };
    for (int c = ACK_OK; c <= ACK_ERROR; c++) {
        fs_t fs;
        (void)fs_init(&fs, SID, sizeof SID, hid, hl, kp.public_key);
        (void)fake_login(&fs, &g_cc, hid, hl, &kp, CC_KEEP_FOR_ROTATE);
        (void)fs_send_login_code(&fs, 0u, 1, 1u, g_in, sizeof g_in, &m);
        (void)cc_login_on_record(&g_cc, g_in, m, &code);
        uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES];
        size_t pl = 0;
        authmsg_rotate_t rot;
        const int built = cc_rotate_build(&g_cc, &nkp, 0u, g_out, sizeof g_out, &n) == CC_OK &&
                          fs_open(&fs, g_out, n, pt, sizeof pt, &pl) == 0 &&
                          authmsg_decode_rotate(pt, pl, &rot) == AUTHMSG_OK &&
                          memcmp(rot.pk_new, nkp.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0;
        int sent = -1;
        switch (c) {
        case ACK_OK:           sent = fs_send_rotate_ack(&fs, hid, hl, nkp.public_key, 7u, g_in, sizeof g_in, &m); break;
        case ACK_OTHER_KEY:    sent = fs_send_rotate_ack(&fs, hid, hl, other.public_key, 7u, g_in, sizeof g_in, &m); break;
        case ACK_OTHER_HANDLE: sent = fs_send_rotate_ack(&fs, wrong_hid, hl, nkp.public_key, 7u, g_in, sizeof g_in, &m); break;
        case ACK_SHORT_HANDLE: sent = fs_send_rotate_ack(&fs, hid, hl - 1u, nkp.public_key, 7u, g_in, sizeof g_in, &m); break;
        default:               sent = fs_send(&fs, err, el, g_in, sizeof g_in, &m); break;
        }
        uint8_t ec = 0;
        const cc_status_t st = (built && sent == 0) ? cc_rotate_on_reply(&g_cc, g_in, m, &ec) : CC_ERR_ARG;
        switch (c) {
        case ACK_OK:
            CHECK(built && st == CC_OK, "fake: ROTATE carries the new key, and a matching ROTATE_ACK is accepted"); break;
        case ACK_OTHER_KEY:
            CHECK(st == CC_ERR_ACK_MISMATCH, "fake: a ROTATE_ACK naming a DIFFERENT key is refused"); break;
        case ACK_OTHER_HANDLE:
            CHECK(st == CC_ERR_ACK_MISMATCH, "fake: a ROTATE_ACK naming a different handle of the SAME length is refused"); break;
        case ACK_SHORT_HANDLE:
            CHECK(st == CC_ERR_ACK_MISMATCH, "fake: a ROTATE_ACK naming a prefix of the handle is refused"); break;
        default:
            CHECK(st == CC_ERR_REFUSED && ec == AUTHMSG_ERR_REJECTED,
                  "fake: an ERROR reply is a refusal, with its code"); break;
        }
        if (c != ACK_OK) {
            CHECK(cc_state(&g_cc) == CC_STATE_LIVE &&
                  cc_rotate_build(&g_cc, &nkp, 0u, g_out, sizeof g_out, &n) == CC_ERR_STATE,
                  "fake: after a non-ACK the session is still usable, but no second ROTATE can be built");
        }
        cc_wipe(&g_cc); fs_wipe(&fs);
    }
    mldsa_keypair_free(&nkp);
    mldsa_keypair_free(&other);

    /* Frames whose length header disagrees with their size never reach the
     * handshake: the core fails at the frame, whatever the payload. Each case
     * gets its own core and server, in the same waiting state. */
    enum { F_MORE, F_LESS, F_SHORT, F_OVER, F_CONTROL };
    static const char *const fnames[] = {
        "frame: a header claiming one byte MORE than is present is refused",
        "frame: a header claiming one byte LESS than is present is refused",
        "frame: a message one byte short of its header is refused",
        "frame: a self-consistent ServerHello one byte over the bound is refused",
        "frame: control -- the untouched ServerHello is accepted by the same state",
    };
    for (int c = F_MORE; c <= F_CONTROL; c++) {
        fs_t fs;
        (void)fs_init(&fs, SID, sizeof SID, hid, hl, kp.public_key);
        cc_init(&g_cc, NULL, NULL);
        (void)cc_pin_server(&g_cc, SID, sizeof SID, fs.kp.public_key);
        (void)cc_login_begin(&g_cc, hid, hl, &kp, 0u, g_out, sizeof g_out, &n);
        (void)fs_on_client_hello(&fs, g_out, n, g_in, sizeof g_in, &m);
        if (c == F_MORE) {
            size_t lo = 0, hi = 0;
            cc_recv_bounds(&g_cc, &lo, &hi);
            CHECK(lo == 1u && hi == FRAME_MAX_SERVER_HELLO, "frame: the ServerHello bounds are the transport's");
        }
        static uint8_t t[4u + FRAME_MAX_SERVER_HELLO + 1u];
        size_t tl = m;
        memcpy(t, g_in, m);
        switch (c) {
        case F_MORE:  fs_put_len(t, m - 4u + 1u); break;
        case F_LESS:  fs_put_len(t, m - 4u - 1u); break;
        case F_SHORT: tl = m - 1u; break;
        case F_OVER:  memset(t, 0, sizeof t); fs_put_len(t, FRAME_MAX_SERVER_HELLO + 1u); tl = sizeof t; break;
        default: break;
        }
        size_t on = 0;
        const cc_status_t st = cc_login_on_server_hello(&g_cc, t, tl, g_out, sizeof g_out, &on);
        if (c == F_CONTROL) {
            CHECK(st == CC_OK && on > 4u, fnames[c]);
        } else {
            CHECK(st == CC_ERR_FRAME && cc_state(&g_cc) == CC_STATE_FAILED && on == 0u &&
                  cc_diag(&g_cc)->kind == CC_DIAG_IO && strcmp(cc_diag(&g_cc)->stage, "server-hello") == 0,
                  fnames[c]);
        }
        cc_wipe(&g_cc); fs_wipe(&fs);
    }

    mldsa_keypair_free(&kp);
}

/* ---- no network ---------------------------------------------------------- */

static void test_offline(void)
{
    const uint8_t hid[] = "d1offl0000000000000000000000000000";
    const size_t hl = CC_HANDLE_LEN;

    { char h[CC_HANDLE_BUF], h2[CC_HANDLE_BUF];
      cc_new_handle(h); cc_new_handle(h2);
      int ok = strlen(h) == CC_HANDLE_LEN && h[0] == 'd' && h[1] == '1' && strcmp(h, h2) != 0;
      for (size_t i = 2; i < CC_HANDLE_LEN; i++) { ok &= (h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'); }
      CHECK(ok, "handle: d1 + 32 lowercase hex, fresh each time (spec 3.1)"); }

    uint8_t ek[8192], pub[4096], pk[MLDSA_PUBLIC_KEY_BYTES], got[MLDSA_PUBLIC_KEY_BYTES];
    size_t el = 0, pl = 0;
    CHECK(cc_seal_new_identity(hid, hl, PASS, strlen(PASS), OPS, MEM, ek, 100u, &el, pub, sizeof pub, &pl, pk, NULL) ==
              CC_ERR_ARG, "seal: an envelope buffer too small -> ARG");
    CHECK(cc_seal_new_identity(hid, hl, PASS, strlen(PASS), OPS, MEM, ek, sizeof ek, &el, pub, sizeof pub, &pl, pk,
                               NULL) == CC_OK &&
          el == keyfile_sealed_len(demo_keys_sk2_image_len(hl)) && pl == demo_keys_public_image_len(hl),
          "seal: an envelope and a public image of exactly the right sizes");
    CHECK(demo_keys_parse_public(pub, pl, hid, hl, got) == DEMO_KEYS_OK && memcmp(got, pk, sizeof pk) == 0,
          "seal: the public image carries the new key under the handle");
    mldsa_keypair_t kp;
    cc_diag_t dg;
    CHECK(cc_open_sealed(ek, el, hid, hl, PASS, strlen(PASS), &kp, &dg) == CC_OK &&
          memcmp(kp.public_key, pk, sizeof pk) == 0,
          "open: the sealed envelope opens to the same key");
    { uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES]; size_t sl = 0; const uint8_t mm[3] = { 1, 2, 3 };
      CHECK(mldsa_sign(sig, &sl, mm, 3, &kp) == 0 && mldsa_verify(mm, 3, sig, sl, pk) == 0,
            "open: and the key signs"); }
    mldsa_keypair_free(&kp);
    CHECK(cc_open_sealed(ek, el, hid, hl, "wrong", 5u, &kp, &dg) == CC_ERR_KEYFILE && kp.secret_key == NULL &&
          dg.kind == CC_DIAG_KEYS && strncmp(dg.detail, "decryption-failed", 17) == 0,
          "open: a wrong passphrase -> KEYFILE, named decryption-failed, no key");

    /* Every header byte, and the last ciphertext byte: none of them may be
     * changed and still open. (The ctest TIMEOUT guards the case where a
     * mutant removes the KDF bounds and a flipped opslimit reaches Argon2id.) */
    { int none = 1; uint8_t t[8192];
      for (size_t i = 0; i <= KEYFILE_HEADER_LEN; i++) {
          const size_t at = (i == KEYFILE_HEADER_LEN) ? el - 1u : i;
          memcpy(t, ek, el);
          t[at] ^= 0x01u;
          if (cc_open_sealed(t, el, hid, hl, PASS, strlen(PASS), &kp, NULL) == CC_OK) {
              printf("  (flip at byte %zu opened!)\n", at); none = 0; mldsa_keypair_free(&kp);
          }
      }
      CHECK(none, "open: a flip in ANY of the 67 header bytes, or in the ciphertext, never opens"); }
    { uint8_t t[8192];
      memcpy(t, ek, el);
      t[10] = 0; t[11] = 0; t[12] = 0; t[13] = 11u;
      CHECK(cc_open_sealed(t, el, hid, hl, PASS, strlen(PASS), &kp, &dg) == CC_ERR_KEYFILE &&
            strcmp(dg.detail, keyfile_status_name(KEYFILE_ERR_PARAMS)) == 0,
            "open: opslimit 11 is refused as out-of-range, before any KDF work"); }

    /* The browser's parameters (spec 12), pinned and exercised once. */
    CHECK(CC_KDF_OPS_BROWSER == 3u && CC_KDF_MEM_BROWSER == 64u * 1024u * 1024u,
          "browser: the KDF parameters are ops 3, 64 MiB (spec 12)");
    { keyfile_header_t h;
      CHECK(cc_seal_new_identity(hid, hl, PASS, strlen(PASS), CC_KDF_OPS_BROWSER, CC_KDF_MEM_BROWSER, ek, sizeof ek,
                                 &el, pub, sizeof pub, &pl, pk, NULL) == CC_OK &&
            keyfile_parse_header(ek, el, &h) == KEYFILE_OK && h.opslimit == 3u && h.memlimit == 64u * 1024u * 1024u &&
            cc_open_sealed(ek, el, hid, hl, PASS, strlen(PASS), &kp, NULL) == CC_OK,
            "browser: an envelope sealed at the browser's parameters says so in its header, and opens");
      mldsa_keypair_free(&kp); }

    /* The pinned server key: id compared by length and bytes; no trailing byte. */
    { mldsa_keypair_t s; uint8_t img[4096];
      CHECK(mldsa_keypair_generate(&s) == 0, "server-pub: a key");
      const size_t il = demo_keys_public_image_len(5);
      (void)demo_keys_build_public_image(img, sizeof img, (const uint8_t *)"authd", 5, s.public_key);
      CHECK(cc_parse_server_pub(img, il, (const uint8_t *)"authd", 5, got, &dg) == CC_OK, "server-pub: parses");
      CHECK(cc_parse_server_pub(img, il, (const uint8_t *)"authx", 5, got, &dg) == CC_ERR_KEYS &&
            strcmp(dg.detail, demo_keys_status_name(DEMO_KEYS_ERR_ID_MISMATCH)) == 0 && sodium_is_zero(got, sizeof got),
            "server-pub: a same-length different id -> ID_MISMATCH, key zeroed");
      CHECK(cc_parse_server_pub(img, il, (const uint8_t *)"auth", 4, got, &dg) == CC_ERR_KEYS,
            "server-pub: a prefix id -> refused");
      img[il] = 0;
      CHECK(cc_parse_server_pub(img, il + 1u, (const uint8_t *)"authd", 5, got, &dg) == CC_ERR_KEYS &&
            strcmp(dg.detail, demo_keys_status_name(DEMO_KEYS_ERR_FORMAT)) == 0,
            "server-pub: one trailing byte -> FORMAT");
      mldsa_keypair_free(&s); }

    /* Sealed login: a wrong passphrase leaves the core PINNED, so it can ask again. */
    { mldsa_keypair_t s; size_t n = 0;
      CHECK(mldsa_keypair_generate(&s) == 0 &&
            cc_seal_new_identity(hid, hl, PASS, strlen(PASS), OPS, MEM, ek, sizeof ek, &el, pub, sizeof pub, &pl,
                                 pk, NULL) == CC_OK, "retry: fixture");
      cc_init(&g_cc, NULL, NULL);
      CHECK(cc_login_begin_sealed(&g_cc, hid, hl, ek, el, PASS, strlen(PASS), 0u, g_out, sizeof g_out, &n) ==
                CC_ERR_STATE, "retry: nothing can begin before the server is pinned");
      (void)cc_pin_server(&g_cc, (const uint8_t *)"authd", 5, s.public_key);
      CHECK(cc_login_begin_sealed(&g_cc, hid, hl, ek, el, "wrong", 5u, 0u, g_out, sizeof g_out, &n) ==
                CC_ERR_KEYFILE && cc_state(&g_cc) == CC_STATE_PINNED && n == 0u && g_cc.own_kp.secret_key == NULL,
            "retry: a wrong passphrase sends nothing and leaves the core PINNED");
      CHECK(cc_login_begin_sealed(&g_cc, hid, hl, ek, el, PASS, strlen(PASS), 0u, g_out, sizeof g_out, &n) ==
                CC_OK && cc_state(&g_cc) == CC_STATE_WAIT_SERVER_HELLO && n > 4u,
            "retry: the right passphrase then produces a ClientHello");
      cc_wipe(&g_cc);
      CHECK(cc_state(&g_cc) == CC_STATE_FAILED && g_cc.own_kp.secret_key == NULL,
            "wipe: cc_wipe frees the owned key and leaves the core FAILED");
      mldsa_keypair_free(&s); }

    /* The .ek.next decision is exported from the core now; its full table is
     * test_authd_cli's test_key_plan. */
    CHECK(client_key_plan(0, 1, 0) == KEY_PLAN_REFUSE && client_key_plan(0, 1, 1) == KEY_PLAN_PROMOTE_NEXT,
          "key-plan: reachable through client_core.h");
}

int main(void)
{
    /* Unbuffered, so every PASS/FAIL line already reported survives a crash
     * (F78: Linux ASan exits without flushing a piped stdout). */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { puts("sodium_init failed"); return 2; }
    snprintf(g_dir, sizeof g_dir, "/tmp/cc_%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) { perror("mkdir"); return 2; }

    test_offline();
    test_fake();
    test_daemon();

    { char cmd[300]; snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf(g_fail ? "\nFAILED\n" : "\nAll checks passed\n");
    return g_fail;
}
