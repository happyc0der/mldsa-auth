/*
 * authd_client -- the device's tool (spec 13): keygen, login, rotate.
 *
 * Split out of authd_cli.c in V4-13a and rebuilt on client_core.c, the same
 * bytes-in/bytes-out core the browser build runs. What stays HERE is only
 * what a browser does differently: sockets (Unix or TCP), the PROXY v2
 * preamble, the WebSocket upgrade, files with custody rules, passphrase
 * files, and the words printed on stderr -- which are unchanged, line for
 * line, because the core reports its failures in the stages this file has
 * always printed (cc_diag_t).
 *
 * The binary links no store and no sqlite3: tests/CMakeLists.txt's
 * client_links_no_sqlite proves it on every build.
 */
#include "client_cli.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_secret.h"
#include "authmsg.h"
#include "cli_common.h"
#include "client_core.h"
#include "demo_app.h"
#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "ws.h"

#define LOGIN_TIMEOUT_MS  20000u

/* ---- one authenticated session, shared by login and rotate --------------- */

/* The core is ~135 KB and there is only ever one session at a time (the
 * rotation-recovery probes run one after another), so it is static here --
 * where the browser build heap-allocates it. */
static cc_t g_cc;

typedef struct {
    net_conn_t  conn;
    cc_t       *cc;
    uint64_t    deadline;
    authmsg_login_code_t code;
    int         live;
    /* The proxy-facing Unix socket speaks WebSocket (spec §7.1); the loopback
     * port an operator tunnels to speaks the frame stream raw. Which one this
     * is decides how a frame is put on the wire, and nothing else -- the
     * handshake, the session and every message above are identical. */
    int         ws;
} client_session_t;

/* ---- the WebSocket carrier, client side -------------------------------- */

/* Announces 127.0.0.1 as the client in a PROXY v2 preamble (spec §7.2). The
 * layout is the one proxy_v2.c parses; building it here rather than exporting
 * a writer from that file keeps the parser a pure decoder with nothing in it
 * that can emit. */
static int write_proxy_v2_local(client_session_t *cs)
{
    static const uint8_t sig[12] = {
        0x0du, 0x0au, 0x0du, 0x0au, 0x00u, 0x0du, 0x0au, 0x51u, 0x55u, 0x49u, 0x54u, 0x0au };
    uint8_t hdr[28];
    memcpy(hdr, sig, sizeof sig);
    hdr[12] = 0x21u;                    /* version 2, command PROXY */
    hdr[13] = 0x11u;                    /* AF_INET, SOCK_STREAM */
    hdr[14] = 0x00u; hdr[15] = 0x0cu;   /* a 12-byte IPv4 address block */
    hdr[16] = 127u; hdr[17] = 0u; hdr[18] = 0u; hdr[19] = 1u;   /* source */
    hdr[20] = 127u; hdr[21] = 0u; hdr[22] = 0u; hdr[23] = 1u;   /* destination */
    hdr[24] = 0u; hdr[25] = 0u;         /* source port: unknown, and unused */
    hdr[26] = 0u; hdr[27] = 0u;
    return (net_write_all(&cs->conn, hdr, sizeof hdr, cs->deadline) == NET_OK) ? 0 : -1;
}

/* Completes the RFC 6455 opening handshake. The accept value is CHECKED: a
 * client that skipped it would happily "upgrade" with something that never
 * read its key. */
static int ws_do_upgrade(client_session_t *cs, const char *state)
{
    uint8_t nonce[16];
    randombytes_buf(nonce, sizeof nonce);

    char req[512];
    size_t req_len = 0;
    char expect[WS_ACCEPT_B64_LEN + 1u];
    if (ws_client_request(req, sizeof req, &req_len, "/authd/v1", state, nonce, expect) != 0) {
        return -1;
    }
    if (net_write_all(&cs->conn, (const uint8_t *)req, req_len, cs->deadline) != NET_OK) {
        return -1;
    }

    /* The response header block is small and bounded; reading it a byte at a
     * time keeps this to one primitive (net_read_exact) and cannot over-read
     * into the first WebSocket frame. */
    uint8_t resp[1024];
    size_t n = 0;
    while (n < sizeof resp) {
        size_t got = 0;
        if (net_read_exact(&cs->conn, resp + n, 1u, cs->deadline, &got) != NET_OK) {
            return -1;
        }
        n++;
        if (n >= 4u && memcmp(resp + n - 4u, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    return ws_client_check_101(resp, n, expect);
}

/* The shared reader in ws.c, over this session's socket. */
static int cs_read_exact(void *ctx, uint8_t *buf, size_t n)
{
    client_session_t *cs = (client_session_t *)ctx;
    size_t got = 0;
    const net_status_t ns = net_read_exact(&cs->conn, buf, n, cs->deadline, &got);
    if (ns == NET_OK)  { return 0; }
    if (ns == NET_EOF && got == 0u) { return 1; }   /* clean EOF at a boundary */
    return -1;
}

/* frame_send/frame_recv, or the same thing inside a WebSocket message. The
 * callers below are identical either way, which is the point. */
static frame_status_t cs_send(client_session_t *cs, uint8_t *buf, size_t payload_len)
{
    if (!cs->ws) {
        /* frame_send, not cs_send: V4-10a wrote the latter here and the raw
         * transport recursed into itself forever (audit finding F55). Nothing
         * caught it because every test and every e2e leg used --unix, where
         * cs->ws is 1 and this branch is dead -- so the operator's own SSH
         * tunnel, the thing milestone A exists for, crashed on its first
         * frame. The e2e now logs in over BOTH transports. */
        return frame_send(&cs->conn, buf, payload_len, cs->deadline);
    }
    frame_put_header(buf, (uint32_t)payload_len);
    static uint8_t wf[WS_SRV_HDR_MAX + 4u + FRAME_BUF_BYTES];
    uint8_t mask[4];
    randombytes_buf(mask, sizeof mask);
    const size_t n = ws_client_frame(wf, sizeof wf, buf, FRAME_HEADER_BYTES + payload_len, mask);
    if (n == 0u) { return FRAME_INVALID_ARG; }
    const net_status_t ns = net_write_all(&cs->conn, wf, n, cs->deadline);
    sodium_memzero(wf, n);
    return (ns == NET_OK) ? FRAME_OK : FRAME_IO;
}

static frame_status_t cs_recv(client_session_t *cs, uint8_t *buf, size_t min_len, size_t max_len,
                              size_t *payload_len)
{
    if (!cs->ws) {
        return frame_recv(&cs->conn, buf, min_len, max_len, payload_len, cs->deadline);
    }
    *payload_len = 0u;
    size_t msg = 0u;
    const ws_client_status_t ws = ws_client_read_message(cs_read_exact, cs, buf,
                                                         FRAME_HEADER_BYTES + max_len, &msg);
    if (ws == WS_CLIENT_CLOSED)   { return FRAME_EOF; }
    if (ws == WS_CLIENT_IO)       { return FRAME_IO; }
    if (ws != WS_CLIENT_OK)       { return FRAME_BAD_LENGTH; }
    if (msg < FRAME_HEADER_BYTES) { return FRAME_TRUNCATED; }
    const uint32_t plen = frame_get_header(buf);
    if ((size_t)plen != msg - FRAME_HEADER_BYTES || plen < min_len || plen > max_len) {
        return FRAME_BAD_LENGTH;
    }
    /* frame_recv's contract: payload at buf + FRAME_HEADER_BYTES. It already is. */
    *payload_len = plen;
    return FRAME_OK;
}

static void client_session_close(client_session_t *cs)
{
    sodium_memzero(&cs->code, sizeof cs->code);
    if (cs->cc != NULL) {
        cc_wipe(cs->cc);
    }
    net_close(&cs->conn);
    cs->live = 0;
}

/* Prints a core failure exactly as the pre-core client printed it. */
static void report(const char *prog, const char *sub, const cc_diag_t *d)
{
    if (d->kind == CC_DIAG_HANDSHAKE || d->kind == CC_DIAG_MESSAGE) {
        fprintf(stderr, "%s %s: %s: %s\n", prog, sub, d->stage, d->detail);
    }
    if (d->kind != CC_DIAG_HANDSHAKE) {
        fprintf(stderr, "%s %s: failed at %s\n", prog, sub, d->stage);
    }
}

/* One inbound frame, bounded by what the core expects next, handed over whole
 * (header included) -- frame_recv and the WebSocket reader both leave the
 * header in buf[0..3]. */
static int cs_recv_for_core(client_session_t *cs, uint8_t *buf, size_t *msg_len)
{
    size_t lo = 0, hi = 0, len = 0;
    cc_recv_bounds(cs->cc, &lo, &hi);
    if (hi == 0u || cs_recv(cs, buf, lo, hi, &len) != FRAME_OK) {
        return -1;
    }
    frame_put_header(buf, (uint32_t)len);
    *msg_len = FRAME_HEADER_BYTES + len;
    return 0;
}

/* Handshake, then receive the LOGIN_CODE the daemon sends as its first record.
 * Returns EX_OK with `cs` live, or an exit status with everything wiped.
 *
 * `quiet` suppresses the diagnostics, because rotate PROBES with keys it fully
 * expects to fail -- a probe that printed an error for every attempt would
 * make a normal interrupted-rename recovery look like a fault.
 *
 * `kp` is lent to the core, which stops referring to it once ClientAuth is
 * signed (or, with CC_KEEP_FOR_ROTATE, once ROTATE is). */
static int client_open_session_ex(const char *prog, const char *sub, int quiet,
                                  const mldsa_keypair_t *kp,
                                  const uint8_t *hid, size_t hid_len,
                                  const uint8_t *sid, size_t sid_len,
                                  const uint8_t *server_pk,
                                  const char *unix_path, uint16_t port,
                                  const char *state, int proxy_v2, int force_ws,
                                  unsigned flags, client_session_t *cs)
{
    memset(cs, 0, sizeof *cs);
    net_conn_init(&cs->conn);
    cs->cc = &g_cc;
    cc_init(cs->cc, NULL, NULL);
    cs->deadline = net_deadline_in(LOGIN_TIMEOUT_MS);

    if (cc_pin_server(cs->cc, sid, sid_len, server_pk) != CC_OK) {
        cc_wipe(cs->cc);
        return EX_FAIL;
    }
    const net_status_t ns = (unix_path != NULL)
                                ? net_connect_unix(unix_path, cs->deadline, &cs->conn)
                                : net_connect_loopback(port, cs->deadline, &cs->conn);
    if (ns != NET_OK) {
        if (!quiet) {
            fprintf(stderr, "%s %s: cannot connect: %s\n", prog, sub, net_status_name(ns));
        }
        cc_wipe(cs->cc);
        return EX_FAIL;
    }

    /* The Unix socket IS the proxy-facing listener, and that one speaks
     * WebSocket (spec §7.1). The loopback port is the operator's tunnel and
     * stays raw. Nothing above this line knows the difference. */
    cs->ws = (unix_path != NULL) || force_ws;
    /* The PROXY v2 preamble goes first, before a byte of HTTP: that ordering is
     * the whole security property -- the client never gets to write ahead of
     * the statement about who it is. */
    if (cs->ws && proxy_v2 && write_proxy_v2_local(cs) != 0) {
        if (!quiet) {
            fprintf(stderr, "%s %s: could not send the PROXY v2 preamble\n", prog, sub);
        }
        net_close(&cs->conn);
        cc_wipe(cs->cc);
        return EX_FAIL;
    }
    if (cs->ws && ws_do_upgrade(cs, state) != 0) {
        if (!quiet) {
            fprintf(stderr, "%s %s: WebSocket upgrade failed\n", prog, sub);
        }
        net_close(&cs->conn);
        cc_wipe(cs->cc);
        return EX_FAIL;
    }

    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    size_t n = 0, m = 0;
    const char *io_stage = "client-hello";   /* where a transport failure is reported */

    if (cc_login_begin(cs->cc, hid, hid_len, kp, flags, tx, sizeof tx, &n) != CC_OK) {
        goto fail_core;
    }
    if (cs_send(cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) { goto fail_io; }
    io_stage = "server-hello";
    if (cs_recv_for_core(cs, rx, &m) != 0) { goto fail_io; }
    /* Spec 4: the core refuses a ServerHello not signed by the pinned key, and
     * then there is no ClientAuth to send -- this device authenticates to
     * nobody but the server it pinned. */
    if (cc_login_on_server_hello(cs->cc, rx, m, tx, sizeof tx, &n) != CC_OK) {
        goto fail_core;
    }
    io_stage = "client-auth";
    if (cs_send(cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) { goto fail_io; }
    io_stage = "login-code";
    if (cs_recv_for_core(cs, rx, &m) != 0) { goto fail_io; }
    if (cc_login_on_record(cs->cc, rx, m, &cs->code) != CC_OK) {
        goto fail_core;
    }
    cs->live = 1;
    return EX_OK;

fail_core:
    if (cc_diag(cs->cc)->kind == CC_DIAG_NONE) {
        goto fail_io;   /* a misuse the core refused without a diagnosis */
    }
    if (!quiet) {
        report(prog, sub, cc_diag(cs->cc));
    }
    client_session_close(cs);
    return EX_FAIL;
fail_io:
    if (!quiet) {
        fprintf(stderr, "%s %s: failed at %s\n", prog, sub, io_stage);
    }
    client_session_close(cs);
    return EX_FAIL;
}

static int client_open_session(const char *prog, const char *sub, int quiet,
                               const mldsa_keypair_t *kp,
                               const uint8_t *hid, size_t hid_len,
                               const uint8_t *sid, size_t sid_len,
                               const uint8_t *server_pk,
                               const char *unix_path, uint16_t port,
                               const char *state, int proxy_v2, int force_ws,
                               client_session_t *cs)
{
    return client_open_session_ex(prog, sub, quiet, kp, hid, hid_len, sid, sid_len, server_pk,
                                  unix_path, port, state, proxy_v2, force_ws, 0u, cs);
}

/* Sends BYE so the daemon releases the slot now rather than at its idle
 * deadline, then closes. Best effort: nothing depends on it arriving. */
static void client_say_bye(client_session_t *cs)
{
    static uint8_t tx[FRAME_BUF_BYTES];
    size_t n = 0;
    if (cs->live && cc_bye(cs->cc, tx, sizeof tx, &n) == CC_OK) {
        (void)cs_send(cs, tx, n - FRAME_HEADER_BYTES);
    }
    client_session_close(cs);
}

/* Generates a keypair for `hid` in the core, then writes the sealed MLDSAEK1
 * envelope at `ek_path` and the MLDSAPK1 public half at `pub_path`, both
 * atomically and never over an existing file. No plaintext secret key is
 * ever written anywhere (spec Req 10): the core seals in memory, and
 * keyfile_write_sealed refuses anything that is not a well-formed envelope.
 * `pk_out`, when non-NULL, receives the public key. */
static int client_seal_new_identity(const char *prog, const char *sub, const char *ek_path,
                                    const char *pub_path, const uint8_t *hid, size_t hid_len,
                                    const char *pass, size_t pass_len, uint8_t *pk_out)
{
    static uint8_t ek[8192];
    static uint8_t pub[4096];
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    size_t el = 0, pl = 0;
    cc_diag_t dg;
    const cc_status_t st = cc_seal_new_identity(hid, hid_len, pass, pass_len, KDF_OPS_OPERATOR, KDF_MEM_256MIB,
                                                ek, sizeof ek, &el, pub, sizeof pub, &pl, pk, &dg);
    if (st != CC_OK) {
        const int on_pub = (dg.stage != NULL && strcmp(dg.stage, "public-key") == 0);
        return failed(prog, sub, on_pub ? pub_path : ek_path, dg.detail != NULL ? dg.detail : cc_status_name(st));
    }
    const keyfile_status_t ks = keyfile_write_sealed(ek_path, ek, el);
    if (ks != KEYFILE_OK) {
        return failed(prog, sub, ek_path, keyfile_status_name(ks));
    }
    const demo_keys_status_t ps = demo_keys_write_public(pub_path, hid, hid_len, pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, sub, pub_path, demo_keys_status_name(ps));
    }
    if (pk_out != NULL) {
        memcpy(pk_out, pk, MLDSA_PUBLIC_KEY_BYTES);
    }
    return EX_OK;
}

static int cmd_client_keygen(int argc, char **argv, const char *prog)
{
    const char *dir = NULL, *pass_path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--dir") == 0 && has)                  { dir = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else { return unexpected(prog, "keygen", argv[i]); }
    }
    if (dir == NULL || pass_path == NULL) {
        return need(prog, "keygen", "--dir DIR --passphrase-file PATH");
    }

    /* Spec 3.1: the handle comes from the core, from 16 random bytes, made
     * HERE with the keypair -- no round trip is needed to learn an identity. */
    char handle[CC_HANDLE_BUF];
    cc_new_handle(handle);

    char ek[PATH_MAX], pub[PATH_MAX];
    char ek_name[64], pub_name[64];
    (void)snprintf(ek_name, sizeof ek_name, "%s.ek", handle);
    (void)snprintf(pub_name, sizeof pub_name, "%s.pub", handle);
    if (join(ek, sizeof ek, dir, ek_name) != 0 || join(pub, sizeof pub, dir, pub_name) != 0) {
        return need(prog, "keygen", "--dir DIR --passphrase-file PATH");
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return failed(prog, "keygen", dir, "cannot-create-directory");
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = read_pass(prog, "keygen", pass_path, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    rc = client_seal_new_identity(prog, "keygen", ek, pub, (const uint8_t *)handle, strlen(handle),
                                  (const char *)pass, pass_len, NULL);
    authd_secret_free(pass, pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    printf("%s\n", handle);
    fprintf(stderr, "%s keygen: wrote %s (MLDSAEK1, mode 0600) and %s\n", prog, ek, pub);
    fprintf(stderr, "%s keygen: give %s to an administrator, who runs:\n"
                    "  authd_admin enroll-operator --socket ADMIN.SOCK --user YOU "
                    "--handle %s --pub %s\n"
                    "The secret key never leaves this machine.\n", prog, pub_name, handle, pub_name);
    return EX_OK;
}

/* Shared option parsing for login and rotate: they take the same connection
 * and identity arguments, and differ only in what they do with the session. */
typedef struct {
    const uint8_t *hid; size_t hid_len;
    const uint8_t *sid; size_t sid_len;
    const char *key_path;
    const char *pass_path;
    const char *server_pub;
    const char *unix_path;
    uint16_t port;
    /* §7.1: the opaque value the site put in its pre-login session. It rides
     * the WebSocket URL, so it means nothing on the raw tunnel listener --
     * which is exactly why the daemon binds SHA-256("") there. */
    const char *state;
    /* Speak PROXY protocol v2 before the upgrade (spec §7.2), announcing
     * 127.0.0.1 as the client.
     *
     * A deployed daemon's proxy-facing socket has `proxy_protocol = v2` and
     * Caddy supplies the preamble; this flag exists so the end-to-end test can
     * drive that same configuration with the shipped binaries instead of only
     * a container. It is not a way to forge a client address: the listener's
     * uid allowlist (Req 11) is what decides who may state one at all. */
    int proxy_v2;
    /* Speak WebSocket over the TCP listener too.
     *
     * A browser reaches the daemon as WebSocket over TCP over TLS, through the
     * site's proxy -- and until this existed nothing in the tree could take
     * that shape: --unix implied WebSocket and --port implied raw frames, so
     * the one arrangement a real deployment uses could only be tested by
     * pretending the proxy was a Unix client. tests/caddy_proxy.sh puts a real
     * Caddy in front of the daemon and drives it with this. */
    int ws;
} client_args_t;

static int parse_client_args(int argc, char **argv, const char *prog, const char *sub,
                             client_args_t *a)
{
    const char *handle = NULL, *server_id = NULL, *port_s = NULL;
    memset(a, 0, sizeof *a);
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--handle") == 0 && has)               { handle = argv[++i]; }
        else if (strcmp(argv[i], "--key") == 0 && has)             { a->key_path = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { a->pass_path = argv[++i]; }
        else if (strcmp(argv[i], "--server-id") == 0 && has)       { server_id = argv[++i]; }
        else if (strcmp(argv[i], "--server-pub") == 0 && has)      { a->server_pub = argv[++i]; }
        else if (strcmp(argv[i], "--unix") == 0 && has)            { a->unix_path = argv[++i]; }
        else if (strcmp(argv[i], "--state") == 0 && has)           { a->state = argv[++i]; }
        else if (strcmp(argv[i], "--port") == 0 && has)            { port_s = argv[++i]; }
        else if (strcmp(argv[i], "--proxy-v2") == 0)               { a->proxy_v2 = 1; }
        else if (strcmp(argv[i], "--ws") == 0)                     { a->ws = 1; }
        else { return unexpected(prog, sub, argv[i]); }
    }
    uint64_t port = 0;
    if (handle == NULL || a->key_path == NULL || a->pass_path == NULL || server_id == NULL ||
        a->server_pub == NULL || (a->unix_path == NULL) == (port_s == NULL) ||
        demo_parse_id(handle, &a->hid, &a->hid_len) != 0 ||
        demo_parse_id(server_id, &a->sid, &a->sid_len) != 0 ||
        (port_s != NULL && demo_parse_u64(port_s, 1u, 65535u, &port) != 0)) {
        return need(prog, sub,
                    "--handle H --key H.ek --passphrase-file PATH --server-id ID "
                    "--server-pub server.pub (--unix PATH | --port N) [--state S] "
                    "[--proxy-v2] [--ws]");
    }
    a->port = (uint16_t)port;
    return EX_OK;
}

/* Decides which key file is live, completing an interrupted rename if that is
 * what happened, and returns the opened keypair.
 *
 * The probe is a REAL handshake against the daemon, not a local check: whether
 * a key is current is a fact the server holds, and "decrypts" says nothing
 * about it. That makes this the slow path -- but it only runs at all when a
 * .ek.next exists, which is the aftermath of an interrupted rotation.
 *
 * Only .ek authenticating lets the caller discard .ek.next. See
 * client_key_plan for why the spec's own wording cannot be used. */
static int client_resolve_key(const char *prog, const char *sub, const client_args_t *a,
                              const char *pass, size_t pass_len, const uint8_t *server_pk,
                              char *next_path, size_t next_cap, mldsa_keypair_t *kp_out)
{
    memset(kp_out, 0, sizeof *kp_out);
    if (snprintf(next_path, next_cap, "%s.next", a->key_path) < 0) {
        return EX_FAIL;
    }
    const int next_present = path_exists(next_path);

    /* The ordinary case: no interrupted rotation, so open .ek and go. */
    if (!next_present) {
        const keyfile_status_t ks = keyfile_open(a->key_path, a->hid, a->hid_len,
                                                 pass, pass_len, kp_out, NULL);
        if (ks != KEYFILE_OK) {
            return failed(prog, sub, a->key_path, keyfile_status_name(ks));
        }
        return EX_OK;
    }

    fprintf(stderr, "%s %s: %s exists -- a rotation was interrupted; asking the daemon "
                    "which key is live\n", prog, sub, next_path);

    int ek_ok = 0, next_ok = 0;
    mldsa_keypair_t ek_kp, next_kp;
    memset(&ek_kp, 0, sizeof ek_kp);
    memset(&next_kp, 0, sizeof next_kp);
    client_session_t probe;

    if (keyfile_open(a->key_path, a->hid, a->hid_len, pass, pass_len, &ek_kp, NULL) == KEYFILE_OK) {
        if (client_open_session(prog, sub, 1, &ek_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, a->proxy_v2, a->ws, &probe) == EX_OK) {
            ek_ok = 1;
            client_say_bye(&probe);
        }
    }
    if (!ek_ok &&
        keyfile_open(next_path, a->hid, a->hid_len, pass, pass_len, &next_kp, NULL) == KEYFILE_OK) {
        if (client_open_session(prog, sub, 1, &next_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, a->proxy_v2, a->ws, &probe) == EX_OK) {
            next_ok = 1;
            client_say_bye(&probe);
        }
    }

    const key_plan_t plan = client_key_plan(ek_ok, next_present, next_ok);
    int rc = EX_FAIL;
    switch (plan) {
    case KEY_PLAN_USE_EK:
        /* .ek is live, so the server never committed .ek.next. THIS is the only
         * proof that makes discarding it safe -- and the caller does the
         * discarding, because login should not delete files. */
        fprintf(stderr, "%s %s: %s is still the live key; %s was never committed\n",
                prog, sub, a->key_path, next_path);
        memcpy(kp_out, &ek_kp, sizeof ek_kp);
        memset(&ek_kp, 0, sizeof ek_kp);
        rc = EX_OK;
        break;
    case KEY_PLAN_PROMOTE_NEXT:
        /* The server committed and the rename was interrupted. Finish it. */
        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {
            (void)failed(prog, sub, a->key_path, "cannot-complete-rename");
            break;
        }
        fprintf(stderr, "%s %s: completed the interrupted rotation; %s now holds the live key\n",
                prog, sub, a->key_path);
        memcpy(kp_out, &next_kp, sizeof next_kp);
        memset(&next_kp, 0, sizeof next_kp);
        rc = EX_OK;
        break;
    case KEY_PLAN_REFUSE:
    default:
        /* Neither worked. Deleting either one now would be guessing with the
         * only copies of the identity, so nothing is touched. */
        fprintf(stderr, "%s %s: neither %s nor %s authenticates. NOTHING has been deleted; "
                        "an administrator must re-enrol this device.\n",
                prog, sub, a->key_path, next_path);
        break;
    }
    mldsa_keypair_free(&ek_kp);
    mldsa_keypair_free(&next_kp);
    return rc;
}

static int cmd_client_login(int argc, char **argv, const char *prog)
{
    client_args_t a;
    int rc = parse_client_args(argc, argv, prog, "login", &a);
    if (rc != EX_OK) { return rc; }

    /* The pinned server key, loaded BEFORE anything is sent. Spec 4: a client
     * MUST reject a ServerHello that is not signed by the pinned key -- that
     * is what makes this deployment phishing-resistant, the same property
     * WebAuthn gets from origin binding. A login without a pin would
     * authenticate this device to whatever answered the socket. */
    static uint8_t server_pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(a.server_pub, a.sid, a.sid_len, server_pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, "login", a.server_pub, demo_keys_status_name(ps));
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = read_pass(prog, "login", a.pass_path, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    /* Every invocation of this tool is a "startup", so the interrupted-rename
     * recovery runs here too -- and in practice this is the command that
     * discovers one, not rotate. */
    char next_path[PATH_MAX];
    mldsa_keypair_t kp;
    rc = client_resolve_key(prog, "login", &a, (const char *)pass, pass_len, server_pk,
                            next_path, sizeof next_path, &kp);
    authd_secret_free(pass, pass_len);
    if (rc != EX_OK) { return rc; }

    client_session_t cs;
    rc = client_open_session(prog, "login", 0, &kp, a.hid, a.hid_len, a.sid, a.sid_len,
                             server_pk, a.unix_path, a.port, a.state, a.proxy_v2, a.ws, &cs);
    mldsa_keypair_free(&kp);
    if (rc != EX_OK) { return rc; }

    /* Base64url, spec 13: this is pasted into the site's form by a human, and
     * 43 unpadded URL-safe characters survive that trip where hex would be 64
     * and standard base64 would carry '+', '/' and '='. */
    char b64[sodium_base64_ENCODED_LEN(AUTHMSG_CODE_BYTES,
                                       sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
    (void)sodium_bin2base64(b64, sizeof b64, cs.code.code, sizeof cs.code.code,
                            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    printf("%s\n", b64);
    sodium_memzero(b64, sizeof b64);
    if ((cs.code.flags & AUTHMSG_FLAG_ROTATION_DUE) != 0u) {
        fprintf(stderr, "%s login: this key is due for rotation -- run `%s rotate`\n", prog, prog);
    }
    fprintf(stderr, "%s login: code valid for %lld more seconds; single use\n", prog,
            (long long)cs.code.code_expires - (long long)time(NULL));
    client_say_bye(&cs);
    return EX_OK;
}

static int cmd_client_rotate(int argc, char **argv, const char *prog)
{
    client_args_t a;
    int rc = parse_client_args(argc, argv, prog, "rotate", &a);
    if (rc != EX_OK) { return rc; }

    static uint8_t server_pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(a.server_pub, a.sid, a.sid_len, server_pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, "rotate", a.server_pub, demo_keys_status_name(ps));
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = read_pass(prog, "rotate", a.pass_path, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    char next_path[PATH_MAX];
    mldsa_keypair_t old_kp;
    rc = client_resolve_key(prog, "rotate", &a, (const char *)pass, pass_len, server_pk,
                            next_path, sizeof next_path, &old_kp);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        return rc;
    }

    /* A leftover .ek.next that the probe did NOT promote is stale -- .ek
     * authenticated, which proves the server never committed it. Only now, on
     * that proof, is deleting it safe; never on the probe failing. */
    if (path_exists(next_path)) {
        (void)unlink(next_path);
    }

    /* Seal the new key BEFORE sending anything (spec 10.2). If everything
     * after this dies, the next invocation's probe decides which key is live
     * and completes or discards the rename -- there is no state in which the
     * only copy of a live key is gone. The new key is sealed under the SAME
     * passphrase: the probe has only one, and changing a passphrase during a
     * rotation is a different operation (`authd_admin rewrap`). */
    uint8_t new_pk[MLDSA_PUBLIC_KEY_BYTES];
    /* THIS DEVICE's public half, beside its own key -- derived from --key, not
     * from --server-pub, which names someone else's file in someone else's
     * directory. It is published only after the daemon accepts, so a failed
     * rotation never leaves a .pub claiming to be current. */
    char pub_path[PATH_MAX], pub_tmp[PATH_MAX];
    {
        const size_t kl = strlen(a.key_path);
        const int has_ek = (kl > 3u && strcmp(a.key_path + kl - 3u, ".ek") == 0);
        if (snprintf(pub_path, sizeof pub_path, "%.*s.pub",
                     (int)(has_ek ? kl - 3u : kl), a.key_path) < 0) {
            authd_secret_free(pass, pass_len);
            mldsa_keypair_free(&old_kp);
            return EX_FAIL;
        }
    }
    /* snprintf's return is CHECKED, not discarded: gcc refuses the discard at
     * both optimisation levels (-Werror=format-truncation), and it is right to
     * -- a truncated temp path would collide with something else. */
    {
        const int pn = snprintf(pub_tmp, sizeof pub_tmp, "%s.newpub.%ld",
                                next_path, (long)getpid());
        if (pn < 0 || (size_t)pn >= sizeof pub_tmp) {
            authd_secret_free(pass, pass_len);
            mldsa_keypair_free(&old_kp);
            return failed(prog, "rotate", next_path, "path-too-long");
        }
    }
    rc = client_seal_new_identity(prog, "rotate", next_path, pub_tmp, a.hid, a.hid_len,
                                  (const char *)pass, pass_len, new_pk);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        mldsa_keypair_free(&old_kp);
        return rc;
    }

    mldsa_keypair_t new_kp;
    memset(&new_kp, 0, sizeof new_kp);
    const keyfile_status_t ks = keyfile_open(next_path, a.hid, a.hid_len,
                                             (const char *)pass, pass_len, &new_kp, NULL);
    authd_secret_free(pass, pass_len);
    if (ks != KEYFILE_OK) {
        mldsa_keypair_free(&old_kp);
        return failed(prog, "rotate", next_path, keyfile_status_name(ks));
    }

    /* CC_KEEP_FOR_ROTATE: the old key signs ROTATE after the session exists,
     * so the core keeps referring to it until cc_rotate_build and no longer. */
    client_session_t cs;
    rc = client_open_session_ex(prog, "rotate", 0, &old_kp, a.hid, a.hid_len, a.sid, a.sid_len,
                                server_pk, a.unix_path, a.port, a.state, a.proxy_v2, a.ws,
                                CC_KEEP_FOR_ROTATE, &cs);
    if (rc != EX_OK) {
        mldsa_keypair_free(&old_kp);
        mldsa_keypair_free(&new_kp);
        return rc;
    }

    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    size_t n = 0, m = 0;
    rc = EX_FAIL;

    const cc_status_t bs = cc_rotate_build(cs.cc, &new_kp, 0u, tx, sizeof tx, &n);
    mldsa_keypair_free(&old_kp);   /* both signatures are made */
    mldsa_keypair_free(&new_kp);
    if (bs != CC_OK && bs != CC_ERR_SESSION) {
        (void)failed(prog, "rotate", next_path, "cannot-build-rotate");
        goto out;
    }
    if (bs != CC_OK || cs_send(&cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) {
        (void)failed(prog, "rotate", next_path, "cannot-send-rotate");
        goto out;
    }
    if (cs_recv_for_core(&cs, rx, &m) != 0) {
        /* No answer is NOT proof that nothing happened -- the daemon may have
         * committed and died before sealing the ACK. .ek.next stays. */
        fprintf(stderr, "%s rotate: no reply; %s is KEPT so the next run can resolve it\n",
                prog, next_path);
        goto out;
    }
    {
        uint8_t code = 0;
        const cc_status_t rs = cc_rotate_on_reply(cs.cc, rx, m, &code);
        if (rs == CC_ERR_SESSION || rs == CC_ERR_FRAME) {
            fprintf(stderr, "%s rotate: the reply did not authenticate; %s is KEPT\n",
                    prog, next_path);
            goto out;
        }
        if (rs == CC_ERR_REFUSED || rs == CC_ERR_MESSAGE) {
            if (rs == CC_ERR_REFUSED) {
                fprintf(stderr, "%s rotate: the daemon refused the rotation (error 0x%02x)\n",
                        prog, code);
            } else {
                fprintf(stderr, "%s rotate: unexpected reply\n", prog);
            }
            /* A refusal is not proof either -- the codes are coarse by design
             * (spec 6.5) and a daemon that committed then crashed answers
             * nothing at all. Keep the file; the probe decides next time. */
            fprintf(stderr, "%s rotate: %s is KEPT so the next run can resolve it\n",
                    prog, next_path);
            goto out;
        }
        /* The core accepts only an ACK naming THIS handle and the key actually
         * sealed, compared in constant time (Req 3). */
        if (rs != CC_OK) {
            fprintf(stderr, "%s rotate: the ACK names a different handle or key -- "
                            "NOT promoting %s\n", prog, next_path);
            goto out;
        }
        if (keyfile_promote(next_path, a.key_path) != KEYFILE_OK) {
            (void)failed(prog, "rotate", a.key_path, "cannot-replace-key");
            goto out;
        }
        /* Replace the device's own .pub so it does not go on naming a key the
         * server no longer accepts. Public data, so a plain rename: the
         * custody rules keyfile_promote enforces are about secrets. */
        if (rename(pub_tmp, pub_path) != 0) {
            fprintf(stderr, "%s rotate: the key rotated but %s could not be updated; "
                            "it still names the OLD key\n", prog, pub_path);
        }
        printf("%s\n", a.key_path);
        fprintf(stderr, "%s rotate: %s now holds the new key; the old one no longer "
                        "authenticates\n", prog, a.key_path);
        rc = EX_OK;
    }
out:
    (void)unlink(pub_tmp);
    client_say_bye(&cs);
    return rc;
}

static void client_usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s keygen --dir DIR --passphrase-file PATH\n"
            "  %s login  --handle H --key H.ek --passphrase-file PATH\n"
            "            --server-id ID --server-pub server.pub (--unix PATH | --port N)\n"
            "            [--state S] [--proxy-v2] [--ws]\n"
            "  %s rotate --handle H --key H.ek --passphrase-file PATH\n"
            "            --server-id ID --server-pub server.pub (--unix PATH | --port N)\n"
            "            [--state S] [--proxy-v2] [--ws]\n"
            "\n"
            "keygen prints the new device handle on stdout; login prints the login code as\n"
            "base64url, for pasting into the site's form. rotate replaces this device's key\n"
            "and keeps its identity: the new key is sealed to <key>.next BEFORE anything is\n"
            "sent, and renamed over <key> only when the daemon acknowledges. If a rotation\n"
            "is interrupted, the next login or rotate asks the daemon which key is live and\n"
            "finishes the job; nothing is ever deleted on a guess.\n"
            "--unix reaches the proxy-facing socket, which speaks WebSocket; --port is the\n"
            "raw loopback listener an operator reaches through an SSH tunnel. Add --proxy-v2\n"
            "when the daemon's proxy_protocol is v2 -- normally a TLS proxy supplies that\n"
            "preamble, and without it the daemon fails the connection closed (spec 7.2).\n"
            "--ws speaks WebSocket over --port as well, which is the shape a browser takes\n"
            "through a TLS proxy.\n"
            "Passphrases are FILES (mode 0600, owned by you): argv and the environment are\n"
            "readable by other processes on this machine.\n"
            "Exit: 0 ok, 1 operation failed, 2 usage, 3 configuration.\n",
            prog, prog, prog);
}

int authd_cli_client(int argc, char **argv)
{
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "authd_client";
    if (argc < 2) {
        client_usage(prog);
        return EX_USAGE;
    }
    if (strcmp(argv[1], "keygen") == 0) { return cmd_client_keygen(argc, argv, prog); }
    if (strcmp(argv[1], "login") == 0)  { return cmd_client_login(argc, argv, prog); }
    if (strcmp(argv[1], "rotate") == 0) { return cmd_client_rotate(argc, argv, prog); }
    fprintf(stderr, "%s: unknown subcommand '%s'\n", prog, argv[1]);
    client_usage(prog);
    return EX_USAGE;
}
