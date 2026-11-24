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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_secret.h"
#include "authmsg.h"
#include "cli_common.h"
#include "cli_prompt.h"
#include "client_core.h"
#include "demo_app.h"
#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "passphrase.h"
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

/* The exit status for a --key that could not be used (F451; spec 13). */
static int client_key_exit(keyfile_status_t ks)
{
    return (ks == KEYFILE_ERR_CRYPTO) ? EX_FAIL : EX_CONFIG;
}

/* The same for --server-pub (F551; erratum 144): a file named on the command
 * line that cannot be used is 3, and only a failure inside this program 1. */
static int client_pub_exit(demo_keys_status_t ps)
{
    return (ps == DEMO_KEYS_ERR_CRYPTO || ps == DEMO_KEYS_ERR_ARG) ? EX_FAIL : EX_CONFIG;
}

/* And for the key's directory, which a run locks (F551). The directory is
 * part of the path the operator gave: one that is missing, is not a
 * directory or may not be opened is 3. Anything else that stops the lock --
 * no descriptors, no locks left -- is this program's, 1. `err` is errno as
 * client_key_lock left it. */
static int client_lock_exit(int err)
{
    return (err == ENOENT || err == ENOTDIR || err == EACCES || err == ELOOP || err == ENAMETOOLONG)
               ? EX_CONFIG : EX_FAIL;
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

/* Why the last client_open_session_ex failed, for a caller that asked it to
 * be quiet (F225). `g_open_judged` is set only when the failure came AFTER
 * ClientAuth was sent: that is the one point at which the daemon has seen
 * the key and can have refused it. Everything earlier -- no connection, no
 * upgrade, a ServerHello that did not arrive or did not verify -- says
 * nothing about whether the key is live, and `g_open_why` says what it was. */
static int g_open_judged;
static int g_open_unanswered;   /* F431: the daemon had the key and could not record the login */
/* F591: the last client_resolve_key gave back the key in .ek.next WITHOUT
 * promoting it, because the .pub could not be replaced (F583). A login goes
 * ahead with that key; a rotation must not. */
static int g_resolve_kept_next;
static char g_open_why[96];

static void open_failed_before_key(const char *what, const char *detail)
{
    g_open_judged = 0;
    (void)snprintf(g_open_why, sizeof g_open_why, "%s%s%s", what,
                   (detail != NULL) ? ": " : "", (detail != NULL) ? detail : "");
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
    g_open_judged = 0;
    g_open_unanswered = 0;
    g_open_why[0] = '\0';

    if (cc_pin_server(cs->cc, sid, sid_len, server_pk) != CC_OK) {
        open_failed_before_key("the server's public key was not accepted", NULL);
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
        open_failed_before_key("cannot connect", net_status_name(ns));
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
        open_failed_before_key("could not send the PROXY v2 preamble", NULL);
        net_close(&cs->conn);
        cc_wipe(cs->cc);
        return EX_FAIL;
    }
    if (cs->ws && ws_do_upgrade(cs, state) != 0) {
        if (!quiet) {
            fprintf(stderr, "%s %s: WebSocket upgrade failed\n", prog, sub);
        }
        open_failed_before_key("WebSocket upgrade failed", NULL);
        net_close(&cs->conn);
        cc_wipe(cs->cc);
        return EX_FAIL;
    }

    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    size_t n = 0, m = 0;
    const char *io_stage = "client-hello";   /* where a transport failure is reported */

    open_failed_before_key("failed at", io_stage);
    if (cc_login_begin(cs->cc, hid, hid_len, kp, flags, tx, sizeof tx, &n) != CC_OK) {
        goto fail_core;
    }
    if (cs_send(cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) { goto fail_io; }
    io_stage = "server-hello";
    open_failed_before_key("failed at", io_stage);
    if (cs_recv_for_core(cs, rx, &m) != 0) { goto fail_io; }
    /* Spec 4: the core refuses a ServerHello not signed by the pinned key, and
     * then there is no ClientAuth to send -- this device authenticates to
     * nobody but the server it pinned. */
    if (cc_login_on_server_hello(cs->cc, rx, m, tx, sizeof tx, &n) != CC_OK) {
        goto fail_core;
    }
    io_stage = "client-auth";
    open_failed_before_key("failed at", io_stage);
    if (cs_send(cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) { goto fail_io; }
    io_stage = "login-code";
    g_open_judged = 1;   /* the daemon has the key now; a failure is its answer */
    if (cs_recv_for_core(cs, rx, &m) != 0) {
        /* F402: unless it never answered. A daemon that stalled after
         * ClientAuth ran both recovery probes to their deadline, and the
         * client then said "neither key authenticates ... an administrator
         * must re-enrol this device" of two keys nobody had refused. */
        if (!client_failure_is_refusal(1, net_now_ms(), cs->deadline)) {
            open_failed_before_key("the daemon did not answer by the deadline at", io_stage);
        }
        goto fail_io;
    }
    {
        const cc_status_t ls = cc_login_on_record(cs->cc, rx, m, &cs->code);
        if (ls == CC_ERR_UNANSWERED) {
            /* F431: the daemon took the key and could not record the login.
             * That is not its answer about the key, so it is not judged. */
            open_failed_before_key("the daemon could not record the login (its store failed) at", io_stage);
            g_open_unanswered = 1;
        }
        if (ls != CC_OK) {
            goto fail_core;
        }
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
        /* V4-282, F469: the key this run just sealed is nobody's yet -- no
         * daemon has seen it, and the run fails without naming it -- so it
         * is not left behind: an orphan .ek beside no .pub after keygen, a
         * staged .ek.next every later login probed after rotate. */
        (void)unlink(ek_path);
        return failed(prog, sub, pub_path, demo_keys_status_name(ps));
    }
    if (pk_out != NULL) {
        memcpy(pk_out, pk, MLDSA_PUBLIC_KEY_BYTES);
    }
    return EX_OK;
}

/* A passphrase from a FILE or from the TERMINAL (V4-13d) -- never argv or the
 * environment (spec 12). The terminal is /dev/tty, opened here, so neither the
 * prompt nor the passphrase goes near stdin or stdout: stdout carries the
 * handle or the login code a script may be capturing. `fresh` asks for a NEW
 * passphrase: typed twice and held to the policy (cli_prompt_new). */
static int get_pass(const char *prog, const char *sub, const char *path, int prompt,
                    const char *what, int fresh, uint8_t **out, size_t *out_len)
{
    if (!prompt) {
        const int r = read_pass(prog, sub, path, out, out_len);
        /* V4-282, F465: one trailing newline is stripped from a file; a
         * CRLF file kept the carriage return, which the prompt drops. A key
         * made from such a file then opened from that file only, never from
         * --passphrase-prompt with the same words. A NEW passphrase is refused
         * by name; an existing key's file is read as it always was, since a
         * key already sealed under it opens with nothing else. */
        if (r == EX_OK && fresh && *out_len > 0u && (*out)[*out_len - 1u] == '\r') {
            authd_secret_free(*out, *out_len);
            *out = NULL;
            *out_len = 0;
            fprintf(stderr, "%s %s: %s: passphrase-ends-in-cr (a CRLF line ending; --passphrase-prompt "
                            "would not give the same passphrase -- remove the carriage return)\n",
                    prog, sub, path);
            return EX_CONFIG;
        }
        return r;
    }
    const int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "%s %s: --passphrase-prompt: %s (use --passphrase-file)\n", prog, sub,
                cli_prompt_status_name(CLI_PROMPT_ERR_NOT_TTY));
        return EX_CONFIG;
    }
    char who[96];
    (void)snprintf(who, sizeof who, "%s %s", prog, sub);
    cli_prompt_status_t st;
    if (fresh) {
        st = cli_prompt_new(fd, who, out, out_len);
    } else {
        char line[160];
        (void)snprintf(line, sizeof line, "Passphrase for %s: ", what);
        st = cli_prompt_read(fd, line, out, out_len);
    }
    (void)close(fd);
    if (st != CLI_PROMPT_OK) {
        fprintf(stderr, "%s %s: --passphrase-prompt: %s\n", prog, sub, cli_prompt_status_name(st));
        return (st == CLI_PROMPT_ERR_NOT_TTY) ? EX_CONFIG : EX_FAIL;
    }
    return EX_OK;
}

/* F552 (V4-317): a flag given twice is a usage error, as it is in
 * authd_admin (F537). The last one used to win without a word: `rotate --key
 * A.ek --key B.ek` rotated B. Unlike authd_admin's, some of this tool's flags
 * take no value, so the arguments are walked: `valued` lists the flags whose
 * next argument is their value, which is skipped and never compared, so a
 * value spelled like a flag is still a value. Returns the repeated flag, or
 * NULL. */
static const char *client_repeated_flag(int argc, char **argv, const char *const *valued)
{
    for (int i = 2; i < argc; i++) {
        int takes = 0;
        for (size_t v = 0; valued[v] != NULL; v++) {
            if (strcmp(argv[i], valued[v]) == 0) { takes = 1; }
        }
        for (int j = 2; j < i; j++) {
            int j_takes = 0;
            for (size_t v = 0; valued[v] != NULL; v++) {
                if (strcmp(argv[j], valued[v]) == 0) { j_takes = 1; }
            }
            if (strcmp(argv[i], argv[j]) == 0) {
                return argv[i];
            }
            if (j_takes) { j++; }
        }
        if (takes) { i++; }
    }
    return NULL;
}

static int client_refuse_repeat(int argc, char **argv, const char *prog, const char *sub,
                                const char *const *valued)
{
    const char *twice = client_repeated_flag(argc, argv, valued);
    if (twice == NULL) {
        return EX_OK;
    }
    fprintf(stderr, "%s %s: %s is given more than once\n", prog, sub, twice);
    return EX_USAGE;
}

static int cmd_client_keygen(int argc, char **argv, const char *prog)
{
    const char *dir = NULL, *pass_path = NULL;
    int prompt = 0;
    {
        static const char *const valued[] = { "--dir", "--passphrase-file", NULL };
        if (client_refuse_repeat(argc, argv, prog, "keygen", valued) != EX_OK) { return EX_USAGE; }
    }
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--dir") == 0 && has)                  { dir = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-prompt") == 0)      { prompt = 1; }
        else { return unexpected(prog, "keygen", argv[i]); }
    }
    if (dir == NULL || (pass_path == NULL) == (prompt == 0)) {
        return need(prog, "keygen", "--dir DIR (--passphrase-file PATH | --passphrase-prompt)");
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
        return need(prog, "keygen", "--dir DIR (--passphrase-file PATH | --passphrase-prompt)");
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return failed(prog, "keygen", dir, "cannot-create-directory");
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = get_pass(prog, "keygen", pass_path, prompt, NULL, 1, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    /* ONE policy for every new passphrase (passphrase.h), whichever way it
     * arrived: the prompt has already applied it, a file has not. Only keygen
     * checks -- rotate re-seals under the SAME passphrase, and refusing there
     * would strand an existing identity that predates the policy. */
    {
        pp_report_t rep;
        const pp_verdict_t v = pp_check(pass, pass_len, &rep);
        if (v != PP_OK) {
            char why[160];
            (void)pp_explain(v, &rep, why, sizeof why);
            authd_secret_free(pass, pass_len);
            fprintf(stderr, "%s keygen: failed: passphrase-policy: %s\n", prog, why);
            return EX_FAIL;
        }
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
    int pass_prompt;              /* --passphrase-prompt instead of a file */
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
    {
        static const char *const valued[] = { "--handle", "--key", "--passphrase-file", "--server-id",
                                              "--server-pub", "--unix", "--state", "--port", NULL };
        if (client_refuse_repeat(argc, argv, prog, sub, valued) != EX_OK) { return EX_USAGE; }
    }
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--handle") == 0 && has)               { handle = argv[++i]; }
        else if (strcmp(argv[i], "--key") == 0 && has)             { a->key_path = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { a->pass_path = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-prompt") == 0)      { a->pass_prompt = 1; }
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
    if (handle == NULL || a->key_path == NULL || (a->pass_path == NULL) == (a->pass_prompt == 0) ||
        server_id == NULL ||
        a->server_pub == NULL || (a->unix_path == NULL) == (port_s == NULL) ||
        demo_parse_id(handle, &a->hid, &a->hid_len) != 0 ||
        demo_parse_id(server_id, &a->sid, &a->sid_len) != 0 ||
        (port_s != NULL && demo_parse_u64(port_s, 1u, 65535u, &port) != 0)) {
        return need(prog, sub,
                    "--handle H --key H.ek (--passphrase-file PATH | --passphrase-prompt) "
                    "--server-id ID --server-pub server.pub (--unix PATH | --port N) "
                    "[--state S] [--proxy-v2] [--ws]");
    }
    a->port = (uint16_t)port;
    /* F352: --state and --proxy-v2 are things a WebSocket connection carries,
     * and --port without --ws is the raw listener. Both were dropped there
     * without a word: `login --port N --state S` exited 0 with a code bound
     * to the EMPTY state, and the site's exchange for S then failed with
     * nothing pointing here. An option that cannot take effect is refused. */
    if (a->unix_path == NULL && !a->ws && (a->state != NULL || a->proxy_v2)) {
        fprintf(stderr, "%s %s: --state and --proxy-v2 need a WebSocket connection: "
                        "with --port, add --ws\n", prog, sub);
        return EX_USAGE;
    }
    /* The daemon's own rule for `state` (ws.c take_state, spec 7.1), asked
     * here so the refusal names it: over 64 bytes or with a space the answer
     * was only "WebSocket upgrade failed", and `a&b` was sent as it stood
     * and bound as `a`. */
    if (a->state != NULL) {
        const size_t sl = strlen(a->state);
        int ok = (sl >= 1u && sl <= WS_STATE_MAX);
        for (size_t i = 0; ok && i < sl; i++) {
            const unsigned char ch = (unsigned char)a->state[i];
            /* F550: and '%', '+' and '#', which the daemon has refused in
             * the URL since V4-287 (F478); this check had not followed. */
            if (ch < 0x21u || ch > 0x7eu || ch == '&' || ch == '%' || ch == '+' || ch == '#') { ok = 0; }
        }
        if (!ok) {
            fprintf(stderr, "%s %s: --state is 1 to %u printable ASCII characters, "
                            "with no space and none of '&', '%%', '+', '#'\n", prog, sub, (unsigned)WS_STATE_MAX);
            return EX_USAGE;
        }
    }
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
/* THIS DEVICE's public file, beside its own key: "<key minus .ek>.pub". */
static int client_pub_path(const char *key_path, char *out, size_t cap)
{
    const size_t kl = strlen(key_path);
    const int has_ek = (kl > 3u && strcmp(key_path + kl - 3u, ".ek") == 0);
    const int n = snprintf(out, cap, "%.*s.pub", (int)(has_ek ? kl - 3u : kl), key_path);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* A recovery that promotes .ek.next republishes the .pub as well (F227).
 * rotate publishes it only after the ACK, so an interrupted rotation leaves
 * the .pub naming the OLD key, and the promotion used to leave it so: the
 * next administrator to enrol from it would install a key this device no
 * longer holds. Written beside the key and renamed, as rotate does, and
 * BEFORE the key is promoted (F466).
 *
 * Returns 0 when the .pub names `pk`, -1 when it could not be replaced. The
 * caller then does NOT promote (F583): promoted, .ek.next was gone, and with
 * it the only thing that makes a later run publish the .pub again. It used
 * to return nothing, and a full disk left the new key under a .pub naming
 * the old one for good -- F401's state, by a failure instead of a crash. */
static int client_republish_pub(const char *prog, const char *sub, const client_args_t *a,
                                const char *next_path, const uint8_t *pk)
{
    char pub_path[PATH_MAX], pub_tmp[PATH_MAX];
    const int pn = snprintf(pub_tmp, sizeof pub_tmp, "%s.newpub.%ld", next_path, (long)getpid());
    if (client_pub_path(a->key_path, pub_path, sizeof pub_path) != 0 ||
        pn < 0 || (size_t)pn >= sizeof pub_tmp) {
        fprintf(stderr, "%s %s: the device's .pub could not be updated (path-too-long); "
                        "it still names the OLD key\n", prog, sub);
        return -1;
    }
    (void)unlink(pub_tmp);
    if (demo_keys_write_public(pub_tmp, a->hid, a->hid_len, pk) != DEMO_KEYS_OK ||
        rename(pub_tmp, pub_path) != 0) {
        (void)unlink(pub_tmp);
        fprintf(stderr, "%s %s: %s could not be updated; it still names the OLD key\n", prog, sub, pub_path);
        return -1;
    }
    return 0;
}

/* V4-217, F293: one run at a time beside a key. The lock is an flock on the
 * key's DIRECTORY -- the key file itself is replaced by a rename, and a lock
 * file would be one more thing left beside a secret. It is held by a rotation
 * from before it reads the key until it exits, and by any run that finds a
 * .ek.next, while it decides what that file is. A second run waits, and says
 * that it is waiting; the kernel drops the lock when its holder dies. Returns
 * the descriptor to close, or -1. */
static int client_key_lock(const char *prog, const char *sub, const char *key_path)
{
    char dir[PATH_MAX];
    const char *slash = strrchr(key_path, '/');
    const size_t dl = (slash == NULL) ? 0u : (size_t)(slash - key_path);
    if (dl >= sizeof dir) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (slash == NULL) {
        memcpy(dir, ".", 2u);
    } else if (dl == 0u) {
        memcpy(dir, "/", 2u);
    } else {
        memcpy(dir, key_path, dl);
        dir[dl] = '\0';
    }
    const int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK) {
            const int e = errno;       /* the caller reads it (F551) */
            (void)close(fd);
            errno = e;
            return -1;
        }
        fprintf(stderr, "%s %s: another run is using the keys in %s; waiting for it to finish\n",
                prog, sub, dir);
        int r;
        do {
            r = flock(fd, LOCK_EX);
        } while (r != 0 && errno == EINTR);
        if (r != 0) {
            const int e = errno;
            (void)close(fd);
            errno = e;
            return -1;
        }
        /* The wait is over, and is said to be (V4-327): the line above
         * leaves a person watching with no sign that anything followed. */
        fprintf(stderr, "%s %s: the other run has finished; going on\n", prog, sub);
    }
    return fd;
}

/* *stale_next is set only when the daemon was ASKED and .ek authenticated
 * with a .ek.next present: the one proof that lets the caller delete it. */
static int client_resolve_key_locked(const char *prog, const char *sub, const client_args_t *a,
                              const char *pass, size_t pass_len, const uint8_t *server_pk,
                              const char *next_path, int next_seen, mldsa_keypair_t *kp_out,
                              int *stale_next)
{
    /* V4-282, F468: only a .ek.next the caller saw -- and so holds the
     * directory's lock for -- is decided about. One that appeared after the
     * caller looked is a rotation in progress, and this run, unlocked, uses
     * .ek and leaves it alone. */
    const int next_present = next_seen && path_exists(next_path);
    g_resolve_kept_next = 0;

    /* The ordinary case: no interrupted rotation, so open .ek and go. */
    if (!next_present) {
        const keyfile_status_t ks = keyfile_open(a->key_path, a->hid, a->hid_len,
                                                 pass, pass_len, kp_out, NULL);
        if (ks != KEYFILE_OK) {
            /* F451: a --key that cannot be used is a file the operator named,
             * 3, as --passphrase-file already was and as authd_admin's --key
             * is (spec 13, errata 51 and 82). Only an internal failure is 1. */
            (void)failed(prog, sub, a->key_path, keyfile_status_name(ks));
            return client_key_exit(ks);
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

    /* F225: WHY each file did not authenticate is kept. "The daemon refused
     * this key" is the only reason that makes an identity dead; a file that
     * would not open, or a daemon that was never asked, is something else. */
    keyfile_status_t ks_ek = KEYFILE_OK, ks_next = KEYFILE_OK;
    int unasked = 0;             /* a probe failed before the daemon saw the key */
    char unasked_why[sizeof g_open_why];
    unasked_why[0] = '\0';

    ks_ek = keyfile_open(a->key_path, a->hid, a->hid_len, pass, pass_len, &ek_kp, NULL);
    if (ks_ek == KEYFILE_OK) {
        if (client_open_session(prog, sub, 1, &ek_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, a->proxy_v2, a->ws, &probe) == EX_OK) {
            ek_ok = 1;
            client_say_bye(&probe);
        } else if (!g_open_judged) {
            unasked = 1;
            memcpy(unasked_why, g_open_why, sizeof unasked_why);
        }
    }
    if (!ek_ok) {
        ks_next = keyfile_open(next_path, a->hid, a->hid_len, pass, pass_len, &next_kp, NULL);
    }
    /* F705 (V4-347): not when the first probe never reached the point of
     * showing the daemon a key. A daemon that could not be reached was
     * waited for twice, forty seconds for one that twenty had shown to be
     * away, to arrive at the same "cannot ask the daemon". */
    if (!ek_ok && ks_next == KEYFILE_OK && !unasked) {
        if (client_open_session(prog, sub, 1, &next_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, a->proxy_v2, a->ws, &probe) == EX_OK) {
            next_ok = 1;
            client_say_bye(&probe);
        } else if (!g_open_judged) {
            unasked = 1;
            memcpy(unasked_why, g_open_why, sizeof unasked_why);
        }
    }

    const key_plan_t plan = client_key_plan(ek_ok, next_present, next_ok);
    int rc = EX_FAIL;
    switch (plan) {
    case KEY_PLAN_USE_EK:
        /* .ek is live, so the server has not committed .ek.next. Not "never
         * will" (F787): a ROTATE that left an earlier run and is still on its
         * way can commit it after this look. So nobody discards it on this:
         * login deletes nothing, and rotate offers the same key again. */
        fprintf(stderr, "%s %s: %s is still the live key; %s has not been committed\n",
                prog, sub, a->key_path, next_path);
        memcpy(kp_out, &ek_kp, sizeof ek_kp);
        memset(&ek_kp, 0, sizeof ek_kp);
        *stale_next = 1;
        rc = EX_OK;
        break;
    case KEY_PLAN_PROMOTE_NEXT:
        /* The server committed and the rename was interrupted. Finish it --
         * the .pub first and the key second, the order erratum 119 gave
         * rotate (V4-282, F466): stopped between the two, .ek.next is still
         * there and the next run promotes it again. In the other order a
         * run stopped between them left the new .ek under a .pub naming the
         * old key, with no .ek.next to say so. next_ok is the proof, as the
         * ACK is for rotate. */
        if (client_republish_pub(prog, sub, a, next_path, next_kp.public_key) != 0) {
            /* F583: the .pub still names the old key, so the rename is not
             * made: .ek.next stays, and the next run comes back here and
             * tries both again. This login goes ahead with the live key. */
            fprintf(stderr, "%s %s: the interrupted rotation is NOT completed: %s is kept, and the next "
                            "run will try again. It holds the live key\n", prog, sub, next_path);
            g_resolve_kept_next = 1;
            memcpy(kp_out, &next_kp, sizeof next_kp);
            memset(&next_kp, 0, sizeof next_kp);
            rc = EX_OK;
            break;
        }
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
         * only copies of the identity, so nothing is touched -- and the
         * report says which of three different things happened (F225). */
        if (ks_ek != KEYFILE_OK) {
            fprintf(stderr, "%s %s: %s: %s\n", prog, sub, a->key_path, keyfile_status_name(ks_ek));
        }
        if (ks_next != KEYFILE_OK) {
            fprintf(stderr, "%s %s: %s: %s\n", prog, sub, next_path, keyfile_status_name(ks_next));
        }
        if (ks_ek != KEYFILE_OK && ks_next != KEYFILE_OK) {
            fprintf(stderr, "%s %s: neither key file could be opened, so the daemon was not asked. "
                            "NOTHING has been deleted.\n", prog, sub);
            /* F543: 1 means the daemon was asked (erratum 141). It was not:
             * these are files that could not be used, 3, unless opening
             * one failed inside this program. */
            rc = (client_key_exit(ks_ek) == EX_FAIL || client_key_exit(ks_next) == EX_FAIL) ? EX_FAIL : EX_CONFIG;
        } else if (unasked) {
            fprintf(stderr, "%s %s: cannot ask the daemon which key is live: %s. "
                            "NOTHING has been deleted; run this again when the daemon answers.\n",
                    prog, sub, unasked_why);
        } else if (ks_ek != KEYFILE_OK || ks_next != KEYFILE_OK) {
            fprintf(stderr, "%s %s: %s does not authenticate and %s could not be opened. "
                            "NOTHING has been deleted; if that file cannot be recovered, "
                            "an administrator must re-enrol this device.\n",
                    prog, sub, (ks_ek == KEYFILE_OK) ? a->key_path : next_path,
                    (ks_ek == KEYFILE_OK) ? next_path : a->key_path);
        } else {
            /* F706 (V4-347): the daemon refuses a key by closing the
             * connection, and so does a daemon that is stopping or a proxy
             * that resets. From here the two cannot be told apart, so the
             * advice begins with the cheap one. */
            fprintf(stderr, "%s %s: neither %s nor %s authenticates: the connection was closed after each "
                            "key was offered, which is how the daemon refuses one, and also what a daemon "
                            "being restarted does. NOTHING has been deleted; run this again, and if it says "
                            "the same, an administrator must re-enrol this device.\n",
                    prog, sub, a->key_path, next_path);
        }
        break;
    }
    mldsa_keypair_free(&ek_kp);
    mldsa_keypair_free(&next_kp);
    return rc;
}

/* have_lock: the caller (rotate) already holds the directory's lock. A login
 * takes it only when there is a .ek.next to decide about -- the ordinary
 * login writes nothing and waits for nobody. */
static int client_resolve_key(const char *prog, const char *sub, const client_args_t *a,
                              const char *pass, size_t pass_len, const uint8_t *server_pk,
                              int have_lock, char *next_path, size_t next_cap,
                              mldsa_keypair_t *kp_out, int *stale_next)
{
    memset(kp_out, 0, sizeof *kp_out);
    *stale_next = 0;
    /* F293: a name that did not fit used to be used as it came out. At
     * PATH_MAX - 1 bytes it came out equal to the key's own path, and the
     * "leftover .ek.next" rotate then deleted was the live key. */
    const int nn = snprintf(next_path, next_cap, "%s.next", a->key_path);
    if (nn < 0 || (size_t)nn >= next_cap) {
        (void)failed(prog, sub, a->key_path, "path-too-long");
        return EX_CONFIG;   /* F558: a --key whose names do not fit is a path that cannot be used */
    }
    int lock_fd = -1;
    const int next_seen = have_lock || path_exists(next_path);
    if (!have_lock && next_seen) {
        lock_fd = client_key_lock(prog, sub, a->key_path);
        if (lock_fd < 0) {
            /* F543: the directory of a --key that cannot be locked is a
             * path the operator named, 3 (spec 13, erratum 141). F551:
             * unless what stopped the lock is not the path. */
            const int lock_err = errno;
            (void)failed(prog, sub, a->key_path, "cannot-lock-key-directory");
            return client_lock_exit(lock_err);
        }
    }
    const int rc = client_resolve_key_locked(prog, sub, a, pass, pass_len, server_pk,
                                             next_path, next_seen, kp_out, stale_next);
    if (lock_fd >= 0) {
        (void)close(lock_fd);
    }
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
        (void)failed(prog, "login", a.server_pub, demo_keys_status_name(ps));
        return client_pub_exit(ps);   /* F551 */
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = get_pass(prog, "login", a.pass_path, a.pass_prompt, a.key_path, 0, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    /* Every invocation of this tool is a "startup", so the interrupted-rename
     * recovery runs here too -- and in practice this is the command that
     * discovers one, not rotate. */
    char next_path[PATH_MAX];
    mldsa_keypair_t kp;
    int stale_next = 0;          /* login deletes nothing */
    rc = client_resolve_key(prog, "login", &a, (const char *)pass, pass_len, server_pk,
                            0, next_path, sizeof next_path, &kp, &stale_next);
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
    /* V4-194, F272: the code is the whole result, it is single-use, and the
     * daemon has issued it. A write that failed (stdout closed, a full disk,
     * a reader that went away) used to be followed by exit 0. */
    const int wrote = printf("%s\n", b64) > 0 && fflush(stdout) == 0;
    sodium_memzero(b64, sizeof b64);
    if (!wrote) {
        client_say_bye(&cs);
        fprintf(stderr, "%s login: the login succeeded but the login code could not be written to "
                        "standard output; it is lost -- log in again\n", prog);
        return EX_FAIL;
    }
    if ((cs.code.flags & AUTHMSG_FLAG_ROTATION_DUE) != 0u) {
        fprintf(stderr, "%s login: this key is due for rotation -- run `%s rotate`\n", prog, prog);
    }
    fprintf(stderr, "%s login: code valid for %llu more seconds; single use\n", prog,
            (unsigned long long)cc_seconds_left(cs.code.code_expires, (int64_t)time(NULL)));
    client_say_bye(&cs);
    return EX_OK;
}

static int client_rotate_run(int argc, char **argv, const char *prog, int *lock_fd);

/* F645 (V4-338): a staged key that was never sent is removed, and when it
 * cannot be, that is SAID. Three of the four places that remove one did so
 * without looking (F573 fixed the fourth): the file stayed, and every later
 * login reported an interrupted rotation and tried both keys, with nothing
 * to say why. A file that is already gone is not a failure. */
static void rotate_say_kept(const char *prog, const char *next_path)
{
    if (errno == ENOENT) {
        return;
    }
    fprintf(stderr, "%s rotate: %s could not be removed: it is KEPT, though the daemon never had it. "
                    "Remove it by hand\n", prog, next_path);
}

static void rotate_drop_unsent(const char *prog, const char *next_path)
{
    if (unlink(next_path) != 0) {
        rotate_say_kept(prog, next_path);
    }
}

/* The lock taken inside is dropped on every way out, by the one caller. */
static int cmd_client_rotate(int argc, char **argv, const char *prog)
{
    int lock_fd = -1;
    const int rc = client_rotate_run(argc, argv, prog, &lock_fd);
    if (lock_fd >= 0) {
        (void)close(lock_fd);
    }
    return rc;
}

static int client_rotate_run(int argc, char **argv, const char *prog, int *lock_fd)
{
    client_args_t a;
    int rc = parse_client_args(argc, argv, prog, "rotate", &a);
    if (rc != EX_OK) { return rc; }

    static uint8_t server_pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(a.server_pub, a.sid, a.sid_len, server_pk);
    if (ps != DEMO_KEYS_OK) {
        (void)failed(prog, "rotate", a.server_pub, demo_keys_status_name(ps));
        return client_pub_exit(ps);   /* F551 */
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = get_pass(prog, "rotate", a.pass_path, a.pass_prompt, a.key_path, 0, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    /* F293: from here to the exit this run is the only one beside this key. */
    *lock_fd = client_key_lock(prog, "rotate", a.key_path);
    if (*lock_fd < 0) {
        const int lock_err = errno;   /* F559: read before anything else can set it */
        authd_secret_free(pass, pass_len);
        (void)failed(prog, "rotate", a.key_path, "cannot-lock-key-directory");   /* F543 */
        return client_lock_exit(lock_err);
    }

    char next_path[PATH_MAX];
    mldsa_keypair_t old_kp;
    int stale_next = 0;
    rc = client_resolve_key(prog, "rotate", &a, (const char *)pass, pass_len, server_pk,
                            1, next_path, sizeof next_path, &old_kp, &stale_next);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        return rc;
    }
    /* F591: .ek.next holds the live key and could not be promoted (F583).
     * A rotation needs that name for the key it makes. It used to go on,
     * seal a new key, and fail at the name with `already-exists` -- on the
     * one file that must not be removed -- having said "Logging in". It
     * stops here and says what is in the way. */
    if (g_resolve_kept_next) {
        authd_secret_free(pass, pass_len);
        mldsa_keypair_free(&old_kp);
        fprintf(stderr, "%s rotate: not rotating: %s holds the LIVE key and could not be put in place, "
                        "because the device's .pub could not be updated (the lines above say how). Do NOT "
                        "remove it. Mend that, log in once (which completes the earlier rotation), then "
                        "rotate\n",
                prog, next_path);
        return EX_FAIL;
    }

    /* V4-364 (F787): a leftover .ek.next beside a live .ek is NOT deleted.
     * It was, on "the server never committed it", and that is only "has not
     * yet": the ROTATE of the run that staged it may still be on its way --
     * that run gave up after twenty seconds, the daemon's session lives for
     * its idle timeout, and a stalled connection delivers what it holds
     * when it clears. Deleted here, and committed a moment later, it was
     * the only copy of the live key. So this rotation offers THAT key
     * again and makes none: whichever ROTATE the daemon takes, it ends on a
     * key this directory holds, and it refuses the other (the old key is no
     * longer the active one). And because the staged key may become live
     * without this run's doing, this run removes it on NO failure: only an
     * ACK moves it, into place.
     * (F293 stands: stale_next is the daemon's answer about a file this run
     * opened under the lock, not the file being there.) */
    const int reoffer = stale_next;

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
    if (client_pub_path(a.key_path, pub_path, sizeof pub_path) != 0) {
        authd_secret_free(pass, pass_len);
        mldsa_keypair_free(&old_kp);
        (void)failed(prog, "rotate", a.key_path, "path-too-long");
        return EX_CONFIG;   /* F558: a --key whose names do not fit is a path that cannot be used */
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
            (void)failed(prog, "rotate", next_path, "path-too-long");
        return EX_CONFIG;   /* F558: a --key whose names do not fit is a path that cannot be used */
        }
    }
    /* F298: a rotation that was KILLED after its seal left this file, and the
     * public-key writer refuses an existing one. A later run with the same
     * pid -- every run, in a container -- then failed here each time and
     * left a fresh .ek.next for the run after it to probe and delete. The
     * key directory's lock is held, so whatever has this name is nobody's. */
    (void)unlink(pub_tmp);
    if (!reoffer) {
        rc = client_seal_new_identity(prog, "rotate", next_path, pub_tmp, a.hid, a.hid_len,
                                      (const char *)pass, pass_len, new_pk);
        if (rc != EX_OK) {
            authd_secret_free(pass, pass_len);
            mldsa_keypair_free(&old_kp);
            return rc;
        }
    }

    mldsa_keypair_t new_kp;
    memset(&new_kp, 0, sizeof new_kp);
    const keyfile_status_t ks = keyfile_open(next_path, a.hid, a.hid_len,
                                             (const char *)pass, pass_len, &new_kp, NULL);
    authd_secret_free(pass, pass_len);
    if (ks != KEYFILE_OK) {
        mldsa_keypair_free(&old_kp);
        (void)unlink(pub_tmp);   /* F118: every exit after the seal, not only `out:` */
        const int rf = failed(prog, "rotate", next_path, keyfile_status_name(ks));
        if (reoffer) {
            /* F787: an earlier rotation's key that this passphrase does not
             * open. It cannot be offered again and it is not this run's to
             * remove: its ROTATE may yet arrive. */
            fprintf(stderr, "%s rotate: not rotating: %s was staged by an earlier rotation and cannot be "
                            "opened, so it cannot be offered again. It is KEPT: that rotation's request may "
                            "still reach the daemon, for as long as the daemon's idle timeout (ten minutes "
                            "at most). After that, if a login still works with %s, remove %s by hand and "
                            "rotate\n", prog, next_path, a.key_path, next_path);
        } else {
            rotate_drop_unsent(prog, next_path); /* F467: nothing was sent */
        }
        return rf;
    }
    if (reoffer) {
        /* The staged key's public half, for the .pub an ACK publishes. */
        fprintf(stderr, "%s rotate: offering the key an earlier rotation staged in %s again; no new key "
                        "is made\n", prog, next_path);
        memcpy(new_pk, new_kp.public_key, sizeof new_pk);
        if (demo_keys_write_public(pub_tmp, a.hid, a.hid_len, new_pk) != DEMO_KEYS_OK) {
            mldsa_keypair_free(&old_kp);
            mldsa_keypair_free(&new_kp);
            (void)unlink(pub_tmp);
            (void)failed(prog, "rotate", pub_tmp, "cannot-write-public-key");
            fprintf(stderr, "%s rotate: %s is KEPT\n", prog, next_path);
            return EX_FAIL;
        }
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
        (void)unlink(pub_tmp);   /* F118 */
        /* F438: a session that failed before ClientAuth was sent -- no
         * daemon, no upgrade, a ServerHello that did not verify -- never
         * showed the daemon this device's key, let alone a ROTATE, so the
         * .ek.next this run just wrote cannot be live: it is removed on that
         * proof. Kept, every later login reported an interrupted rotation and
         * probed with both keys. V4-282, F467: so is one refused AFTER
         * ClientAuth. ROTATE is built only on a live session, so none was
         * sent either way (erratum 126); the file was kept, before, only
         * because a test scanned it. */
        if (reoffer) {
            /* F787: not this run's key to remove. This is the very case: the
             * session is refused BECAUSE the earlier ROTATE has landed. */
            fprintf(stderr, "%s rotate: no session was opened; %s, staged by an earlier rotation, is KEPT "
                            "so the next run can resolve it\n", prog, next_path);
        } else if (unlink(next_path) != 0) {
            rotate_say_kept(prog, next_path);   /* F645 */
        } else {
            /* F553: when the session failed before the daemon judged the
             * key, WHY is already known, and "the daemon was not reached" was
             * said of a daemon that had answered and then gone quiet, and of a
             * ServerHello the pin refused. */
            fprintf(stderr, "%s rotate: %s, so the new key was never sent; it is not kept\n", prog,
                    g_open_judged ? "the daemon refused the session"
                    : g_open_unanswered ? "the daemon could not record the login"
                    : (g_open_why[0] != '\0') ? g_open_why
                    : "the session did not open");
        }
        return rc;
    }

    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    size_t n = 0, m = 0;
    rc = EX_FAIL;

    const cc_status_t bs = cc_rotate_build(cs.cc, &new_kp, 0u, tx, sizeof tx, &n);
    mldsa_keypair_free(&old_kp);   /* both signatures are made */
    mldsa_keypair_free(&new_kp);
    if (bs != CC_OK) {
        /* F467: ROTATE was not built, so it was not sent: the staged key goes. */
        (void)failed(prog, "rotate", next_path, bs == CC_ERR_SESSION ? "cannot-send-rotate" : "cannot-build-rotate");
        if (reoffer) {
            fprintf(stderr, "%s rotate: %s, staged by an earlier rotation, is KEPT\n", prog, next_path);
        } else {
            rotate_drop_unsent(prog, next_path);
        }
        goto out;
    }
    if (cs_send(&cs, tx, n - FRAME_HEADER_BYTES) != FRAME_OK) {
        (void)failed(prog, "rotate", next_path, "cannot-send-rotate");
        /* F564: a write that failed did not hand the whole record to the
         * daemon, and the daemon cannot act on part of one (it does not
         * authenticate). So the staged key is discarded, as spec 10.2 says
         * of a ROTATE never handed to the transport and as the browser does.
         * It was kept, without a word, and the next login then probed with
         * both keys. */
        const int unsent_gone = !reoffer && (unlink(next_path) == 0);
        if (reoffer) {
            fprintf(stderr, "%s rotate: ROTATE could not be sent; %s, staged by an earlier rotation, is "
                            "KEPT so the next run can resolve it\n", prog, next_path);
        } else if (unsent_gone) {
            fprintf(stderr, "%s rotate: ROTATE could not be sent, so the new key was never sent; "
                            "it is not kept\n", prog);
        } else {
            /* F573: the silence F564 was raised for, on the path that fixes it. */
            fprintf(stderr, "%s rotate: ROTATE could not be sent, and %s could not be removed: it is "
                            "KEPT, though the daemon never had it. Remove it by hand\n", prog, next_path);
        }
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
        /* Replace the device's own .pub so it does not go on naming a key the
         * server no longer accepts. Public data, so a plain rename: the
         * custody rules keyfile_promote enforces are about secrets.
         *
         * F401: BEFORE the key is promoted. The ACK is verified, so the new
         * key is the live one whatever happens next. In the other order a
         * process killed between the two renames left .ek new and .pub old
         * with no .ek.next, and no later run compares them: the .pub, which
         * is what an administrator enrols from, named a dead key for good.
         * In this order the same death leaves .ek.next, and the recovery
         * that promotes it republishes the .pub too (F227). */
        if (rename(pub_tmp, pub_path) != 0) {
            /* F583: and so the key is not promoted either. The daemon has
             * the new key; it is in .ek.next, which the next login finds
             * live and promotes, publishing the .pub first. Promoted here,
             * nothing would ever have published it, and this exited 0. */
            fprintf(stderr, "%s rotate: the key rotated at the daemon but %s could not be updated; it "
                            "still names the OLD key. %s is KEPT and holds the new key: the next login "
                            "completes the rotation\n", prog, pub_path, next_path);
            goto out;
        }
        if (keyfile_promote(next_path, a.key_path) != KEYFILE_OK) {
            (void)failed(prog, "rotate", a.key_path, "cannot-replace-key");
            /* F645 (V4-338): what that leaves, as F583 says it one step
             * earlier. The line above alone read as a rotation that had not
             * happened; it has, and the only copy of the live key is the
             * file a tidy person would now delete. */
            fprintf(stderr, "%s rotate: the key ROTATED at the daemon, and %s names the new key. %s still "
                            "holds the old one, which no longer authenticates. %s is KEPT and holds the new "
                            "key -- do not remove it: the next login completes the rotation\n",
                    prog, pub_path, a.key_path, next_path);
            goto out;
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
            "  %s keygen --dir DIR (--passphrase-file PATH | --passphrase-prompt)\n"
            "  %s login  --handle H --key H.ek (--passphrase-file PATH | --passphrase-prompt)\n"
            "            --server-id ID --server-pub server.pub (--unix PATH | --port N)\n"
            "            [--state S] [--proxy-v2] [--ws]\n"
            "  %s rotate --handle H --key H.ek (--passphrase-file PATH | --passphrase-prompt)\n"
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
            "A passphrase comes from a FILE (mode 0600, owned by you) or is typed at the\n"
            "terminal with --passphrase-prompt; never argv or the environment, which other\n"
            "processes on this machine can read. keygen holds a new passphrase to the policy\n"
            "the browser uses (at least 12 characters, not a common password, not\n"
            "predictable) and asks for it twice.\n"
            "Exit: 0 ok, 1 operation failed, 2 usage, 3 configuration.\n",
            prog, prog, prog);
}

static int client_dispatch(int argc, char **argv, const char *prog);

int authd_cli_client(int argc, char **argv)
{
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "authd_client";
    return cli_finish_stdout(prog, client_dispatch(argc, argv, prog));
}

static int client_dispatch(int argc, char **argv, const char *prog)
{
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
