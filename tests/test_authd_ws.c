/*
 * V4-10a: the WebSocket carrier (spec mldsa-authd §7.1, RFC 6455).
 *
 * Two properties are worth more than the rest and shape this file:
 *
 *   1. A login over WebSocket and a login over the raw tunnel are the SAME
 *      handshake. §7.1 claims "one reassembler serves both"; the test proves
 *      it by running the same client code over both transports against the
 *      same daemon and comparing what comes out.
 *   2. The `state` on the URL is bound into the login code (Req 5). That is
 *      the login-CSRF defence, and V4-8b could only build the mechanism --
 *      the raw listener has no URL. This is where it becomes real.
 *
 * The upgrade parser is the first attacker-facing TEXT parser in the tree, so
 * its refusals are enumerated rather than sampled.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "authd_harness.h"
#include "sha1.h"

static int g_fail = 0;
static int g_checks = 0;
static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) { printf("FAIL: %s\n", what); g_fail = 1; }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

static char g_dir[256];
static const uint8_t U1[]      = { 'u','1' };
static const uint8_t HANDLE1[] = { 'd','1','a','a' };

/* ------------------------------------------------------- the codec alone */

static void test_codec(void)
{
    char acc[WS_ACCEPT_B64_LEN + 1u];

    /* RFC 6455 §1.3's worked example. A vendored SHA-1 with no KAT is a
     * vendored SHA-1 nobody has checked. */
    CHECK(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", 24u, acc) == 0 &&
          strcmp(acc, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0,
          "ws: the RFC 6455 accept KAT reproduces s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    /* FIPS 180-1's published SHA-1 vectors, since the hash is ours now. */
    { uint8_t d[SHA1_DIGEST_BYTES];
      static const uint8_t want_abc[SHA1_DIGEST_BYTES] = {
          0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
          0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
      sha1((const uint8_t *)"abc", 3u, d);
      CHECK(memcmp(d, want_abc, sizeof d) == 0, "sha1: FIPS 180-1 vector \"abc\"");

      static const uint8_t want_448[SHA1_DIGEST_BYTES] = {
          0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,
          0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 };
      const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
      sha1((const uint8_t *)m, strlen(m), d);
      CHECK(memcmp(d, want_448, sizeof d) == 0, "sha1: FIPS 180-1 448-bit vector");

      static const uint8_t want_e[SHA1_DIGEST_BYTES] = {
          0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,
          0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09 };
      sha1((const uint8_t *)"", 0u, d);
      CHECK(memcmp(d, want_e, sizeof d) == 0, "sha1: the empty message"); }

    CHECK(ws_accept_key("short", 5u, acc) != 0, "ws: a key that is not 24 characters is refused");
    CHECK(ws_accept_key("!!!!!!!!!!!!!!!!!!!!!!!=", 24u, acc) != 0,
          "ws: a key that is not valid base64 is refused");

    /* Server frame headers, from literal arithmetic. */
    { uint8_t h[WS_SRV_HDR_MAX];
      CHECK(ws_server_header(h, 5u, WS_OP_BINARY) == 2u && h[0] == 0x82u && h[1] == 5u,
            "ws: a small server header is two bytes, FIN|binary");
      CHECK(ws_server_header(h, 200u, WS_OP_BINARY) == 4u && h[1] == 126u &&
            h[2] == 0u && h[3] == 200u, "ws: 126 selects a 16-bit length");
      CHECK(ws_server_header(h, 70000u, WS_OP_BINARY) == 10u && h[1] == 127u,
            "ws: 127 selects a 64-bit length");
      CHECK((h[1] & 0x80u) == 0u, "ws: a SERVER frame is never masked (RFC 6455 5.1)"); }
}

/* --------------------------------------------------- the upgrade parser */

static ws_status_t upgrade_of(const char *req, ws_t *out)
{
    ws_init(out);
    return ws_upgrade(out, (const uint8_t *)req, strlen(req));
}

static void test_upgrade(void)
{
    ws_t w;
    CHECK(upgrade_of(
        "GET /authd/v1?state=abc HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
        "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", &w) == WS_OK &&
        w.stage == WS_STAGE_OPEN && w.state_len == 3u && memcmp(w.state, "abc", 3) == 0,
        "upgrade: a well-formed request is accepted and `state` is taken from the query");
    CHECK(strstr((const char *)w.reply, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL &&
          strncmp((const char *)w.reply, "HTTP/1.1 101 ", 13) == 0,
          "upgrade: the reply is a 101 carrying the accept value");

    /* `Connection: keep-alive, Upgrade` above is the reason the token match is
     * a list walk rather than an equality: browsers and proxies send both. */
    CHECK(upgrade_of("GET /a HTTP/1.1\r\nUPGRADE: WebSocket\r\nCONNECTION: UPGRADE\r\n"
                     "SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ==\r\nSEC-WEBSOCKET-VERSION: 13\r\n\r\n",
                     &w) == WS_OK,
          "upgrade: header names match case-insensitively");

    struct { const char *name, *req; } bad[] = {
      { "upgrade: POST is refused",
        "POST /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: HTTP/1.0 is refused",
        "GET /a HTTP/1.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a version other than 13 is refused",
        "GET /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n" },
      { "upgrade: a missing Sec-WebSocket-Key is refused",
        "GET /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a missing Upgrade header is refused",
        "GET /a HTTP/1.1\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a missing Connection header is refused",
        "GET /a HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a key that is not 16 bytes of base64 is refused",
        "GET /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a state longer than 64 bytes is refused (7.1)",
        "GET /a?state=012345678901234567890123456789012345678901234567890123456789012345 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
      { "upgrade: a state with a non-printable byte is refused",
        "GET /a?state=ab\x01" "cd HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        CHECK(upgrade_of(bad[i].req, &w) == WS_ERR_PROTOCOL, bad[i].name);
    }

    CHECK(upgrade_of("GET /authd/v1 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                     &w) == WS_OK && w.state_len == 0u,
          "upgrade: no query means the EMPTY state, not a refusal");
}

/* ------------------------------------------------------- the frame codec */

static uint8_t g_sunk[8192];
static size_t  g_sunk_len;
static int sink(void *ctx, const uint8_t *p, size_t n)
{
    (void)ctx;
    if (g_sunk_len + n > sizeof g_sunk) { return -1; }
    memcpy(g_sunk + g_sunk_len, p, n);
    g_sunk_len += n;
    return 0;
}

static size_t client_frame(uint8_t *out, uint8_t op, int fin, const uint8_t *pay, size_t n,
                           const uint8_t m[4])
{
    size_t o = 0;
    out[o++] = (uint8_t)((fin ? 0x80u : 0u) | op);
    if (n < 126u) { out[o++] = (uint8_t)(0x80u | n); }
    else { out[o++] = (uint8_t)(0x80u | 126u); out[o++] = (uint8_t)(n >> 8); out[o++] = (uint8_t)n; }
    memcpy(out + o, m, 4u); o += 4u;
    for (size_t i = 0; i < n; i++) { out[o + i] = (uint8_t)(pay[i] ^ m[i & 3u]); }
    return o + n;
}

static void test_frames(void)
{
    const uint8_t m[4] = { 0xde, 0xad, 0xbe, 0xef };
    uint8_t f[4096];
    ws_t w;

    ws_init(&w); w.stage = WS_STAGE_OPEN; g_sunk_len = 0;
    size_t fl = client_frame(f, WS_OP_BINARY, 1, (const uint8_t *)"payload!", 8u, m);
    CHECK(ws_consume(&w, f, fl, sink, NULL) != WS_ERR_PROTOCOL &&
          g_sunk_len == 8u && memcmp(g_sunk, "payload!", 8) == 0,
          "frames: a masked binary frame is unmasked into the sink");

    /* §7.1: "message boundaries on input are irrelevant". */
    ws_init(&w); w.stage = WS_STAGE_OPEN; g_sunk_len = 0;
    fl = client_frame(f, WS_OP_BINARY, 1, (const uint8_t *)"payload!", 8u, m);
    { int bad = 0;
      for (size_t k = 0; k < fl; k++) {
          if (ws_consume(&w, f + k, 1u, sink, NULL) == WS_ERR_PROTOCOL) { bad = 1; }
      }
      CHECK(!bad && g_sunk_len == 8u && memcmp(g_sunk, "payload!", 8) == 0,
            "frames: the same frame delivered one byte at a time is identical"); }

    ws_init(&w); w.stage = WS_STAGE_OPEN; g_sunk_len = 0;
    { uint8_t a[64], b[64];
      const size_t al = client_frame(a, WS_OP_BINARY, 0, (const uint8_t *)"abc", 3u, m);
      const size_t bl = client_frame(b, WS_OP_CONT, 1, (const uint8_t *)"def", 3u, m);
      (void)ws_consume(&w, a, al, sink, NULL);
      (void)ws_consume(&w, b, bl, sink, NULL);
      CHECK(g_sunk_len == 6u && memcmp(g_sunk, "abcdef", 6) == 0,
            "frames: a fragmented message reassembles in order"); }

    ws_init(&w); w.stage = WS_STAGE_OPEN;
    { uint8_t u[8] = { 0x82u, 0x03u, 'a', 'b', 'c' };
      CHECK(ws_consume(&w, u, 5u, sink, NULL) == WS_ERR_PROTOCOL,
            "frames: an UNMASKED client frame fails the connection (RFC 6455 5.1)"); }

    ws_init(&w); w.stage = WS_STAGE_OPEN;
    fl = client_frame(f, 0x1u, 1, (const uint8_t *)"hi", 2u, m);
    CHECK(ws_consume(&w, f, fl, sink, NULL) == WS_ERR_PROTOCOL,
          "frames: a TEXT frame is refused -- this carries binary only");

    ws_init(&w); w.stage = WS_STAGE_OPEN;
    fl = client_frame(f, WS_OP_BINARY, 1, (const uint8_t *)"hi", 2u, m); f[0] = (uint8_t)(f[0] | 0x40u);
    CHECK(ws_consume(&w, f, fl, sink, NULL) == WS_ERR_PROTOCOL,
          "frames: a frame with an RSV bit set is refused (no extensions)");

    ws_init(&w); w.stage = WS_STAGE_OPEN;
    fl = client_frame(f, WS_OP_CONT, 1, (const uint8_t *)"hi", 2u, m);
    CHECK(ws_consume(&w, f, fl, sink, NULL) == WS_ERR_PROTOCOL,
          "frames: a continuation with no message open is refused");

    /* A Ping is answered, and its payload never reaches the protocol stream. */
    ws_init(&w); w.stage = WS_STAGE_OPEN; g_sunk_len = 0;
    fl = client_frame(f, WS_OP_PING, 1, (const uint8_t *)"hi", 2u, m);
    (void)ws_consume(&w, f, fl, sink, NULL);
    CHECK(w.reply_len == 4u && w.reply[0] == (0x80u | WS_OP_PONG) && w.reply[1] == 2u &&
          memcmp(w.reply + 2, "hi", 2) == 0,
          "frames: a Ping is answered with a Pong carrying the same payload");
    CHECK(g_sunk_len == 0u, "frames: a CONTROL payload never reaches the protocol stream");

    ws_init(&w); w.stage = WS_STAGE_OPEN;
    { uint8_t cp[2] = { 0x03u, 0xe8u };
      fl = client_frame(f, WS_OP_CLOSE, 1, cp, 2u, m);
      (void)ws_consume(&w, f, fl, sink, NULL);
      CHECK(w.stage == WS_STAGE_CLOSED && w.reply[0] == (0x80u | WS_OP_CLOSE),
            "frames: a Close is echoed and closes the stage"); }

    /* The sink's bound is the caller's, and refusing it is terminal. */
    ws_init(&w); w.stage = WS_STAGE_OPEN; g_sunk_len = sizeof g_sunk - 2u;
    fl = client_frame(f, WS_OP_BINARY, 1, (const uint8_t *)"payload!", 8u, m);
    CHECK(ws_consume(&w, f, fl, sink, NULL) == WS_ERR_PROTOCOL,
          "frames: a sink refusal fails the connection (AUTHD_FRAME_MAX, upstream)");
    g_sunk_len = 0;
}

/* ------------------------------------------- the upgrade across two reads */

/* The request arriving in more than one read is what a real network does the
 * moment it crosses a segment boundary. It poisoned the connection until
 * V4-10a, because conn_io_next_frame() -- which the event loop calls after
 * EVERY read -- interpreted the buffered "GET " as a 1195725856-byte frame
 * length. Every hand-written test wrote the request in one write() and passed;
 * fuzz_ws found it on its first run. */
static void test_split_upgrade(void)
{
    static const char req[] =
        "GET /authd/v1?state=xy HTTP/1.1\r\nHost: authd\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    const size_t n = sizeof req - 1u;

    for (size_t split = 1u; split < n; split += 7u) {
        static conn_io_t io;
        conn_io_reset(&io);
        conn_io_set_mode(&io, CONN_IO_MODE_WS);

        int poisoned = 0;
        if (conn_io_push(&io, (const uint8_t *)req, split) != CONN_IO_OK) { poisoned = 1; }
        /* what the event loop does after every read */
        const uint8_t *p = NULL; size_t len = 0;
        (void)conn_io_next_frame(&io, &p, &len);
        if (!poisoned && conn_io_push(&io, (const uint8_t *)req + split, n - split) != CONN_IO_OK) {
            poisoned = 1;
        }
        (void)conn_io_next_frame(&io, &p, &len);

        if (poisoned || io.ws.stage != WS_STAGE_OPEN) {
            char msg[128];
            /* The FAILURE text must carry the same phrase as the success
             * text: the mutation runner greps FAIL: lines for the spec's
             * expectation, so a message that only describes the offset is a
             * mutation that survives for want of a substring (v49d's G12/G14,
             * again). */
            snprintf(msg, sizeof msg,
                     "upgrade: the request completes however it is split across reads "
                     "(failed at offset %zu)", split);
            CHECK(0, msg);
            conn_io_reset(&io);
            return;
        }
        conn_io_reset(&io);
    }
    CHECK(1, "upgrade: the request completes however it is split across reads (every offset)");

    /* The other half of the same story: a peer that pipelines its first frame
     * behind the request, or a proxy that coalesces the two into one write,
     * delivers far more than WS_UPGRADE_MAX in one push while the REQUEST is
     * ~160 bytes. Capping the stream rather than the header block refused it. */
    { static conn_io_t io;
      static uint8_t buf[8192];
      memcpy(buf, req, n);
      size_t off = n;
      /* one binary message carrying a 4-byte-length frame of 6000 bytes */
      static uint8_t inner[6004];
      inner[0] = 0u; inner[1] = 0u; inner[2] = 0x17u; inner[3] = 0x70u;   /* 6000 */
      const uint8_t m[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
      buf[off++] = 0x82u; buf[off++] = (uint8_t)(0x80u | 126u);
      buf[off++] = (uint8_t)((6004u) >> 8); buf[off++] = (uint8_t)(6004u & 0xffu);
      memcpy(buf + off, m, 4u); off += 4u;
      for (size_t i = 0; i < 6004u; i++) { buf[off + i] = (uint8_t)(inner[i] ^ m[i & 3u]); }
      off += 6004u;

      conn_io_reset(&io);
      conn_io_set_mode(&io, CONN_IO_MODE_WS);
      const conn_io_status_t st = conn_io_push(&io, buf, off);
      CHECK(st == CONN_IO_OK && io.ws.stage == WS_STAGE_OPEN,
            "upgrade: an upgrade pipelined with its first frame is accepted in one push");
      const uint8_t *p = NULL; size_t fl = 0;
      CHECK(conn_io_next_frame(&io, &p, &fl) == 1 && fl == 6000u,
            "upgrade: ...and the pipelined frame is delivered intact");
      conn_io_reset(&io); }
}

/* ------------------------------------------------- end to end, in process */

static void enroll_direct(h_daemon_t *d, const uint8_t *handle, size_t hl, mldsa_keypair_t *kp)
{
    CHECK(mldsa_keypair_generate(kp) == 0, "fixture: device key");
    (void)store_add_user(d->store, U1, sizeof U1, STORE_ROLE_USER);
    CHECK(store_enroll_device(d->store, handle, hl, U1, sizeof U1,
                              kp->public_key, "site", "test", NULL, 0) == STORE_OK,
          "fixture: enroll");
}

static void test_login_over_ws(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "ws.sqlite3", 1) == 0, "e2e: daemon starts with both listeners");

    mldsa_keypair_t kp;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    /* The same client code, the same daemon, two transports. */
    h_client_t raw, wsc;
    uint8_t code_raw[32], code_ws[32];
    CHECK(h_login(&d, &raw, HANDLE1, sizeof HANDLE1, &kp) == 0,
          "e2e: a login over the RAW tunnel listener succeeds");
    CHECK(h_get_login_code(&d, &raw, code_raw) == 0, "e2e: the raw login yields a code");
    h_client_close(&raw);

    CHECK(h_login_on(&d, &wsc, HANDLE1, sizeof HANDLE1, &kp, "st8") == 0,
          "e2e: a login over the WEBSOCKET listener succeeds -- the same handshake");
    CHECK(h_get_login_code(&d, &wsc, code_ws) == 0, "e2e: the WebSocket login yields a code");
    CHECK(memcmp(code_raw, code_ws, 32) != 0, "e2e: the two codes are different (they are random)");

    /* Req 5: the code is bound to SHA-256(state). The raw listener binds the
     * empty string; the WebSocket one binds what the URL carried. */
    char uh[160], req[512], resp[8192], hex[80];
    h_hex(uh, sizeof uh, U1, sizeof U1);
    const int site = h_dial_unix(d.site_path);
    CHECK(site >= 0, "e2e: connect to site.sock");

    h_hex(hex, sizeof hex, code_ws, 32u);
    { char sh[16]; h_hex(sh, sizeof sh, (const uint8_t *)"st8", 3u);
      snprintf(req, sizeof req, "EXCHANGE code=%s state=%s", hex, "6162");   /* "ab", the wrong one */
      CHECK(h_local_cmd(&d, site, req, resp, sizeof resp) == 0 &&
            strncmp(resp, "ERR code=state-mismatch", 23) == 0,
            "e2e: the code is REFUSED against a different state (Req 5, login-CSRF)");
      snprintf(req, sizeof req, "EXCHANGE code=%s state=%s", hex, sh);
      CHECK(h_local_cmd(&d, site, req, resp, sizeof resp) == 0 && strncmp(resp, "OK token=", 9) == 0,
            "e2e: the code is ACCEPTED against the state the URL carried"); }

    /* ...and the raw listener still binds the empty state, unchanged. */
    h_hex(hex, sizeof hex, code_raw, 32u);
    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hex);
    CHECK(h_local_cmd(&d, site, req, resp, sizeof resp) == 0 && strncmp(resp, "OK token=", 9) == 0,
          "e2e: the RAW listener still binds the empty state (V4-8b, unchanged)");

    (void)close(site);
    h_client_close(&wsc);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

int main(void)
{
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);
    snprintf(g_dir, sizeof g_dir, "/tmp/authd-ws-%ld", (long)getpid());
    if (mkdir(g_dir, 0700) != 0) { printf("FAIL: mkdir\n"); return 1; }

    test_codec();
    test_upgrade();
    test_frames();
    test_split_upgrade();
    test_login_over_ws();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf("%s: test_authd_ws (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
