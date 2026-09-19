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


/* =======================================================================
 * V4-10b: the PROXY v2 preamble, the client address and the rate limiter
 * ======================================================================= */

/* Builds a PROXY v2 preamble into `out`. `cmd_fam` is the two bytes at offsets
 * 12 and 13, so a test can state a version, a command and a family that the
 * happy path never would. Returns the total length. */
static size_t mk_proxy(uint8_t *out, uint8_t ver_cmd, uint8_t fam_proto,
                       const uint8_t *block, size_t block_len,
                       const uint8_t *tlv, size_t tlv_len)
{
    static const uint8_t sig[12] = {
        0x0du, 0x0au, 0x0du, 0x0au, 0x00u, 0x0du, 0x0au, 0x51u, 0x55u, 0x49u, 0x54u, 0x0au };
    memcpy(out, sig, sizeof sig);
    out[12] = ver_cmd;
    out[13] = fam_proto;
    const size_t body = block_len + tlv_len;
    out[14] = (uint8_t)(body >> 8);
    out[15] = (uint8_t)(body & 0xffu);
    if (block_len > 0u) { memcpy(out + 16, block, block_len); }
    if (tlv_len > 0u)   { memcpy(out + 16 + block_len, tlv, tlv_len); }
    return 16u + body;
}

static const uint8_t V4BLOCK[12] = {
    203u, 0u, 113u, 7u,        /* source */
    10u, 0u, 0u, 1u,           /* destination */
    0x9cu, 0x40u, 0x00u, 0x50u /* ports */
};
static const uint8_t V6BLOCK[36] = {
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x01,      /* source 2001:db8::1 */
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x02,      /* destination */
    0x9cu, 0x40u, 0x00u, 0x50u
};

static void test_proxy_parse(void)
{
    proxy_v2_t p;
    uint8_t buf[512];
    size_t used = 0, n;

    /* A well-formed IPv4 PROXY header, in one go. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_OK && used == n &&
          p.addr.family == 4u && memcmp(p.addr.addr, V4BLOCK, 4) == 0,
          "proxy: an IPv4 PROXY header yields the source address");

    { char s[AUTHD_ADDR_STR_MAX];
      authd_addr_str(&p.addr, s, sizeof s);
      CHECK(strcmp(s, "203.0.113.7") == 0, "proxy: the address renders as 203.0.113.7"); }

    /* IPv6, and the /64 key -- the reason a full-address key would be useless. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x21u, V6BLOCK, sizeof V6BLOCK, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_OK && p.addr.family == 6u &&
          memcmp(p.addr.addr, V6BLOCK, 16) == 0,
          "proxy: an IPv6 PROXY header yields the source address");
    { uint8_t k[16];
      CHECK(authd_addr_key(&p.addr, k) == 8u && memcmp(k, V6BLOCK, 8) == 0,
            "proxy: an IPv6 address is rate-limited on its /64, not its full 128 bits"); }
    { authd_addr_t v4 = { 4u, { 1u, 2u, 3u, 4u } };
      uint8_t k[16];
      CHECK(authd_addr_key(&v4, k) == 4u && memcmp(k, "\x01\x02\x03\x04", 4) == 0,
            "proxy: an IPv4 address is rate-limited on all four of its bytes"); }

    /* TLVs are skipped by length and never walked. */
    proxy_v2_init(&p);
    { uint8_t tlv[40];
      memset(tlv, 0xabu, sizeof tlv);
      n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, tlv, sizeof tlv);
      CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_OK && used == n &&
            p.addr.family == 4u,
            "proxy: TLVs after the address block are skipped, not interpreted"); }

    /* LOCAL is a health check: well-formed, and NO client address. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x20u, 0x00u, NULL, 0u, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_NO_ADDR && p.addr.family == 0u,
          "proxy: a LOCAL command is well-formed and carries NO client address");

    /* AF_UNIX likewise -- structurally fine, nothing to rate-limit. */
    proxy_v2_init(&p);
    { uint8_t blk[216];
      memset(blk, 0x41u, sizeof blk);
      n = mk_proxy(buf, 0x21u, 0x31u, blk, sizeof blk, NULL, 0u);
      CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_NO_ADDR && p.addr.family == 0u,
            "proxy: an AF_UNIX PROXY header carries no client address"); }

    /* Every refusal. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    buf[3] ^= 0xffu;
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_ERR,
          "proxy: a header whose signature is wrong in ONE byte is refused");

    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x31u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_ERR,
          "proxy: version 3 is refused");

    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x22u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_ERR,
          "proxy: a command other than LOCAL or PROXY is refused");

    /* A family whose address block does not fit the body the header declared:
     * truncation wearing a valid length. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    buf[15] = 0x08u;                     /* claims 8 bytes for a 12-byte family */
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_ERR,
          "proxy: an IPv4 header declaring a body too short for its address block is refused");

    /* A declared body over the ceiling: a 16-bit length must not decide how
     * long a connection may occupy a slot saying nothing. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    buf[14] = 0xffu; buf[15] = 0xffu;
    CHECK(proxy_v2_consume(&p, buf, n, &used) == PROXY_V2_ERR,
          "proxy: a declared body length over PROXY_V2_LEN_MAX is refused");

    /* A truncated header is NEED_MORE, never a verdict. */
    proxy_v2_init(&p);
    n = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    CHECK(proxy_v2_consume(&p, buf, n - 1u, &used) == PROXY_V2_NEED_MORE &&
          p.addr.family == 0u,
          "proxy: a truncated preamble is NEED_MORE and establishes nothing");

    /* Split at EVERY offset: the property a real network forces and the one
     * that cost V4-10a its highest finding on the HTTP side. */
    { uint8_t tlv[24];
      memset(tlv, 0x5au, sizeof tlv);
      const size_t total = mk_proxy(buf, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, tlv, sizeof tlv);
      int bad_at = -1;
      for (size_t split = 1u; split < total && bad_at < 0; split++) {
          proxy_v2_t q;
          proxy_v2_init(&q);
          size_t u1 = 0, u2 = 0;
          const proxy_v2_status_t s1 = proxy_v2_consume(&q, buf, split, &u1);
          if (s1 != PROXY_V2_NEED_MORE && s1 != PROXY_V2_OK) { bad_at = (int)split; break; }
          const proxy_v2_status_t s2 = proxy_v2_consume(&q, buf + u1, total - u1, &u2);
          const proxy_v2_status_t fin = (s1 == PROXY_V2_OK) ? s1 : s2;
          if (fin != PROXY_V2_OK || q.addr.family != 4u ||
              memcmp(q.addr.addr, V4BLOCK, 4) != 0) {
              bad_at = (int)split;
          }
      }
      if (bad_at >= 0) {
          char msg[160];
          snprintf(msg, sizeof msg,
                   "proxy: the preamble completes however it is split across reads "
                   "(failed at offset %d)", bad_at);
          CHECK(0, msg);
      } else {
          CHECK(1, "proxy: the preamble completes however it is split across reads (every offset)");
      } }
}

/* The preamble, the upgrade and the first frame down one conn_io, including
 * the event loop's habit of calling conn_io_next_frame after every read. The
 * signature begins "\r\n\r\n" = 218,893,066 as a length, so this is the F50
 * trap wearing a different hat. */
static void test_proxy_pipeline(void)
{
    static const char req[] =
        "GET /authd/v1?state=pq HTTP/1.1\r\nHost: authd\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    static uint8_t wire[1024];
    size_t total = mk_proxy(wire, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    memcpy(wire + total, req, sizeof req - 1u);
    total += sizeof req - 1u;
    /* one masked binary message carrying a 4-byte-length frame of 3 bytes */
    { const uint8_t m[4] = { 0xa1u, 0xb2u, 0xc3u, 0xd4u };
      const uint8_t inner[7] = { 0u, 0u, 0u, 3u, 'a', 'b', 'c' };
      wire[total++] = 0x82u;
      wire[total++] = (uint8_t)(0x80u | 7u);
      memcpy(wire + total, m, 4u); total += 4u;
      for (size_t i = 0; i < 7u; i++) { wire[total + i] = (uint8_t)(inner[i] ^ m[i & 3u]); }
      total += 7u; }

    int bad_at = -1;
    for (size_t split = 1u; split < total && bad_at < 0; split++) {
        static conn_io_t io;
        conn_io_reset(&io);
        conn_io_set_mode(&io, CONN_IO_MODE_WS);
        conn_io_set_proxy(&io, 1);

        const uint8_t *p = NULL; size_t fl = 0;
        int ok = (conn_io_push(&io, wire, split) == CONN_IO_OK);
        (void)conn_io_next_frame(&io, &p, &fl);      /* what the loop does after every read */
        if (ok) { ok = (conn_io_push(&io, wire + split, total - split) == CONN_IO_OK); }
        if (ok) {
            ok = conn_io_proxy_settled(&io) &&
                 conn_io_client_addr(&io)->family == 4u &&
                 memcmp(conn_io_client_addr(&io)->addr, V4BLOCK, 4) == 0 &&
                 io.ws.stage == WS_STAGE_OPEN &&
                 conn_io_next_frame(&io, &p, &fl) == 1 && fl == 3u &&
                 memcmp(p, "abc", 3) == 0;
        }
        if (!ok) { bad_at = (int)split; }
        conn_io_reset(&io);
    }
    if (bad_at >= 0) {
        char msg[176];
        snprintf(msg, sizeof msg,
                 "proxy: preamble, upgrade and first frame survive any split and the "
                 "address arrives intact (failed at offset %d)", bad_at);
        CHECK(0, msg);
    } else {
        CHECK(1, "proxy: preamble, upgrade and first frame survive any split and the "
                 "address arrives intact (every offset)");
    }

    /* A connection with no preamble at all: the GET is read as a PROXY header,
     * fails its signature, and the connection is poisoned. Req 12, fail closed. */
    { static conn_io_t io;
      conn_io_reset(&io);
      conn_io_set_mode(&io, CONN_IO_MODE_WS);
      conn_io_set_proxy(&io, 1);
      CHECK(conn_io_push(&io, (const uint8_t *)req, sizeof req - 1u) == CONN_IO_ERR_PROTOCOL,
            "proxy: a connection that sends no preamble is refused before any HTTP is parsed");
      conn_io_reset(&io); }

    /* The refusal response, rendered. */
    { static conn_io_t io;
      conn_io_reset(&io);
      conn_io_set_mode(&io, CONN_IO_MODE_WS);
      conn_io_set_proxy(&io, 1);
      CHECK(conn_io_ws_refuse(&io, 429u) == CONN_IO_OK &&
            conn_io_pending(&io) > 0u &&
            memcmp(conn_io_pending_ptr(&io), "HTTP/1.1 429 Too Many Requests\r\n", 32) == 0,
            "proxy: a rate-limited connection is answered with HTTP 429");
      conn_io_reset(&io);
      conn_io_set_mode(&io, CONN_IO_MODE_WS);
      CHECK(conn_io_ws_refuse(&io, 503u) == CONN_IO_OK &&
            memcmp(conn_io_pending_ptr(&io), "HTTP/1.1 503 Service Unavailable\r\n", 34) == 0,
            "proxy: a limiter with no room to track an address answers 503, not 429");
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

/* ------------------------------------------------------- the limiter alone */

static void test_ratelimit(void)
{
    static ratelimit_t r;
    const authd_addr_t a = { 4u, { 203u, 0u, 113u, 7u } };
    const authd_addr_t b = { 4u, { 203u, 0u, 113u, 8u } };
    const authd_addr_t none = { 0u, { 0 } };

    /* Req 12 again, at the limiter: no address is not a bucket, it is a refusal. */
    ratelimit_init(&r, 5u, 2u, 1000u, 8u, 1000u);
    CHECK(ratelimit_admit(&r, &none, 1000u) == RATELIMIT_DENY_NO_ADDR,
          "limiter: a connection with no client address is refused, not pooled");

    /* The burst, then the exact refill boundary. 5 a minute is one token every
     * 12000 ms, so 11999 must still be empty -- a limiter without a lower
     * bound is a limiter that might just be slow. */
    CHECK(ratelimit_admit(&r, &a, 1000u) == RATELIMIT_ALLOW &&
          ratelimit_admit(&r, &a, 1000u) == RATELIMIT_ALLOW,
          "limiter: the burst is spendable at once");
    CHECK(ratelimit_admit(&r, &a, 1000u) == RATELIMIT_DENY_ADDR,
          "limiter: one more than the burst is refused");
    CHECK(ratelimit_admit(&r, &a, 1000u + 11999u) == RATELIMIT_DENY_ADDR,
          "limiter: at 11999 ms the bucket has NOT yet refilled (5 a minute)");
    CHECK(ratelimit_admit(&r, &a, 1000u + 12000u) == RATELIMIT_ALLOW,
          "limiter: at 12000 ms exactly one token has returned");
    CHECK(ratelimit_admit(&r, &b, 1000u) == RATELIMIT_ALLOW,
          "limiter: a different address has its own bucket");
    CHECK(r.denied_addr == 2u, "limiter: every per-address refusal is counted");

    /* The global bucket, which is what bounds the damage when the addresses
     * are many and genuine -- or when the proxy is lying about them. */
    ratelimit_init(&r, 1000u, 1000u, 2u, 100u, 0u);
    { authd_addr_t c = { 4u, { 198u, 51u, 100u, 0u } };
      c.addr[3] = 1u; CHECK(ratelimit_admit(&r, &c, 0u) == RATELIMIT_ALLOW, "limiter: global 1");
      c.addr[3] = 2u; CHECK(ratelimit_admit(&r, &c, 0u) == RATELIMIT_ALLOW, "limiter: global 2");
      c.addr[3] = 3u;
      CHECK(ratelimit_admit(&r, &c, 0u) == RATELIMIT_DENY_GLOBAL,
            "limiter: the global bucket refuses a THIRD fresh address in the same instant");
      CHECK(ratelimit_admit(&r, &c, 499u) == RATELIMIT_DENY_GLOBAL,
            "limiter: at 499 ms the global bucket has not refilled (2 a second)");
      CHECK(ratelimit_admit(&r, &c, 500u) == RATELIMIT_ALLOW,
            "limiter: at 500 ms exactly one global token has returned"); }

    /* Concurrency, and the release that must balance it. */
    ratelimit_init(&r, 1000u, 1000u, 10000u, 2u, 0u);
    CHECK(ratelimit_admit(&r, &a, 0u) == RATELIMIT_ALLOW &&
          ratelimit_admit(&r, &a, 0u) == RATELIMIT_ALLOW &&
          ratelimit_conns(&r, &a) == 2u,
          "limiter: concurrent connections from one address are counted");
    CHECK(ratelimit_admit(&r, &a, 0u) == RATELIMIT_DENY_CONNS,
          "limiter: one more than max_conns_per_addr is refused");
    ratelimit_release(&r, &a);
    CHECK(ratelimit_conns(&r, &a) == 1u,
          "limiter: releasing a connection gives its slot back");
    CHECK(ratelimit_admit(&r, &a, 0u) == RATELIMIT_ALLOW,
          "limiter: ...and the address can connect again");
    /* A refused connection must not have been charged: if DENY_CONNS also
     * spent a token, an address at its connection cap would be rate-limited
     * for something it never got to do. */
    { const uint64_t before = r.admitted;
      ratelimit_init(&r, 1000u, 1000u, 10000u, 1u, 0u);
      (void)ratelimit_admit(&r, &a, 0u);
      const uint64_t g = r.global_tokens_milli;
      CHECK(ratelimit_admit(&r, &a, 0u) == RATELIMIT_DENY_CONNS &&
            r.global_tokens_milli == g && ratelimit_conns(&r, &a) == 1u,
            "limiter: a refusal changes nothing -- no token, no connection count");
      (void)before; }

    /* The table refuses rather than evicting: forgetting the address that is
     * attacking you is the one behaviour a limiter must never have. */
    ratelimit_init(&r, 1000u, 1000u, 10000u, 4u, 0u);
    { size_t admitted = 0;
      authd_addr_t c = { 4u, { 10u, 0u, 0u, 0u } };
      for (size_t i = 0; i < RATELIMIT_ENTRIES + 8u; i++) {
          c.addr[1] = (uint8_t)(i >> 16); c.addr[2] = (uint8_t)(i >> 8); c.addr[3] = (uint8_t)i;
          if (ratelimit_admit(&r, &c, 0u) == RATELIMIT_ALLOW) { admitted++; }
      }
      CHECK(admitted == RATELIMIT_ENTRIES && r.denied_table == 8u,
            "limiter: a full table refuses new addresses instead of evicting live ones");
      /* Release one and its entry becomes reclaimable, so the limiter recovers
       * on its own rather than needing a restart. */
      c.addr[1] = 0u; c.addr[2] = 0u; c.addr[3] = 0u;
      ratelimit_release(&r, &c);
      authd_addr_t fresh = { 4u, { 172u, 16u, 9u, 9u } };
      /* A minute later that entry has refilled to the brim and holds no
       * connection, so it says nothing a fresh address does not -- which is
       * the whole expiry condition. Reclaiming it forgets nothing. */
      CHECK(ratelimit_admit(&r, &fresh, 60000u) == RATELIMIT_ALLOW,
            "limiter: an idle, refilled entry is reclaimed so the table recovers"); }
}

/* --------------------------------------- the limiter, through the real loop */

/* Dials the WebSocket listener, sends `pre` then an upgrade request, and
 * returns whatever the daemon answers. Deliberately lower-level than
 * h_ws_connect: the interesting cases are the ones that never reach a 101. */
static int ws_raw_try(h_daemon_t *d, const uint8_t *pre, size_t pre_len, char *out, size_t cap)
{
    static const char req[] =
        "GET /authd/v1 HTTP/1.1\r\nHost: authd\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    const int fd = h_dial_unix(d->ws_path);
    if (fd < 0) { return -1; }
    /* ONE write, deliberately: coalescing the preamble and the request is what
     * a real proxy does, and it is the ordering in which ws_upgrade has
     * already built a 101 by the time the address is judged. Sending them
     * separately would let a refusal LOOK silent because the request had not
     * arrived yet -- the check would then pass on a daemon that answers
     * 101-then-EOF whenever the two land together. */
    static uint8_t one[1024];
    size_t on = 0;
    if (pre_len > 0u) { memcpy(one, pre, pre_len); on = pre_len; }
    memcpy(one + on, req, sizeof req - 1u);
    on += sizeof req - 1u;
    if (write(fd, one, on) != (ssize_t)on) { (void)close(fd); return -1; }
    size_t n = 0;
    for (int i = 0; i < 4000 && n + 1u < cap; i++) {
        h_tick(d);
        const ssize_t k = recv(fd, out + n, 1u, MSG_DONTWAIT);
        if (k > 0) { n += (size_t)k; }
        else if (k == 0) { break; }
        if (n >= 4u && memcmp(out + n - 4u, "\r\n\r\n", 4) == 0) { break; }
    }
    out[n] = '\0';
    (void)close(fd);
    for (int i = 0; i < 50; i++) { h_tick(d); }   /* let the daemon reap the slot */
    return (int)n;
}

static void test_proxy_through_loop(void)
{
    static h_daemon_t d;
    CHECK(h_start_ex(&d, g_dir, "px.sqlite3", 1, 1) == 0,
          "proxy-loop: the daemon starts with a PROXY v2 WebSocket listener");
    mldsa_keypair_t kp;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    uint8_t pre[64];
    const size_t pre_len = mk_proxy(pre, 0x21u, 0x11u, V4BLOCK, sizeof V4BLOCK, NULL, 0u);
    const authd_addr_t A = { 4u, { 203u, 0u, 113u, 7u } };

    /* A real login through the proxy path, and the connection counted against
     * the address while it is open. The canary matters: without it "0 after
     * close" would pass on a daemon that never counted anything. */
    { h_client_t c;
      CHECK(h_login_on(&d, &c, HANDLE1, sizeof HANDLE1, &kp, "st9") == 0,
            "proxy-loop: a login completes through the PROXY v2 listener");
      CHECK(ratelimit_conns(&d.rl, &A) == 1u,
            "proxy-loop: the connection is counted against its client address while open");
      uint8_t code[32];
      CHECK(h_get_login_code(&d, &c, code) == 0, "proxy-loop: it yields a login code");
      h_client_close(&c);
      const int ok = H_PUMP_UNTIL(&d, ratelimit_conns(&d.rl, &A) == 0u);
      CHECK(ok, "proxy-loop: closing the connection gives its count back"); }

    /* Req 12 through the loop: a LOCAL preamble is well-formed and carries no
     * client, so the connection is closed with nothing said. */
    { char resp[512];
      uint8_t loc[32];
      const size_t ln = mk_proxy(loc, 0x20u, 0x00u, NULL, 0u, NULL, 0u);
      const uint64_t before = d.app.refused_no_address;
      const int n = ws_raw_try(&d, loc, ln, resp, sizeof resp);
      CHECK(n == 0 && d.app.refused_no_address == before + 1u,
            "proxy-loop: a preamble with no client address is closed, and nothing is said"); }

    /* The limiter refuses BEFORE the ServerHello signature. The pending ledger
     * is the pin: handshake_responder_create_server_hello is what inserts into
     * it, so an empty ledger after a refusal is proof no signature was spent --
     * which is the cost 7.3 assigns to "the rate limiter's problem". */
    { ratelimit_init(&d.rl, 1u, 1u, 10000u, 8u, d.app.now_ms);
      char resp[512];
      const int n1 = ws_raw_try(&d, pre, pre_len, resp, sizeof resp);
      CHECK(n1 > 0 && strncmp(resp, "HTTP/1.1 101", 12) == 0,
            "proxy-loop: the first connection from an address is upgraded (the canary)");
      const int n2 = ws_raw_try(&d, pre, pre_len, resp, sizeof resp);
      CHECK(n2 > 0 && strncmp(resp, "HTTP/1.1 429", 12) == 0,
            "proxy-loop: the next one is answered 429 at the upgrade, not at the handshake");
      CHECK(handshake_pending_active_count(&d.pending) == 0u,
            "proxy-loop: a refused connection cost no ServerHello signature (7.3)"); }

    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* Req 11: the proxy-facing listener serves only the uid that is the proxy. */
static void test_proxy_uid_allowlist(void)
{
    static h_daemon_t d;
    CHECK(h_start_ex(&d, g_dir, "uid.sqlite3", 0, 0) == 0,
          "proxy-uid: the daemon starts");

    char path[384];
    snprintf(path, sizeof path, "%s/deny.sock", g_dir);
    int fd = -1;
    CHECK(listener_open_unix(path, 8, LISTENER_MODE_GROUP, &fd) == LISTENER_OK,
          "proxy-uid: a second WebSocket listener opens");
    const uid_t nobody[1] = { (uid_t)(getuid() + 1u) };
    CHECK(evloop_add_ws_listener(&d.ev, fd, nobody, 1u, 0) == 0,
          "proxy-uid: ...with an allowlist this process is NOT in");

    const uint64_t before_peer = d.ev.closed_peer;
    const uint64_t before_acc = d.ev.accepted;
    int c = h_dial_unix(path);
    CHECK(c >= 0, "proxy-uid: the connection is made at the socket layer");
    (void)H_PUMP_UNTIL(&d, d.ev.closed_peer > before_peer);
    CHECK(d.ev.closed_peer == before_peer + 1u && d.ev.accepted == before_acc,
          "proxy-uid: a peer outside the allowlist is refused at accept, occupying no slot");
    if (c >= 0) { (void)close(c); }

    /* The canary: the SAME code path serves a uid that IS allowed, so the
     * refusal above is the allowlist and not a broken listener. */
    { int fd2 = -1;
      char p2[384];
      snprintf(p2, sizeof p2, "%s/allow.sock", g_dir);
      CHECK(listener_open_unix(p2, 8, LISTENER_MODE_GROUP, &fd2) == LISTENER_OK,
            "proxy-uid: a third listener opens");
      const uid_t me[1] = { getuid() };
      CHECK(evloop_add_ws_listener(&d.ev, fd2, me, 1u, 0) == 0,
            "proxy-uid: ...with an allowlist this process IS in");
      const uint64_t acc = d.ev.accepted;
      int c2 = h_dial_unix(p2);
      CHECK(c2 >= 0, "proxy-uid: the allowed connection is made");
      (void)H_PUMP_UNTIL(&d, d.ev.accepted > acc);
      CHECK(d.ev.accepted == acc + 1u,
            "proxy-uid: a peer inside the allowlist IS served (the canary)");
      if (c2 >= 0) { (void)close(c2); }
      listener_close(&fd2, p2); }

    listener_close(&fd, path);
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
    test_proxy_parse();
    test_proxy_pipeline();
    test_login_over_ws();
    test_ratelimit();
    test_proxy_through_loop();
    test_proxy_uid_allowlist();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf("%s: test_authd_ws (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
