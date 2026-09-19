#include "conn_io.h"

#include <string.h>

#include <sodium.h>

const char *conn_io_status_name(conn_io_status_t st)
{
    switch (st) {
    case CONN_IO_OK:            return "ok";
    case CONN_IO_ERR_ARG:       return "bad-argument";
    case CONN_IO_ERR_OVERFLOW:  return "buffer-overflow";
    case CONN_IO_ERR_PROTOCOL:  return "protocol";
    case CONN_IO_ERR_BUSY:      return "send-busy";
    default:                    return "unknown";
    }
}

void conn_io_set_mode(conn_io_t *c, conn_io_mode_t mode)
{
    if (c != NULL) {
        c->mode = mode;
        if (mode == CONN_IO_MODE_WS) {
            ws_init(&c->ws);
        }
    }
}

size_t conn_io_out_capacity(void)
{
    return (size_t)AUTHD_FRAME_MAX;
}

void conn_io_reset(conn_io_t *c)
{
    if (c == NULL) {
        return;
    }
    /* sodium_memzero, not memset: these buffers hold handshake messages and
     * decrypted records, and a slot is reused by the next connection. */
    sodium_memzero(c, sizeof *c);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* LINE mode's only structural rule: a line must terminate within
 * AUTHD_LINE_MAX bytes. Buffering past that without an LF is a protocol error
 * and is sticky, exactly as an illegal frame length is -- otherwise a peer
 * could hold a slot open forever by never sending a terminator. */
static conn_io_status_t note_line_cap(conn_io_t *c)
{
    for (size_t i = 0; i < c->in_len; i++) {
        if (c->in[i] == (uint8_t)'\n') {
            return CONN_IO_OK;          /* a complete line is present */
        }
    }
    if (c->in_len >= AUTHD_LINE_MAX) {
        c->failed = 1;
        return CONN_IO_ERR_PROTOCOL;
    }
    return CONN_IO_OK;
}

/* Reads the header once enough bytes are present and validates the declared
 * length. Sets c->failed on an illegal length so the error is sticky: a peer
 * cannot follow a bad frame with a good one and be forgiven. */
static conn_io_status_t note_header(conn_io_t *c)
{
    /* While a WebSocket connection is still buffering its HTTP request, `in`
     * holds TEXT, not a frame header. "GET " read as a big-endian length is
     * 1195725856, which poisons the connection before the upgrade is even
     * parsed. push_ws() already knows not to call this -- but
     * conn_io_next_frame() calls it too, and the event loop calls THAT after
     * every read, so the guard has to live here, at the single point that
     * interprets `in` as a frame.
     *
     * Found by fuzz_ws on its first run, and it was a deployable bug rather
     * than a theoretical one: it only appears when the request arrives in more
     * than one read, which is what a real network does as soon as the request
     * crosses a segment boundary. Every hand-written test wrote it in one
     * write() and passed. */
    if (c->mode == CONN_IO_MODE_WS && c->ws.stage == WS_STAGE_UPGRADE) {
        return CONN_IO_OK;
    }
    if (c->frame_len != 0u || c->in_len < AUTHD_FRAME_HEADER) {
        return CONN_IO_OK;
    }
    const uint32_t len = be32(c->in);
    if (len == 0u || len > (uint32_t)AUTHD_FRAME_MAX) {
        c->failed = 1;
        return CONN_IO_ERR_PROTOCOL;
    }
    c->frame_len = (size_t)len;
    return CONN_IO_OK;
}

/* Unmasked DATA payload goes straight into the frame buffer: that is what
 * makes the WebSocket invisible to conn_io_next_frame and to on_frame. */
static int ws_sink_in(void *ctx, const uint8_t *p, size_t n)
{
    conn_io_t *c = (conn_io_t *)ctx;
    if (n > sizeof c->in - c->in_len) {
        return -1;                       /* AUTHD_FRAME_MAX, enforced here */
    }
    memcpy(c->in + c->in_len, p, n);
    c->in_len += n;
    return 0;
}

static conn_io_status_t ws_feed(conn_io_t *c, const uint8_t *p, size_t n)
{
    if (ws_consume(&c->ws, p, n, ws_sink_in, c) == WS_ERR_PROTOCOL) {
        c->failed = 1;
        return CONN_IO_ERR_PROTOCOL;
    }
    return note_header(c);
}

/* Finds the end of an HTTP header block, returning its length including the
 * terminator, or 0 while it is still incomplete. */
static size_t end_of_headers(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i + 3u < n; i++) {
        if (p[i] == '\r' && p[i + 1u] == '\n' && p[i + 2u] == '\r' && p[i + 3u] == '\n') {
            return i + 4u;
        }
    }
    return 0u;
}

static conn_io_status_t push_ws(conn_io_t *c, const uint8_t *data, size_t n)
{
    if (c->ws.stage != WS_STAGE_UPGRADE) {
        return ws_feed(c, data, n);
    }

    /* The request is staged in `in` -- nothing else is there yet, and
     * note_header() is deliberately NOT called while it sits there: "GET "
     * read as a big-endian length is 1195725856, which would poison the
     * connection before the upgrade was even parsed. */
    if (n > sizeof c->in - c->in_len) {
        c->failed = 1;
        return CONN_IO_ERR_OVERFLOW;
    }
    memcpy(c->in + c->in_len, data, n);
    c->in_len += n;

    const size_t req_len = end_of_headers(c->in, c->in_len);
    if (req_len == 0u) {
        /* The cap applies to the HEADER BLOCK, and therefore only while it is
         * still incomplete. Applying it to `in_len` outright was wrong: a peer
         * that pipelines its first frame behind the request -- or a proxy that
         * coalesces the two into one write -- delivers far more than 4096
         * bytes in a single push while the request itself is ~160, and the
         * connection was refused for a request that was never over-long.
         * fuzz_ws found it: one push failed where byte-at-a-time succeeded. */
        if (c->in_len > WS_UPGRADE_MAX) {
            c->failed = 1;
            return CONN_IO_ERR_PROTOCOL;
        }
        return CONN_IO_OK;               /* still buffering the request */
    }
    if (req_len > WS_UPGRADE_MAX) {
        c->failed = 1;
        return CONN_IO_ERR_PROTOCOL;
    }
    if (ws_upgrade(&c->ws, c->in, req_len) != WS_OK) {
        c->failed = 1;
        return CONN_IO_ERR_PROTOCOL;
    }

    /* Anything the client pipelined behind the request is already WebSocket.
     *
     * This buffer is sized from the INPUT BUFFER, not from WS_UPGRADE_MAX. It
     * was WS_UPGRADE_MAX, which was safe only while the cap applied to the
     * whole stream -- and the fix one commit earlier (F51) deliberately made
     * the cap apply to the header block alone, so the leftover can now be as
     * large as `in` itself. ASan caught the overflow the same afternoon the
     * fix created it, which is the argument for running the sanitizer tree
     * before the campaign rather than after.
     *
     * It is `static` because the daemon is one process and one thread by
     * design (V4 decision 2) and push_ws is not reentrant in any case; a
     * 12 KB frame on the event loop's stack for every read would be the
     * worse trade. Wiped below, like every other buffer that held peer bytes. */
    static uint8_t rest[AUTHD_IN_BUF_BYTES];
    const size_t rest_len = c->in_len - req_len;
    memcpy(rest, c->in + req_len, rest_len);
    sodium_memzero(c->in, c->in_len);
    c->in_len = 0u;
    const conn_io_status_t r = (rest_len > 0u) ? ws_feed(c, rest, rest_len) : CONN_IO_OK;
    sodium_memzero(rest, rest_len);
    return r;
}

conn_io_status_t conn_io_push(conn_io_t *c, const uint8_t *data, size_t n)
{
    if (c == NULL || (data == NULL && n != 0u)) {
        return CONN_IO_ERR_ARG;
    }
    if (c->failed) {
        return CONN_IO_ERR_PROTOCOL;
    }
    if (c->mode == CONN_IO_MODE_WS) {
        return push_ws(c, data, n);
    }
    if (n == 0u) {
        return (c->mode == CONN_IO_MODE_LINE) ? note_line_cap(c) : note_header(c);
    }
    if (n > sizeof c->in - c->in_len) {
        c->failed = 1;
        return CONN_IO_ERR_OVERFLOW;
    }
    memcpy(c->in + c->in_len, data, n);
    c->in_len += n;
    return (c->mode == CONN_IO_MODE_LINE) ? note_line_cap(c) : note_header(c);
}

int conn_io_next_line(conn_io_t *c, const uint8_t **line, size_t *len)
{
    if (c == NULL || line == NULL || len == NULL || c->failed || c->mode != CONN_IO_MODE_LINE) {
        return 0;
    }
    for (size_t i = 0; i < c->in_len; i++) {
        if (c->in[i] != (uint8_t)'\n') {
            continue;
        }
        c->line_total = i + 1u;             /* including the LF */
        size_t n = i;
        if (n > 0u && c->in[n - 1u] == (uint8_t)'\r') {
            n--;                            /* tolerate CRLF */
        }
        *line = c->in;
        *len = n;
        return 1;
    }
    return 0;
}

void conn_io_consume_line(conn_io_t *c)
{
    if (c == NULL || c->line_total == 0u || c->in_len < c->line_total) {
        return;
    }
    const size_t total = c->line_total;
    const size_t rest = c->in_len - total;
    if (rest > 0u) {
        memmove(c->in, c->in + total, rest);
    }
    sodium_memzero(c->in + rest, c->in_len - rest);
    c->in_len = rest;
    c->line_total = 0u;
}

int conn_io_next_frame(conn_io_t *c, const uint8_t **payload, size_t *len)
{
    if (c == NULL || payload == NULL || len == NULL || c->failed) {
        return 0;
    }
    if (note_header(c) != CONN_IO_OK) {
        return 0;
    }
    if (c->frame_len == 0u) {
        return 0;                       /* header not complete yet */
    }
    if (c->in_len < AUTHD_FRAME_HEADER + c->frame_len) {
        return 0;                       /* payload still arriving */
    }
    *payload = c->in + AUTHD_FRAME_HEADER;
    *len = c->frame_len;
    return 1;
}

void conn_io_consume_frame(conn_io_t *c)
{
    if (c == NULL || c->frame_len == 0u) {
        return;
    }
    const size_t total = AUTHD_FRAME_HEADER + c->frame_len;
    if (c->in_len < total) {
        return;                         /* not complete; nothing to drop */
    }
    const size_t rest = c->in_len - total;
    if (rest > 0u) {
        memmove(c->in, c->in + total, rest);
    }
    /* wipe the tail so a consumed frame's bytes do not linger in the slot */
    sodium_memzero(c->in + rest, c->in_len - rest);
    c->in_len = rest;
    c->frame_len = 0u;
    (void)note_header(c);               /* a following frame's header may already be here */
}

conn_io_status_t conn_io_queue(conn_io_t *c, const uint8_t *payload, size_t len)
{
    if (c == NULL || payload == NULL) {
        return CONN_IO_ERR_ARG;
    }
    if (len == 0u || len > (size_t)AUTHD_FRAME_MAX) {
        return CONN_IO_ERR_ARG;
    }
    if (c->out_len != c->out_sent) {
        return CONN_IO_ERR_BUSY;
    }
    if (c->mode == CONN_IO_MODE_LINE) {
        /* verbatim: the caller's bytes already carry their own terminators */
        memcpy(c->out, payload, len);
        c->out_len = len;
        c->out_sent = 0u;
        return CONN_IO_OK;
    }
    if (c->mode == CONN_IO_MODE_WS) {
        /* One protocol frame per binary message (spec §7.1), so the length
         * prefix goes INSIDE the WebSocket payload and the caller's bound is
         * unchanged. Server frames are never masked (RFC 6455 §5.1). */
        const size_t inner = (size_t)AUTHD_FRAME_HEADER + len;
        uint8_t h[WS_SRV_HDR_MAX];
        const size_t hl = ws_server_header(h, (uint64_t)inner, WS_OP_BINARY);
        if (hl + inner > sizeof c->out) {
            return CONN_IO_ERR_ARG;
        }
        memcpy(c->out, h, hl);
        c->out[hl]      = (uint8_t)((len >> 24) & 0xffu);
        c->out[hl + 1u] = (uint8_t)((len >> 16) & 0xffu);
        c->out[hl + 2u] = (uint8_t)((len >> 8) & 0xffu);
        c->out[hl + 3u] = (uint8_t)(len & 0xffu);
        memcpy(c->out + hl + AUTHD_FRAME_HEADER, payload, len);
        c->out_len = hl + inner;
        c->out_sent = 0u;
        return CONN_IO_OK;
    }
    c->out[0] = (uint8_t)((len >> 24) & 0xffu);
    c->out[1] = (uint8_t)((len >> 16) & 0xffu);
    c->out[2] = (uint8_t)((len >> 8) & 0xffu);
    c->out[3] = (uint8_t)(len & 0xffu);
    memcpy(c->out + AUTHD_FRAME_HEADER, payload, len);
    c->out_len = AUTHD_FRAME_HEADER + len;
    c->out_sent = 0u;
    return CONN_IO_OK;
}

/* WS control and handshake replies jump the queue. The write path in evloop.c
 * goes through conn_io_pending/_ptr/_sent and nothing else, so giving
 * `ws.reply` priority here IS the whole output integration: slot_writable does
 * not change, and the half-duplex rule now correctly counts a pending 101 or
 * Pong as "there is something to send". */
static int ws_reply_pending(const conn_io_t *c)
{
    return c->mode == CONN_IO_MODE_WS && c->ws.reply_len > c->ws.reply_sent;
}

size_t conn_io_pending(const conn_io_t *c)
{
    if (c == NULL) {
        return 0u;
    }
    if (ws_reply_pending(c)) {
        return c->ws.reply_len - c->ws.reply_sent;
    }
    if (c->out_len <= c->out_sent) {
        return 0u;
    }
    return c->out_len - c->out_sent;
}

const uint8_t *conn_io_pending_ptr(const conn_io_t *c)
{
    if (c == NULL) {
        return NULL;
    }
    if (ws_reply_pending(c)) {
        return c->ws.reply + c->ws.reply_sent;
    }
    return c->out + c->out_sent;
}

void conn_io_sent(conn_io_t *c, size_t n)
{
    if (c == NULL) {
        return;
    }
    if (ws_reply_pending(c)) {
        const size_t left = c->ws.reply_len - c->ws.reply_sent;
        c->ws.reply_sent += (n > left) ? left : n;
        if (c->ws.reply_sent >= c->ws.reply_len) {
            sodium_memzero(c->ws.reply, c->ws.reply_len);
            c->ws.reply_len = 0u;
            c->ws.reply_sent = 0u;
        }
        return;
    }
    const size_t pending = conn_io_pending(c);
    c->out_sent += (n > pending) ? pending : n;
    if (c->out_sent == c->out_len) {
        /* fully flushed: wipe and reset so the buffer never holds a stale record */
        sodium_memzero(c->out, c->out_len);
        c->out_len = 0u;
        c->out_sent = 0u;
    }
}
