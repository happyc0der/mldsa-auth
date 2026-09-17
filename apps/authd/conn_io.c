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

conn_io_status_t conn_io_push(conn_io_t *c, const uint8_t *data, size_t n)
{
    if (c == NULL || (data == NULL && n != 0u)) {
        return CONN_IO_ERR_ARG;
    }
    if (c->failed) {
        return CONN_IO_ERR_PROTOCOL;
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
    c->out[0] = (uint8_t)((len >> 24) & 0xffu);
    c->out[1] = (uint8_t)((len >> 16) & 0xffu);
    c->out[2] = (uint8_t)((len >> 8) & 0xffu);
    c->out[3] = (uint8_t)(len & 0xffu);
    memcpy(c->out + AUTHD_FRAME_HEADER, payload, len);
    c->out_len = AUTHD_FRAME_HEADER + len;
    c->out_sent = 0u;
    return CONN_IO_OK;
}

size_t conn_io_pending(const conn_io_t *c)
{
    if (c == NULL || c->out_len <= c->out_sent) {
        return 0u;
    }
    return c->out_len - c->out_sent;
}

const uint8_t *conn_io_pending_ptr(const conn_io_t *c)
{
    if (c == NULL) {
        return NULL;
    }
    return c->out + c->out_sent;
}

void conn_io_sent(conn_io_t *c, size_t n)
{
    if (c == NULL) {
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
