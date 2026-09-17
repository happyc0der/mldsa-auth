#ifndef MLDSA_AUTHD_CONN_IO_H
#define MLDSA_AUTHD_CONN_IO_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

/*
 * Non-blocking frame reassembly for one connection (V4-8a).
 *
 * Why this exists instead of apps/frame.c: that layer is blocking-with-deadline
 * (net_read_exact / frame_recv) and is depended on by the demo apps, test_net
 * and demo_e2e. The daemon is a single poll() loop over many slots and can
 * never block on one peer, so it needs a reassembler driven by "here are the
 * bytes that happened to arrive". Bending frame.c into both shapes would
 * rewrite a surface three verified things rely on; the duplication is
 * deliberate and recorded in docs/decisions.md.
 *
 * This component owns NO socket and makes no syscalls: bytes are pushed in and
 * pulled out. That is what lets it be tested exhaustively -- every split point
 * of every boundary case -- without a network.
 *
 * Wire shape is spec-v2 §6.5's unchanged framing: a 4-byte big-endian length
 * followed by that many payload bytes.
 */

/* The daemon tightens spec-v2 §6.5.1's 65561-byte record maximum, because it
 * never needs 65 KiB records and a smaller cap means smaller fixed per-slot
 * buffers (spec mldsa-authd §6.1). The largest application message is ROTATE
 * at 8612 bytes of content. */
#define AUTHD_MAX_CONTENT 9216u
#define AUTHD_MAX_RECORD  SESSION_RECORD_LEN(AUTHD_MAX_CONTENT, SESSION_PAD_BUCKET_MAX)

/* Handshake messages are larger than any application record, so the frame cap
 * is the larger of the two; a receive buffer is sized from THIS, never from
 * expected content (spec-v2 §6.4's pt_cap rule, and the mistake V2-6 made). */
#define AUTHD_FRAME_MAX \
    ((AUTHD_MAX_RECORD > SERVER_HELLO_MAX_ENCODED_LEN) ? AUTHD_MAX_RECORD : SERVER_HELLO_MAX_ENCODED_LEN)

/* The local API (spec 8) is line-oriented: one LF-terminated request per line,
 * at most 8192 bytes. A line that reaches the cap without an LF is a protocol
 * error, exactly as an over-long frame is. */
#define AUTHD_LINE_MAX 8192u

#define AUTHD_FRAME_HEADER 4u
#define AUTHD_IN_BUF_BYTES  (AUTHD_FRAME_HEADER + AUTHD_FRAME_MAX)
#define AUTHD_OUT_BUF_BYTES (AUTHD_FRAME_HEADER + AUTHD_FRAME_MAX)

/* A connection is either framed (the protocol listeners) or line-oriented
 * (the local API sockets). The mode is fixed when the slot is bound and
 * decides how push() interprets the bytes: in FRAME mode the first four bytes
 * are a length, in LINE mode they are the start of a command, and confusing
 * the two would make `PING` a 1347375947-byte frame. */
typedef enum {
    CONN_IO_MODE_FRAME = 0,
    CONN_IO_MODE_LINE
} conn_io_mode_t;

typedef enum {
    CONN_IO_OK = 0,
    CONN_IO_ERR_ARG,
    CONN_IO_ERR_OVERFLOW,   /* more bytes pushed than the buffer can hold */
    CONN_IO_ERR_PROTOCOL,   /* a declared frame length of 0 or > AUTHD_FRAME_MAX */
    CONN_IO_ERR_BUSY        /* queue attempted while a frame is still unsent */
} conn_io_status_t;

typedef struct {
    conn_io_mode_t mode;
    uint8_t in[AUTHD_IN_BUF_BYTES];
    size_t  in_len;        /* bytes currently buffered */
    size_t  frame_len;     /* FRAME: payload length at the head, 0 = not yet known */
    size_t  line_total;    /* LINE: bytes to drop for the line most recently returned */
    int     failed;        /* sticky: a protocol error poisons the connection */

    uint8_t out[AUTHD_OUT_BUF_BYTES];
    size_t  out_len;       /* total bytes queued (header + payload) */
    size_t  out_sent;      /* how many of them have been written */
} conn_io_t;

/* Zeroes the whole struct, including buffers. Used on slot reuse, so one
 * peer's bytes can never be visible to the next. */
void conn_io_reset(conn_io_t *c);

/* Sets the framing mode. Call immediately after conn_io_reset() when a slot is
 * bound; the mode survives until the next reset. */
void conn_io_set_mode(conn_io_t *c, conn_io_mode_t mode);

const char *conn_io_status_name(conn_io_status_t st);

/* Adds `n` freshly read bytes. Returns OVERFLOW if they do not fit (which can
 * only happen if the peer sent more than one maximum frame ahead), PROTOCOL if
 * the declared length is illegal. Both are terminal for the connection. */
conn_io_status_t conn_io_push(conn_io_t *c, const uint8_t *data, size_t n);

/* If a complete frame is buffered, sets `*payload` and `*len` to it and returns 1.
 * The pointer is into the connection's own buffer and stays valid until
 * conn_io_consume_frame(). Returns 0 when more bytes are needed. */
int conn_io_next_frame(conn_io_t *c, const uint8_t **payload, size_t *len);

/* Drops the frame most recently returned by conn_io_next_frame, sliding any
 * following bytes down. */
void conn_io_consume_frame(conn_io_t *c);

/* LINE MODE ONLY. If a complete LF-terminated line is buffered, sets
 * `*line`/`*len` to it WITHOUT the terminator (a trailing CR is stripped too,
 * so a client that sends CRLF is not punished for it) and returns 1. The
 * pointer is into the connection's buffer and stays valid until
 * conn_io_consume_line(). Returns 0 when more bytes are needed. */
int conn_io_next_line(conn_io_t *c, const uint8_t **line, size_t *len);

/* Drops the line most recently returned by conn_io_next_line, including its
 * terminator, sliding any following bytes down. */
void conn_io_consume_line(conn_io_t *c);

/* Queues exactly one outbound frame (header written for you). BUSY if the
 * previous one has not finished sending -- the daemon is half-duplex per slot
 * by design, so this is a caller bug, not a runtime condition.
 *
 * In LINE mode no header is written: the bytes are queued verbatim, and the
 * caller supplies its own LF terminator(s). One call may carry a whole
 * multi-line list response. */
conn_io_status_t conn_io_queue(conn_io_t *c, const uint8_t *payload, size_t len);

/* Capacity available to one queued response, so a caller can bound a list
 * before it starts building one. */
size_t conn_io_out_capacity(void);

/* Bytes still waiting to go out, and a pointer to the first of them. */
size_t conn_io_pending(const conn_io_t *c);
const uint8_t *conn_io_pending_ptr(const conn_io_t *c);

/* Records that `n` pending bytes were written. */
void conn_io_sent(conn_io_t *c, size_t n);

#endif /* MLDSA_AUTHD_CONN_IO_H */
