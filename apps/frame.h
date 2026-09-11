#ifndef MLDSA_AUTH_APPS_FRAME_H
#define MLDSA_AUTH_APPS_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "net_io.h"
#include "session.h"    /* SESSION_MAX_RECORD_BYTES, SESSION_OVERHEAD_BYTES */
#include "transcript.h" /* *_MAX_ENCODED_LEN */

/*
 * Reference transport framing (spec §6.5):
 *
 *   frame = length (4 bytes, big-endian, unsigned) || payload (length bytes)
 *
 * There is no separate frame-type byte: the payload's first byte is already
 * the protocol message type (0x01-0x03 handshake, 0x04 session record), and
 * each state expects exactly one type, which the library decoders and
 * session_open() enforce. The length is not authenticated and needs no
 * authentication: a wrong length changes the payload boundaries, and the
 * strict full-consumption decoders or the AEAD then fail (terminal).
 *
 * Every read is bounded by a PER-STATE maximum, checked on the 4 header
 * bytes BEFORE any payload byte is read. Frames live in caller-owned
 * FRAME_BUF_BYTES buffers with the payload at buf + FRAME_HEADER_BYTES, so a
 * send is one contiguous write and nothing is allocated per frame.
 */

#define FRAME_HEADER_BYTES 4u
#define FRAME_MAX_PAYLOAD SESSION_MAX_RECORD_BYTES /* 65561 */
#define FRAME_BUF_BYTES (FRAME_HEADER_BYTES + FRAME_MAX_PAYLOAD)

/* Per-state limits (payload bytes). */
#define FRAME_MAX_CLIENT_HELLO CLIENT_HELLO_MAX_ENCODED_LEN /* 146 */
#define FRAME_MAX_SERVER_HELLO SERVER_HELLO_MAX_ENCODED_LEN /* 3457 */
#define FRAME_MAX_CLIENT_AUTH CLIENT_AUTH_MAX_ENCODED_LEN   /* 3328 */
#define FRAME_CONFIRM_LEN SESSION_OVERHEAD_BYTES            /* 25: the empty record */
#define FRAME_MIN_RECORD SESSION_OVERHEAD_BYTES             /* 25 */
#define FRAME_MAX_RECORD SESSION_MAX_RECORD_BYTES           /* 65561 */

typedef enum {
    FRAME_OK = 0,
    FRAME_EOF,        /* peer closed before any header byte: a clean boundary */
    FRAME_TRUNCATED,  /* peer closed mid-header or mid-payload */
    FRAME_TIMEOUT,
    FRAME_IO,
    FRAME_BAD_LENGTH, /* length 0, < min_len or > max_len: rejected before the payload */
    FRAME_INVALID_ARG /* programming error */
} frame_status_t;

void frame_put_header(uint8_t hdr[FRAME_HEADER_BYTES], uint32_t len);
uint32_t frame_get_header(const uint8_t hdr[FRAME_HEADER_BYTES]);

/* Sends buf[0 .. 4 + payload_len): the payload must already be at
 * buf + FRAME_HEADER_BYTES; the header is written here. 1 <= payload_len
 * <= FRAME_MAX_PAYLOAD. */
frame_status_t frame_send(net_conn_t *c, uint8_t *buf, size_t payload_len, uint64_t deadline_ms);

/* Receives one frame into buf (payload at buf + FRAME_HEADER_BYTES; buf must
 * hold FRAME_HEADER_BYTES + max_len bytes). Requires 1 <= min_len <= max_len
 * <= FRAME_MAX_PAYLOAD. On any status but FRAME_OK, *payload_len is 0 and the
 * caller must end the connection. */
frame_status_t frame_recv(net_conn_t *c, uint8_t *buf, size_t min_len, size_t max_len,
                          size_t *payload_len, uint64_t deadline_ms);

const char *frame_status_name(frame_status_t st);

#endif /* MLDSA_AUTH_APPS_FRAME_H */
