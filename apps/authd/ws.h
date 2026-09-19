#ifndef MLDSA_AUTHD_WS_H
#define MLDSA_AUTHD_WS_H

#include <stddef.h>
#include <stdint.h>

/*
 * WebSocket (RFC 6455) for the proxy-facing listener (V4-10a), spec
 * mldsa-authd §7.1.
 *
 * WHAT THIS IS NOT: a general WebSocket implementation. It carries exactly one
 * thing -- the existing 4-byte length-prefixed frame stream (spec §6.5),
 * unchanged -- so that "one reassembler serves both the WebSocket listener and
 * a raw listener" (§7.1). Text frames, extensions, subprotocols and
 * server-initiated pings are all absent because nothing needs them, and every
 * absent feature is a parser that cannot be attacked.
 *
 * THE SHAPE, and why it is this shape:
 *
 *   A WebSocket frame is a 2..14 byte header followed by masked payload. If
 *   the whole frame were staged before de-framing, every slot would need a
 *   second AUTHD_FRAME_MAX buffer -- doubling ~12 KB per connection. It does
 *   not need to be: only the HEADER has to be staged, because once it is
 *   parsed the payload can be unmasked byte-by-byte as it arrives and appended
 *   straight into the caller's frame buffer. So this holds a 14-byte header
 *   staging area and a 125-byte control-payload area, and nothing else that
 *   scales with message size.
 *
 *   The consequence worth stating: DATA payload bytes are handed to the
 *   caller's buffer, CONTROL payload bytes never are. A Ping cannot push the
 *   frame reassembler around, which is what stops a control frame from being
 *   confused with protocol input.
 *
 * STRICTNESS, per the house rules. Every refusal is terminal and the caller
 * poisons the connection; a peer does not get to follow a bad frame with a
 * good one. In particular (RFC 6455 §5.1) an UNMASKED client frame MUST fail
 * the connection -- masking is not a security property, but accepting an
 * unmasked frame means accepting bytes no browser would ever send.
 */

#define WS_GUID            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_KEY_B64_LEN     24u    /* base64 of 16 bytes, padded */
#define WS_ACCEPT_B64_LEN  28u    /* base64 of the 20-byte SHA-1, padded */
#define WS_UPGRADE_MAX     4096u  /* a request header block larger than this is refused */
#define WS_STATE_MAX       64u    /* spec §7.1: `state` is at most 64 bytes */
#define WS_CTRL_MAX        125u   /* RFC 6455 §5.5: control payloads are <= 125 */
#define WS_HDR_MAX         14u    /* 2 + 8 length + 4 mask */
#define WS_SRV_HDR_MAX     10u    /* server frames are unmasked: 2 + 8 length */

/* Opcodes this implementation knows. Anything else fails the connection. */
#define WS_OP_CONT   0x0u
#define WS_OP_BINARY 0x2u
#define WS_OP_CLOSE  0x8u
#define WS_OP_PING   0x9u
#define WS_OP_PONG   0xau

typedef enum {
    WS_STAGE_UPGRADE = 0,  /* buffering the HTTP request */
    WS_STAGE_OPEN,         /* framed */
    WS_STAGE_CLOSED
} ws_stage_t;

typedef enum {
    WS_OK = 0,
    WS_NEED_MORE,      /* nothing wrong; more bytes required */
    WS_ERR_PROTOCOL    /* terminal: the caller must poison the connection */
} ws_status_t;

typedef struct {
    ws_stage_t stage;

    /* §7.1: the opaque `state` from the request-target query. This is the one
     * attacker-controlled value that reaches the store, so it is bounded here
     * and validated as printable before it can be hashed into a login code. */
    uint8_t state[WS_STATE_MAX];
    size_t  state_len;

    /* Header staging for the frame being decoded. */
    uint8_t  hdr[WS_HDR_MAX];
    size_t   hdr_len;
    size_t   hdr_need;        /* total header bytes for this frame once known */
    uint64_t payload_left;
    uint8_t  mask[4];
    unsigned mask_off;
    uint8_t  opcode;          /* of the frame in progress */
    uint8_t  is_control;
    int      in_message;      /* a fragmented data message is open */
    /* RFC 6455 §5.1: client->server frames MUST be masked, server->client
     * frames MUST NOT be. One decoder serves both directions because the only
     * difference is which of those two it insists on. */
    uint8_t  expect_mask;

    /* Control payloads never reach the caller's frame buffer. */
    uint8_t  ctrl[WS_CTRL_MAX];
    size_t   ctrl_len;

    /* Set when a Pong or Close must be emitted; drained by the caller. */
    uint8_t  reply[WS_SRV_HDR_MAX + WS_CTRL_MAX];
    size_t   reply_len;
    size_t   reply_sent;
} ws_t;

void ws_init(ws_t *w);

/* The client half, used by authd_client and by the test harness so there is
 * ONE WebSocket implementation in the tree rather than one per consumer.
 * ws_init_client() starts already OPEN -- the caller has completed the
 * handshake with the three functions below -- and expects UNMASKED frames. */
void ws_init_client(ws_t *w);

/* Builds the upgrade request for `path` (and `state`, which may be NULL or
 * empty). `nonce` is 16 random bytes. `expect` receives the accept value the
 * server must return. Returns 0, or -1 if it does not fit. */
int ws_client_request(char *out, size_t cap, size_t *out_len,
                      const char *path, const char *state,
                      const uint8_t nonce[16], char expect[WS_ACCEPT_B64_LEN + 1u]);

/* Returns 0 if `resp` is a 101 carrying exactly `expect`. */
int ws_client_check_101(const uint8_t *resp, size_t len, const char *expect);

/* Wraps `payload` in a MASKED client binary frame. Returns the total length
 * written, or 0 if it does not fit. */
size_t ws_client_frame(uint8_t *out, size_t cap, const uint8_t *payload, size_t n,
                       const uint8_t mask[4]);

/* Reads exactly `n` bytes. 0 on success, -1 on any failure (including EOF),
 * and +1 for a clean EOF at a message boundary. */
typedef int (*ws_read_fn)(void *ctx, uint8_t *buf, size_t n);

/* One server->client binary message into `out`. Control frames are consumed
 * here and a Close reports WS_CLIENT_CLOSED, so a caller never sees one.
 * Shared by authd_client and the test harness: one reader, not one per
 * consumer. */
typedef enum {
    WS_CLIENT_OK = 0,
    WS_CLIENT_CLOSED,     /* the peer sent Close, or a clean EOF */
    WS_CLIENT_IO,
    WS_CLIENT_PROTOCOL
} ws_client_status_t;
ws_client_status_t ws_client_read_message(ws_read_fn rd, void *ctx,
                                          uint8_t *out, size_t cap, size_t *out_len);

/* Computes the RFC 6455 accept value for a 24-character base64 key.
 * `out` receives WS_ACCEPT_B64_LEN characters plus a NUL.
 * Returns 0, or -1 if the key is not 16 bytes of base64. */
int ws_accept_key(const char *key_b64, size_t key_len, char out[WS_ACCEPT_B64_LEN + 1u]);

/* Parses a complete HTTP upgrade request from `req` (the caller has already
 * found the terminating CRLFCRLF). On WS_OK the 101 response is in
 * w->reply[0..reply_len) and `state` has been extracted. */
ws_status_t ws_upgrade(ws_t *w, const uint8_t *req, size_t len);

/* Consumes `n` client bytes in WS_STAGE_OPEN. Unmasked DATA payload is
 * appended through `sink` (which returns 0 on success, -1 when it cannot take
 * the bytes -- a bound the caller owns). Control frames are handled here and
 * may leave a reply in w->reply. */
typedef int (*ws_sink_fn)(void *ctx, const uint8_t *p, size_t n);
ws_status_t ws_consume(ws_t *w, const uint8_t *p, size_t n, ws_sink_fn sink, void *ctx);

/* Writes an unmasked server frame header for `payload_len` bytes of `opcode`.
 * Returns the header length (2..10). */
size_t ws_server_header(uint8_t out[WS_SRV_HDR_MAX], uint64_t payload_len, uint8_t opcode);

#endif /* MLDSA_AUTHD_WS_H */
