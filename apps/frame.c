#include "frame.h"

_Static_assert(FRAME_MAX_CLIENT_HELLO <= FRAME_MAX_PAYLOAD, "ClientHello fits a frame");
_Static_assert(FRAME_MAX_SERVER_HELLO <= FRAME_MAX_PAYLOAD, "ServerHello fits a frame");
_Static_assert(FRAME_MAX_CLIENT_AUTH <= FRAME_MAX_PAYLOAD, "ClientAuth fits a frame");
_Static_assert(FRAME_MAX_RECORD == FRAME_MAX_PAYLOAD, "the largest frame is the largest record");
_Static_assert(FRAME_CONFIRM_MIN == FRAME_MIN_RECORD, "an unpadded confirmation is the smallest record");
_Static_assert(FRAME_CONFIRM_MAX <= FRAME_MAX_RECORD, "a padded confirmation is still a record");
_Static_assert(FRAME_MAX_PAYLOAD <= UINT32_MAX, "length prefix is 32 bits");

void frame_put_header(uint8_t hdr[FRAME_HEADER_BYTES], uint32_t len) {
    hdr[0] = (uint8_t)(len >> 24);
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;
}

uint32_t frame_get_header(const uint8_t hdr[FRAME_HEADER_BYTES]) {
    return ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) |
           (uint32_t)hdr[3];
}

static frame_status_t from_net(net_status_t st) {
    switch (st) {
    case NET_OK: return FRAME_OK;
    case NET_TIMEOUT: return FRAME_TIMEOUT;
    case NET_ERR_INVALID_ARG: return FRAME_INVALID_ARG;
    case NET_EOF: /* callers map EOF themselves (boundary vs truncation) */
    case NET_ERR_IO: break;
    }
    return FRAME_IO;
}

frame_status_t frame_send(net_conn_t *c, uint8_t *buf, size_t payload_len, uint64_t deadline_ms) {
    if (c == NULL || buf == NULL || payload_len == 0 || payload_len > FRAME_MAX_PAYLOAD) {
        return FRAME_INVALID_ARG;
    }
    frame_put_header(buf, (uint32_t)payload_len);
    const net_status_t st = net_write_all(c, buf, FRAME_HEADER_BYTES + payload_len, deadline_ms);
    return (st == NET_EOF) ? FRAME_IO : from_net(st);
}

frame_status_t frame_recv(net_conn_t *c, uint8_t *buf, size_t min_len, size_t max_len,
                          size_t *payload_len, uint64_t deadline_ms) {
    if (payload_len != NULL) {
        *payload_len = 0;
    }
    if (c == NULL || buf == NULL || payload_len == NULL || min_len == 0 || min_len > max_len ||
        max_len > FRAME_MAX_PAYLOAD) {
        return FRAME_INVALID_ARG;
    }

    size_t got = 0;
    net_status_t st = net_read_exact(c, buf, FRAME_HEADER_BYTES, deadline_ms, &got);
    if (st == NET_EOF) {
        return (got == 0) ? FRAME_EOF : FRAME_TRUNCATED;
    }
    if (st != NET_OK) {
        return from_net(st);
    }

    /* The per-state bound is enforced on the header alone: an oversize (or
     * zero) length is rejected before a single payload byte is read. */
    const uint32_t len = frame_get_header(buf);
    if ((size_t)len < min_len || (size_t)len > max_len) {
        return FRAME_BAD_LENGTH;
    }

    st = net_read_exact(c, buf + FRAME_HEADER_BYTES, len, deadline_ms, &got);
    if (st == NET_EOF) {
        return FRAME_TRUNCATED;
    }
    if (st != NET_OK) {
        return from_net(st);
    }
    *payload_len = len;
    return FRAME_OK;
}

const char *frame_status_name(frame_status_t st) {
    switch (st) {
    case FRAME_OK: return "ok";
    case FRAME_EOF: return "eof";
    case FRAME_TRUNCATED: return "truncated";
    case FRAME_TIMEOUT: return "timeout";
    case FRAME_IO: return "io-error";
    case FRAME_BAD_LENGTH: return "bad-length";
    case FRAME_INVALID_ARG: return "invalid-arg";
    }
    return "unknown";
}
