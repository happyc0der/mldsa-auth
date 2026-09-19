#include "ws.h"

#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "sha1.h"

/* ---------------------------------------------------------------- helpers */

/* ASCII-only case folding. The C library's tolower() is locale-dependent, and
 * a locale where 'I' does not fold to 'i' would quietly change which headers
 * match -- the daemon never sets a locale, but a parser should not depend on
 * that. HTTP header names are ASCII by definition (RFC 9110 §5.1). */
static int ci_eq(const uint8_t *a, size_t alen, const char *b)
{
    const size_t blen = strlen(b);
    if (alen != blen) { return 0; }
    for (size_t i = 0; i < alen; i++) {
        uint8_t x = a[i], y = (uint8_t)b[i];
        if (x >= 'A' && x <= 'Z') { x = (uint8_t)(x + 32); }
        if (y >= 'A' && y <= 'Z') { y = (uint8_t)(y + 32); }
        if (x != y) { return 0; }
    }
    return 1;
}

/* Does a comma-separated header value contain `tok`, case-insensitively?
 * `Connection: keep-alive, Upgrade` is legal and common. */
static int has_token(const uint8_t *v, size_t n, const char *tok)
{
    size_t i = 0;
    while (i < n) {
        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) { i++; }
        size_t s = i;
        while (i < n && v[i] != ',') { i++; }
        size_t e = i;
        while (e > s && (v[e - 1u] == ' ' || v[e - 1u] == '\t')) { e--; }
        if (e > s && ci_eq(v + s, e - s, tok)) { return 1; }
    }
    return 0;
}

void ws_init(ws_t *w)
{
    memset(w, 0, sizeof *w);
    w->stage = WS_STAGE_UPGRADE;
    w->expect_mask = 1u;          /* a server reads client frames */
}

void ws_init_client(ws_t *w)
{
    memset(w, 0, sizeof *w);
    w->stage = WS_STAGE_OPEN;     /* the caller has already done the handshake */
    w->expect_mask = 0u;          /* a client reads server frames */
}

/* ---------------------------------------------------------------- upgrade */

int ws_accept_key(const char *key_b64, size_t key_len, char out[WS_ACCEPT_B64_LEN + 1u])
{
    memset(out, 0, WS_ACCEPT_B64_LEN + 1u);
    if (key_b64 == NULL || key_len != WS_KEY_B64_LEN) {
        return -1;
    }
    /* RFC 6455 §4.1: the key is base64 of exactly 16 random bytes. Checking
     * that here means a malformed key is refused before it is concatenated. */
    uint8_t raw[16];
    size_t raw_len = 0;
    if (sodium_base642bin(raw, sizeof raw, key_b64, key_len, NULL, &raw_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || raw_len != sizeof raw) {
        sodium_memzero(raw, sizeof raw);
        return -1;
    }
    sodium_memzero(raw, sizeof raw);

    uint8_t buf[WS_KEY_B64_LEN + sizeof WS_GUID];   /* sizeof includes the NUL */
    memcpy(buf, key_b64, WS_KEY_B64_LEN);
    memcpy(buf + WS_KEY_B64_LEN, WS_GUID, sizeof WS_GUID - 1u);
    const size_t n = WS_KEY_B64_LEN + (sizeof WS_GUID - 1u);

    uint8_t digest[SHA1_DIGEST_BYTES];
    sha1(buf, n, digest);
    (void)sodium_bin2base64(out, WS_ACCEPT_B64_LEN + 1u, digest, sizeof digest,
                            sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

/* Extracts `state` from a request-target's query. Absent is legal and yields
 * an empty value; present-but-unusable is not. */
static ws_status_t take_state(ws_t *w, const uint8_t *target, size_t n)
{
    const uint8_t *q = memchr(target, '?', n);
    if (q == NULL) {
        return WS_OK;                       /* no query: the empty state */
    }
    size_t i = (size_t)(q - target) + 1u;
    while (i < n) {
        size_t s = i;
        while (i < n && target[i] != '&') { i++; }
        size_t e = i;
        if (i < n) { i++; }
        if (e - s > 6u && memcmp(target + s, "state=", 6) == 0) {
            const uint8_t *v = target + s + 6u;
            const size_t vn = (e - s) - 6u;
            if (vn > WS_STATE_MAX) {
                return WS_ERR_PROTOCOL;     /* §7.1 bounds it at 64 */
            }
            /* Printable ASCII only: this value is hashed into a login code and
             * echoed by the site, and the log escapes nothing it is given. */
            for (size_t k = 0; k < vn; k++) {
                if (v[k] < 0x21u || v[k] > 0x7eu) { return WS_ERR_PROTOCOL; }
            }
            memcpy(w->state, v, vn);
            w->state_len = vn;
            return WS_OK;
        }
    }
    return WS_OK;
}

ws_status_t ws_upgrade(ws_t *w, const uint8_t *req, size_t len)
{
    if (w == NULL || req == NULL || len == 0u || len > WS_UPGRADE_MAX) {
        return WS_ERR_PROTOCOL;
    }

    /* Request line: METHOD SP target SP HTTP/1.1 */
    const uint8_t *eol = memchr(req, '\n', len);
    if (eol == NULL) { return WS_ERR_PROTOCOL; }
    size_t line_len = (size_t)(eol - req);
    if (line_len > 0u && req[line_len - 1u] == '\r') { line_len--; }

    if (line_len < 14u || memcmp(req, "GET ", 4) != 0) { return WS_ERR_PROTOCOL; }
    const uint8_t *tgt = req + 4;
    const uint8_t *sp = memchr(tgt, ' ', line_len - 4u);
    if (sp == NULL) { return WS_ERR_PROTOCOL; }
    const size_t tgt_len = (size_t)(sp - tgt);
    const size_t ver_len = line_len - 4u - tgt_len - 1u;
    if (!(ver_len == 8u && memcmp(sp + 1, "HTTP/1.1", 8) == 0)) { return WS_ERR_PROTOCOL; }
    if (take_state(w, tgt, tgt_len) != WS_OK) { return WS_ERR_PROTOCOL; }

    /* Headers. Only the four RFC 6455 requires are read; everything else is
     * ignored rather than rejected, because a proxy legitimately adds its own. */
    int have_upgrade = 0, have_connection = 0, have_version = 0;
    const char *key = NULL;
    size_t key_len = 0;

    size_t off = (size_t)(eol - req) + 1u;
    while (off < len) {
        const uint8_t *e = memchr(req + off, '\n', len - off);
        if (e == NULL) { return WS_ERR_PROTOCOL; }
        size_t hl = (size_t)(e - (req + off));
        if (hl > 0u && req[off + hl - 1u] == '\r') { hl--; }
        if (hl == 0u) { break; }                       /* end of the header block */

        const uint8_t *h = req + off;
        const uint8_t *colon = memchr(h, ':', hl);
        if (colon == NULL) { return WS_ERR_PROTOCOL; }
        const size_t nlen = (size_t)(colon - h);
        size_t vs = nlen + 1u;
        while (vs < hl && (h[vs] == ' ' || h[vs] == '\t')) { vs++; }
        size_t ve = hl;
        while (ve > vs && (h[ve - 1u] == ' ' || h[ve - 1u] == '\t')) { ve--; }
        const uint8_t *v = h + vs;
        const size_t vn = ve - vs;

        if (ci_eq(h, nlen, "Upgrade")) {
            have_upgrade = has_token(v, vn, "websocket");
        } else if (ci_eq(h, nlen, "Connection")) {
            have_connection = has_token(v, vn, "Upgrade");
        } else if (ci_eq(h, nlen, "Sec-WebSocket-Version")) {
            have_version = (vn == 2u && v[0] == '1' && v[1] == '3');
        } else if (ci_eq(h, nlen, "Sec-WebSocket-Key")) {
            key = (const char *)v;
            key_len = vn;
        }
        off += (size_t)(e - (req + off)) + 1u;
    }

    if (!have_upgrade || !have_connection || !have_version || key == NULL) {
        return WS_ERR_PROTOCOL;
    }

    char accept[WS_ACCEPT_B64_LEN + 1u];
    if (ws_accept_key(key, key_len, accept) != 0) {
        return WS_ERR_PROTOCOL;
    }

    const int n = snprintf((char *)w->reply, sizeof w->reply,
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    if (n <= 0 || (size_t)n >= sizeof w->reply) {
        return WS_ERR_PROTOCOL;
    }
    w->reply_len = (size_t)n;
    w->reply_sent = 0u;
    w->stage = WS_STAGE_OPEN;
    return WS_OK;
}

ws_status_t ws_refuse(ws_t *w, unsigned code)
{
    if (w == NULL) {
        return WS_ERR_PROTOCOL;
    }
    const char *status = (code == 429u) ? "429 Too Many Requests" : "503 Service Unavailable";
    const int n = snprintf((char *)w->reply, sizeof w->reply,
                           "HTTP/1.1 %s\r\n"
                           "Connection: close\r\n"
                           "Content-Length: 0\r\n\r\n", status);
    if (n <= 0 || (size_t)n >= sizeof w->reply) {
        /* Unreachable for either literal, but a truncated response is worse
         * than none: leave the buffer empty and let the caller close. */
        w->reply_len = 0u;
        w->reply_sent = 0u;
        w->stage = WS_STAGE_CLOSED;
        return WS_ERR_PROTOCOL;
    }
    /* Overwrites whatever was queued -- specifically a 101 built moments ago by
     * ws_upgrade, when the preamble and the request arrived in one read. A 101
     * followed by a 429 is not a thing, so the refusal replaces it. Nothing has
     * been written to the socket yet: the event loop computes its POLLOUT set
     * before the read that got us here. */
    w->reply_len = (size_t)n;
    w->reply_sent = 0u;
    w->stage = WS_STAGE_CLOSED;
    return WS_OK;
}

/* ----------------------------------------------------------------- frames */

size_t ws_server_header(uint8_t out[WS_SRV_HDR_MAX], uint64_t payload_len, uint8_t opcode)
{
    out[0] = (uint8_t)(0x80u | (opcode & 0x0fu));    /* FIN, no RSV */
    if (payload_len < 126u) {
        out[1] = (uint8_t)payload_len;
        return 2u;
    }
    if (payload_len <= 0xffffu) {
        out[1] = 126u;
        out[2] = (uint8_t)(payload_len >> 8);
        out[3] = (uint8_t)payload_len;
        return 4u;
    }
    out[1] = 127u;
    for (unsigned i = 0; i < 8u; i++) {
        out[2u + i] = (uint8_t)(payload_len >> (8u * (7u - i)));
    }
    return 10u;
}

static void queue_ctrl(ws_t *w, uint8_t opcode, const uint8_t *p, size_t n)
{
    /* Control replies have their own buffer precisely so that queueing one
     * cannot collide with a data reply already waiting to go out -- the event
     * loop is half-duplex and would answer CONN_IO_ERR_BUSY. */
    if (w->reply_len != w->reply_sent) {
        return;                              /* one control reply in flight is enough */
    }
    if (n > WS_CTRL_MAX) { n = WS_CTRL_MAX; }
    const size_t hl = ws_server_header(w->reply, n, opcode);
    memcpy(w->reply + hl, p, n);
    w->reply_len = hl + n;
    w->reply_sent = 0u;
}

ws_status_t ws_consume(ws_t *w, const uint8_t *p, size_t n, ws_sink_fn sink, void *ctx)
{
    if (w == NULL || (p == NULL && n > 0u) || sink == NULL) {
        return WS_ERR_PROTOCOL;
    }
    if (w->stage == WS_STAGE_CLOSED) {
        /* After a Close, nothing further is interpreted -- and that has to be
         * true whether the peer's trailing bytes arrived in the SAME read as
         * the Close or a later one. Treating the later case as a protocol
         * error while silently dropping the earlier one is a divergence a
         * coalescing proxy turns into a spurious error in the operator's log,
         * for bytes that can no longer affect anything. fuzz_ws found it. */
        return WS_OK;
    }
    if (w->stage != WS_STAGE_OPEN) {
        return WS_ERR_PROTOCOL;
    }

    size_t i = 0;
    while (i < n) {
        /* --- header --- */
        if (w->payload_left == 0u && (w->hdr_need == 0u || w->hdr_len < w->hdr_need)) {
            while (i < n && (w->hdr_need == 0u || w->hdr_len < w->hdr_need)) {
                if (w->hdr_len >= WS_HDR_MAX) { return WS_ERR_PROTOCOL; }
                w->hdr[w->hdr_len++] = p[i++];

                if (w->hdr_len == 2u) {
                    const uint8_t b0 = w->hdr[0], b1 = w->hdr[1];
                    if ((b0 & 0x70u) != 0u) { return WS_ERR_PROTOCOL; }   /* RSV set: no extensions */
                    /* §5.1, both directions: a client frame MUST be masked and
                     * a server frame MUST NOT be. Accepting the wrong one means
                     * accepting bytes the peer it claims to be never sends. */
                    const int masked = (b1 & 0x80u) != 0u;
                    if (masked != (w->expect_mask != 0u)) { return WS_ERR_PROTOCOL; }
                    const uint8_t len7 = (uint8_t)(b1 & 0x7fu);
                    w->hdr_need = 2u + (masked ? 4u : 0u) +
                                  ((len7 == 126u) ? 2u : (len7 == 127u) ? 8u : 0u);
                    w->opcode = (uint8_t)(b0 & 0x0fu);
                    w->is_control = (uint8_t)((w->opcode & 0x08u) != 0u);
                    if (w->is_control) {
                        /* §5.5: control frames are never fragmented and carry <= 125 bytes. */
                        if ((b0 & 0x80u) == 0u || len7 > 125u) { return WS_ERR_PROTOCOL; }
                        if (w->opcode != WS_OP_CLOSE && w->opcode != WS_OP_PING &&
                            w->opcode != WS_OP_PONG) {
                            return WS_ERR_PROTOCOL;
                        }
                    } else if (w->opcode != WS_OP_BINARY && w->opcode != WS_OP_CONT) {
                        return WS_ERR_PROTOCOL;   /* text and the reserved opcodes */
                    }
                }
            }
            if (w->hdr_need == 0u || w->hdr_len < w->hdr_need) {
                return WS_NEED_MORE;
            }

            /* header complete */
            const uint8_t len7 = (uint8_t)(w->hdr[1] & 0x7fu);
            size_t off = 2u;
            if (len7 == 126u) {
                w->payload_left = ((uint64_t)w->hdr[2] << 8) | w->hdr[3];
                off = 4u;
                if (w->payload_left < 126u) { return WS_ERR_PROTOCOL; }   /* not minimally encoded */
            } else if (len7 == 127u) {
                w->payload_left = 0u;
                for (unsigned k = 0; k < 8u; k++) {
                    w->payload_left = (w->payload_left << 8) | w->hdr[2u + k];
                }
                off = 10u;
                if (w->payload_left <= 0xffffu) { return WS_ERR_PROTOCOL; }
                if ((w->payload_left >> 63) != 0u) { return WS_ERR_PROTOCOL; }   /* §5.2: MSB must be 0 */
            } else {
                w->payload_left = len7;
            }
            if (w->expect_mask) {
                memcpy(w->mask, w->hdr + off, 4u);
            } else {
                memset(w->mask, 0, sizeof w->mask);   /* XOR with zero: unmasked */
            }
            w->mask_off = 0u;
            w->ctrl_len = 0u;

            if (!w->is_control) {
                const int fin = (w->hdr[0] & 0x80u) != 0u;
                if (w->opcode == WS_OP_CONT && !w->in_message) {
                    return WS_ERR_PROTOCOL;       /* continuation with nothing open */
                }
                if (w->opcode == WS_OP_BINARY && w->in_message) {
                    return WS_ERR_PROTOCOL;       /* a new message inside an open one */
                }
                w->in_message = !fin;
            }

            if (w->payload_left == 0u) {
                /* An empty frame still completes: reset and go round again. */
                goto frame_done;
            }
            continue;
        }

        /* --- payload --- */
        {
            size_t take = n - i;
            if ((uint64_t)take > w->payload_left) { take = (size_t)w->payload_left; }

            uint8_t tmp[512];
            size_t done = 0;
            while (done < take) {
                size_t chunk = take - done;
                if (chunk > sizeof tmp) { chunk = sizeof tmp; }
                for (size_t k = 0; k < chunk; k++) {
                    tmp[k] = (uint8_t)(p[i + done + k] ^ w->mask[(w->mask_off + k) & 3u]);
                }
                w->mask_off = (unsigned)((w->mask_off + chunk) & 3u);

                if (w->is_control) {
                    if (w->ctrl_len + chunk > WS_CTRL_MAX) {
                        sodium_memzero(tmp, sizeof tmp);
                        return WS_ERR_PROTOCOL;
                    }
                    memcpy(w->ctrl + w->ctrl_len, tmp, chunk);
                    w->ctrl_len += chunk;
                } else if (sink(ctx, tmp, chunk) != 0) {
                    sodium_memzero(tmp, sizeof tmp);
                    return WS_ERR_PROTOCOL;       /* the caller's bound, e.g. AUTHD_FRAME_MAX */
                }
                done += chunk;
            }
            sodium_memzero(tmp, sizeof tmp);

            i += take;
            w->payload_left -= (uint64_t)take;
            if (w->payload_left != 0u) {
                return WS_NEED_MORE;
            }
        }

    frame_done:
        if (w->is_control) {
            if (w->opcode == WS_OP_PING) {
                queue_ctrl(w, WS_OP_PONG, w->ctrl, w->ctrl_len);
            } else if (w->opcode == WS_OP_CLOSE) {
                /* Echo the code if one was given, then stop reading. */
                queue_ctrl(w, WS_OP_CLOSE, w->ctrl, (w->ctrl_len >= 2u) ? 2u : 0u);
                w->stage = WS_STAGE_CLOSED;
                w->hdr_len = 0u; w->hdr_need = 0u;
                return WS_OK;
            }
            /* PONG is accepted and ignored: nothing here ever pings. */
        }
        w->hdr_len = 0u;
        w->hdr_need = 0u;
        w->ctrl_len = 0u;
    }
    return WS_NEED_MORE;
}

/* --------------------------------------------------------------- client */

int ws_client_request(char *out, size_t cap, size_t *out_len,
                      const char *path, const char *state,
                      const uint8_t nonce[16], char expect[WS_ACCEPT_B64_LEN + 1u])
{
    if (out == NULL || out_len == NULL || path == NULL || nonce == NULL || expect == NULL) {
        return -1;
    }
    char key[WS_KEY_B64_LEN + 1u];
    (void)sodium_bin2base64(key, sizeof key, nonce, 16u, sodium_base64_VARIANT_ORIGINAL);
    if (ws_accept_key(key, WS_KEY_B64_LEN, expect) != 0) {
        return -1;
    }
    const int n = snprintf(out, cap,
                           "GET %s%s%s HTTP/1.1\r\n"
                           "Host: authd\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Key: %s\r\n"
                           "Sec-WebSocket-Version: 13\r\n\r\n",
                           path,
                           (state != NULL && state[0] != '\0') ? "?state=" : "",
                           (state != NULL && state[0] != '\0') ? state : "",
                           key);
    sodium_memzero(key, sizeof key);
    if (n <= 0 || (size_t)n >= cap) {
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

int ws_client_check_101(const uint8_t *resp, size_t len, const char *expect)
{
    if (resp == NULL || expect == NULL || len < 12u) {
        return -1;
    }
    if (memcmp(resp, "HTTP/1.1 101", 12) != 0) {
        return -1;
    }
    /* The accept value is the point of the handshake: without checking it a
     * client would complete an "upgrade" with something that never read its
     * key (RFC 6455 §1.3). */
    const size_t elen = strlen(expect);
    for (size_t i = 0; i + elen <= len; i++) {
        if (memcmp(resp + i, expect, elen) == 0) {
            return 0;
        }
    }
    return -1;
}

size_t ws_client_frame(uint8_t *out, size_t cap, const uint8_t *payload, size_t n,
                       const uint8_t mask[4])
{
    if (out == NULL || payload == NULL || mask == NULL) {
        return 0u;
    }
    uint8_t h[WS_SRV_HDR_MAX];
    const size_t hl = ws_server_header(h, (uint64_t)n, WS_OP_BINARY);
    if (hl + 4u + n > cap) {
        return 0u;
    }
    memcpy(out, h, hl);
    out[1] = (uint8_t)(out[1] | 0x80u);        /* MASK */
    memcpy(out + hl, mask, 4u);
    for (size_t i = 0; i < n; i++) {
        out[hl + 4u + i] = (uint8_t)(payload[i] ^ mask[i & 3u]);
    }
    return hl + 4u + n;
}

ws_client_status_t ws_client_read_message(ws_read_fn rd, void *ctx,
                                          uint8_t *out, size_t cap, size_t *out_len)
{
    if (rd == NULL || out == NULL || out_len == NULL) {
        return WS_CLIENT_PROTOCOL;
    }
    *out_len = 0u;
    for (;;) {
        uint8_t h[8];
        const int first = rd(ctx, h, 2u);
        if (first > 0)  { return WS_CLIENT_CLOSED; }     /* clean EOF at a boundary */
        if (first < 0)  { return WS_CLIENT_IO; }

        if ((h[0] & 0x70u) != 0u) { return WS_CLIENT_PROTOCOL; }   /* RSV: no extensions */
        if ((h[1] & 0x80u) != 0u) { return WS_CLIENT_PROTOCOL; }   /* §5.1: server frames are UNMASKED */

        /* Captured BEFORE the extended-length read, which reuses `h`. Reading
         * the opcode out of the length bytes is a real bug, not a
         * hypothetical: it cost a debugging pass on the 4545-byte ServerHello,
         * the first message long enough to need a 16-bit length. */
        const uint8_t b0 = h[0];

        uint64_t len = (uint64_t)(h[1] & 0x7fu);
        if (len == 126u) {
            if (rd(ctx, h, 2u) != 0) { return WS_CLIENT_IO; }
            len = ((uint64_t)h[0] << 8) | h[1];
        } else if (len == 127u) {
            if (rd(ctx, h, 8u) != 0) { return WS_CLIENT_IO; }
            len = 0u;
            for (unsigned i = 0; i < 8u; i++) { len = (len << 8) | h[i]; }
            if ((len >> 63) != 0u) { return WS_CLIENT_PROTOCOL; }
        }

        const uint8_t op = (uint8_t)(b0 & 0x0fu);
        if (op == WS_OP_CLOSE) { return WS_CLIENT_CLOSED; }
        if (op == WS_OP_PING || op == WS_OP_PONG) {
            uint8_t drain[WS_CTRL_MAX];
            if (len > sizeof drain) { return WS_CLIENT_PROTOCOL; }
            if (len > 0u && rd(ctx, drain, (size_t)len) != 0) { return WS_CLIENT_IO; }
            continue;                        /* control frames carry no protocol bytes */
        }
        if (op != WS_OP_BINARY || (b0 & 0x80u) == 0u) {
            return WS_CLIENT_PROTOCOL;       /* text, a continuation, or a fragment */
        }
        if (len > (uint64_t)cap) { return WS_CLIENT_PROTOCOL; }
        if (len > 0u && rd(ctx, out, (size_t)len) != 0) { return WS_CLIENT_IO; }
        *out_len = (size_t)len;
        return WS_CLIENT_OK;
    }
}
