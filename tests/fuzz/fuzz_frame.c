/*
 * F4 fuzz_frame -- the Step 6 frame reader (spec 6.5.1) on a byte stream.
 *
 * Input: selector % 5 picks the reader state's (min, max) bounds; the payload
 * is written into one end of an AF_UNIX socketpair (buffers checked at
 * start-up to hold the largest input), the writer is closed, and
 * frame_recv() is called until it returns anything but FRAME_OK (at most 16
 * frames). No listener, no TCP, no net_listen/net_accept/net_connect: the
 * net_conn_t wrapping the socketpair end is the one white-box fixture step.
 *
 * Oracle: a reference stream parser predicts every status. On
 * FRAME_BAD_LENGTH exactly 4 bytes were consumed (nothing of the payload is
 * read before an out-of-bounds length is rejected); on FRAME_OK the payload
 * matches and exactly 4 + len bytes were consumed; EOF only at a boundary,
 * otherwise TRUNCATED; *payload_len == 0 on every non-OK status.
 */

#include "fuzz_common.h"

#include "frame.h"
#include "net_io.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char *const fuzz_target_name = "frame";
const size_t fuzz_target_max_len = 140000;

#define SOCK_BUF (512 * 1024)

static const struct {
    size_t min;
    size_t max;
} STATES[5] = {
    {1, FRAME_MAX_CLIENT_HELLO},
    {1, FRAME_MAX_SERVER_HELLO},
    {1, FRAME_MAX_CLIENT_AUTH},
    {FRAME_CONFIRM_MIN, FRAME_CONFIRM_MAX},
    {FRAME_MIN_RECORD, FRAME_MAX_RECORD},
};

static uint8_t *g_buf;

int fuzz_target_command(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return -1;
}

static void make_pair(int sv[2]) {
    const int big = SOCK_BUF;
    FUZZ_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    FUZZ_ASSERT(setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big)) == 0 &&
                    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big)) == 0 &&
                    fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0 && fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0,
                "socketpair configuration");
}

/* Writes all n bytes without blocking; the buffers hold the largest input. */
static void write_stream(int fd, const uint8_t *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t w = write(fd, p + off, n - off);
        FUZZ_ASSERT(w > 0, "the socketpair must buffer the whole input");
        off += (size_t)w;
    }
}

static void cleanup(void) {
    free(g_buf);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fuzz_common_init();
    g_buf = malloc(FRAME_BUF_BYTES);
    FUZZ_ASSERT(g_buf != NULL, "buffer");
    (void)atexit(cleanup);
    /* Start-up check: the largest possible input fits without a reader. */
    int sv[2];
    uint8_t *big = calloc(1, fuzz_target_max_len);
    FUZZ_ASSERT(big != NULL, "buffer");
    make_pair(sv);
    write_stream(sv[1], big, fuzz_target_max_len);
    close(sv[0]);
    close(sv[1]);
    free(big);
    return 0;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const unsigned state = fuzz_selector(data, size, 0) % 5u;
    const size_t min = STATES[state].min;
    const size_t max = STATES[state].max;
    const uint8_t *p = NULL;
    size_t n = 0;
    fuzz_payload(data, size, &p, &n);

    int sv[2];
    make_pair(sv);
    write_stream(sv[1], p, n);
    close(sv[1]);

    net_conn_t c;
    net_conn_init(&c);
    c.fd = sv[0];

    size_t off = 0;
    for (int frame = 0; frame < 16; frame++) {
        const uint64_t before = c.stats.bytes_rx;
        size_t plen = 777;
        const frame_status_t st = frame_recv(&c, g_buf, min, max, &plen, net_deadline_in(10000));
        const uint64_t consumed = c.stats.bytes_rx - before;
        const size_t rem = n - off;

        frame_status_t want;
        size_t want_consumed;
        size_t len = 0;
        if (rem == 0) {
            want = FRAME_EOF;
            want_consumed = 0;
        } else if (rem < FRAME_HEADER_BYTES) {
            want = FRAME_TRUNCATED;
            want_consumed = rem;
        } else {
            len = be32(p + off);
            if (len < min || len > max) {
                want = FRAME_BAD_LENGTH;
                want_consumed = FRAME_HEADER_BYTES;
            } else if (rem - FRAME_HEADER_BYTES < len) {
                want = FRAME_TRUNCATED;
                want_consumed = rem;
            } else {
                want = FRAME_OK;
                want_consumed = FRAME_HEADER_BYTES + len;
            }
        }
        FUZZ_ASSERT(st == want, "frame_recv status disagrees with the reference stream parser");
        FUZZ_ASSERT(consumed == want_consumed,
                    "bytes consumed (BAD_LENGTH must consume exactly the 4 header bytes, nothing of the payload)");
        if (st != FRAME_OK) {
            FUZZ_ASSERT(plen == 0, "*payload_len must be 0 on every non-OK status");
            break;
        }
        FUZZ_ASSERT(plen == len && memcmp(g_buf + FRAME_HEADER_BYTES, p + off + FRAME_HEADER_BYTES, len) == 0,
                    "FRAME_OK must deliver exactly the framed payload");
        off += FRAME_HEADER_BYTES + len;
    }
    net_close(&c);
    return 0;
}

/* ---- seeds ------------------------------------------------------------------ */

static void emit_frame(fuzz_emit_fn emit, void *ctx, const char *name, uint8_t state, uint32_t hdr_len,
                       const uint8_t *payload, size_t payload_len) {
    static uint8_t seed[1 + FRAME_BUF_BYTES];
    seed[0] = state;
    frame_put_header(seed + 1, hdr_len);
    if (payload_len != 0) {
        memcpy(seed + 1 + FRAME_HEADER_BYTES, payload, payload_len);
    }
    emit(ctx, name, seed, 1 + FRAME_HEADER_BYTES + payload_len);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    static uint8_t rec[FRAME_MAX_RECORD];
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    memset(rec, 0x04, sizeof(rec));
    emit(ctx, "empty", fuzz_empty, 0);
    emit_frame(emit, ctx, "client-hello", 0, (uint32_t)g->ch_len, g->ch, g->ch_len);
    emit_frame(emit, ctx, "server-hello", 1, (uint32_t)g->sh_len, g->sh, g->sh_len);
    emit_frame(emit, ctx, "client-auth", 2, (uint32_t)g->ca_len, g->ca, g->ca_len);
    emit_frame(emit, ctx, "confirmation", 3, FRAME_CONFIRM_MIN, rec, FRAME_CONFIRM_MIN);
    emit_frame(emit, ctx, "confirmation-padded", 3, FRAME_CONFIRM_MAX, rec, FRAME_CONFIRM_MAX);
    emit_frame(emit, ctx, "record", 4, 100, rec, 100);
    emit_frame(emit, ctx, "record-max", 4, FRAME_MAX_RECORD, rec, FRAME_MAX_RECORD);
    emit_frame(emit, ctx, "header-only", 1, (uint32_t)g->sh_len, NULL, 0);
    emit_frame(emit, ctx, "length-0", 0, 0, NULL, 0);
    emit_frame(emit, ctx, "ch-147", 0, FRAME_MAX_CLIENT_HELLO + 1u, rec, 8);
    emit_frame(emit, ctx, "sh-3458", 1, FRAME_MAX_SERVER_HELLO + 1u, rec, 8);
    emit_frame(emit, ctx, "ca-3329", 2, FRAME_MAX_CLIENT_AUTH + 1u, rec, 8);
    emit_frame(emit, ctx, "confirm-26", 3, FRAME_CONFIRM_MIN - 1u, rec, 26);
    emit_frame(emit, ctx, "confirm-4122", 3, FRAME_CONFIRM_MAX + 1u, rec, 32);
    emit_frame(emit, ctx, "record-65562", 4, FRAME_MAX_RECORD + 1u, rec, 8);
    emit_frame(emit, ctx, "length-ffffffff", 4, 0xFFFFFFFFu, rec, 8);

    /* Two back-to-back frames, and a 3-byte partial header. */
    static uint8_t two[1 + 2 * (FRAME_HEADER_BYTES + 30)];
    size_t k = 0;
    two[k++] = 4;
    for (int i = 0; i < 2; i++) {
        frame_put_header(two + k, 30);
        k += FRAME_HEADER_BYTES;
        memset(two + k, 0x04, 30);
        k += 30;
    }
    emit(ctx, "two-frames", two, k);
    const uint8_t partial[4] = {0, 0, 0, 1};
    emit(ctx, "partial-header", partial, sizeof(partial));
}
