/* V4-10a: the WebSocket carrier as the daemon actually runs it.
 *
 * This drives conn_io in CONN_IO_MODE_WS, which is the whole attacker-facing
 * surface in one place: the HTTP upgrade parser (the first TEXT parser in this
 * tree, and the first with case-insensitive matching), the RFC 6455 frame
 * decoder, the unmasking, and the 4-byte frame reassembler the payload feeds.
 * Fuzzing ws.c alone would miss the seam where those meet, and the seam is
 * where the buffer accounting lives.
 *
 * THE ORACLE IS SELF-CONSISTENCY, which is worth more here than a second
 * decoder would be:
 *
 *   1. CHUNKING IS IRRELEVANT. Spec §7.1 says "message boundaries on input are
 *      irrelevant" -- so feeding the input in one push and feeding it one byte
 *      at a time must produce the SAME frames, in the same order, and the same
 *      terminal verdict. That is a real property of the state machine and no
 *      amount of arithmetic luck satisfies it by accident. A decoder that
 *      keeps state in a local, or that mis-resumes a split header or a split
 *      mask, fails this and nothing else.
 *   2. FAILURE IS STICKY. Once poisoned, every later push fails too: a peer
 *      does not get to follow a bad frame with a good one.
 *   3. NO AMPLIFICATION. The de-framed bytes handed upward never exceed the
 *      bytes pushed in -- masking and header stripping only ever remove.
 *   4. EVERY FRAME IS BOUNDED by AUTHD_FRAME_MAX, which is what the fixed
 *      per-slot buffers are sized from.
 *   5. DETERMINISTIC, and the input is not modified.
 *
 * V4-10b adds the PROXY v2 preamble to the same conn_io path, and this target
 * runs EVERY input through both configurations -- preamble expected and not --
 * rather than spending a selector byte on it. A selector would have changed
 * what every existing corpus entry means; running both keeps the corpus valid
 * and doubles what each input tests. The preamble's own split-resumption is
 * then covered by property (1), which is precisely the property that found
 * F50's HTTP twin.
 *
 * What this does NOT cover, so nobody concludes otherwise: the login itself.
 * Reaching a handshake needs valid ML-DSA signatures that random bytes will
 * never produce. test_authd_ws pins the login over this carrier, and the v50a
 * campaign kills the properties there.
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "conn_io.h"
#include "ws.h"

const char *const fuzz_target_name = "ws";
const size_t fuzz_target_max_len = 16384;

int fuzz_target_command(int argc, char **argv) { (void)argc; (void)argv; return -1; }

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_common_init();
    return 0;
}

/* Everything one run observes: the frames handed upward, and how it ended. */
typedef struct {
    uint8_t  frames[32768];
    size_t   total;
    size_t   count;
    int      failed;
    int      truncated;      /* the record buffer filled: stop comparing */
} run_t;

static void drain(conn_io_t *io, run_t *r)
{
    for (;;) {
        const uint8_t *p = NULL;
        size_t n = 0;
        if (!conn_io_next_frame(io, &p, &n)) { break; }
        FUZZ_ASSERT(n >= 1u && n <= (size_t)AUTHD_FRAME_MAX,
                    "a de-framed WebSocket payload is outside AUTHD_FRAME_MAX");
        if (r->total + n <= sizeof r->frames) {
            memcpy(r->frames + r->total, p, n);
            r->total += n;
            r->count++;
        } else {
            r->truncated = 1;
        }
        conn_io_consume_frame(io);
    }
}

/* `chunk` of 0 means one push; otherwise push in `chunk`-sized pieces.
 * `proxy` makes the connection expect a PROXY v2 preamble first (spec §7.2). */
static void run(const uint8_t *data, size_t size, size_t chunk, int proxy, run_t *r)
{
    static conn_io_t io;                       /* ~12 KB: static, not stack */
    memset(r, 0, sizeof *r);
    conn_io_reset(&io);
    conn_io_set_mode(&io, CONN_IO_MODE_WS);
    conn_io_set_proxy(&io, proxy);

    /* NOTHING is drained between pushes, and that is deliberate. Draining
     * frees buffer space, so a consumer that drains after every byte survives
     * a stream that one big push cannot -- which made the two runs diverge on
     * CAPACITY rather than on de-framing, and made the oracle below a false
     * alarm. Accumulating identically in both runs removes the asymmetry, and
     * lets the comparison be exact instead of "a common prefix" -- a weaker
     * form that this target proved was too weak to catch a mask offset that
     * failed to carry across a split payload. */
    size_t off = 0;
    while (off < size) {
        size_t take = (chunk == 0u) ? (size - off) : chunk;
        if (take > size - off) { take = size - off; }
        if (conn_io_push(&io, data + off, take) != CONN_IO_OK) {
            r->failed = 1;
            break;
        }
        off += take;
    }
    if (!r->failed) {
        drain(&io, r);
        /* The preamble either settled or it did not, and either way the
         * address it established must agree with that: a family set on a
         * connection whose preamble never completed would be an address
         * invented out of a partial read. */
        if (proxy && !conn_io_proxy_settled(&io)) {
            FUZZ_ASSERT(conn_io_client_addr(&io)->family == 0u,
                        "a client address appeared before the PROXY preamble completed");
        }
    } else {
        /* (2) sticky: once poisoned, nothing is ever accepted again. */
        const uint8_t probe[1] = { 0x00u };
        FUZZ_ASSERT(conn_io_push(&io, probe, 1u) != CONN_IO_OK,
                    "a poisoned WebSocket connection accepted a later push");
    }
    conn_io_reset(&io);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > fuzz_target_max_len) { return 0; }

    static uint8_t copy[16384];
    memcpy(copy, data, size);

    static run_t whole, split, again;
    run(data, size, 0u, 0, &whole);
    run(data, size, 0u, 0, &again);
    run(data, size, 1u, 0, &split);

    /* (5) deterministic, and the input is untouched. */
    FUZZ_ASSERT(memcmp(copy, data, size) == 0, "the WebSocket decoder modified its input");
    FUZZ_ASSERT(whole.failed == again.failed && whole.total == again.total &&
                whole.count == again.count &&
                memcmp(whole.frames, again.frames, whole.total) == 0,
                "the WebSocket decoder is not deterministic");

    /* (1) the property spec §7.1 claims, stated as strongly as it is TRUE.
     *
     * Not "the two runs are identical": the consumer drains between pushes, so
     * byte-at-a-time frees buffer space that one big push does not, and a
     * stream long enough to hit AUTHD_FRAME_MAX legitimately fails in one and
     * survives in the other. That is capacity, not de-framing. Asserting
     * equality there was wrong and this target said so on its second run --
     * an oracle stating more than it can justify is a false alarm waiting to
     * happen, and the fix is to state the real property, not to delete it.
     *
     * The real property is PREFIX CONSISTENCY: up to wherever either run
     * stopped, both produced the same bytes in the same order. A decoder that
     * mis-resumes a split header, a split length or a split mask breaks this
     * immediately; capacity cannot. */
    if (!whole.truncated && !split.truncated) {
        FUZZ_ASSERT(whole.failed == split.failed,
                    "chunking changed the VERDICT: one push and byte-at-a-time disagree");
        FUZZ_ASSERT(whole.count == split.count && whole.total == split.total,
                    "chunking changed how many frames came out");
        FUZZ_ASSERT(memcmp(whole.frames, split.frames, whole.total) == 0,
                    "chunking changed the BYTES that came out");
    }

    /* (3) de-framing only ever removes. */
    FUZZ_ASSERT(whole.total <= size, "more bytes came out of the WebSocket layer than went in");

    /* The same input again, this time through a connection that expects a
     * PROXY v2 preamble. Every property above is asserted again -- the
     * preamble is part of the same state machine and splits the same way. */
    static run_t pwhole, psplit, pagain;
    run(data, size, 0u, 1, &pwhole);
    run(data, size, 0u, 1, &pagain);
    run(data, size, 1u, 1, &psplit);

    FUZZ_ASSERT(memcmp(copy, data, size) == 0, "the PROXY+WebSocket decoder modified its input");
    FUZZ_ASSERT(pwhole.failed == pagain.failed && pwhole.total == pagain.total &&
                pwhole.count == pagain.count &&
                memcmp(pwhole.frames, pagain.frames, pwhole.total) == 0,
                "the PROXY+WebSocket decoder is not deterministic");
    if (!pwhole.truncated && !psplit.truncated) {
        FUZZ_ASSERT(pwhole.failed == psplit.failed,
                    "chunking changed the VERDICT behind a PROXY preamble");
        FUZZ_ASSERT(pwhole.count == psplit.count && pwhole.total == psplit.total,
                    "chunking changed how many frames came out behind a PROXY preamble");
        FUZZ_ASSERT(memcmp(pwhole.frames, psplit.frames, pwhole.total) == 0,
                    "chunking changed the BYTES that came out behind a PROXY preamble");
    }
    FUZZ_ASSERT(pwhole.total <= size, "more bytes came out of the PROXY+WebSocket layer than went in");
    return 0;
}

/* A valid upgrade, so the fuzzer starts from the far side of the handshake
 * rather than having to synthesise base64 and a GUID hash. */
#define UPGRADE \
    "GET /authd/v1?state=ab HTTP/1.1\r\n" \
    "Host: authd\r\n" \
    "Upgrade: websocket\r\n" \
    "Connection: Upgrade\r\n" \
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" \
    "Sec-WebSocket-Version: 13\r\n\r\n"

static size_t put_frame(uint8_t *out, size_t off, uint8_t op, int fin,
                        const uint8_t *pay, size_t n)
{
    static const uint8_t m[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
    out[off++] = (uint8_t)((fin ? 0x80u : 0u) | op);
    if (n < 126u) { out[off++] = (uint8_t)(0x80u | n); }
    else { out[off++] = (uint8_t)(0x80u | 126u); out[off++] = (uint8_t)(n >> 8); out[off++] = (uint8_t)n; }
    memcpy(out + off, m, 4u); off += 4u;
    for (size_t i = 0; i < n; i++) { out[off + i] = (uint8_t)(pay[i] ^ m[i & 3u]); }
    return off + n;
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx)
{
    static uint8_t b[16384];
    const size_t u = strlen(UPGRADE);

    emit(ctx, "empty", fuzz_empty, 0);
    emit(ctx, "upgrade-only", (const uint8_t *)UPGRADE, u);
    emit(ctx, "upgrade-partial", (const uint8_t *)UPGRADE, u - 2u);
    { const char *bad = "GET /a HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
      emit(ctx, "upgrade-missing-key", (const uint8_t *)bad, strlen(bad)); }
    { const char *post = "POST /a HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
      emit(ctx, "upgrade-post", (const uint8_t *)post, strlen(post)); }

    /* One protocol frame (4-byte length + payload) inside one binary message. */
    { uint8_t inner[64] = { 0x00u, 0x00u, 0x00u, 0x08u, 1,2,3,4,5,6,7,8 };
      memcpy(b, UPGRADE, u);
      size_t n = put_frame(b, u, WS_OP_BINARY, 1, inner, 12u);
      emit(ctx, "one-frame", b, n);

      /* the same, fragmented across two WebSocket frames */
      memcpy(b, UPGRADE, u);
      n = put_frame(b, u, WS_OP_BINARY, 0, inner, 6u);
      n = put_frame(b, n, WS_OP_CONT, 1, inner + 6, 6u);
      emit(ctx, "one-frame-fragmented", b, n);

      /* two back to back, which is what a pipelining peer sends */
      memcpy(b, UPGRADE, u);
      n = put_frame(b, u, WS_OP_BINARY, 1, inner, 12u);
      n = put_frame(b, n, WS_OP_BINARY, 1, inner, 12u);
      emit(ctx, "two-frames", b, n);

      memcpy(b, UPGRADE, u);
      n = put_frame(b, u, WS_OP_PING, 1, (const uint8_t *)"hi", 2u);
      emit(ctx, "ping", b, n);

      memcpy(b, UPGRADE, u);
      n = put_frame(b, u, WS_OP_CLOSE, 1, (const uint8_t *)"\x03\xe8", 2u);
      emit(ctx, "close", b, n);

      memcpy(b, UPGRADE, u);
      n = put_frame(b, u, 0x1u, 1, inner, 12u);
      emit(ctx, "text-opcode", b, n);

      /* an UNMASKED client frame: must fail the connection */
      memcpy(b, UPGRADE, u);
      b[u] = 0x82u; b[u + 1u] = 0x04u; b[u + 2u] = 0x00u; b[u + 3u] = 0x00u;
      b[u + 4u] = 0x00u; b[u + 5u] = 0x00u;
      emit(ctx, "unmasked", b, u + 6u);

      /* a declared length past AUTHD_FRAME_MAX */
      memcpy(b, UPGRADE, u);
      uint8_t big[8] = { 0xffu, 0xffu, 0xffu, 0xffu, 0,0,0,0 };
      n = put_frame(b, u, WS_OP_BINARY, 1, big, 8u);
      emit(ctx, "frame-len-huge", b, n); }

    /* PROXY v2 preambles (V4-10b). These are only meaningful to the half of
     * each run that expects one -- in the other half they are junk the HTTP
     * parser refuses, which is itself worth an input. */
    { static const uint8_t sig[12] = {
          0x0du,0x0au,0x0du,0x0au,0x00u,0x0du,0x0au,0x51u,0x55u,0x49u,0x54u,0x0au };
      static const uint8_t v4[12] = { 203u,0u,113u,7u, 10u,0u,0u,1u, 0x9cu,0x40u,0u,80u };
      uint8_t pre[64];
      memcpy(pre, sig, 12);
      pre[12] = 0x21u; pre[13] = 0x11u; pre[14] = 0u; pre[15] = 12u;
      memcpy(pre + 16, v4, 12);
      const size_t pl = 28u;

      emit(ctx, "proxy-only", pre, pl);
      emit(ctx, "proxy-truncated", pre, pl - 1u);

      memcpy(b, pre, pl);
      memcpy(b + pl, UPGRADE, u);
      emit(ctx, "proxy-upgrade", b, pl + u);

      { uint8_t inner[16] = { 0x00u, 0x00u, 0x00u, 0x08u, 1,2,3,4,5,6,7,8 };
        memcpy(b, pre, pl);
        memcpy(b + pl, UPGRADE, u);
        const size_t n2 = put_frame(b, pl + u, WS_OP_BINARY, 1, inner, 12u);
        emit(ctx, "proxy-upgrade-frame", b, n2); }

      /* LOCAL: well formed, no client address */
      { uint8_t loc[16];
        memcpy(loc, sig, 12);
        loc[12] = 0x20u; loc[13] = 0x00u; loc[14] = 0u; loc[15] = 0u;
        memcpy(b, loc, 16u);
        memcpy(b + 16u, UPGRADE, u);
        emit(ctx, "proxy-local-upgrade", b, 16u + u); }

      /* one signature byte wrong */
      { uint8_t badsig[64];
        memcpy(badsig, pre, pl);
        badsig[3] ^= 0xffu;
        emit(ctx, "proxy-bad-signature", badsig, pl); }

      /* a body of TLVs after the address block */
      { uint8_t tlv[64];
        memcpy(tlv, pre, 16u);
        tlv[15] = (uint8_t)(12u + 16u);
        memcpy(tlv + 16, v4, 12);
        memset(tlv + 28, 0xabu, 16u);
        emit(ctx, "proxy-tlv", tlv, 44u); }

      /* a declared body length far past the ceiling */
      { uint8_t huge[64];
        memcpy(huge, pre, pl);
        huge[14] = 0xffu; huge[15] = 0xffu;
        emit(ctx, "proxy-len-huge", huge, pl); } }
}
