/*
 * F1 fuzz_wire -- Step 3 wire decoders and transcript helpers (spec 6.3.1-6.3.4).
 *
 * Input: the whole input is one candidate wire message (no selector split),
 * fed to all three decoders. For the transcript helpers it is split at
 * k = fuzz_selector(data, size, 0) % (size + 1) into ch = input[0..k) and
 * sh = input[k..size).
 *
 * Oracles: at most one decoder accepts, only for its own type byte, with
 * full consumption and a canonical round trip (encode(decode(x)) == x); the
 * ServerHello unsigned-prefix length agrees with the decoded structure; and
 * each transcript helper equals a digest built INDEPENDENTLY here with raw
 * crypto_hash_sha256 updates and literal label bytes, deterministically.
 * There is deliberately NO pairwise digest-inequality assertion: equal
 * SHA-256 outputs would be a hash collision, not a functional bug.
 */

#include "fuzz_common.h"

#include <sodium.h>

#include <string.h>

const char *const fuzz_target_name = "wire";
const size_t fuzz_target_max_len = 4096;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fuzz_common_init();
    return 0;
}

int fuzz_target_command(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return -1;
}

/* SHA-256(label || 0x00 || a || b), built without the code under test. */
static void expected_digest(uint8_t out[32], const char *label, const uint8_t *a, size_t an, const uint8_t *b,
                            size_t bn) {
    static const uint8_t sep = 0x00;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)label, strlen(label));
    crypto_hash_sha256_update(&st, &sep, 1);
    crypto_hash_sha256_update(&st, a, an);
    crypto_hash_sha256_update(&st, b, bn);
    crypto_hash_sha256_final(&st, out);
}

static size_t expected_unsigned_len(uint8_t id_len) {
    return (id_len >= 1u && id_len <= 64u) ? (size_t)(1u + 1u + id_len + 32u + 32u + 16u) : 0u;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static uint8_t re[4096];
    if (size > fuzz_target_max_len) {
        return 0;
    }
    const uint8_t *in = fuzz_ptr(data, size);
    const uint8_t first = fuzz_selector(data, size, 0);

    /* ---- decoders ---- */
    client_hello_t ch;
    server_hello_t sh;
    client_auth_t ca;
    size_t c1 = 0;
    size_t c2 = 0;
    size_t c3 = 0;
    const int ok1 = decode_client_hello(in, size, &ch, &c1) == 0;
    const int ok2 = decode_server_hello(in, size, &sh, &c2) == 0;
    const int ok3 = decode_client_auth(in, size, &ca, &c3) == 0;
    FUZZ_ASSERT(ok1 + ok2 + ok3 <= 1, "at most one decoder accepts any input");
    FUZZ_ASSERT(size != 0 || (!ok1 && !ok2 && !ok3), "the empty input is never a message");

    size_t rl = 0;
    if (ok1) {
        FUZZ_ASSERT(first == MSG_TYPE_CLIENT_HELLO, "ClientHello decoder accepted a foreign type byte");
        FUZZ_ASSERT(c1 == size, "ClientHello decode must consume the whole buffer");
        FUZZ_ASSERT(encode_client_hello(&ch, re, sizeof(re), &rl) == 0 && rl == size && memcmp(re, in, size) == 0,
                    "ClientHello must round-trip canonically");
    }
    if (ok2) {
        FUZZ_ASSERT(first == MSG_TYPE_SERVER_HELLO, "ServerHello decoder accepted a foreign type byte");
        FUZZ_ASSERT(c2 == size, "ServerHello decode must consume the whole buffer");
        FUZZ_ASSERT(encode_server_hello(&sh, re, sizeof(re), &rl) == 0 && rl == size && memcmp(re, in, size) == 0,
                    "ServerHello must round-trip canonically");
        const size_t u = transcript_server_hello_unsigned_len(sh.id_len);
        FUZZ_ASSERT(u == size - 2u - sh.sig_len, "unsigned prefix length must match the decoded structure");
        FUZZ_ASSERT(encode_server_hello_unsigned(&sh, re, sizeof(re), &rl) == 0 && rl == u && memcmp(re, in, u) == 0,
                    "ServerHello_unsigned must be exactly the input prefix");
    }
    if (ok3) {
        FUZZ_ASSERT(first == MSG_TYPE_CLIENT_AUTH, "ClientAuth decoder accepted a foreign type byte");
        FUZZ_ASSERT(c3 == size, "ClientAuth decode must consume the whole buffer");
        FUZZ_ASSERT(encode_client_auth(&ca, re, sizeof(re), &rl) == 0 && rl == size && memcmp(re, in, size) == 0,
                    "ClientAuth must round-trip canonically");
    }
    FUZZ_ASSERT(transcript_server_hello_unsigned_len(first) == expected_unsigned_len(first),
                "transcript_server_hello_unsigned_len boundary behavior");

    /* ---- transcript helpers ---- */
    const size_t k = (size == 0) ? 0 : (size_t)first % (size + 1u);
    const uint8_t *chp = (k != 0) ? in : fuzz_empty;
    const size_t chn = k;
    const uint8_t *shp = (size - k != 0) ? in + k : fuzz_empty;
    const size_t shn = size - k;

    /* sh_unsigned: the validated prefix if sh is a strict ServerHello,
     * otherwise the raw bytes (the helper hashes any byte string). */
    size_t u = shn;
    server_hello_t sh2;
    size_t c4 = 0;
    if (decode_server_hello(shp, shn, &sh2, &c4) == 0) {
        u = transcript_server_hello_unsigned_len(sh2.id_len);
    }
    const uint8_t *shup = (u != 0) ? shp : fuzz_empty;

    uint8_t got1[32], got1b[32], want1[32];
    uint8_t got2[32], got2b[32], want2[32];
    uint8_t got3[16], got3b[16], want3[32];
    FUZZ_ASSERT(transcript_hash_server_auth(chp, chn, shup, u, got1) == 0 &&
                    transcript_hash_server_auth(chp, chn, shup, u, got1b) == 0,
                "transcript_hash_server_auth must accept any byte strings");
    FUZZ_ASSERT(transcript_hash_client_auth(chp, chn, shp, shn, got2) == 0 &&
                    transcript_hash_client_auth(chp, chn, shp, shn, got2b) == 0,
                "transcript_hash_client_auth must accept any byte strings");
    FUZZ_ASSERT(transcript_handshake_id(chp, chn, shp, shn, got3) == 0 &&
                    transcript_handshake_id(chp, chn, shp, shn, got3b) == 0,
                "transcript_handshake_id must accept any byte strings");

    expected_digest(want1, "mldsa-auth/v1/server-auth", chp, chn, shup, u);
    expected_digest(want2, "mldsa-auth/v1/client-auth", chp, chn, shp, shn);
    expected_digest(want3, "mldsa-auth/v1/handshake-id", chp, chn, shp, shn);
    FUZZ_ASSERT(memcmp(got1, want1, 32) == 0, "server-auth digest != independently built expected value");
    FUZZ_ASSERT(memcmp(got2, want2, 32) == 0, "client-auth digest != independently built expected value");
    FUZZ_ASSERT(memcmp(got3, want3, 16) == 0, "handshake_id != first 16 bytes of the expected digest");
    FUZZ_ASSERT(memcmp(got1, got1b, 32) == 0 && memcmp(got2, got2b, 32) == 0 && memcmp(got3, got3b, 16) == 0,
                "transcript helpers must be deterministic");
    return 0;
}

/* ---- seeds ------------------------------------------------------------------ */

static void emit_with_id(fuzz_emit_fn emit, void *ctx, const char *name, int server, uint8_t id_len) {
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    uint8_t buf[4096];
    size_t n = 0;
    size_t used = 0;
    if (!server) {
        client_hello_t m;
        if (decode_client_hello(g->ch, g->ch_len, &m, &used) != 0) {
            return;
        }
        memset(m.id, 'x', sizeof(m.id));
        m.id_len = id_len;
        if (encode_client_hello(&m, buf, sizeof(buf), &n) == 0) {
            emit(ctx, name, buf, n);
        }
    } else {
        server_hello_t m;
        if (decode_server_hello(g->sh, g->sh_len, &m, &used) != 0) {
            return;
        }
        memset(m.id, 'y', sizeof(m.id));
        m.id_len = id_len;
        if (encode_server_hello(&m, buf, sizeof(buf), &n) == 0) {
            emit(ctx, name, buf, n);
        }
    }
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    const fuzz_transcript_t *g = fuzz_genuine_transcript();
    uint8_t buf[4096];
    emit(ctx, "empty", fuzz_empty, 0);
    emit(ctx, "client-hello", g->ch, g->ch_len);
    emit(ctx, "server-hello", g->sh, g->sh_len);
    emit(ctx, "client-auth", g->ca, g->ca_len);
    emit_with_id(emit, ctx, "client-hello-id1", 0, 1);
    emit_with_id(emit, ctx, "client-hello-id64", 0, 64);
    emit_with_id(emit, ctx, "server-hello-id1", 1, 1);
    emit_with_id(emit, ctx, "server-hello-id64", 1, 64);

    const struct {
        const char *name;
        const uint8_t *m;
        size_t n;
    } msgs[] = {{"client-hello", g->ch, g->ch_len}, {"server-hello", g->sh, g->sh_len}, {"client-auth", g->ca, g->ca_len}};
    for (size_t i = 0; i < 3; i++) {
        char name[64];
        snprintf(name, sizeof(name), "%s-truncated", msgs[i].name);
        emit(ctx, name, msgs[i].m, msgs[i].n - 1u);
        memcpy(buf, msgs[i].m, msgs[i].n);
        buf[msgs[i].n] = 0x00;
        snprintf(name, sizeof(name), "%s-trailing", msgs[i].name);
        emit(ctx, name, buf, msgs[i].n + 1u);
    }

    /* ServerHello declaring a 3310-byte signature (one over the bound). */
    const size_t u = transcript_server_hello_unsigned_len((uint8_t)FUZZ_ID_B_LEN);
    memcpy(buf, g->sh, g->sh_len);
    buf[u] = 0x0c;
    buf[u + 1u] = 0xee;
    buf[g->sh_len] = 0x5a;
    emit(ctx, "server-hello-sig3310", buf, g->sh_len + 1u);

    /* sig_len = 0 (one under the bound), with nothing after it. */
    memcpy(buf, g->sh, u);
    buf[u] = 0x00;
    buf[u + 1u] = 0x00;
    emit(ctx, "server-hello-sig0", buf, u + 2u);
    memcpy(buf, g->ca, 1u + WIRE_HANDSHAKE_ID_LEN);
    buf[1u + WIRE_HANDSHAKE_ID_LEN] = 0x00;
    buf[2u + WIRE_HANDSHAKE_ID_LEN] = 0x00;
    emit(ctx, "client-auth-sig0", buf, 3u + WIRE_HANDSHAKE_ID_LEN);
}
