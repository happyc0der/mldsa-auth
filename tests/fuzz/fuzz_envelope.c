/* V4-6: the MLDSAEK1 header parser (apps/authd/keyfile.c:keyfile_parse_header).
 *
 * This is the first envelope code to touch an attacker-influenced file, so it
 * is fuzzed -- but only the parse, which stops BEFORE the KDF. Fuzzing the
 * whole open would let an in-bounds memlimit of up to 1 GiB burn a gigabyte
 * per input; the KDF/AEAD/image path is covered by test_authd_keyfile at low
 * parameters instead.
 *
 * The oracle is an INDEPENDENT re-implementation of the header rules from the
 * spec (mldsa-authd 12): the harness predicts FORMAT / PARAMS / OK from the
 * bytes alone and requires keyfile_parse_header to agree exactly. */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "keyfile.h"
#include "demo_keys.h"
#include <sodium.h>

const char *const fuzz_target_name = "envelope";
const size_t fuzz_target_max_len = 8192;

int fuzz_target_command(int argc, char **argv) {
    (void)argc; (void)argv;
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    fuzz_common_init();
    return 0;
}

/* Field offsets, restated here so the oracle is independent of keyfile.c. */
enum { O_MAGIC = 0, O_VER = 8, O_KDF = 9, O_OPS = 10, O_MEM = 14,
       O_SALT = 22, O_AEAD = 38, O_NONCE = 39, O_CTLEN = 63, HDR = 67 };

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) { v = (v << 8) | p[i]; } return v;
}

/* The independent model: what keyfile_parse_header MUST return for `total`
 * bytes. Mirrors the spec, not the code. */
static keyfile_status_t model(const uint8_t *b, size_t total) {
    const size_t max_ct = demo_keys_sk2_image_len(64) + 16u; /* +ABYTES */
    if (total <= (size_t)HDR || total > (size_t)HDR + max_ct) { return KEYFILE_ERR_FORMAT; }
    if (memcmp(b + O_MAGIC, "MLDSAEK1", 8) != 0) { return KEYFILE_ERR_FORMAT; }
    if (b[O_VER] != 0x01u || b[O_KDF] != 0x01u || b[O_AEAD] != 0x01u) { return KEYFILE_ERR_FORMAT; }
    const uint32_t ct = be32(b + O_CTLEN);
    if ((size_t)ct != total - (size_t)HDR || ct <= 16u) { return KEYFILE_ERR_FORMAT; }
    const uint32_t ops = be32(b + O_OPS);
    const uint64_t mem = be64(b + O_MEM);
    if (ops < 1u || ops > 10u || mem < (8u * 1024u * 1024u) || mem > (1024u * 1024u * 1024u)) {
        return KEYFILE_ERR_PARAMS;
    }
    return KEYFILE_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) { return 0; }
    const uint8_t *in = fuzz_ptr(data, size);
    keyfile_header_t hdr;
    const keyfile_status_t got = keyfile_parse_header(in, size, &hdr);
    const keyfile_status_t want = model(in, size);
    FUZZ_ASSERT(got == want, "keyfile_parse_header disagrees with the independent model");
    /* On OK the reported lengths are consistent with the input. */
    if (got == KEYFILE_OK) {
        FUZZ_ASSERT((size_t)hdr.ct_len == size - (size_t)HDR &&
                        hdr.img_len == hdr.ct_len - 16u,
                    "parsed lengths inconsistent with the input size");
    }
    return 0;
}

/* Seeds: a valid header (for a minimal in-bounds image), and the structural
 * boundaries -- bad magic/version/alg, ct_len off by one, params at and just
 * past each bound. */
static void emit_hdr(fuzz_emit_fn emit, void *ctx, const char *name,
                     uint8_t ver, uint8_t kdf, uint8_t aead,
                     uint32_t ops, uint64_t mem, uint32_t ct, size_t total) {
    static uint8_t buf[8192];
    if (total > sizeof(buf)) { return; }
    memset(buf, 0, total);
    memcpy(buf + O_MAGIC, "MLDSAEK1", 8);
    buf[O_VER] = ver; buf[O_KDF] = kdf; buf[O_AEAD] = aead;
    for (int i = 0; i < 4; i++) { buf[O_OPS + i] = (uint8_t)(ops >> (24 - 8 * i)); }
    for (int i = 0; i < 8; i++) { buf[O_MEM + i] = (uint8_t)(mem >> (56 - 8 * i)); }
    for (int i = 0; i < 4; i++) { buf[O_CTLEN + i] = (uint8_t)(ct >> (24 - 8 * i)); }
    emit(ctx, name, buf, total);
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    const uint32_t img = 6026u;                 /* SK2 image for a 1-byte id */
    const uint32_t ct = img + 16u;
    const size_t total = HDR + ct;
    const uint64_t MEM = 8u * 1024u * 1024u;
    emit(ctx, "empty", fuzz_empty, 0);
    emit_hdr(emit, ctx, "valid",          0x01, 0x01, 0x01, 1u, MEM, ct, total);
    emit_hdr(emit, ctx, "bad-version",    0x02, 0x01, 0x01, 1u, MEM, ct, total);
    emit_hdr(emit, ctx, "bad-kdf",        0x01, 0x02, 0x01, 1u, MEM, ct, total);
    emit_hdr(emit, ctx, "bad-aead",       0x01, 0x01, 0x02, 1u, MEM, ct, total);
    emit_hdr(emit, ctx, "ops-0",          0x01, 0x01, 0x01, 0u, MEM, ct, total);
    emit_hdr(emit, ctx, "ops-11",         0x01, 0x01, 0x01, 11u, MEM, ct, total);
    emit_hdr(emit, ctx, "ops-10",         0x01, 0x01, 0x01, 10u, MEM, ct, total);
    emit_hdr(emit, ctx, "mem-under",      0x01, 0x01, 0x01, 1u, MEM - 1u, ct, total);
    emit_hdr(emit, ctx, "mem-over",       0x01, 0x01, 0x01, 1u, (1024u*1024u*1024u) + 1u, ct, total);
    emit_hdr(emit, ctx, "ctlen-off",      0x01, 0x01, 0x01, 1u, MEM, ct + 1u, total);
    emit_hdr(emit, ctx, "ctlen-tiny",     0x01, 0x01, 0x01, 1u, MEM, 16u, HDR + 16u);
    /* header only, and one byte over the header */
    { static uint8_t h[HDR + 1]; memset(h, 0, sizeof(h)); memcpy(h, "MLDSAEK1", 8);
      emit(ctx, "header-only", h, HDR); emit(ctx, "header-plus-1", h, HDR + 1u); }
}
