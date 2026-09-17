/* V4-9c: the daemon's application-message decoders (apps/authd/authmsg.c).
 *
 * ROTATE is the first message in this protocol with a VARIABLE-length body and
 * two attacker-declared length fields, and it is the largest thing a peer can
 * send -- 8642 bytes at the maximum handle. Every other message here has one
 * exact length, so this is the decoder where "the declared length is believed
 * one field too far" becomes possible for the first time.
 *
 * WHAT THIS DOES NOT COVER, said plainly so a future reader does not conclude
 * rotation is fuzz-covered: this fuzzes the DECODER, not the acceptance path.
 * Everything interesting in spec 6.3 -- the digest binding, the pinned old key,
 * one-rotation-per-session, the store's transaction -- needs two valid ML-DSA
 * signatures over a session-specific handshake_id, which random bytes will
 * never produce. Those properties are pinned by test_authd_conn, and the
 * mutation campaign kills each of them there.
 *
 * THE ORACLE IS THE DECODER'S CONTRACT, not a second decoder:
 *
 *   on OK   -- every borrowed pointer lies inside the input, the fields
 *              reconstruct the input EXACTLY (re-encoding returns the same
 *              bytes), and every declared bound holds;
 *   on FAIL -- nothing is handed back: the struct is all-zero, so no partial
 *              parse escapes to a caller that only checked for OK;
 *   always  -- deterministic, and the input is not modified.
 *
 * Re-encoding is what makes "the pointers are right" more than an assertion
 * about arithmetic: if the decoder mis-splits the two signatures, the bytes
 * coming back differ even though every pointer is still in range.
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "authmsg.h"
#include "mldsa_wrap.h"
#include "store.h"

const char *const fuzz_target_name = "authmsg";
const size_t fuzz_target_max_len = 9216;      /* AUTHD_MAX_CONTENT */

int fuzz_target_command(int argc, char **argv) {
    (void)argc; (void)argv;
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    fuzz_common_init();
    return 0;
}

static int all_zero(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++) { if (b[i] != 0u) { return 0; } }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) { return 0; }
    const uint8_t *in = fuzz_ptr(data, size);

    /* ---- ROTATE ---- */
    authmsg_rotate_t r;
    const authmsg_status_t rs = authmsg_decode_rotate(in, size, &r);
    {
        authmsg_rotate_t r2;
        const authmsg_status_t rs2 = authmsg_decode_rotate(in, size, &r2);
        FUZZ_ASSERT(rs2 == rs && memcmp(&r, &r2, sizeof r) == 0,
                    "authmsg_decode_rotate is not deterministic");
    }
    if (rs == AUTHMSG_OK) {
        FUZZ_ASSERT(r.handle_len >= 1u && r.handle_len <= STORE_ID_MAX, "handle_len out of range");
        FUZZ_ASSERT(r.sig_old_len >= 1u && r.sig_old_len <= MLDSA_SIGNATURE_MAX_BYTES,
                    "sig_old_len out of range");
        FUZZ_ASSERT(r.sig_new_len >= 1u && r.sig_new_len <= MLDSA_SIGNATURE_MAX_BYTES,
                    "sig_new_len out of range");
        FUZZ_ASSERT((r.flags & (uint8_t)~AUTHMSG_FLAG_ROTATE_DROP_TOKENS) == 0u,
                    "a reserved flag bit survived the decoder");
        /* every borrowed pointer inside the input */
        FUZZ_ASSERT(r.handle >= in && r.handle + r.handle_len <= in + size, "handle out of bounds");
        FUZZ_ASSERT(r.pk_new >= in && r.pk_new + MLDSA_PUBLIC_KEY_BYTES <= in + size,
                    "pk_new out of bounds");
        FUZZ_ASSERT(r.sig_old >= in && r.sig_old + r.sig_old_len <= in + size,
                    "sig_old out of bounds");
        FUZZ_ASSERT(r.sig_new >= in && r.sig_new + r.sig_new_len <= in + size,
                    "sig_new out of bounds");
        /* and the fields reconstruct the input exactly */
        static uint8_t again[AUTHMSG_ROTATE_MAX_CONTENT];
        size_t n = 0;
        FUZZ_ASSERT(authmsg_encode_rotate(again, sizeof again, &n, r.flags, r.handle, r.handle_len,
                                          r.pk_new, r.sig_old, r.sig_old_len,
                                          r.sig_new, r.sig_new_len) == AUTHMSG_OK,
                    "a decoded ROTATE does not re-encode");
        FUZZ_ASSERT(n == size && memcmp(again, in, size) == 0,
                    "re-encoding a decoded ROTATE changed the bytes");
    } else {
        FUZZ_ASSERT(all_zero(&r, sizeof r), "a failed ROTATE decode left fields behind");
    }

    /* ---- ROTATE_ACK ---- */
    authmsg_rotate_ack_t a;
    const authmsg_status_t as = authmsg_decode_rotate_ack(in, size, &a);
    if (as == AUTHMSG_OK) {
        FUZZ_ASSERT(a.handle_len >= 1u && a.handle_len <= STORE_ID_MAX, "ack handle_len out of range");
        FUZZ_ASSERT(a.handle >= in && a.handle + a.handle_len <= in + size, "ack handle out of bounds");
        FUZZ_ASSERT(size == AUTHMSG_ROTATE_ACK_CONTENT_LEN(a.handle_len),
                    "ack accepted at the wrong length");
    } else {
        FUZZ_ASSERT(a.handle == NULL && a.handle_len == 0u,
                    "a failed ROTATE_ACK decode left fields behind");
    }

    /* ---- the fixed-length messages, for free ---- */
    authmsg_login_code_t lc;
    (void)authmsg_decode_login_code(in, size, &lc);
    uint8_t code = 0;
    (void)authmsg_decode_error(in, size, &code);
    uint8_t op = 0;
    (void)authmsg_peek_op(in, size, &op);
    return 0;
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    emit(ctx, "empty", fuzz_empty, 0);

    /* A structurally valid ROTATE: the signatures are nonsense, which does not
     * matter -- the decoder never looks at them, and the acceptance path this
     * target cannot reach is where they are checked. */
    static uint8_t rot[AUTHMSG_ROTATE_MAX_CONTENT];
    static uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    static uint8_t sg[MLDSA_SIGNATURE_MAX_BYTES];
    static const uint8_t handle[] = { 'd','1','a','a' };
    memset(pk, 0xa5, sizeof pk);
    memset(sg, 0x5a, sizeof sg);
    size_t n = 0;
    if (authmsg_encode_rotate(rot, sizeof rot, &n, 0u, handle, sizeof handle, pk,
                              sg, 64u, sg, 64u) == AUTHMSG_OK) {
        emit(ctx, "rotate-small-sigs", rot, n);
        /* one byte longer: full consumption is a rule, not a courtesy */
        if (n + 1u <= sizeof rot) {
            rot[n] = 0x00u;
            emit(ctx, "rotate-trailing-byte", rot, n + 1u);
        }
    }
    /* the maximum: 64-byte handle and full-length signatures -- 8642 bytes,
     * which is the figure a buffer sized from the spec's quoted 8612 would
     * overrun by thirty */
    static uint8_t big_handle[STORE_ID_MAX];
    memset(big_handle, 'z', sizeof big_handle);
    if (authmsg_encode_rotate(rot, sizeof rot, &n, AUTHMSG_FLAG_ROTATE_DROP_TOKENS,
                              big_handle, sizeof big_handle, pk,
                              sg, MLDSA_SIGNATURE_MAX_BYTES,
                              sg, MLDSA_SIGNATURE_MAX_BYTES) == AUTHMSG_OK) {
        emit(ctx, "rotate-maximal", rot, n);
    }
    /* a declared signature length that runs off the end */
    if (n > 8u) {
        static uint8_t bad[AUTHMSG_ROTATE_MAX_CONTENT];
        memcpy(bad, rot, n);
        bad[4u + STORE_ID_MAX + MLDSA_PUBLIC_KEY_BYTES] = 0xffu;
        emit(ctx, "rotate-siglen-overrun", bad, n);
    }

    static uint8_t ack[AUTHMSG_ROTATE_ACK_CONTENT_LEN(STORE_ID_MAX)];
    static uint8_t fp[32];
    memset(fp, 0x11, sizeof fp);
    if (authmsg_encode_rotate_ack(ack, sizeof ack, &n, handle, sizeof handle, fp,
                                  1700000000ull) == AUTHMSG_OK) {
        emit(ctx, "rotate-ack", ack, n);
    }
    { const uint8_t bye[] = { 0x20u };                    emit(ctx, "bye", bye, sizeof bye); }
    { const uint8_t err[] = { 0x1fu, 0x01u, 0x03u };      emit(ctx, "error", err, sizeof err); }
    { const uint8_t hdr[] = { 0x11u, 0x01u, 0x00u, 0x00u }; emit(ctx, "rotate-zero-handle", hdr, sizeof hdr); }
}
