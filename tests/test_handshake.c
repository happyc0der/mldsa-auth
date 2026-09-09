/*
 * Step 3 wire-format tests: deterministic serialization for the three
 * handshake messages (ClientHello, ServerHello, ClientAuth), transcript
 * hashing, and malformed/truncated-input rejection. This is the
 * serialization-level slice of "happy path + adversarial cases" -- Step 4
 * extends this same file with real two-party handshake_ctx-level cases
 * once that state machine exists.
 *
 * No actual cryptographic keys are generated or verified here -- sig/
 * handshake_id byte contents are arbitrary filler for structural testing;
 * Step 3 is a pure serialization layer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sodium.h>

#include "transcript.h"

static int g_failures = 0;

#define CHECK(cond, name)                    \
    do {                                      \
        if (cond) {                           \
            printf("PASS: %s\n", name);       \
        } else {                               \
            printf("FAIL: %s\n", name);       \
            g_failures++;                      \
        }                                      \
    } while (0)

/* ---------------------------------------------------------------------
 * Fixture helpers
 * ------------------------------------------------------------------- */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

static void make_client_hello(client_hello_t *ch, uint8_t id_len, uint8_t seed) {
    memset(ch, 0, sizeof(*ch));
    ch->id_len = id_len;
    fill_pattern(ch->id, id_len, seed);
    fill_pattern(ch->ephemeral_pub, WIRE_X25519_PUB_LEN, (uint8_t)(seed + 1));
    fill_pattern(ch->session_id, WIRE_SESSION_ID_LEN, (uint8_t)(seed + 2));
    fill_pattern(ch->nonce, WIRE_NONCE_LEN, (uint8_t)(seed + 3));
}

static void make_server_hello(server_hello_t *sh, uint8_t id_len, uint16_t sig_len, uint8_t seed) {
    memset(sh, 0, sizeof(*sh));
    sh->id_len = id_len;
    fill_pattern(sh->id, id_len, seed);
    fill_pattern(sh->ephemeral_pub, WIRE_X25519_PUB_LEN, (uint8_t)(seed + 1));
    fill_pattern(sh->nonce, WIRE_NONCE_LEN, (uint8_t)(seed + 2));
    fill_pattern(sh->session_id_echo, WIRE_SESSION_ID_LEN, (uint8_t)(seed + 3));
    sh->sig_len = sig_len;
    fill_pattern(sh->sig, sig_len, (uint8_t)(seed + 4));
}

static void make_client_auth(client_auth_t *ca, uint16_t sig_len, uint8_t seed) {
    memset(ca, 0, sizeof(*ca));
    fill_pattern(ca->handshake_id, WIRE_HANDSHAKE_ID_LEN, seed);
    ca->sig_len = sig_len;
    fill_pattern(ca->sig, sig_len, (uint8_t)(seed + 1));
}

/* ---------------------------------------------------------------------
 * Test 1: round-trip
 * ------------------------------------------------------------------- */

static void test_round_trip_client_hello(uint8_t id_len) {
    client_hello_t in, out;
    make_client_hello(&in, id_len, 0x10);

    uint8_t buf[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t enc_len = 0;
    int rc = encode_client_hello(&in, buf, sizeof buf, &enc_len);
    char name[128];
    snprintf(name, sizeof name, "round_trip_client_hello(id_len=%u): encode succeeds", id_len);
    CHECK(rc == 0, name);
    if (rc != 0) {
        return;
    }

    size_t consumed = 0;
    rc = decode_client_hello(buf, enc_len, &out, &consumed);
    snprintf(name, sizeof name, "round_trip_client_hello(id_len=%u): decode succeeds and consumes exactly enc_len", id_len);
    CHECK(rc == 0 && consumed == enc_len, name);

    snprintf(name, sizeof name, "round_trip_client_hello(id_len=%u): decoded struct matches original field-for-field", id_len);
    CHECK(memcmp(&in, &out, sizeof in) == 0, name);
}

static void test_round_trip_server_hello(uint8_t id_len) {
    server_hello_t in, out;
    make_server_hello(&in, id_len, 128, 0x20);

    uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t enc_len = 0;
    int rc = encode_server_hello(&in, buf, sizeof buf, &enc_len);
    char name[128];
    snprintf(name, sizeof name, "round_trip_server_hello(id_len=%u): encode succeeds", id_len);
    CHECK(rc == 0, name);
    if (rc != 0) {
        return;
    }

    size_t consumed = 0;
    rc = decode_server_hello(buf, enc_len, &out, &consumed);
    snprintf(name, sizeof name, "round_trip_server_hello(id_len=%u): decode succeeds and consumes exactly enc_len", id_len);
    CHECK(rc == 0 && consumed == enc_len, name);

    snprintf(name, sizeof name, "round_trip_server_hello(id_len=%u): decoded struct matches original field-for-field", id_len);
    CHECK(memcmp(&in, &out, sizeof in) == 0, name);
}

static void test_round_trip_client_auth(void) {
    client_auth_t in, out;
    make_client_auth(&in, 3309, 0x30);

    uint8_t buf[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t enc_len = 0;
    int rc = encode_client_auth(&in, buf, sizeof buf, &enc_len);
    CHECK(rc == 0, "round_trip_client_auth: encode succeeds");
    if (rc != 0) {
        return;
    }

    size_t consumed = 0;
    rc = decode_client_auth(buf, enc_len, &out, &consumed);
    CHECK(rc == 0 && consumed == enc_len, "round_trip_client_auth: decode succeeds and consumes exactly enc_len");
    CHECK(memcmp(&in, &out, sizeof in) == 0, "round_trip_client_auth: decoded struct matches original field-for-field");
    CHECK(memcmp(in.handshake_id, out.handshake_id, WIRE_HANDSHAKE_ID_LEN) == 0,
          "round_trip_client_auth: handshake_id survives encode/decode unchanged");
}

/* ---------------------------------------------------------------------
 * Test 2: transcript hash correctness and domain separation
 * ------------------------------------------------------------------- */

static void hand_hash(const char *label, const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len, uint8_t out[32]) {
    crypto_hash_sha256_state st;
    uint8_t zero = 0x00;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)label, strlen(label));
    crypto_hash_sha256_update(&st, &zero, 1);
    crypto_hash_sha256_update(&st, a, a_len);
    crypto_hash_sha256_update(&st, b, b_len);
    crypto_hash_sha256_final(&st, out);
}

static void test_transcript_hashes(void) {
    client_hello_t ch;
    server_hello_t sh;
    make_client_hello(&ch, 10, 0x40);
    make_server_hello(&sh, 12, 200, 0x50);

    uint8_t ch_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len = 0;
    CHECK(encode_client_hello(&ch, ch_bytes, sizeof ch_bytes, &ch_len) == 0,
          "transcript_hashes: fixture ClientHello encodes");

    uint8_t sh_unsigned_bytes[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
    size_t sh_unsigned_len = 0;
    CHECK(encode_server_hello_unsigned(&sh, sh_unsigned_bytes, sizeof sh_unsigned_bytes, &sh_unsigned_len) == 0,
          "transcript_hashes: fixture SH_unsigned encodes");

    uint8_t sh_bytes[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    CHECK(encode_server_hello(&sh, sh_bytes, sizeof sh_bytes, &sh_len) == 0,
          "transcript_hashes: fixture full ServerHello encodes");

    /* SH_unsigned must be a literal prefix of the full ServerHello. */
    CHECK(sh_len > sh_unsigned_len && memcmp(sh_bytes, sh_unsigned_bytes, sh_unsigned_len) == 0,
          "transcript_hashes: SH_unsigned is a literal prefix of encode(ServerHello)");

    /* --- independent reimplementation matches --- */
    uint8_t th_server_auth[32], th_server_auth_expected[32];
    CHECK(transcript_hash_server_auth(ch_bytes, ch_len, sh_unsigned_bytes, sh_unsigned_len, th_server_auth) == 0,
          "transcript_hashes: transcript_hash_server_auth succeeds");
    hand_hash(TRANSCRIPT_LABEL_SERVER_AUTH, ch_bytes, ch_len, sh_unsigned_bytes, sh_unsigned_len, th_server_auth_expected);
    CHECK(memcmp(th_server_auth, th_server_auth_expected, 32) == 0,
          "transcript_hashes: transcript_hash_server_auth matches independent hand-built SHA-256(label||0x00||CH||SH_unsigned)");

    uint8_t th_client_auth[32], th_client_auth_expected[32];
    CHECK(transcript_hash_client_auth(ch_bytes, ch_len, sh_bytes, sh_len, th_client_auth) == 0,
          "transcript_hashes: transcript_hash_client_auth succeeds");
    hand_hash(TRANSCRIPT_LABEL_CLIENT_AUTH, ch_bytes, ch_len, sh_bytes, sh_len, th_client_auth_expected);
    CHECK(memcmp(th_client_auth, th_client_auth_expected, 32) == 0,
          "transcript_hashes: transcript_hash_client_auth matches independent hand-built SHA-256(label||0x00||CH||SH)");

    uint8_t handshake_id[16];
    uint8_t handshake_id_full_expected[32];
    CHECK(transcript_handshake_id(ch_bytes, ch_len, sh_bytes, sh_len, handshake_id) == 0,
          "transcript_hashes: transcript_handshake_id succeeds");
    hand_hash(TRANSCRIPT_LABEL_HANDSHAKE_ID, ch_bytes, ch_len, sh_bytes, sh_len, handshake_id_full_expected);
    CHECK(memcmp(handshake_id, handshake_id_full_expected, 16) == 0,
          "transcript_hashes: transcript_handshake_id == independently-computed digest[0:16]");

    /* --- domain separation: TH_server_auth != TH_client_auth for these
     * concrete inputs (regression check -- equality would require a
     * SHA-256 collision, not something this test claims to formally
     * rule out) --- */
    CHECK(memcmp(th_server_auth, th_client_auth, 32) != 0,
          "transcript_hashes: TH_server_auth (32B) != TH_client_auth (32B) for this fixture");

    /* handshake_id vs. a transcript-hash prefix: fixture-specific,
     * non-security regression assertion only -- different byte
     * lengths, different roles, no protocol guarantee either way. */
    CHECK(memcmp(handshake_id, th_client_auth, 16) != 0,
          "transcript_hashes: handshake_id != TH_client_auth[0:16] for this fixture (non-security regression check)");

    /* --- SH_unsigned-field binding: flipping B_id, B_ephemeral_pub,
     * nonce_b, or session_id_echo each alone changes TH_server_auth --
     * this is the test that would catch the original bug where sig_B
     * didn't cover ServerHello's own unsigned fields --- */
    {
        server_hello_t sh2 = sh;
        sh2.id[0] ^= 0x01;
        uint8_t sh2_unsigned[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
        size_t sh2_unsigned_len = 0;
        encode_server_hello_unsigned(&sh2, sh2_unsigned, sizeof sh2_unsigned, &sh2_unsigned_len);
        uint8_t th2[32];
        transcript_hash_server_auth(ch_bytes, ch_len, sh2_unsigned, sh2_unsigned_len, th2);
        CHECK(memcmp(th2, th_server_auth, 32) != 0, "transcript_hashes: flipping B_id changes TH_server_auth");
    }
    {
        server_hello_t sh2 = sh;
        sh2.ephemeral_pub[0] ^= 0x01;
        uint8_t sh2_unsigned[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
        size_t sh2_unsigned_len = 0;
        encode_server_hello_unsigned(&sh2, sh2_unsigned, sizeof sh2_unsigned, &sh2_unsigned_len);
        uint8_t th2[32];
        transcript_hash_server_auth(ch_bytes, ch_len, sh2_unsigned, sh2_unsigned_len, th2);
        CHECK(memcmp(th2, th_server_auth, 32) != 0, "transcript_hashes: flipping B_ephemeral_pub changes TH_server_auth");
    }
    {
        server_hello_t sh2 = sh;
        sh2.nonce[0] ^= 0x01;
        uint8_t sh2_unsigned[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
        size_t sh2_unsigned_len = 0;
        encode_server_hello_unsigned(&sh2, sh2_unsigned, sizeof sh2_unsigned, &sh2_unsigned_len);
        uint8_t th2[32];
        transcript_hash_server_auth(ch_bytes, ch_len, sh2_unsigned, sh2_unsigned_len, th2);
        CHECK(memcmp(th2, th_server_auth, 32) != 0, "transcript_hashes: flipping nonce_b changes TH_server_auth");
    }
    {
        server_hello_t sh2 = sh;
        sh2.session_id_echo[0] ^= 0x01;
        uint8_t sh2_unsigned[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
        size_t sh2_unsigned_len = 0;
        encode_server_hello_unsigned(&sh2, sh2_unsigned, sizeof sh2_unsigned, &sh2_unsigned_len);
        uint8_t th2[32];
        transcript_hash_server_auth(ch_bytes, ch_len, sh2_unsigned, sh2_unsigned_len, th2);
        CHECK(memcmp(th2, th_server_auth, 32) != 0, "transcript_hashes: flipping session_id_echo changes TH_server_auth");
    }

    /* --- general per-field sensitivity: flipping ClientHello.session_id
     * changes both TH_server_auth and TH_client_auth (transitively, via
     * encode(ClientHello)) --- */
    {
        client_hello_t ch2 = ch;
        ch2.session_id[0] ^= 0x01;
        uint8_t ch2_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
        size_t ch2_len = 0;
        encode_client_hello(&ch2, ch2_bytes, sizeof ch2_bytes, &ch2_len);

        uint8_t th2a[32], th2b[32];
        transcript_hash_server_auth(ch2_bytes, ch2_len, sh_unsigned_bytes, sh_unsigned_len, th2a);
        transcript_hash_client_auth(ch2_bytes, ch2_len, sh_bytes, sh_len, th2b);
        CHECK(memcmp(th2a, th_server_auth, 32) != 0,
              "transcript_hashes: flipping ClientHello.session_id changes TH_server_auth");
        CHECK(memcmp(th2b, th_client_auth, 32) != 0,
              "transcript_hashes: flipping ClientHello.session_id changes TH_client_auth");
    }

    /* --- handshake_id sensitivity to the full pre-ClientAuth transcript --- */
    {
        client_hello_t ch2 = ch;
        ch2.nonce[0] ^= 0x01;
        uint8_t ch2_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
        size_t ch2_len = 0;
        encode_client_hello(&ch2, ch2_bytes, sizeof ch2_bytes, &ch2_len);
        uint8_t hid2[16];
        transcript_handshake_id(ch2_bytes, ch2_len, sh_bytes, sh_len, hid2);
        CHECK(memcmp(hid2, handshake_id, 16) != 0,
              "transcript_hashes: flipping a ClientHello byte changes handshake_id");
    }
    {
        server_hello_t sh2 = sh;
        sh2.sig[0] ^= 0x01;
        uint8_t sh2_bytes[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t sh2_len = 0;
        encode_server_hello(&sh2, sh2_bytes, sizeof sh2_bytes, &sh2_len);
        uint8_t hid2[16];
        transcript_handshake_id(ch_bytes, ch_len, sh2_bytes, sh2_len, hid2);
        CHECK(memcmp(hid2, handshake_id, 16) != 0,
              "transcript_hashes: flipping a full-ServerHello byte (in sig_b) changes handshake_id");
    }
}

/* ---------------------------------------------------------------------
 * Test 3: order-sensitivity
 * ------------------------------------------------------------------- */

static void test_order_sensitivity(void) {
    client_hello_t ch;
    server_hello_t sh;
    make_client_hello(&ch, 8, 0x60);
    make_server_hello(&sh, 8, 100, 0x70);

    uint8_t ch_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len = 0;
    encode_client_hello(&ch, ch_bytes, sizeof ch_bytes, &ch_len);

    uint8_t sh_bytes[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    encode_server_hello(&sh, sh_bytes, sizeof sh_bytes, &sh_len);

    CHECK(ch_len != sh_len || memcmp(ch_bytes, sh_bytes, ch_len) != 0,
          "order_sensitivity: fixture ClientHello and ServerHello bytes actually differ (precondition)");

    uint8_t forward[32], reversed[32];
    transcript_hash_client_auth(ch_bytes, ch_len, sh_bytes, sh_len, forward);
    transcript_hash_client_auth(sh_bytes, sh_len, ch_bytes, ch_len, reversed);

    CHECK(memcmp(forward, reversed, 32) != 0,
          "order_sensitivity: transcript_hash_client_auth(A,B) != transcript_hash_client_auth(B,A)");
}

/* ---------------------------------------------------------------------
 * Test 4: cross-type confusion
 * ------------------------------------------------------------------- */

static void test_cross_type_confusion(void) {
    client_hello_t ch;
    server_hello_t sh;
    client_auth_t ca;
    make_client_hello(&ch, 8, 0x80);
    make_server_hello(&sh, 8, 64, 0x90);
    make_client_auth(&ca, 64, 0xA0);

    uint8_t ch_bytes[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len = 0;
    encode_client_hello(&ch, ch_bytes, sizeof ch_bytes, &ch_len);

    uint8_t sh_bytes[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    encode_server_hello(&sh, sh_bytes, sizeof sh_bytes, &sh_len);

    uint8_t ca_bytes[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ca_len = 0;
    encode_client_auth(&ca, ca_bytes, sizeof ca_bytes, &ca_len);

    client_hello_t tmp_ch;
    server_hello_t tmp_sh;
    client_auth_t tmp_ca;
    size_t consumed;

    CHECK(decode_server_hello(ch_bytes, ch_len, &tmp_sh, &consumed) != 0,
          "cross_type_confusion: decode_server_hello rejects a valid ClientHello");
    CHECK(decode_client_auth(ch_bytes, ch_len, &tmp_ca, &consumed) != 0,
          "cross_type_confusion: decode_client_auth rejects a valid ClientHello");

    CHECK(decode_client_hello(sh_bytes, sh_len, &tmp_ch, &consumed) != 0,
          "cross_type_confusion: decode_client_hello rejects a valid ServerHello");
    CHECK(decode_client_auth(sh_bytes, sh_len, &tmp_ca, &consumed) != 0,
          "cross_type_confusion: decode_client_auth rejects a valid ServerHello");

    CHECK(decode_client_hello(ca_bytes, ca_len, &tmp_ch, &consumed) != 0,
          "cross_type_confusion: decode_client_hello rejects a valid ClientAuth");
    CHECK(decode_server_hello(ca_bytes, ca_len, &tmp_sh, &consumed) != 0,
          "cross_type_confusion: decode_server_hello rejects a valid ClientAuth");
}

/* ---------------------------------------------------------------------
 * Test 5: malformed/truncated input
 * ------------------------------------------------------------------- */

/* Allocates an EXACTLY `n`-byte heap buffer (never 0, malloc(0) is
 * implementation-defined) holding the first `n` bytes of `src`. Used by
 * the truncation sweeps below so that a decoder bug reading past the
 * declared length is a genuine heap-buffer-overflow -- catchable by
 * ASan and a real crash risk in production -- not masked by a shared,
 * over-sized backing array that happens to still hold valid bytes past
 * the declared length (which is what a fixed-size stack array shared
 * across all truncation points would do; a real network read gives you
 * a buffer of exactly that size, never more). */
static uint8_t *exact_size_copy(const uint8_t *src, size_t n) {
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (buf != NULL && n > 0) {
        memcpy(buf, src, n);
    }
    return buf;
}

static void test_truncation_sweep_client_hello(void) {
    client_hello_t ch, tmp;
    make_client_hello(&ch, 20, 0xB0);
    uint8_t full_buf[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t full_len = 0;
    encode_client_hello(&ch, full_buf, sizeof full_buf, &full_len);

    int all_ok = 1;
    for (size_t trunc_len = 0; trunc_len < full_len; trunc_len++) {
        uint8_t *trunc_buf = exact_size_copy(full_buf, trunc_len);
        if (trunc_buf == NULL) {
            all_ok = 0;
            break;
        }
        size_t consumed;
        int rc = decode_client_hello(trunc_buf, trunc_len, &tmp, &consumed);
        free(trunc_buf);
        if (rc == 0) {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "truncation_sweep: decode_client_hello rejects every truncation point from 0 to full_len-1 (exact-size buffers)");
}

static void test_truncation_sweep_server_hello(void) {
    server_hello_t sh, tmp;
    make_server_hello(&sh, 20, 150, 0xC0);
    uint8_t full_buf[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t full_len = 0;
    encode_server_hello(&sh, full_buf, sizeof full_buf, &full_len);

    int all_ok = 1;
    for (size_t trunc_len = 0; trunc_len < full_len; trunc_len++) {
        uint8_t *trunc_buf = exact_size_copy(full_buf, trunc_len);
        if (trunc_buf == NULL) {
            all_ok = 0;
            break;
        }
        size_t consumed;
        int rc = decode_server_hello(trunc_buf, trunc_len, &tmp, &consumed);
        free(trunc_buf);
        if (rc == 0) {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "truncation_sweep: decode_server_hello rejects every truncation point from 0 to full_len-1 (exact-size buffers)");
}

static void test_truncation_sweep_client_auth(void) {
    client_auth_t ca, tmp;
    make_client_auth(&ca, 150, 0xD0);
    uint8_t full_buf[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t full_len = 0;
    encode_client_auth(&ca, full_buf, sizeof full_buf, &full_len);

    int all_ok = 1;
    for (size_t trunc_len = 0; trunc_len < full_len; trunc_len++) {
        uint8_t *trunc_buf = exact_size_copy(full_buf, trunc_len);
        if (trunc_buf == NULL) {
            all_ok = 0;
            break;
        }
        size_t consumed;
        int rc = decode_client_auth(trunc_buf, trunc_len, &tmp, &consumed);
        free(trunc_buf);
        if (rc == 0) {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "truncation_sweep: decode_client_auth rejects every truncation point from 0 to full_len-1 (exact-size buffers)");
}

static void test_malformed_lengths_and_trailing_bytes(void) {
    client_hello_t ch, tmp_ch;
    server_hello_t sh, tmp_sh;
    client_auth_t ca, tmp_ca;
    size_t consumed;

    /* id_len == 0 */
    make_client_hello(&ch, 1, 0xE0);
    {
        uint8_t buf[CLIENT_HELLO_MAX_ENCODED_LEN];
        size_t len = 0;
        encode_client_hello(&ch, buf, sizeof buf, &len);
        buf[1] = 0; /* overwrite id_len field with 0 */
        CHECK(decode_client_hello(buf, len, &tmp_ch, &consumed) != 0,
              "malformed: decode_client_hello rejects id_len == 0");
    }

    /* id_len == 65, with enough trailing bytes that truncation isn't
     * the reason for rejection */
    {
        uint8_t buf[CLIENT_HELLO_MAX_ENCODED_LEN + 1] = {0};
        buf[0] = MSG_TYPE_CLIENT_HELLO;
        buf[1] = 65;
        /* fill the rest with arbitrary bytes -- plenty of them */
        size_t len = 2 + 65 + WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN;
        CHECK(decode_client_hello(buf, len, &tmp_ch, &consumed) != 0,
              "malformed: decode_client_hello rejects id_len == 65 (one past max) even with enough trailing bytes");
    }

    /* sig_len == 0 (ServerHello) */
    make_server_hello(&sh, 10, 1, 0xF0);
    {
        uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t len = 0;
        encode_server_hello(&sh, buf, sizeof buf, &len);
        size_t unsigned_len = 1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
        buf[unsigned_len] = 0;
        buf[unsigned_len + 1] = 0; /* sig_len = 0, big-endian */
        CHECK(decode_server_hello(buf, len, &tmp_sh, &consumed) != 0,
              "malformed: decode_server_hello rejects sig_len == 0");
    }

    /* sig_len > MLDSA_SIGNATURE_MAX_BYTES */
    make_server_hello(&sh, 10, 1, 0x11);
    {
        uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN + 8];
        size_t len = 0;
        encode_server_hello(&sh, buf, sizeof buf, &len);
        size_t unsigned_len = 1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
        uint16_t too_big = (uint16_t)(MLDSA_SIGNATURE_MAX_BYTES + 1);
        buf[unsigned_len] = (uint8_t)(too_big >> 8);
        buf[unsigned_len + 1] = (uint8_t)(too_big & 0xFF);
        CHECK(decode_server_hello(buf, len, &tmp_sh, &consumed) != 0,
              "malformed: decode_server_hello rejects sig_len > MLDSA_SIGNATURE_MAX_BYTES");
    }

    /* sig_len declares more than the actual remaining buffer */
    make_server_hello(&sh, 10, 100, 0x22);
    {
        uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t len = 0;
        encode_server_hello(&sh, buf, sizeof buf, &len);
        size_t unsigned_len = 1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
        uint16_t bigger_than_remaining = (uint16_t)(sh.sig_len + 50);
        buf[unsigned_len] = (uint8_t)(bigger_than_remaining >> 8);
        buf[unsigned_len + 1] = (uint8_t)(bigger_than_remaining & 0xFF);
        /* len is unchanged -- still only sh.sig_len bytes of signature
         * actually follow, but the declared length now claims more */
        CHECK(decode_server_hello(buf, len, &tmp_sh, &consumed) != 0,
              "malformed: decode_server_hello rejects sig_len declaring more than the remaining buffer");
    }

    /* unknown message_type */
    make_client_hello(&ch, 10, 0x33);
    {
        uint8_t buf[CLIENT_HELLO_MAX_ENCODED_LEN];
        size_t len = 0;
        encode_client_hello(&ch, buf, sizeof buf, &len);
        buf[0] = 0x99;
        CHECK(decode_client_hello(buf, len, &tmp_ch, &consumed) != 0,
              "malformed: decode_client_hello rejects an unknown message_type byte");
    }

    /* valid message + one trailing byte, all three types (strict mode) */
    make_client_hello(&ch, 10, 0x44);
    {
        uint8_t buf[CLIENT_HELLO_MAX_ENCODED_LEN + 1] = {0};
        size_t len = 0;
        encode_client_hello(&ch, buf, sizeof buf, &len);
        buf[len] = 0xFF; /* one trailing byte */
        CHECK(decode_client_hello(buf, len + 1, &tmp_ch, &consumed) != 0,
              "malformed: decode_client_hello rejects valid message plus one trailing byte (strict mode)");
    }
    make_server_hello(&sh, 10, 100, 0x55);
    {
        uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN + 1] = {0};
        size_t len = 0;
        encode_server_hello(&sh, buf, sizeof buf, &len);
        buf[len] = 0xFF;
        CHECK(decode_server_hello(buf, len + 1, &tmp_sh, &consumed) != 0,
              "malformed: decode_server_hello rejects valid message plus one trailing byte (strict mode)");
    }
    make_client_auth(&ca, 100, 0x66);
    {
        uint8_t buf[CLIENT_AUTH_MAX_ENCODED_LEN + 1] = {0};
        size_t len = 0;
        encode_client_auth(&ca, buf, sizeof buf, &len);
        buf[len] = 0xFF;
        CHECK(decode_client_auth(buf, len + 1, &tmp_ca, &consumed) != 0,
              "malformed: decode_client_auth rejects valid message plus one trailing byte (strict mode)");
    }

    /* Structurally-valid but semantically-mismatched session correlation
     * fields decode successfully at THIS layer -- Step 3 does no
     * cross-message comparison. Documented here, not enforced here;
     * Step 4's handshake state machine is what rejects these. */
    {
        client_hello_t ch_real;
        make_client_hello(&ch_real, 10, 0x77);
        server_hello_t sh_mismatched;
        make_server_hello(&sh_mismatched, 10, 50, 0x88);
        /* sh_mismatched.session_id_echo (seed 0x88+3) deliberately does
         * NOT equal ch_real.session_id (seed 0x77+2) -- different
         * fixtures, no attempt made to match them. */
        uint8_t sh_buf[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t sh_len = 0;
        encode_server_hello(&sh_mismatched, sh_buf, sizeof sh_buf, &sh_len);
        server_hello_t decoded_sh;
        int rc = decode_server_hello(sh_buf, sh_len, &decoded_sh, &consumed);
        CHECK(rc == 0 && memcmp(decoded_sh.session_id_echo, ch_real.session_id, WIRE_SESSION_ID_LEN) != 0,
              "malformed: a ServerHello with session_id_echo mismatched against some ClientHello decodes fine at Step 3 -- rejection is Step 4's job, not checked here");
    }
    {
        client_auth_t ca_random_hid;
        make_client_auth(&ca_random_hid, 50, 0x99);
        /* handshake_id here is just fill_pattern() bytes, not derived
         * from any real transcript -- decode doesn't and structurally
         * can't detect that. */
        uint8_t ca_buf[CLIENT_AUTH_MAX_ENCODED_LEN];
        size_t ca_buf_len = 0;
        encode_client_auth(&ca_random_hid, ca_buf, sizeof ca_buf, &ca_buf_len);
        client_auth_t decoded_ca;
        int rc = decode_client_auth(ca_buf, ca_buf_len, &decoded_ca, &consumed);
        CHECK(rc == 0,
              "malformed: a ClientAuth with a random/wrong handshake_id decodes successfully at Step 3 -- rejected at Step 4's lookup or sig_A verification, not checked here");
    }
}

/* ---------------------------------------------------------------------
 * Test 6: encoder-negative tests
 * ------------------------------------------------------------------- */

static void test_encoder_negative(void) {
    client_hello_t ch;
    server_hello_t sh;
    client_auth_t ca;
    size_t out_len;
    uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN + 16];

    /* id_len == 0 */
    make_client_hello(&ch, 1, 0x00);
    ch.id_len = 0;
    CHECK(encode_client_hello(&ch, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_client_hello rejects id_len == 0");

    /* id_len == 65 */
    make_client_hello(&ch, 1, 0x00);
    ch.id_len = 65;
    CHECK(encode_client_hello(&ch, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_client_hello rejects id_len == 65");

    make_server_hello(&sh, 1, 10, 0x00);
    sh.id_len = 0;
    CHECK(encode_server_hello_unsigned(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello_unsigned rejects id_len == 0");
    CHECK(encode_server_hello(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello rejects id_len == 0");

    make_server_hello(&sh, 1, 10, 0x00);
    sh.id_len = 65;
    CHECK(encode_server_hello_unsigned(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello_unsigned rejects id_len == 65");
    CHECK(encode_server_hello(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello rejects id_len == 65");

    /* sig_len == 0 */
    make_server_hello(&sh, 10, 1, 0x00);
    sh.sig_len = 0;
    CHECK(encode_server_hello(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello rejects sig_len == 0");

    make_client_auth(&ca, 1, 0x00);
    ca.sig_len = 0;
    CHECK(encode_client_auth(&ca, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_client_auth rejects sig_len == 0");

    /* sig_len > MLDSA_SIGNATURE_MAX_BYTES */
    make_server_hello(&sh, 10, 1, 0x00);
    sh.sig_len = (uint16_t)(MLDSA_SIGNATURE_MAX_BYTES + 1);
    CHECK(encode_server_hello(&sh, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_server_hello rejects sig_len > MLDSA_SIGNATURE_MAX_BYTES");

    make_client_auth(&ca, 1, 0x00);
    ca.sig_len = (uint16_t)(MLDSA_SIGNATURE_MAX_BYTES + 1);
    CHECK(encode_client_auth(&ca, buf, sizeof buf, &out_len) != 0,
          "encoder_negative: encode_client_auth rejects sig_len > MLDSA_SIGNATURE_MAX_BYTES");

    /* output buffer capacity one byte below the exact required length */
    make_client_hello(&ch, 10, 0x00);
    {
        size_t exact_len = 0;
        uint8_t scratch[CLIENT_HELLO_MAX_ENCODED_LEN];
        encode_client_hello(&ch, scratch, sizeof scratch, &exact_len);
        CHECK(encode_client_hello(&ch, buf, exact_len - 1, &out_len) != 0,
              "encoder_negative: encode_client_hello rejects out_cap one byte short of exact required length");
    }
    make_server_hello(&sh, 10, 50, 0x00);
    {
        size_t exact_len = 0;
        uint8_t scratch[SERVER_HELLO_MAX_ENCODED_LEN];
        encode_server_hello(&sh, scratch, sizeof scratch, &exact_len);
        CHECK(encode_server_hello(&sh, buf, exact_len - 1, &out_len) != 0,
              "encoder_negative: encode_server_hello rejects out_cap one byte short of exact required length");
    }
    make_client_auth(&ca, 50, 0x00);
    {
        size_t exact_len = 0;
        uint8_t scratch[CLIENT_AUTH_MAX_ENCODED_LEN];
        encode_client_auth(&ca, scratch, sizeof scratch, &exact_len);
        CHECK(encode_client_auth(&ca, buf, exact_len - 1, &out_len) != 0,
              "encoder_negative: encode_client_auth rejects out_cap one byte short of exact required length");
    }
}

/* ---------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------- */

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return EXIT_FAILURE;
    }

    /* Test 1: round-trip, including boundary id lengths */
    test_round_trip_client_hello(1);
    test_round_trip_client_hello(64);
    test_round_trip_server_hello(1);
    test_round_trip_server_hello(64);
    test_round_trip_client_auth();

    /* Test 2: transcript hash correctness and domain separation */
    test_transcript_hashes();

    /* Test 3: order-sensitivity */
    test_order_sensitivity();

    /* Test 4: cross-type confusion */
    test_cross_type_confusion();

    /* Test 5: malformed/truncated input */
    test_truncation_sweep_client_hello();
    test_truncation_sweep_server_hello();
    test_truncation_sweep_client_auth();
    test_malformed_lengths_and_trailing_bytes();

    /* Test 6: encoder-negative tests */
    test_encoder_negative();

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
