/*
 * "Happy path + adversarial cases" for the handshake (spec §7), in two parts:
 *
 * STEP 3 -- wire format: deterministic serialization for ClientHello,
 * ServerHello and ClientAuth, transcript hashing, and malformed/truncated
 * input rejection. Pure serialization: the sig/handshake_id bytes in that
 * section are arbitrary filler, and no keys are generated or verified.
 *
 * STEP 4 -- the handshake state machine, keystore, pending-handshake
 * ledger, and the corrected KDF info encoding. Uses real ML-DSA-65
 * identity keys and real X25519 ephemerals.
 *
 * SINGLE-THREADED BY CONSTRUCTION (spec §6.3.6): every handshake context,
 * keystore and pending store in this file is created and used from this
 * one thread only. No test here exercises concurrent access, and none
 * claims to cover it -- concurrency is a documented v1 boundary, not a
 * tested property.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sodium.h>

#include "handshake.h"
#include "kex.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "mlkem_wrap.h"
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
    fill_pattern(ch->mlkem_ek, WIRE_MLKEM_EK_LEN, (uint8_t)(seed + 4));
    fill_pattern(ch->session_id, WIRE_SESSION_ID_LEN, (uint8_t)(seed + 2));
    fill_pattern(ch->nonce, WIRE_NONCE_LEN, (uint8_t)(seed + 3));
}

static void make_server_hello(server_hello_t *sh, uint8_t id_len, uint16_t sig_len, uint8_t seed) {
    memset(sh, 0, sizeof(*sh));
    sh->id_len = id_len;
    fill_pattern(sh->id, id_len, seed);
    fill_pattern(sh->ephemeral_pub, WIRE_X25519_PUB_LEN, (uint8_t)(seed + 1));
    fill_pattern(sh->mlkem_ct, WIRE_MLKEM_CT_LEN, (uint8_t)(seed + 5));
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
    /* The labels are spelled out here, NOT taken from TRANSCRIPT_LABEL_*:
     * passing the macro would make this test agree with any label the
     * header happens to contain, including a v1 one left behind. Same
     * discipline hand_kdf_info_v2() applies to the KDF label. */
    hand_hash("mldsa-auth/v2/server-auth", ch_bytes, ch_len, sh_unsigned_bytes, sh_unsigned_len,
              th_server_auth_expected);
    CHECK(memcmp(th_server_auth, th_server_auth_expected, 32) == 0,
          "transcript_hashes: transcript_hash_server_auth matches independent hand-built SHA-256(label||0x00||CH||SH_unsigned)");

    uint8_t th_client_auth[32], th_client_auth_expected[32];
    CHECK(transcript_hash_client_auth(ch_bytes, ch_len, sh_bytes, sh_len, th_client_auth) == 0,
          "transcript_hashes: transcript_hash_client_auth succeeds");
    hand_hash("mldsa-auth/v2/client-auth", ch_bytes, ch_len, sh_bytes, sh_len, th_client_auth_expected);
    CHECK(memcmp(th_client_auth, th_client_auth_expected, 32) == 0,
          "transcript_hashes: transcript_hash_client_auth matches independent hand-built SHA-256(label||0x00||CH||SH)");

    uint8_t handshake_id[16];
    uint8_t handshake_id_full_expected[32];
    CHECK(transcript_handshake_id(ch_bytes, ch_len, sh_bytes, sh_len, handshake_id) == 0,
          "transcript_hashes: transcript_handshake_id succeeds");
    hand_hash("mldsa-auth/v2/handshake-id", ch_bytes, ch_len, sh_bytes, sh_len, handshake_id_full_expected);
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
        size_t len = 2 + 65 + WIRE_X25519_PUB_LEN + WIRE_MLKEM_EK_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN;
        CHECK(decode_client_hello(buf, len, &tmp_ch, &consumed) != 0,
              "malformed: decode_client_hello rejects id_len == 65 (one past max) even with enough trailing bytes");
    }

    /* sig_len == 0 (ServerHello) */
    make_server_hello(&sh, 10, 1, 0xF0);
    {
        uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t len = 0;
        encode_server_hello(&sh, buf, sizeof buf, &len);
        size_t unsigned_len =
            1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_MLKEM_CT_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
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
        size_t unsigned_len =
            1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_MLKEM_CT_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
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
        size_t unsigned_len =
            1 + 1 + sh.id_len + WIRE_X25519_PUB_LEN + WIRE_MLKEM_CT_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
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
 * V2-4 W1-W5: the v2 wire format (spec-v2 6.3.1).
 *
 * Everything here is written against LITERAL numbers and LITERAL bytes.
 * The tests above are all self-consistent: they encode with the same code
 * they decode with, so a wrong-but-symmetric layout passes them. These do
 * not.
 * ------------------------------------------------------------------- */

static void test_v24_wire_constants(void) {
    /* W1 -- the four maxima against spec-v2 6.3.1's table. Checked before
     * anything else, because every buffer below is sized by these macros:
     * if they are wrong, a later failure could be an overflow rather than
     * the size error itself. The values are moved through arrays so the
     * comparison is between variables, not a constant folded at compile
     * time. */
    const size_t got[6] = {CLIENT_HELLO_MAX_ENCODED_LEN, SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN,
                           SERVER_HELLO_MAX_ENCODED_LEN, CLIENT_AUTH_MAX_ENCODED_LEN,
                           WIRE_MLKEM_EK_LEN, WIRE_MLKEM_CT_LEN};
    const size_t want[6] = {1330u, 1234u, 4545u, 3328u, 1184u, 1088u};
    int ok = 1;
    for (size_t i = 0; i < 6; i++) {
        if (got[i] != want[i]) {
            ok = 0;
            printf("      W1: constant %zu is %zu, expected %zu\n", i, got[i], want[i]);
        }
    }
    CHECK(ok, "v2-4 W1: CH/SH_unsigned/SH/CA maxima are 1330/1234/4545/3328 and the ML-KEM fields 1184/1088");

    /* W2 -- exact encoded sizes from literal arithmetic, at both id
     * boundaries. 1267 = 2+1+32+1184+16+32; 1171 = 2+1+32+1088+32+16. */
    client_hello_t ch;
    server_hello_t sh;
    uint8_t chb[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t shb[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t n1 = 0, n64 = 0, u1 = 0, u64 = 0, full = 0;
    make_client_hello(&ch, 1, 0x01);
    encode_client_hello(&ch, chb, sizeof chb, &n1);
    make_client_hello(&ch, 64, 0x01);
    encode_client_hello(&ch, chb, sizeof chb, &n64);
    make_server_hello(&sh, 1, 3309, 0x02);
    encode_server_hello_unsigned(&sh, shb, sizeof shb, &u1);
    make_server_hello(&sh, 64, 3309, 0x02);
    encode_server_hello_unsigned(&sh, shb, sizeof shb, &u64);
    encode_server_hello(&sh, shb, sizeof shb, &full);
    CHECK(n1 == 1267u && n64 == 1330u && u1 == 1171u && u64 == 1234u && full == 4545u,
          "v2-4 W2: encoded sizes are 1267/1330 (ClientHello id 1/64), 1171/1234 (SH_unsigned), 4545 (full SH)");
    CHECK(transcript_server_hello_unsigned_len(1) == 1171u && transcript_server_hello_unsigned_len(64) == 1234u &&
              transcript_server_hello_unsigned_len(0) == 0u && transcript_server_hello_unsigned_len(65) == 0u,
          "v2-4 W2: transcript_server_hello_unsigned_len is 1171/1234 in range and 0 outside it");

    /* W3 -- field ORDER, read at literal offsets. Each field gets a
     * distinct constant byte, so a layout that moved mlkem_ek before
     * ephemeral_pub in BOTH the encoder and the decoder -- which every
     * round-trip test above would still pass -- is caught here. */
    memset(&ch, 0, sizeof ch);
    ch.id_len = 5;
    memset(ch.id, 0x11, 5);
    memset(ch.ephemeral_pub, 0x22, WIRE_X25519_PUB_LEN);
    memset(ch.mlkem_ek, 0x33, WIRE_MLKEM_EK_LEN);
    memset(ch.session_id, 0x44, WIRE_SESSION_ID_LEN);
    memset(ch.nonce, 0x55, WIRE_NONCE_LEN);
    size_t cn = 0;
    int layout = encode_client_hello(&ch, chb, sizeof chb, &cn) == 0 && cn == 1271u;
    {
        size_t o = 0;
        layout = layout && chb[o] == 0x01 && chb[1] == 5;
        o = 2;
        for (size_t i = 0; i < 5u; i++) {
            layout = layout && chb[o + i] == 0x11;
        }
        o += 5u;
        for (size_t i = 0; i < WIRE_X25519_PUB_LEN; i++) {
            layout = layout && chb[o + i] == 0x22;
        }
        o += WIRE_X25519_PUB_LEN;
        for (size_t i = 0; i < WIRE_MLKEM_EK_LEN; i++) {
            layout = layout && chb[o + i] == 0x33;
        }
        o += WIRE_MLKEM_EK_LEN;
        for (size_t i = 0; i < WIRE_SESSION_ID_LEN; i++) {
            layout = layout && chb[o + i] == 0x44;
        }
        o += WIRE_SESSION_ID_LEN;
        for (size_t i = 0; i < WIRE_NONCE_LEN; i++) {
            layout = layout && chb[o + i] == 0x55;
        }
        layout = layout && (o + WIRE_NONCE_LEN) == cn;
    }
    CHECK(layout, "v2-4 W3: ClientHello bytes are type|id_len|id|x25519_pub|mlkem_ek|session_id|nonce, at literal "
                  "offsets");

    memset(&sh, 0, sizeof sh);
    sh.id_len = 3;
    memset(sh.id, 0x66, 3);
    memset(sh.ephemeral_pub, 0x77, WIRE_X25519_PUB_LEN);
    memset(sh.mlkem_ct, 0x88, WIRE_MLKEM_CT_LEN);
    memset(sh.nonce, 0x99, WIRE_NONCE_LEN);
    memset(sh.session_id_echo, 0xAA, WIRE_SESSION_ID_LEN);
    sh.sig_len = 8;
    memset(sh.sig, 0xBB, 8);
    size_t sn = 0;
    int slayout = encode_server_hello(&sh, shb, sizeof shb, &sn) == 0 && sn == 1173u + 2u + 8u;
    {
        size_t o = 0;
        slayout = slayout && shb[0] == 0x02 && shb[1] == 3;
        o = 2;
        for (size_t i = 0; i < 3u; i++) {
            slayout = slayout && shb[o + i] == 0x66;
        }
        o += 3u;
        for (size_t i = 0; i < WIRE_X25519_PUB_LEN; i++) {
            slayout = slayout && shb[o + i] == 0x77;
        }
        o += WIRE_X25519_PUB_LEN;
        for (size_t i = 0; i < WIRE_MLKEM_CT_LEN; i++) {
            slayout = slayout && shb[o + i] == 0x88;
        }
        o += WIRE_MLKEM_CT_LEN;
        for (size_t i = 0; i < WIRE_NONCE_LEN; i++) {
            slayout = slayout && shb[o + i] == 0x99;
        }
        o += WIRE_NONCE_LEN;
        for (size_t i = 0; i < WIRE_SESSION_ID_LEN; i++) {
            slayout = slayout && shb[o + i] == 0xAA;
        }
        o += WIRE_SESSION_ID_LEN;
        /* the signature length field sits exactly at the end of the
         * unsigned prefix: 1173 = 2+3+32+1088+32+16 */
        slayout = slayout && o == 1173u && shb[o] == 0x00 && shb[o + 1u] == 0x08 && shb[o + 2u] == 0xBB;
    }
    CHECK(slayout, "v2-4 W3: ServerHello_unsigned bytes are type|id_len|id|x25519_pub|mlkem_ct|nonce|session_id_echo, "
                   "with sig_len at offset 1173");
}

static void test_v24_new_field_binding(void) {
    /* W4 -- the new fields are inside what the signatures cover. Flipping
     * the first and last byte of each must change every digest that
     * includes it. Without this, a decoder that silently dropped ek/ct
     * from the hashed bytes would go unnoticed. */
    client_hello_t ch;
    server_hello_t sh;
    make_client_hello(&ch, 10, 0xC1);
    make_server_hello(&sh, 12, 200, 0xD1);

    uint8_t chb[CLIENT_HELLO_MAX_ENCODED_LEN], shb[SERVER_HELLO_MAX_ENCODED_LEN],
        shu[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
    size_t chn = 0, shn = 0, shun = 0;
    encode_client_hello(&ch, chb, sizeof chb, &chn);
    encode_server_hello(&sh, shb, sizeof shb, &shn);
    encode_server_hello_unsigned(&sh, shu, sizeof shu, &shun);

    uint8_t base_sa[32], base_ca[32], base_hid[16];
    transcript_hash_server_auth(chb, chn, shu, shun, base_sa);
    transcript_hash_client_auth(chb, chn, shb, shn, base_ca);
    transcript_handshake_id(chb, chn, shb, shn, base_hid);

    int ek_binds = 1;
    const size_t ek_probe[2] = {0u, WIRE_MLKEM_EK_LEN - 1u};
    for (size_t p = 0; p < 2; p++) {
        client_hello_t ch2 = ch;
        ch2.mlkem_ek[ek_probe[p]] ^= 0x01;
        uint8_t b2[CLIENT_HELLO_MAX_ENCODED_LEN];
        size_t n2 = 0;
        uint8_t sa2[32], ca2[32], hid2[16];
        encode_client_hello(&ch2, b2, sizeof b2, &n2);
        transcript_hash_server_auth(b2, n2, shu, shun, sa2);
        transcript_hash_client_auth(b2, n2, shb, shn, ca2);
        transcript_handshake_id(b2, n2, shb, shn, hid2);
        ek_binds = ek_binds && memcmp(sa2, base_sa, 32) != 0 && memcmp(ca2, base_ca, 32) != 0 &&
                   memcmp(hid2, base_hid, 16) != 0;
    }
    CHECK(ek_binds, "v2-4 W4: flipping mlkem_ek[0] or mlkem_ek[1183] changes TH_server_auth, TH_client_auth and "
                    "handshake_id");

    int ct_binds = 1;
    const size_t ct_probe[2] = {0u, WIRE_MLKEM_CT_LEN - 1u};
    for (size_t p = 0; p < 2; p++) {
        server_hello_t sh2 = sh;
        sh2.mlkem_ct[ct_probe[p]] ^= 0x01;
        uint8_t u2[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN], f2[SERVER_HELLO_MAX_ENCODED_LEN];
        size_t un2 = 0, fn2 = 0;
        uint8_t sa2[32], ca2[32];
        encode_server_hello_unsigned(&sh2, u2, sizeof u2, &un2);
        encode_server_hello(&sh2, f2, sizeof f2, &fn2);
        transcript_hash_server_auth(chb, chn, u2, un2, sa2);
        transcript_hash_client_auth(chb, chn, f2, fn2, ca2);
        ct_binds = ct_binds && memcmp(sa2, base_sa, 32) != 0 && memcmp(ca2, base_ca, 32) != 0;
    }
    CHECK(ct_binds, "v2-4 W4: flipping mlkem_ct[0] or mlkem_ct[1087] changes TH_server_auth (it is inside "
                    "ServerHello_unsigned) and TH_client_auth");
}

static void test_v24_v1_messages_rejected(void) {
    /* W5 -- spec-v2 6.3.4: a v1 message MUST fail a v2 decoder. Both
     * messages are built from literal bytes in the v1 layout, not by
     * any code in this repository, since v1's encoders no longer exist. */
    client_hello_t ch;
    server_hello_t sh;
    size_t consumed = 0;

    /* v1 ClientHello: 01 | 05 | "alice" | 32 | 16 | 32 = 87 bytes. */
    uint8_t v1_ch[87];
    memset(v1_ch, 0x5a, sizeof v1_ch);
    v1_ch[0] = 0x01;
    v1_ch[1] = 0x05;
    memcpy(v1_ch + 2, "alice", 5);
    CHECK(decode_client_hello(v1_ch, sizeof v1_ch, &ch, &consumed) != 0,
          "v2-4 W5: an 87-byte v1 ClientHello is rejected by the v2 decoder (short by mlkem_ek)");

    /* v1 ServerHello: 02 | 03 | "bob" | 32 | 32 | 16 | 0c ed | 3309
     * signature bytes = 3396. The v2 decoder reads sig_len at offset
     * 1173, which lands inside the old signature (0x5a5a = 23130 > 3309),
     * so the rejection is deterministic rather than length-dependent. */
    uint8_t v1_sh[3396];
    memset(v1_sh, 0x5a, sizeof v1_sh);
    v1_sh[0] = 0x02;
    v1_sh[1] = 0x03;
    memcpy(v1_sh + 2, "bob", 3);
    v1_sh[85] = 0x0c;
    v1_sh[86] = 0xed;
    CHECK(v1_sh[1173] == 0x5a && v1_sh[1174] == 0x5a,
          "v2-4 W5 (precondition): the v2 sig_len offset falls inside the v1 signature");
    CHECK(decode_server_hello(v1_sh, sizeof v1_sh, &sh, &consumed) != 0,
          "v2-4 W5: a 3396-byte v1 ServerHello is rejected by the v2 decoder");

    /* The honest boundary of that claim, in this file's usual style: the
     * v1 ClientHello padded with 1184 bytes has exactly a v2 length and
     * DOES decode structurally -- a byte layout cannot tell versions
     * apart, it can only fail on length. What separates the versions
     * cryptographically is the /v2/ labels in every transcript hash, so
     * such a message cannot produce a signature either peer accepts. */
    uint8_t padded[1271];
    memset(padded, 0, sizeof padded);
    memcpy(padded, v1_ch, sizeof v1_ch);
    CHECK(decode_client_hello(padded, sizeof padded, &ch, &consumed) == 0 && consumed == sizeof padded,
          "v2-4 W5: a v1 ClientHello padded to 1271 bytes decodes structurally -- version separation is the /v2/ "
          "labels, not the layout (documented, not enforced here)");
}

/* ---------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------- */

/* =========================================================================
 * STEP 4 -- handshake state machine, keystore, pending ledger, KDF info.
 * Every check is labelled "step4 T<n>" after the numbered test plan, so a
 * mutation's intended target can be identified from the output alone.
 * ======================================================================= */

/* Opaque identities -- deliberately NOT NUL-terminated C strings. */
static const uint8_t ID_A[] = {'a', 'l', 'i', 'c', 'e'};
static const uint8_t ID_B[] = {'b', 'o', 'b'};
static const uint8_t ID_C[] = {'c', 'a', 'r', 'o', 'l'};

/* Vendored verbatim from libsodium's test/default/scalarmult.c (the same
 * vector Step 2's tests/test_vectors.c uses): crypto_scalarmult() rejects
 * this known small-order point. */
static const uint8_t SMALL_ORDER_POINT[32] = {
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa,
    0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
    0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
};

static mldsa_keypair_t g_kp_a, g_kp_b, g_kp_c;
static keystore_t g_ks;        /* pins A, B and C */
static keystore_t g_ks_b_only; /* pins B only: A is unknown */

static void fatal(const char *what) {
    fprintf(stderr, "FATAL fixture failure: %s\n", what);
    exit(EXIT_FAILURE);
}

/* ---- Controllable monotonic clock ---------------------------------------
 * Normally returns `now`. When armed, the next `calls_until_switch` reads
 * return `now`, and every read after that returns `switch_to`. This makes
 * "the entry expires partway through one call" deterministic, with no
 * sleeps and no test hooks in production code. */
typedef struct {
    uint64_t now;
    uint64_t switch_to;
    int calls_until_switch;
    int armed;
} test_clock_t;

static test_clock_t g_clock;
#define TEST_BASE_MS 1000u
#define TEST_TTL_MS 5000u

static uint64_t test_clock_fn(void *p) {
    test_clock_t *c = (test_clock_t *)p;
    if (c->armed) {
        if (c->calls_until_switch > 0) {
            c->calls_until_switch--;
            return c->now;
        }
        c->now = c->switch_to;
        c->armed = 0;
    }
    return c->now;
}

static void clock_reset(void) {
    memset(&g_clock, 0, sizeof(g_clock));
    g_clock.now = TEST_BASE_MS;
}

/* Expire everything live at the next-but-`live_reads` clock read. */
static void clock_arm_expiry_after(int live_reads) {
    g_clock.calls_until_switch = live_reads;
    g_clock.switch_to = g_clock.now + TEST_TTL_MS + 1u;
    g_clock.armed = 1;
}

static void store_fresh(handshake_pending_store_t *s, size_t capacity) {
    if (handshake_pending_store_init(s, capacity, TEST_TTL_MS, test_clock_fn, &g_clock) != PENDING_OK) {
        fatal("handshake_pending_store_init");
    }
}

/* ---- Handshake pair --------------------------------------------------- */

typedef struct {
    handshake_ctx_t ini; /* A, dialing B */
    handshake_ctx_t res; /* B */
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len;
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len;
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ca_len;
} pair_t;

static void pair_init(pair_t *p, handshake_pending_store_t *store, const keystore_t *res_ks) {
    memset(p, 0, sizeof(*p));
    if (handshake_initiator_init(&p->ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK) {
        fatal("handshake_initiator_init");
    }
    if (handshake_responder_init(&p->res, ID_B, sizeof(ID_B), &g_kp_b, res_ks, store) != HANDSHAKE_OK) {
        fatal("handshake_responder_init");
    }
}

static void pair_wipe(pair_t *p) {
    handshake_ctx_wipe(&p->ini);
    handshake_ctx_wipe(&p->res);
}

static handshake_status_t pair_to_server_hello(pair_t *p) {
    handshake_status_t st = handshake_initiator_create_client_hello(&p->ini, p->ch, sizeof(p->ch), &p->ch_len);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    st = handshake_responder_accept_client_hello(&p->res, p->ch, p->ch_len);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    return handshake_responder_create_server_hello(&p->res, p->sh, sizeof(p->sh), &p->sh_len);
}

static handshake_status_t pair_to_client_auth(pair_t *p) {
    handshake_status_t st = pair_to_server_hello(p);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    st = handshake_initiator_verify_server_hello(&p->ini, p->sh, p->sh_len);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    return handshake_initiator_create_client_auth(&p->ini, p->ca, sizeof(p->ca), &p->ca_len);
}

static handshake_status_t pair_finish_both(pair_t *p) {
    handshake_status_t st = handshake_responder_verify_client_auth(&p->res, p->ca, p->ca_len);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    st = handshake_responder_finish(&p->res);
    if (st != HANDSHAKE_OK) {
        return st;
    }
    return handshake_initiator_finish(&p->ini);
}

/* handshake_id from the exact wire bytes. */
static void hid_of(const uint8_t *ch, size_t ch_len, const uint8_t *sh, size_t sh_len, uint8_t hid[16]) {
    if (transcript_handshake_id(ch, ch_len, sh, sh_len, hid) != 0) {
        fatal("transcript_handshake_id");
    }
}

/* True iff neither key accessor succeeds, both NULL their output, and no
 * key is flagged committed. keys_committed is read white-box: the struct
 * is visible only because storage is caller-provided. */
static int no_keys_exposed(const handshake_ctx_t *ctx) {
    static const uint8_t sentinel = 0;
    const uint8_t *k1 = &sentinel;
    const uint8_t *k2 = &sentinel;
    const handshake_status_t a = handshake_session_key_c2s(ctx, &k1);
    const handshake_status_t b = handshake_session_key_s2c(ctx, &k2);
    return a != HANDSHAKE_OK && b != HANDSHAKE_OK && k1 == NULL && k2 == NULL && !ctx->keys_committed;
}

/* No keys AND not peer-confirmed: what every pre-ESTABLISHED state owes. */
static int pre_established_ok(const handshake_ctx_t *ctx) {
    return no_keys_exposed(ctx) && !handshake_is_peer_confirmed(ctx);
}

/* ---- Message builders for a test-driven ("manual") peer ---------------- */

/* mlkem_ek may be NULL, which builds a ClientHello whose encapsulation key
 * is all zeros -- structurally valid, and rejected by encapsulation's
 * FIPS 203 7.2 check, which several tests rely on. */
static int build_client_hello(const uint8_t *id, size_t id_len, const uint8_t eph_pub[32],
                              const uint8_t *mlkem_ek, uint8_t *out, size_t cap, size_t *len) {
    client_hello_t ch;
    memset(&ch, 0, sizeof(ch));
    memcpy(ch.id, id, id_len);
    ch.id_len = (uint8_t)id_len;
    memcpy(ch.ephemeral_pub, eph_pub, 32);
    if (mlkem_ek != NULL) {
        memcpy(ch.mlkem_ek, mlkem_ek, WIRE_MLKEM_EK_LEN);
    }
    randombytes_buf(ch.session_id, WIRE_SESSION_ID_LEN);
    randombytes_buf(ch.nonce, WIRE_NONCE_LEN);
    return encode_client_hello(&ch, out, cap, len);
}

/* Encapsulates to the encapsulation key carried by a ClientHello, the way
 * a responder would: the test then HOLDS ss_k and can predict the keys. */
static int encaps_for(const uint8_t *ch, size_t ch_len, uint8_t ct_out[WIRE_MLKEM_CT_LEN],
                      uint8_t ss_out[32]) {
    client_hello_t msg;
    size_t consumed = 0;
    if (decode_client_hello(ch, ch_len, &msg, &consumed) != 0) {
        return -1;
    }
    return mlkem_encaps(ct_out, ss_out, msg.mlkem_ek);
}

/* The v2 traffic keys, built from the literal spec-v2 6.3.7 layout with
 * kex_hkdf_sha256 -- deliberately independent of kex_derive_session_key_v2
 * AND of handshake.c, so a symmetric bug in either (dropping ss_k,
 * swapping the secrets, omitting the transcript digest) is caught rather
 * than reproduced. a_id is always the initiator. */
static void expected_keys(const uint8_t ss_x[32], const uint8_t ss_k[32], const uint8_t sid[16],
                          const uint8_t *a_id, size_t a_len, const uint8_t *b_id, size_t b_len,
                          const uint8_t th[32], uint8_t c2s[32], uint8_t s2c[32]) {
    static const uint8_t label[17] = {'m', 'l', 'd', 's', 'a', '-', 'a', 'u', 't',
                                      'h', '/', 'v', '2', '/', 'k', 'd', 'f'};
    const uint8_t dirs[2] = {KEX_DIR_C2S, KEX_DIR_S2C};
    uint8_t *outs[2] = {c2s, s2c};
    uint8_t ikm[64];
    memcpy(ikm, ss_x, 32);
    memcpy(ikm + 32, ss_k, 32);
    for (size_t d = 0; d < 2; d++) {
        uint8_t info[KEX_KDF_V2_INFO_MAX_LEN];
        size_t off = 0;
        memcpy(info, label, sizeof(label));
        off += sizeof(label);
        info[off++] = 0x00;
        info[off++] = (uint8_t)a_len;
        memcpy(info + off, a_id, a_len);
        off += a_len;
        info[off++] = (uint8_t)b_len;
        memcpy(info + off, b_id, b_len);
        off += b_len;
        memcpy(info + off, th, 32);
        off += 32;
        info[off++] = dirs[d];
        if (kex_hkdf_sha256(outs[d], 32, ikm, sizeof(ikm), sid, 16, info, off) != 0) {
            fatal("expected_keys: kex_hkdf_sha256");
        }
    }
    sodium_memzero(ikm, sizeof(ikm));
}

/* The exit criterion of V2-5: every per-handshake hybrid secret is gone.
 * Reads context internals deliberately -- there is no public accessor for
 * "is this wiped", and a wipe that only the implementation can see is
 * exactly what a mutation would remove. */
static int hybrid_secrets_wiped(const handshake_ctx_t *ctx) {
    return ctx->kem.secret_key == NULL && ctx->ss_kem == NULL &&
           sodium_is_zero(ctx->peer_mlkem_ct, sizeof(ctx->peer_mlkem_ct));
}

/* A VALIDLY SIGNED ServerHello answering `ch`, with every field chosen by
 * the test -- so the one field under test is the only thing that can fail.
 * sig_B is computed over the exact CH bytes || SH_unsigned. */
/* mlkem_ct may be NULL for an all-zero ciphertext. The signature is
 * computed over whatever ct is passed, so a caller that tampers with the
 * ciphertext BEFORE calling gets a validly-signed tampered message -- the
 * only way to reach implicit rejection without forging sig_B. */
static int build_signed_server_hello(const uint8_t *ch, size_t ch_len,
                                     const uint8_t *id, size_t id_len, const mldsa_keypair_t *kp,
                                     const uint8_t eph_pub[32], const uint8_t *mlkem_ct,
                                     const uint8_t echo[16],
                                     uint8_t *out, size_t cap, size_t *len) {
    server_hello_t sh;
    uint8_t shu[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
    uint8_t th[32];
    size_t shu_len = 0;
    size_t sig_len = 0;
    memset(&sh, 0, sizeof(sh));
    memcpy(sh.id, id, id_len);
    sh.id_len = (uint8_t)id_len;
    memcpy(sh.ephemeral_pub, eph_pub, 32);
    if (mlkem_ct != NULL) {
        memcpy(sh.mlkem_ct, mlkem_ct, WIRE_MLKEM_CT_LEN);
    }
    randombytes_buf(sh.nonce, WIRE_NONCE_LEN);
    memcpy(sh.session_id_echo, echo, WIRE_SESSION_ID_LEN);
    if (encode_server_hello_unsigned(&sh, shu, sizeof(shu), &shu_len) != 0 ||
        transcript_hash_server_auth(ch, ch_len, shu, shu_len, th) != 0 ||
        mldsa_sign(sh.sig, &sig_len, th, sizeof(th), kp) != 0) {
        return -1;
    }
    sh.sig_len = (uint16_t)sig_len;
    return encode_server_hello(&sh, out, cap, len);
}

/* A VALIDLY SIGNED ClientAuth over the exact CH || SH bytes. */
static int build_signed_client_auth(const uint8_t *ch, size_t ch_len, const uint8_t *sh, size_t sh_len,
                                    const mldsa_keypair_t *kp, uint8_t *out, size_t cap, size_t *len) {
    client_auth_t ca;
    uint8_t th[32];
    size_t sig_len = 0;
    memset(&ca, 0, sizeof(ca));
    if (transcript_hash_client_auth(ch, ch_len, sh, sh_len, th) != 0 ||
        transcript_handshake_id(ch, ch_len, sh, sh_len, ca.handshake_id) != 0 ||
        mldsa_sign(ca.sig, &sig_len, th, sizeof(th), kp) != 0) {
        return -1;
    }
    ca.sig_len = (uint16_t)sig_len;
    return encode_client_auth(&ca, out, cap, len);
}

static void session_id_of(const uint8_t *ch, size_t ch_len, uint8_t sid[16]) {
    client_hello_t msg;
    size_t consumed = 0;
    if (decode_client_hello(ch, ch_len, &msg, &consumed) != 0) {
        fatal("decode_client_hello");
    }
    memcpy(sid, msg.session_id, WIRE_SESSION_ID_LEN);
}

/* Byte offsets inside encoded messages, for tampering. */
#define CA_HANDSHAKE_ID_OFFSET 1u
#define CA_SIG_OFFSET (1u + WIRE_HANDSHAKE_ID_LEN + 2u)

/* ---- T1 / T15 / T20 / T21: happy path ---------------------------------- */

static void test_step4_happy_path(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(handshake_get_state(&p.ini) == HANDSHAKE_STATE_NEW && handshake_get_state(&p.res) == HANDSHAKE_STATE_NEW,
          "step4 T1: both contexts start NEW");
    CHECK(pre_established_ok(&p.ini) && pre_established_ok(&p.res),
          "step4 T15/T20: no keys, not peer-confirmed in NEW (both roles)");

    handshake_status_t st = handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.ini) == HANDSHAKE_STATE_CLIENT_HELLO_CREATED,
          "step4 T1: initiator creates ClientHello -> CLIENT_HELLO_CREATED");
    CHECK(pre_established_ok(&p.ini), "step4 T15/T20: no keys in initiator CLIENT_HELLO_CREATED");

    st = handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED,
          "step4 T1: responder accepts ClientHello -> CLIENT_HELLO_ACCEPTED");
    CHECK(pre_established_ok(&p.res), "step4 T15/T20: no keys in responder CLIENT_HELLO_ACCEPTED");

    st = handshake_responder_create_server_hello(&p.res, p.sh, sizeof(p.sh), &p.sh_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T1: responder creates ServerHello -> SERVER_HELLO_CREATED");
    CHECK(pre_established_ok(&p.res), "step4 T15/T20: no keys in responder SERVER_HELLO_CREATED");

    st = handshake_initiator_verify_server_hello(&p.ini, p.sh, p.sh_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.ini) == HANDSHAKE_STATE_SERVER_HELLO_VERIFIED,
          "step4 T1: initiator verifies ServerHello -> SERVER_HELLO_VERIFIED");
    CHECK(pre_established_ok(&p.ini),
          "step4 T15/T20: NO traffic keys in initiator SERVER_HELLO_VERIFIED (mutual auth incomplete)");

    st = handshake_initiator_create_client_auth(&p.ini, p.ca, sizeof(p.ca), &p.ca_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.ini) == HANDSHAKE_STATE_CLIENT_AUTH_CREATED,
          "step4 T1: initiator creates ClientAuth -> CLIENT_AUTH_CREATED");
    CHECK(pre_established_ok(&p.ini), "step4 T15/T20: no keys in initiator CLIENT_AUTH_CREATED");

    st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED,
          "step4 T1: responder verifies ClientAuth -> CLIENT_AUTH_VERIFIED");
    {
        /* Keys ARE committed to context state at CLIENT_AUTH_VERIFIED (so
         * no_keys_exposed(), which also checks the committed flag, would
         * rightly be false here) -- but they must NOT be retrievable. */
        const uint8_t *k = NULL;
        CHECK(handshake_session_key_c2s(&p.res, &k) == HANDSHAKE_ERR_UNEXPECTED_STATE && k == NULL &&
                  !handshake_is_peer_confirmed(&p.res),
              "step4 T15/T20: responder keys not retrievable in CLIENT_AUTH_VERIFIED");
    }

    st = handshake_responder_finish(&p.res);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_ESTABLISHED,
          "step4 T1: responder finish -> ESTABLISHED");
    st = handshake_initiator_finish(&p.ini);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.ini) == HANDSHAKE_STATE_ESTABLISHED,
          "step4 T1: initiator finish -> ESTABLISHED");

    const uint8_t *ic2s = NULL, *is2c = NULL, *rc2s = NULL, *rs2c = NULL;
    const int got = handshake_session_key_c2s(&p.ini, &ic2s) == HANDSHAKE_OK &&
                    handshake_session_key_s2c(&p.ini, &is2c) == HANDSHAKE_OK &&
                    handshake_session_key_c2s(&p.res, &rc2s) == HANDSHAKE_OK &&
                    handshake_session_key_s2c(&p.res, &rs2c) == HANDSHAKE_OK;
    CHECK(got, "step4 T1: all four key accessors succeed in ESTABLISHED");
    if (got) {
        CHECK(sodium_memcmp(ic2s, rc2s, KEX_SESSION_KEY_BYTES) == 0 &&
                  sodium_memcmp(is2c, rs2c, KEX_SESSION_KEY_BYTES) == 0,
              "step4 T1: initiator and responder derive identical c2s and identical s2c");
        CHECK(sodium_memcmp(ic2s, is2c, KEX_SESSION_KEY_BYTES) != 0, "step4 T1: c2s != s2c");
        CHECK(!sodium_is_zero(ic2s, KEX_SESSION_KEY_BYTES) && !sodium_is_zero(is2c, KEX_SESSION_KEY_BYTES),
              "step4 T1: session keys are non-zero");
        CHECK(p.ini.eph.private_key == NULL,
              "step4 T21: initiator retained no shared secret, recomputed it in finish(), keys match, "
              "and its ephemeral scalar is now wiped");
        CHECK(hybrid_secrets_wiped(&p.ini) && hybrid_secrets_wiped(&p.res),
              "v2-5 T21: ...and both hybrid secrets (dk, ss_kem) and the retained ciphertext are wiped too");
    }
    CHECK(!handshake_is_peer_confirmed(&p.ini),
          "step4 T20: initiator ESTABLISHED is NOT peer-confirmed (optimistic)");
    CHECK(handshake_is_peer_confirmed(&p.res), "step4 T20: responder ESTABLISHED IS peer-confirmed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T2: unknown peer id ----------------------------------------------- */

static void test_step4_unknown_peer(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks_b_only);

    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK,
          "step4 T2: fixture ClientHello created");
    const handshake_status_t st = handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len);
    CHECK(st == HANDSHAKE_ERR_UNKNOWN_IDENTITY && handshake_get_state(&p.res) == HANDSHAKE_STATE_FAILED,
          "step4 T2: unpinned initiator -> UNKNOWN_IDENTITY, responder FAILED");
    CHECK(handshake_pending_active_count(&store) == 0, "step4 T2: no pending entry was created");
    CHECK(no_keys_exposed(&p.res), "step4 T15 (after T2): no keys exposed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T3: session_id_echo mismatch, validly signed ---------------------- */

static void test_step4_session_id_echo_mismatch(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    kex_keypair_t eph;
    uint8_t sid[16];
    uint8_t ct[WIRE_MLKEM_CT_LEN];
    uint8_t ss_k[32];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK,
          "step4 T3: fixture ClientHello created");
    session_id_of(p.ch, p.ch_len, sid);
    sid[0] ^= 0x01; /* the ONLY wrong field */
    if (encaps_for(p.ch, p.ch_len, ct, ss_k) != 0 || kex_keypair_generate(&eph) != 0 ||
        build_signed_server_hello(p.ch, p.ch_len, ID_B, sizeof(ID_B), &g_kp_b, eph.public_key, ct, sid,
                                  sh, sizeof(sh), &sh_len) != 0) {
        fatal("T3 fixture");
    }

    const handshake_status_t st = handshake_initiator_verify_server_hello(&p.ini, sh, sh_len);
    CHECK(st == HANDSHAKE_ERR_SESSION_ID_MISMATCH && handshake_get_state(&p.ini) == HANDSHAKE_STATE_FAILED,
          "step4 T3: validly signed ServerHello with wrong session_id_echo -> SESSION_ID_MISMATCH, FAILED");
    CHECK(no_keys_exposed(&p.ini), "step4 T15 (after T3): no keys exposed");

    kex_keypair_free(&eph);
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T4: tampered sig_b ------------------------------------------------ */

static void test_step4_tampered_sig_b(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_server_hello(&p) == HANDSHAKE_OK, "step4 T4: fixture ServerHello created");
    const size_t sig_off = transcript_server_hello_unsigned_len((uint8_t)sizeof(ID_B)) + 2u;
    p.sh[sig_off + 10u] ^= 0x01; /* inside sig_b only */

    const handshake_status_t st = handshake_initiator_verify_server_hello(&p.ini, p.sh, p.sh_len);
    CHECK(st == HANDSHAKE_ERR_SIGNATURE && handshake_get_state(&p.ini) == HANDSHAKE_STATE_FAILED,
          "step4 T4: tampered sig_b -> SIGNATURE, initiator FAILED");
    CHECK(no_keys_exposed(&p.ini), "step4 T15 (after T4): no keys exposed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T5: unexpected responder identity, validly signed ----------------- */

static void test_step4_peer_identity_mismatch(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    kex_keypair_t eph;
    uint8_t sid[16];
    uint8_t ct[WIRE_MLKEM_CT_LEN];
    uint8_t ss_k[32];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks); /* initiator dials B */

    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK,
          "step4 T5: fixture ClientHello created");
    session_id_of(p.ch, p.ch_len, sid); /* correct echo */
    /* C is pinned and signs correctly: without identity binding this passes. */
    if (encaps_for(p.ch, p.ch_len, ct, ss_k) != 0 || kex_keypair_generate(&eph) != 0 ||
        build_signed_server_hello(p.ch, p.ch_len, ID_C, sizeof(ID_C), &g_kp_c, eph.public_key, ct, sid,
                                  sh, sizeof(sh), &sh_len) != 0) {
        fatal("T5 fixture");
    }

    const handshake_status_t st = handshake_initiator_verify_server_hello(&p.ini, sh, sh_len);
    CHECK(st == HANDSHAKE_ERR_PEER_IDENTITY_MISMATCH && handshake_get_state(&p.ini) == HANDSHAKE_STATE_FAILED,
          "step4 T5: ServerHello from pinned-but-undialed peer C -> PEER_IDENTITY_MISMATCH, FAILED");
    CHECK(no_keys_exposed(&p.ini), "step4 T15 (after T5): no keys exposed");

    kex_keypair_free(&eph);
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T6: mutated handshake_id, then the genuine ClientAuth ------------- */

static void test_step4_mutated_handshake_id(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t bad[CLIENT_AUTH_MAX_ENCODED_LEN];
    uint8_t hid[16];
    pending_slot_state_t slot;
    uint8_t count = 0xFF;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T6: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    memcpy(bad, p.ca, p.ca_len);
    bad[CA_HANDSHAKE_ID_OFFSET + 3u] ^= 0x01; /* sig_A stays valid: it does not cover this field */

    handshake_status_t st = handshake_responder_verify_client_auth(&p.res, bad, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH &&
              handshake_get_state(&p.res) == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T6: mutated handshake_id -> HANDSHAKE_ID_MISMATCH, responder stays SERVER_HELLO_CREATED");
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_OK && slot == PENDING_SLOT_ACTIVE &&
              count == 0,
          "step4 T6: genuine entry untouched (ACTIVE, failure_count 0)");
    CHECK(no_keys_exposed(&p.res), "step4 T15 (after T6): no keys exposed");

    st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED,
          "step4 T6: the genuine ClientAuth still succeeds afterwards");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T7: one forged sig_A, then the legitimate ClientAuth ------------- */

static void test_step4_one_forged_then_legit(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t bad[CLIENT_AUTH_MAX_ENCODED_LEN];
    uint8_t hid[16];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T7: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    memcpy(bad, p.ca, p.ca_len);
    bad[CA_SIG_OFFSET + 10u] ^= 0x01;

    handshake_status_t st = handshake_responder_verify_client_auth(&p.res, bad, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_SIGNATURE && handshake_get_state(&p.res) == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T7: one forged sig_A -> SIGNATURE (retryable), responder stays SERVER_HELLO_CREATED");
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_OK && slot == PENDING_SLOT_ACTIVE &&
              count == 1,
          "step4 T7: entry preserved and counted (ACTIVE, failure_count 1)");
    CHECK(no_keys_exposed(&p.res), "step4 T15 (after T7): no keys exposed");

    st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_OK && handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED,
          "step4 T7: the legitimate ClientAuth then succeeds");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T8: exactly three invalid matching-id ClientAuths ---------------- */

static void test_step4_three_forged(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t bad[3][CLIENT_AUTH_MAX_ENCODED_LEN];
    uint8_t hid[16];
    uint8_t scratch[32];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T8: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    for (size_t i = 0; i < 3; i++) {
        memcpy(bad[i], p.ca, p.ca_len);
        bad[i][CA_SIG_OFFSET + 10u + 10u * i] ^= 0x01; /* three different forgeries */
    }

    const handshake_status_t s1 = handshake_responder_verify_client_auth(&p.res, bad[0], p.ca_len);
    const handshake_state_t a1 = handshake_get_state(&p.res);
    const handshake_status_t s2 = handshake_responder_verify_client_auth(&p.res, bad[1], p.ca_len);
    const handshake_state_t a2 = handshake_get_state(&p.res);
    const handshake_status_t s3 = handshake_responder_verify_client_auth(&p.res, bad[2], p.ca_len);
    const handshake_state_t a3 = handshake_get_state(&p.res);

    CHECK(s1 == HANDSHAKE_ERR_SIGNATURE && a1 == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T8: forgery #1 -> SIGNATURE, still SERVER_HELLO_CREATED");
    CHECK(s2 == HANDSHAKE_ERR_SIGNATURE && a2 == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T8: forgery #2 -> SIGNATURE, still SERVER_HELLO_CREATED");
    CHECK(s3 == HANDSHAKE_ERR_AUTH_FAILURE_LIMIT && a3 == HANDSHAKE_STATE_FAILED,
          "step4 T8: forgery #3 -> AUTH_FAILURE_LIMIT, terminal FAILED");
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_ERR_AUTH_LIMIT &&
              slot == PENDING_SLOT_AUTH_LIMITED && count == 3,
          "step4 T8: entry tombstoned AUTH_LIMITED with failure_count 3");

    const handshake_status_t s4 = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(s4 == HANDSHAKE_ERR_UNEXPECTED_STATE, "step4 T8: genuine ClientAuth afterwards -> UNEXPECTED_STATE");
    CHECK(handshake_pending_get_digest(&store, hid, scratch) == PENDING_ERR_AUTH_LIMIT,
          "step4 T8: store layer reports PENDING_ERR_AUTH_LIMIT");
    CHECK(no_keys_exposed(&p.res), "step4 T15 (after T8): no keys exposed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T9: replay after successful consumption ------------------------- */

static void test_step4_replay_after_success(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t hid[16];
    uint8_t scratch[32];
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T9: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    CHECK(handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len) == HANDSHAKE_OK,
          "step4 T9: first ClientAuth accepted");

    handshake_status_t st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_UNEXPECTED_STATE &&
              handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED,
          "step4 T9: replay (context layer) -> UNEXPECTED_STATE, state unchanged");
    CHECK(handshake_pending_get_digest(&store, hid, scratch) == PENDING_ERR_CONSUMED,
          "step4 T9: replay (store layer) -> PENDING_ERR_CONSUMED");

    CHECK(handshake_responder_finish(&p.res) == HANDSHAKE_OK, "step4 T9: responder finish");
    st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_UNEXPECTED_STATE && handshake_get_state(&p.res) == HANDSHAKE_STATE_ESTABLISHED,
          "step4 T9: replay after ESTABLISHED -> UNEXPECTED_STATE, state unchanged");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T10: duplicate ClientHello, two responders, one shared store ----- */

static int expected_responder_keys(const kex_keypair_t *ini_eph, const mlkem_keypair_t *ini_kem,
                                   const uint8_t *ch, size_t ch_len,
                                   const uint8_t *sh, size_t sh_len, uint8_t c2s[32], uint8_t s2c[32]) {
    server_hello_t msg;
    size_t consumed = 0;
    uint8_t sid[16];
    uint8_t ss_x[32];
    uint8_t ss_k[32];
    uint8_t th[32];
    if (decode_server_hello(sh, sh_len, &msg, &consumed) != 0) {
        return -1;
    }
    session_id_of(ch, ch_len, sid);
    /* Both halves, computed the way the initiator would: X25519 against
     * B's ephemeral key, and decapsulation of the ciphertext B returned. */
    if (kex_shared_secret(ss_x, ini_eph, msg.ephemeral_pub) != 0 ||
        mlkem_decaps(ss_k, msg.mlkem_ct, ini_kem) != 0 ||
        transcript_hash_client_auth(ch, ch_len, sh, sh_len, th) != 0) {
        sodium_memzero(ss_x, sizeof(ss_x));
        sodium_memzero(ss_k, sizeof(ss_k));
        return -1;
    }
    expected_keys(ss_x, ss_k, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, c2s, s2c);
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_k, sizeof(ss_k));
    return 0;
}

static void test_step4_duplicate_client_hello(void) {
    static handshake_pending_store_t store;
    static handshake_ctx_t r1, r2;
    static uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh1[SERVER_HELLO_MAX_ENCODED_LEN],
        sh2[SERVER_HELLO_MAX_ENCODED_LEN], ca1[CLIENT_AUTH_MAX_ENCODED_LEN], ca2[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh1_len = 0, sh2_len = 0, ca1_len = 0, ca2_len = 0;
    uint8_t hid1[16], hid2[16];
    uint8_t e1c2s[32], e1s2c[32], e2c2s[32], e2s2c[32];
    pending_slot_state_t st1s, st2s;
    uint8_t n1 = 0xFF, n2 = 0xFF;
    kex_keypair_t ini_eph; /* a test-driven initiator, so BOTH sessions' keys can be checked */
    mlkem_keypair_t ini_kem;
    clock_reset();
    store_fresh(&store, 16);

    if (kex_keypair_generate(&ini_eph) != 0 || mlkem_keypair_generate(&ini_kem) != 0 ||
        build_client_hello(ID_A, sizeof(ID_A), ini_eph.public_key, ini_kem.public_key, ch, sizeof(ch),
                           &ch_len) != 0 ||
        handshake_responder_init(&r1, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) != HANDSHAKE_OK ||
        handshake_responder_init(&r2, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) != HANDSHAKE_OK) {
        fatal("T10 fixture");
    }

    /* (a) */
    const int a_ok = handshake_responder_accept_client_hello(&r1, ch, ch_len) == HANDSHAKE_OK &&
                     handshake_responder_accept_client_hello(&r2, ch, ch_len) == HANDSHAKE_OK &&
                     handshake_responder_create_server_hello(&r1, sh1, sizeof(sh1), &sh1_len) == HANDSHAKE_OK &&
                     handshake_responder_create_server_hello(&r2, sh2, sizeof(sh2), &sh2_len) == HANDSHAKE_OK;
    CHECK(a_ok && handshake_get_state(&r1) == HANDSHAKE_STATE_SERVER_HELLO_CREATED &&
              handshake_get_state(&r2) == HANDSHAKE_STATE_SERVER_HELLO_CREATED &&
              handshake_pending_active_count(&store) == 2,
          "step4 T10(a): same ClientHello accepted by both responders; 2 active entries");
    if (!a_ok) {
        fatal("T10 setup");
    }

    /* (b) */
    hid_of(ch, ch_len, sh1, sh1_len, hid1);
    hid_of(ch, ch_len, sh2, sh2_len, hid2);
    CHECK((sh1_len != sh2_len || memcmp(sh1, sh2, sh1_len) != 0) && memcmp(hid1, hid2, 16) != 0,
          "step4 T10(b): distinct ServerHellos and distinct handshake_ids");

    if (build_signed_client_auth(ch, ch_len, sh1, sh1_len, &g_kp_a, ca1, sizeof(ca1), &ca1_len) != 0 ||
        build_signed_client_auth(ch, ch_len, sh2, sh2_len, &g_kp_a, ca2, sizeof(ca2), &ca2_len) != 0) {
        fatal("T10 ClientAuth fixtures");
    }

    /* (c) cross-delivery */
    const handshake_status_t x1 = handshake_responder_verify_client_auth(&r2, ca1, ca1_len);
    const handshake_status_t x2 = handshake_responder_verify_client_auth(&r1, ca2, ca2_len);
    CHECK(x1 == HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH && x2 == HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH &&
              handshake_get_state(&r1) == HANDSHAKE_STATE_SERVER_HELLO_CREATED &&
              handshake_get_state(&r2) == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          "step4 T10(c): cross-delivered ClientAuths -> HANDSHAKE_ID_MISMATCH, both stay SERVER_HELLO_CREATED");

    /* (d) the assertion that makes this test meaningful */
    CHECK(handshake_pending_inspect(&store, hid1, &st1s, &n1) == PENDING_OK && st1s == PENDING_SLOT_ACTIVE &&
              n1 == 0 && handshake_pending_inspect(&store, hid2, &st2s, &n2) == PENDING_OK &&
              st2s == PENDING_SLOT_ACTIVE && n2 == 0,
          "step4 T10(d): cross-delivery consumed nothing and burned no N=3 budget (both ACTIVE, count 0)");

    /* (e) genuine delivery to the originating contexts */
    const int e_ok = handshake_responder_verify_client_auth(&r1, ca1, ca1_len) == HANDSHAKE_OK &&
                     handshake_responder_verify_client_auth(&r2, ca2, ca2_len) == HANDSHAKE_OK &&
                     handshake_responder_finish(&r1) == HANDSHAKE_OK &&
                     handshake_responder_finish(&r2) == HANDSHAKE_OK;
    CHECK(e_ok && handshake_get_state(&r1) == HANDSHAKE_STATE_ESTABLISHED &&
              handshake_get_state(&r2) == HANDSHAKE_STATE_ESTABLISHED,
          "step4 T10(e): each genuine ClientAuth succeeds on its own originating context");

    /* (f) independent, and each matches its own (test-driven) initiator */
    const uint8_t *r1c2s = NULL, *r1s2c = NULL, *r2c2s = NULL, *r2s2c = NULL;
    const int f_ok = e_ok &&
                     expected_responder_keys(&ini_eph, &ini_kem, ch, ch_len, sh1, sh1_len, e1c2s, e1s2c) == 0 &&
                     expected_responder_keys(&ini_eph, &ini_kem, ch, ch_len, sh2, sh2_len, e2c2s, e2s2c) == 0 &&
                     handshake_session_key_c2s(&r1, &r1c2s) == HANDSHAKE_OK &&
                     handshake_session_key_s2c(&r1, &r1s2c) == HANDSHAKE_OK &&
                     handshake_session_key_c2s(&r2, &r2c2s) == HANDSHAKE_OK &&
                     handshake_session_key_s2c(&r2, &r2s2c) == HANDSHAKE_OK;
    CHECK(f_ok && sodium_memcmp(r1c2s, e1c2s, 32) == 0 && sodium_memcmp(r1s2c, e1s2c, 32) == 0 &&
              sodium_memcmp(r2c2s, e2c2s, 32) == 0 && sodium_memcmp(r2s2c, e2s2c, 32) == 0 &&
              sodium_memcmp(r1c2s, r2c2s, 32) != 0,
          "step4 T10(f): R1/R2 keys differ from each other and each matches its own initiator");

    kex_keypair_free(&ini_eph);
    mlkem_keypair_free(&ini_kem);
    handshake_ctx_wipe(&r1);
    handshake_ctx_wipe(&r2);
    handshake_pending_store_wipe(&store);
}

/* ---- T11: expired pending handshake ----------------------------------- */

static void test_step4_expired(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t hid[16];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T11: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    g_clock.now += TEST_TTL_MS; /* now == deadline -> expired */

    const handshake_status_t st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_EXPIRED && handshake_get_state(&p.res) == HANDSHAKE_STATE_FAILED,
          "step4 T11: ClientAuth after TTL -> EXPIRED, responder FAILED");
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_ERR_NOT_FOUND,
          "step4 T11: expired entry was evicted");
    CHECK(no_keys_exposed(&p.res), "step4 T15 (after T11): no keys exposed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T12: capacity exhaustion ----------------------------------------- */

static void test_step4_capacity_exhaustion(void) {
    static handshake_pending_store_t store;
    static pair_t p1, p2, p3;
    clock_reset();
    store_fresh(&store, 2);
    pair_init(&p1, &store, &g_ks);
    pair_init(&p2, &store, &g_ks);
    pair_init(&p3, &store, &g_ks);

    CHECK(pair_to_server_hello(&p1) == HANDSHAKE_OK && pair_to_server_hello(&p2) == HANDSHAKE_OK,
          "step4 T12: two handshakes fill a capacity-2 store");
    const handshake_status_t st = pair_to_server_hello(&p3);
    CHECK(st == HANDSHAKE_ERR_RESOURCE_EXHAUSTED && handshake_get_state(&p3.res) == HANDSHAKE_STATE_FAILED,
          "step4 T12: third ServerHello -> RESOURCE_EXHAUSTED, that responder FAILED");
    CHECK(handshake_pending_active_count(&store) == 2, "step4 T12: the two live entries were not evicted");
    CHECK(no_keys_exposed(&p3.res), "step4 T15 (after T12): no keys exposed");

    const int completed =
        handshake_initiator_verify_server_hello(&p1.ini, p1.sh, p1.sh_len) == HANDSHAKE_OK &&
        handshake_initiator_create_client_auth(&p1.ini, p1.ca, sizeof(p1.ca), &p1.ca_len) == HANDSHAKE_OK &&
        pair_finish_both(&p1) == HANDSHAKE_OK &&
        handshake_initiator_verify_server_hello(&p2.ini, p2.sh, p2.sh_len) == HANDSHAKE_OK &&
        handshake_initiator_create_client_auth(&p2.ini, p2.ca, sizeof(p2.ca), &p2.ca_len) == HANDSHAKE_OK &&
        pair_finish_both(&p2) == HANDSHAKE_OK;
    CHECK(completed, "step4 T12: both live handshakes remain completable to ESTABLISHED");

    pair_wipe(&p1);
    pair_wipe(&p2);
    pair_wipe(&p3);
    handshake_pending_store_wipe(&store);
}

/* ---- T13: wrong state/order, every public function x every state ------ */

enum { FN_I_CH, FN_I_VSH, FN_I_CA, FN_I_FIN, FN_R_ACH, FN_R_SH, FN_R_VCA, FN_R_FIN, FN_COUNT };

static handshake_status_t call_fn(int fn, handshake_ctx_t *ctx) {
    static uint8_t buf[SERVER_HELLO_MAX_ENCODED_LEN + 16];
    static const uint8_t junk[64] = {0};
    size_t len = 0;
    switch (fn) {
    case FN_I_CH: return handshake_initiator_create_client_hello(ctx, buf, sizeof(buf), &len);
    case FN_I_VSH: return handshake_initiator_verify_server_hello(ctx, junk, sizeof(junk));
    case FN_I_CA: return handshake_initiator_create_client_auth(ctx, buf, sizeof(buf), &len);
    case FN_I_FIN: return handshake_initiator_finish(ctx);
    case FN_R_ACH: return handshake_responder_accept_client_hello(ctx, junk, sizeof(junk));
    case FN_R_SH: return handshake_responder_create_server_hello(ctx, buf, sizeof(buf), &len);
    case FN_R_VCA: return handshake_responder_verify_client_auth(ctx, junk, sizeof(junk));
    case FN_R_FIN: return handshake_responder_finish(ctx);
    default: return HANDSHAKE_ERR_INTERNAL;
    }
}

static int valid_fn_for(handshake_role_t role, handshake_state_t state) {
    if (role == HANDSHAKE_ROLE_INITIATOR) {
        switch (state) {
        case HANDSHAKE_STATE_NEW: return FN_I_CH;
        case HANDSHAKE_STATE_CLIENT_HELLO_CREATED: return FN_I_VSH;
        case HANDSHAKE_STATE_SERVER_HELLO_VERIFIED: return FN_I_CA;
        case HANDSHAKE_STATE_CLIENT_AUTH_CREATED: return FN_I_FIN;
        default: return -1;
        }
    }
    switch (state) {
    case HANDSHAKE_STATE_NEW: return FN_R_ACH;
    case HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED: return FN_R_SH;
    case HANDSHAKE_STATE_SERVER_HELLO_CREATED: return FN_R_VCA;
    case HANDSHAKE_STATE_CLIENT_AUTH_VERIFIED: return FN_R_FIN;
    default: return -1;
    }
}

/* Every function other than the one valid here must return
 * UNEXPECTED_STATE and leave the state unchanged. */
static void reject_all_invalid(handshake_ctx_t *ctx, handshake_role_t role, const char *label) {
    const handshake_state_t before = handshake_get_state(ctx);
    const int ok_fn = valid_fn_for(role, before);
    int calls = 0, violations = 0;
    for (int fn = 0; fn < FN_COUNT; fn++) {
        if (fn == ok_fn) {
            continue;
        }
        const handshake_status_t st = call_fn(fn, ctx);
        calls++;
        if (st != HANDSHAKE_ERR_UNEXPECTED_STATE || handshake_get_state(ctx) != before) {
            violations++;
            printf("      T13 violation in %s: fn=%d returned %d, state %d -> %d\n", label, fn, (int)st,
                   (int)before, (int)handshake_get_state(ctx));
        }
    }
    char name[160];
    snprintf(name, sizeof(name), "step4 T13: %s -- all %d invalid calls -> UNEXPECTED_STATE, state unchanged",
             label, calls);
    CHECK(violations == 0, name);
}

static void test_step4_wrong_state_matrix(void) {
    static handshake_pending_store_t store;
    static pair_t p, f;
    static const uint8_t junk[64] = {0};
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    reject_all_invalid(&p.ini, HANDSHAKE_ROLE_INITIATOR, "initiator NEW");
    reject_all_invalid(&p.res, HANDSHAKE_ROLE_RESPONDER, "responder NEW");
    if (handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.ini, HANDSHAKE_ROLE_INITIATOR, "initiator CLIENT_HELLO_CREATED");
    if (handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.res, HANDSHAKE_ROLE_RESPONDER, "responder CLIENT_HELLO_ACCEPTED");
    if (handshake_responder_create_server_hello(&p.res, p.sh, sizeof(p.sh), &p.sh_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.res, HANDSHAKE_ROLE_RESPONDER, "responder SERVER_HELLO_CREATED");
    if (handshake_initiator_verify_server_hello(&p.ini, p.sh, p.sh_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.ini, HANDSHAKE_ROLE_INITIATOR, "initiator SERVER_HELLO_VERIFIED");
    if (handshake_initiator_create_client_auth(&p.ini, p.ca, sizeof(p.ca), &p.ca_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.ini, HANDSHAKE_ROLE_INITIATOR, "initiator CLIENT_AUTH_CREATED");
    if (handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.res, HANDSHAKE_ROLE_RESPONDER, "responder CLIENT_AUTH_VERIFIED");
    if (handshake_responder_finish(&p.res) != HANDSHAKE_OK || handshake_initiator_finish(&p.ini) != HANDSHAKE_OK) {
        fatal("T13 walk");
    }
    reject_all_invalid(&p.res, HANDSHAKE_ROLE_RESPONDER, "responder ESTABLISHED");
    reject_all_invalid(&p.ini, HANDSHAKE_ROLE_INITIATOR, "initiator ESTABLISHED");

    /* FAILED is terminal for both roles. */
    pair_init(&f, &store, &g_ks);
    if (handshake_initiator_create_client_hello(&f.ini, f.ch, sizeof(f.ch), &f.ch_len) != HANDSHAKE_OK ||
        handshake_initiator_verify_server_hello(&f.ini, junk, sizeof(junk)) != HANDSHAKE_ERR_MALFORMED ||
        handshake_responder_accept_client_hello(&f.res, junk, sizeof(junk)) != HANDSHAKE_ERR_MALFORMED) {
        fatal("T13 FAILED fixtures");
    }
    reject_all_invalid(&f.ini, HANDSHAKE_ROLE_INITIATOR, "initiator FAILED");
    reject_all_invalid(&f.res, HANDSHAKE_ROLE_RESPONDER, "responder FAILED");

    CHECK(call_fn(FN_I_CH, NULL) == HANDSHAKE_ERR_INVALID_ARG && call_fn(FN_R_VCA, NULL) == HANDSHAKE_ERR_INVALID_ARG,
          "step4 T13: NULL context -> INVALID_ARG");

    pair_wipe(&p);
    pair_wipe(&f);
    handshake_pending_store_wipe(&store);
}

/* ---- T14: low-order X25519 in a validly-signed ServerHello ------------ */

static void test_step4_initiator_low_order(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t sid[16];
    uint8_t ct[WIRE_MLKEM_CT_LEN];
    uint8_t ss_k[32];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len = 0;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK,
          "step4 T14: fixture ClientHello created");
    session_id_of(p.ch, p.ch_len, sid);
    if (encaps_for(p.ch, p.ch_len, ct, ss_k) != 0 ||
        build_signed_server_hello(p.ch, p.ch_len, ID_B, sizeof(ID_B), &g_kp_b, SMALL_ORDER_POINT, ct, sid,
                                  sh, sizeof(sh), &sh_len) != 0) {
        fatal("T14 fixture");
    }

    const handshake_status_t st = handshake_initiator_verify_server_hello(&p.ini, sh, sh_len);
    CHECK(st == HANDSHAKE_ERR_KEX && handshake_get_state(&p.ini) == HANDSHAKE_STATE_FAILED,
          "step4 T14: low-order point in a validly-signed ServerHello -> KEX (after identity/echo/sig pass), FAILED");
    CHECK(no_keys_exposed(&p.ini), "step4 T15 (after T14): no keys exposed");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T16: keystore -------------------------------------------------- */

static void test_step4_keystore(void) {
    static keystore_t ks;
    const uint8_t *pk = NULL;
    const uint8_t id_ab[] = {'a', 'b'};
    const uint8_t id_abc[] = {'a', 'b', 'c'};
    const uint8_t id_nul[] = {'x', 0x00, 'y'}; /* embedded NUL: opaque bytes, not a C string */
    const uint8_t id_x[] = {'x'};
    uint8_t long_id[65];
    memset(long_id, 'L', sizeof(long_id));
    keystore_init(&ks);

    CHECK(keystore_lookup(&ks, ID_A, sizeof(ID_A), &pk) == KEYSTORE_ERR_NOT_FOUND && pk == NULL,
          "step4 T16: unknown id -> NOT_FOUND, NULL key");
    CHECK(keystore_add(&ks, ID_A, sizeof(ID_A), g_kp_a.public_key) == KEYSTORE_OK && keystore_count(&ks) == 1,
          "step4 T16: add new id -> OK");
    CHECK(keystore_add(&ks, ID_A, sizeof(ID_A), g_kp_a.public_key) == KEYSTORE_OK_ALREADY_PRESENT &&
              keystore_count(&ks) == 1,
          "step4 T16: identical re-add -> OK_ALREADY_PRESENT, count unchanged");
    CHECK(keystore_add(&ks, ID_A, sizeof(ID_A), g_kp_b.public_key) == KEYSTORE_ERR_KEY_MISMATCH,
          "step4 T16: same id, different key -> KEY_MISMATCH");
    CHECK(keystore_lookup(&ks, ID_A, sizeof(ID_A), &pk) == KEYSTORE_OK &&
              memcmp(pk, g_kp_a.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
          "step4 T16: the pinned key was NOT replaced by the mismatching add");
    CHECK(keystore_add(&ks, ID_A, 0, g_kp_a.public_key) == KEYSTORE_ERR_INVALID_ARG &&
              keystore_add(&ks, long_id, 65, g_kp_a.public_key) == KEYSTORE_ERR_INVALID_ARG,
          "step4 T16: id length 0 and 65 rejected");
    CHECK(keystore_add(&ks, id_ab, sizeof(id_ab), g_kp_b.public_key) == KEYSTORE_OK &&
              keystore_lookup(&ks, id_abc, sizeof(id_abc), &pk) == KEYSTORE_ERR_NOT_FOUND,
          "step4 T16: \"ab\" and \"abc\" are distinct identities (length-sensitive)");
    CHECK(keystore_add(&ks, id_nul, sizeof(id_nul), g_kp_c.public_key) == KEYSTORE_OK &&
              keystore_lookup(&ks, id_nul, sizeof(id_nul), &pk) == KEYSTORE_OK &&
              keystore_lookup(&ks, id_x, sizeof(id_x), &pk) == KEYSTORE_ERR_NOT_FOUND,
          "step4 T16: id with an embedded NUL round-trips; its C-string prefix does not match");

    int filled = 1;
    for (uint8_t i = 0; keystore_count(&ks) < KEYSTORE_MAX_ENTRIES; i++) {
        const uint8_t id[] = {'k', i};
        if (keystore_add(&ks, id, sizeof(id), g_kp_a.public_key) != KEYSTORE_OK) {
            filled = 0;
            break;
        }
    }
    const uint8_t extra[] = {'z', 'z'};
    CHECK(filled && keystore_add(&ks, extra, sizeof(extra), g_kp_a.public_key) == KEYSTORE_ERR_FULL,
          "step4 T16: full keystore -> FULL");
    keystore_wipe(&ks);
}

/* ---- T17: SH_unsigned length helper does not drift -------------------- */

static void test_step4_unsigned_len_helper(void) {
    const uint8_t lens[] = {1, 32, 64};
    int ok = 1;
    for (size_t i = 0; i < sizeof(lens); i++) {
        server_hello_t sh;
        uint8_t buf[SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN];
        size_t len = 0;
        make_server_hello(&sh, lens[i], 10, 0x11);
        if (encode_server_hello_unsigned(&sh, buf, sizeof(buf), &len) != 0 ||
            transcript_server_hello_unsigned_len(lens[i]) != len) {
            ok = 0;
        }
    }
    CHECK(ok, "step4 T17: transcript_server_hello_unsigned_len == encode_server_hello_unsigned length (1/32/64)");
    CHECK(transcript_server_hello_unsigned_len(0) == 0 && transcript_server_hello_unsigned_len(65) == 0,
          "step4 T17: invalid id lengths 0 and 65 -> 0 sentinel");
}

/* ---- T18: get_digest copy-out semantics ------------------------------- */

static int all_zero(const uint8_t *b, size_t n) {
    return sodium_is_zero(b, n) == 1;
}

static void test_step4_get_digest_copy_out(void) {
    static handshake_pending_store_t s;
    uint8_t h[5][16], th[5][32], scratch[32];
    clock_reset();
    store_fresh(&s, 8);
    for (int i = 0; i < 5; i++) {
        memset(h[i], 0x10 + i, 16);
        memset(th[i], 0x60 + i, 32);
    }

    memset(scratch, 0xAA, sizeof(scratch));
    CHECK(handshake_pending_get_digest(&s, h[4], scratch) == PENDING_ERR_NOT_FOUND && all_zero(scratch, 32),
          "step4 T18: absent id -> NOT_FOUND and scratch zeroed");

    CHECK(handshake_pending_insert(&s, h[0], th[0]) == PENDING_OK &&
              handshake_pending_get_digest(&s, h[0], scratch) == PENDING_OK && memcmp(scratch, th[0], 32) == 0,
          "step4 T18: live id -> OK and the digest is copied out");

    handshake_pending_insert(&s, h[1], th[1]);
    handshake_pending_consume_success(&s, h[1]);
    memset(scratch, 0xAA, sizeof(scratch));
    CHECK(handshake_pending_get_digest(&s, h[1], scratch) == PENDING_ERR_CONSUMED && all_zero(scratch, 32),
          "step4 T18: consumed id -> CONSUMED and scratch zeroed");

    handshake_pending_insert(&s, h[2], th[2]);
    for (int i = 0; i < 3; i++) {
        handshake_pending_record_failure(&s, h[2]);
    }
    memset(scratch, 0xAA, sizeof(scratch));
    CHECK(handshake_pending_get_digest(&s, h[2], scratch) == PENDING_ERR_AUTH_LIMIT && all_zero(scratch, 32),
          "step4 T18: auth-limited id -> AUTH_LIMIT and scratch zeroed");

    handshake_pending_insert(&s, h[3], th[3]);
    g_clock.now += TEST_TTL_MS;
    memset(scratch, 0xAA, sizeof(scratch));
    CHECK(handshake_pending_get_digest(&s, h[3], scratch) == PENDING_ERR_EXPIRED && all_zero(scratch, 32),
          "step4 T18: expired id -> EXPIRED and scratch zeroed");
    handshake_pending_store_wipe(&s);
}

/* ---- T19: inspect -- read-only expiry reporting, then eviction ------- */

static void test_step4_inspect_expiry(void) {
    static handshake_pending_store_t s;
    uint8_t h[16], h2[16], th[32], scratch[32];
    pending_slot_state_t s1, s2;
    uint8_t c1 = 0xEE, c2 = 0xEE;
    clock_reset();
    store_fresh(&s, 4);
    memset(h, 0x21, 16);
    memset(h2, 0x22, 16);
    memset(th, 0x33, 32);

    CHECK(handshake_pending_insert(&s, h, th) == PENDING_OK && handshake_pending_active_count(&s) == 1,
          "step4 T19(a): insert -> OK, active_count 1");
    g_clock.now += TEST_TTL_MS; /* (b) now == deadline */
    const pending_status_t r1 = handshake_pending_inspect(&s, h, &s1, &c1);
    CHECK(r1 == PENDING_ERR_EXPIRED && s1 == PENDING_SLOT_EXPIRED && c1 == 0,
          "step4 T19(c): inspect reports EXPIRED / PENDING_SLOT_EXPIRED -- never as live");
    const pending_status_t r2 = handshake_pending_inspect(&s, h, &s2, &c2);
    CHECK(r2 == r1 && s2 == s1 && c2 == c1, "step4 T19(d): a second inspect is identical -- nothing mutated");
    CHECK(handshake_pending_active_count(&s) == 0, "step4 T19(e): active_count excludes the expired entry");
    CHECK(handshake_pending_get_digest(&s, h, scratch) == PENDING_ERR_EXPIRED && all_zero(scratch, 32),
          "step4 T19(f): get_digest -> EXPIRED and physically frees the slot");
    CHECK(handshake_pending_inspect(&s, h, &s1, &c1) == PENDING_ERR_NOT_FOUND,
          "step4 T19(g): inspect -> NOT_FOUND, so (f) -- not (c)/(d) -- performed the eviction");

    /* Same again, with sweep() doing the physical eviction. */
    CHECK(handshake_pending_insert(&s, h2, th) == PENDING_OK, "step4 T19: second entry inserted");
    g_clock.now += TEST_TTL_MS;
    CHECK(handshake_pending_inspect(&s, h2, &s1, &c1) == PENDING_ERR_EXPIRED,
          "step4 T19: expired entry reported by inspect before sweep");
    handshake_pending_sweep(&s);
    CHECK(handshake_pending_inspect(&s, h2, &s1, &c1) == PENDING_ERR_NOT_FOUND,
          "step4 T19: sweep physically evicts it");
    handshake_pending_store_wipe(&s);
}

/* ---- T22: consume_success fails after successful derivation ---------- */

static void test_step4_commit_fails_after_derivation(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t hid[16];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&store, 4);
    pair_init(&p, &store, &g_ks);

    CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK, "step4 T22: fixture ClientAuth created");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid);
    /* Read #1 (get_digest) is live; read #2 (consume_success) is expired. */
    clock_arm_expiry_after(1);

    const handshake_status_t st = handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len);
    CHECK(st == HANDSHAKE_ERR_EXPIRED && handshake_get_state(&p.res) == HANDSHAKE_STATE_FAILED,
          "step4 T22: commit fails after derivation -> EXPIRED, responder FAILED");
    CHECK(no_keys_exposed(&p.res) && !handshake_is_peer_confirmed(&p.res),
          "step4 T22: no key accessible and key-valid flag false after the failed commit");
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_ERR_NOT_FOUND,
          "step4 T22: ledger state is exactly what consume_success's expiry semantics dictate (evicted)");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- V2-4 D1-D6: the hybrid key schedule (spec-v2 6.3.7) --------------
 *
 * The bug this section exists for is a combiner that drops, reorders or
 * mis-binds one of the two secrets. Such a bug is SYMMETRIC: both peers
 * compute the same wrong key, every handshake succeeds, every round-trip
 * test passes, and the post-quantum protection is silently gone. Only
 * vectors computed OUTSIDE this codebase can see it, which is what D3 is.
 */

/* The normative v2 layout rebuilt by hand from literal bytes --
 * deliberately independent of KEX_KDF_V2_LABEL and of
 * kex_build_kdf_info_v2(). Note the literal '2'. */
static size_t hand_kdf_info_v2(uint8_t *out, const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                               const uint8_t th[32], uint8_t dir) {
    static const uint8_t label[17] = {'m', 'l', 'd', 's', 'a', '-', 'a', 'u', 't',
                                      'h', '/', 'v', '2', '/', 'k', 'd', 'f'};
    size_t off = 0;
    memcpy(out, label, sizeof(label));
    off += sizeof(label);
    out[off++] = 0x00;
    out[off++] = (uint8_t)a_len;
    memcpy(out + off, a, a_len);
    off += a_len;
    out[off++] = (uint8_t)b_len;
    memcpy(out + off, b, b_len);
    off += b_len;
    memcpy(out + off, th, 32);
    off += 32;
    out[off++] = dir;
    return off;
}

static void derive_v2_or_die(uint8_t key[32], const uint8_t ssx[32], const uint8_t ssk[32], const uint8_t sid[16],
                             const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, const uint8_t th[32],
                             uint8_t dir) {
    if (kex_derive_session_key_v2(key, ssx, ssk, sid, 16, a, a_len, b, b_len, th, dir) != 0) {
        fatal("kex_derive_session_key_v2");
    }
}

static void test_v24_kdf_v2(void) {
    uint8_t a[64], b[64], ssx[32], ssk[32], sid[16], th[32];
    for (size_t i = 0; i < 64; i++) {
        a[i] = (uint8_t)(0x40 + i);
        b[i] = (uint8_t)(0x90 + i);
    }
    randombytes_buf(ssx, sizeof(ssx));
    randombytes_buf(ssk, sizeof(ssk));
    randombytes_buf(sid, sizeof(sid));
    randombytes_buf(th, sizeof(th));
    const uint8_t dirs[2] = {KEX_DIR_C2S, KEX_DIR_S2C};

    /* D1 -- byte-exact against the hand-built layout, at both id
     * boundaries. 55 = 17+1+1+1+1+1+32+1, 181 = the same with 64-byte ids. */
    const size_t shapes[4][2] = {{1, 1}, {1, 64}, {64, 1}, {64, 64}};
    int exact = 1;
    size_t seen_min = SIZE_MAX, seen_max = 0;
    for (size_t s = 0; s < 4; s++) {
        for (size_t d = 0; d < 2; d++) {
            uint8_t expect[KEX_KDF_V2_INFO_MAX_LEN], got[KEX_KDF_V2_INFO_MAX_LEN];
            size_t got_len = 0;
            const size_t exp_len = hand_kdf_info_v2(expect, a, shapes[s][0], b, shapes[s][1], th, dirs[d]);
            if (kex_build_kdf_info_v2(got, sizeof(got), &got_len, a, shapes[s][0], b, shapes[s][1], th, dirs[d]) != 0 ||
                got_len != exp_len || memcmp(got, expect, exp_len) != 0 ||
                got_len != 55u + (shapes[s][0] - 1u) + (shapes[s][1] - 1u)) {
                exact = 0;
            }
            seen_min = (exp_len < seen_min) ? exp_len : seen_min;
            seen_max = (exp_len > seen_max) ? exp_len : seen_max;
        }
    }
    CHECK(exact, "v2-4 D1: kex_build_kdf_info_v2 is byte-exact vs the hand-built v2 layout (1/1,1/64,64/1,64/64 x both "
                 "dirs)");
    CHECK(seen_min == KEX_KDF_V2_INFO_MIN_LEN && seen_max == KEX_KDF_V2_INFO_MAX_LEN && seen_min == 55u &&
              seen_max == 181u,
          "v2-4 D1: the info length spans exactly 55..181 bytes (spec-v2 6.3.7)");

    /* D2 -- composition: the derive function is HKDF over the hybrid IKM,
     * with nothing else mixed in. IKM is concatenated here by hand. */
    int composes = 1;
    for (size_t d = 0; d < 2; d++) {
        uint8_t info[KEX_KDF_V2_INFO_MAX_LEN], ikm[64], k1[32], k2[32];
        const size_t info_len = hand_kdf_info_v2(info, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, dirs[d]);
        memcpy(ikm, ssx, 32);
        memcpy(ikm + 32, ssk, 32);
        derive_v2_or_die(k1, ssx, ssk, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, dirs[d]);
        if (kex_hkdf_sha256(k2, 32, ikm, 64, sid, 16, info, info_len) != 0 || memcmp(k1, k2, 32) != 0) {
            composes = 0;
        }
    }
    CHECK(composes, "v2-4 D2: kex_derive_session_key_v2 == HKDF(IKM=ss_x||ss_k, salt=session_id, info=hand-built v2 "
                    "kdf_info)");

    /* D3 -- THE test for this step. Literal inputs, literal expected
     * outputs, produced by an independent RFC 5869 implementation
     * (Python hmac/hashlib, no libsodium) run outside this codebase:
     *
     *   import hmac, hashlib
     *   ssx = bytes(range(32)); ssk = bytes(0xff - i for i in range(32))
     *   sid = bytes(0xa0 + i for i in range(16))
     *   th  = bytes(0x80 + i for i in range(32))
     *   a = b"alice"; b = b"bob"
     *   for d in (0x43, 0x53):
     *       info = (b"mldsa-auth/v2/kdf" + b"\0" + bytes([len(a)]) + a +
     *               bytes([len(b)]) + b + th + bytes([d]))
     *       prk = hmac.new(sid, ssx + ssk, hashlib.sha256).digest()
     *       print(hex(d), hmac.new(prk, info + b"\1", hashlib.sha256).digest().hex())
     *
     * A combiner that dropped ss_k, swapped the two secrets, omitted the
     * transcript digest, or kept a /v1/ label produces a DIFFERENT key
     * here while remaining perfectly self-consistent -- which is exactly
     * why a round trip between two copies of this code is not evidence. */
    {
        uint8_t v_ssx[32], v_ssk[32], v_sid[16], v_th[32];
        for (size_t i = 0; i < 32; i++) {
            v_ssx[i] = (uint8_t)i;
            v_ssk[i] = (uint8_t)(0xff - i);
            v_th[i] = (uint8_t)(0x80 + i);
        }
        for (size_t i = 0; i < 16; i++) {
            v_sid[i] = (uint8_t)(0xa0 + i);
        }
        static const uint8_t V_ID_A[5] = {'a', 'l', 'i', 'c', 'e'};
        static const uint8_t V_ID_B[3] = {'b', 'o', 'b'};
        static const uint8_t EXPECT_C2S[32] = {
            0x79, 0x1e, 0x53, 0xd2, 0xcb, 0xd7, 0x0f, 0x63, 0x27, 0x63, 0x04,
            0xf9, 0x09, 0xa6, 0x88, 0x34, 0xd5, 0xde, 0x49, 0x61, 0x35, 0xa9,
            0x90, 0x83, 0xf7, 0x85, 0x8a, 0xed, 0xa5, 0xd9, 0x1c, 0x5a,
        };
        static const uint8_t EXPECT_S2C[32] = {
            0xdd, 0xb6, 0x4a, 0x76, 0xf4, 0x85, 0xbd, 0x11, 0x38, 0x7a, 0x12,
            0x95, 0x74, 0xf7, 0xb4, 0x25, 0xd9, 0xf6, 0x68, 0x6b, 0x93, 0x6b,
            0x9e, 0x6b, 0x08, 0x6a, 0xf0, 0xde, 0x69, 0xd7, 0x15, 0xaf,
        };
        uint8_t kc[32], ks[32];
        derive_v2_or_die(kc, v_ssx, v_ssk, v_sid, V_ID_A, sizeof(V_ID_A), V_ID_B, sizeof(V_ID_B), v_th, KEX_DIR_C2S);
        derive_v2_or_die(ks, v_ssx, v_ssk, v_sid, V_ID_A, sizeof(V_ID_A), V_ID_B, sizeof(V_ID_B), v_th, KEX_DIR_S2C);
        CHECK(memcmp(kc, EXPECT_C2S, 32) == 0,
              "v2-4 D3: the c2s key matches the independently computed byte-exact vector");
        CHECK(memcmp(ks, EXPECT_S2C, 32) == 0,
              "v2-4 D3: the s2c key matches the independently computed byte-exact vector");

        /* And the same inputs through the info builder, so a builder
         * defect is attributed to the builder rather than to HKDF. */
        uint8_t got[KEX_KDF_V2_INFO_MAX_LEN];
        size_t got_len = 0;
        CHECK(kex_build_kdf_info_v2(got, sizeof(got), &got_len, V_ID_A, sizeof(V_ID_A), V_ID_B, sizeof(V_ID_B), v_th,
                                    KEX_DIR_C2S) == 0 &&
                  got_len == 61u && got[17] == 0x00 && got[18] == 5u && memcmp(got + 19, "alice", 5) == 0 &&
                  got[24] == 3u && memcmp(got + 25, "bob", 3) == 0 && memcmp(got + 28, v_th, 32) == 0 &&
                  got[60] == KEX_DIR_C2S,
              "v2-4 D3: the vector's kdf_info is 61 bytes with the digest at offset 28 and the direction last");
    }

    /* D4 -- every input changes the key: each secret alone, their order,
     * the transcript digest, both identities, both lengths, direction. */
    {
        uint8_t alt_ssx[32], alt_ssk[32], alt_th[32];
        memcpy(alt_ssx, ssx, 32);
        memcpy(alt_ssk, ssk, 32);
        memcpy(alt_th, th, 32);
        alt_ssx[0] ^= 0x01;
        alt_ssk[31] ^= 0x01;
        alt_th[16] ^= 0x01;
        const uint8_t la[3] = {'a', 'b', 'c'}, lb[3] = {'x', 'y', 'z'};
        uint8_t v[9][32];
        derive_v2_or_die(v[0], ssx, ssk, sid, la, 2, lb, 2, th, KEX_DIR_C2S);     /* baseline */
        derive_v2_or_die(v[1], alt_ssx, ssk, sid, la, 2, lb, 2, th, KEX_DIR_C2S); /* ss_x byte */
        derive_v2_or_die(v[2], ssx, alt_ssk, sid, la, 2, lb, 2, th, KEX_DIR_C2S); /* ss_k byte */
        derive_v2_or_die(v[3], ssk, ssx, sid, la, 2, lb, 2, th, KEX_DIR_C2S);     /* secrets SWAPPED */
        derive_v2_or_die(v[4], ssx, ssk, sid, la, 2, lb, 2, alt_th, KEX_DIR_C2S); /* TH byte */
        derive_v2_or_die(v[5], ssx, ssk, sid, lb, 2, lb, 2, th, KEX_DIR_C2S);     /* A_id */
        derive_v2_or_die(v[6], ssx, ssk, sid, la, 2, la, 2, th, KEX_DIR_C2S);     /* B_id */
        derive_v2_or_die(v[7], ssx, ssk, sid, la, 3, lb, 2, th, KEX_DIR_C2S);     /* A length */
        derive_v2_or_die(v[8], ssx, ssk, sid, la, 2, lb, 2, th, KEX_DIR_S2C);     /* direction */
        int distinct = 1;
        for (int x = 0; x < 9; x++) {
            for (int y = x + 1; y < 9; y++) {
                if (memcmp(v[x], v[y], 32) == 0) {
                    distinct = 0;
                }
            }
        }
        CHECK(distinct, "v2-4 D4: changing ss_x, ss_k, their order, TH_client_auth, either id, either length, or the "
                        "direction each changes the key (all pairwise distinct)");
    }

    /* D5 -- injectivity survives the added field: the v1 ambiguity case
     * ("ab","c") vs ("a","bc") still produces different info and keys. */
    {
        const uint8_t a1[] = {'a', 'b'}, b1[] = {'c'};
        const uint8_t a2[] = {'a'}, b2[] = {'b', 'c'};
        uint8_t i1[KEX_KDF_V2_INFO_MAX_LEN], i2[KEX_KDF_V2_INFO_MAX_LEN], k1[32], k2[32];
        size_t l1 = 0, l2 = 0;
        const int built = kex_build_kdf_info_v2(i1, sizeof(i1), &l1, a1, 2, b1, 1, th, KEX_DIR_C2S) == 0 &&
                          kex_build_kdf_info_v2(i2, sizeof(i2), &l2, a2, 1, b2, 2, th, KEX_DIR_C2S) == 0;
        derive_v2_or_die(k1, ssx, ssk, sid, a1, 2, b1, 1, th, KEX_DIR_C2S);
        derive_v2_or_die(k2, ssx, ssk, sid, a2, 1, b2, 2, th, KEX_DIR_C2S);
        CHECK(built && (l1 != l2 || memcmp(i1, i2, l1) != 0) && memcmp(k1, k2, 32) != 0,
              "v2-4 D5: A=\"ab\",B=\"c\" and A=\"a\",B=\"bc\" still produce different v2 kdf_info and different keys");
    }

    /* D6 -- validation, in T28's shape: nothing is written on any
     * rejected input. */
    {
        uint8_t big[128];
        memset(big, 'q', sizeof(big));
        const struct {
            const uint8_t *a;
            size_t al;
            const uint8_t *b;
            size_t bl;
            const uint8_t *th;
            uint8_t dir;
        } bad[] = {
            {big, 0, big, 3, th, KEX_DIR_C2S},   {big, 65, big, 3, th, KEX_DIR_C2S},
            {big, 3, big, 0, th, KEX_DIR_C2S},   {big, 3, big, 65, th, KEX_DIR_C2S},
            {NULL, 3, big, 3, th, KEX_DIR_C2S},  {big, 3, NULL, 3, th, KEX_DIR_C2S},
            {big, 3, big, 3, NULL, KEX_DIR_C2S}, {big, 3, big, 3, th, 0x00},
            {big, 3, big, 3, th, 0x44},          {big, 3, big, 3, th, 0xFF},
        };
        int rejected = 1;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            uint8_t out[KEX_KDF_V2_INFO_MAX_LEN + 8], key[32];
            size_t out_len = 777;
            memset(out, 0xAA, sizeof(out));
            memset(key, 0xAA, sizeof(key));
            const int r1 = kex_build_kdf_info_v2(out, sizeof(out), &out_len, bad[i].a, bad[i].al, bad[i].b, bad[i].bl,
                                                 bad[i].th, bad[i].dir);
            const int r2 = kex_derive_session_key_v2(key, ssx, ssk, sid, 16, bad[i].a, bad[i].al, bad[i].b, bad[i].bl,
                                                     bad[i].th, bad[i].dir);
            uint8_t untouched_out = 1, untouched_key = 1;
            for (size_t j = 0; j < sizeof(out); j++) {
                untouched_out &= (uint8_t)(out[j] == 0xAA);
            }
            for (size_t j = 0; j < sizeof(key); j++) {
                untouched_key &= (uint8_t)(key[j] == 0xAA);
            }
            if (r1 == 0 || r2 == 0 || out_len != 777 || !untouched_out || !untouched_key) {
                rejected = 0;
                printf("      D6 case %zu not rejected cleanly (r1=%d r2=%d)\n", i, r1, r2);
            }
        }
        {
            /* NULL secrets, wrong session_id lengths, and out_cap exactly
             * one byte short (59 = 55 + 2 + 2 for ids of length 3). */
            uint8_t out[KEX_KDF_V2_INFO_MAX_LEN], key[32];
            size_t out_len = 777;
            memset(out, 0xAA, sizeof(out));
            memset(key, 0xAA, sizeof(key));
            const size_t need = 55u + 2u + 2u;
            if (kex_build_kdf_info_v2(out, need - 1u, &out_len, big, 3, big, 3, th, KEX_DIR_C2S) == 0 ||
                out_len != 777 || out[0] != 0xAA ||
                kex_derive_session_key_v2(key, NULL, ssk, sid, 16, big, 3, big, 3, th, KEX_DIR_C2S) == 0 ||
                kex_derive_session_key_v2(key, ssx, NULL, sid, 16, big, 3, big, 3, th, KEX_DIR_C2S) == 0 ||
                kex_derive_session_key_v2(key, ssx, ssk, sid, 15, big, 3, big, 3, th, KEX_DIR_C2S) == 0 ||
                kex_derive_session_key_v2(key, ssx, ssk, sid, 17, big, 3, big, 3, th, KEX_DIR_C2S) == 0 ||
                key[0] != 0xAA) {
                rejected = 0;
                printf("      D6 NULL-secret/capacity/session_id case not rejected cleanly\n");
            }
        }
        CHECK(rejected, "v2-4 D6: id len 0/65, NULL ids/digest/secrets, bad direction, short out_cap and "
                        "session_id_len != 16 are all rejected, writing nothing");
    }
}

/* ---- V2-5 H1-H7: the hybrid handshake (spec-v2 6.3) -------------------
 *
 * H1 and H2 are MANUAL-PEER oracles: one side is the real implementation,
 * the other is played by the test, which therefore holds the KEM secret
 * itself and can predict the traffic keys with expected_keys() -- built
 * from the literal spec layout, not from the code under test. A
 * real-vs-real handshake cannot do this: a combiner that drops ss_k or
 * swaps the two secrets makes BOTH peers agree on the same wrong key, so
 * every interop assertion still passes.
 */

/* Field offsets in the encoded messages, from the spec-v2 6.3.1 layout.
 * Used to splice one handshake's KEM contribution into another's message. */
#define CH_EK_OFFSET(id_len) (2u + (size_t)(id_len) + WIRE_X25519_PUB_LEN)
#define SH_CT_OFFSET(id_len) (2u + (size_t)(id_len) + WIRE_X25519_PUB_LEN)

static void test_v25_h1_manual_responder(void) {
    static handshake_ctx_t ini;
    kex_keypair_t b_eph;
    client_hello_t chm;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh[SERVER_HELLO_MAX_ENCODED_LEN],
        ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh_len = 0, ca_len = 0, consumed = 0;
    uint8_t ct[WIRE_MLKEM_CT_LEN], ss_k[32], ss_x[32], sid[16], th[32];
    uint8_t want_c2s[32], want_s2c[32];

    if (handshake_initiator_init(&ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini, ch, sizeof(ch), &ch_len) != HANDSHAKE_OK ||
        kex_keypair_generate(&b_eph) != 0 || encaps_for(ch, ch_len, ct, ss_k) != 0) {
        fatal("H1 fixture");
    }
    session_id_of(ch, ch_len, sid);
    if (build_signed_server_hello(ch, ch_len, ID_B, sizeof(ID_B), &g_kp_b, b_eph.public_key, ct, sid, sh,
                                  sizeof(sh), &sh_len) != 0) {
        fatal("H1 ServerHello");
    }

    const int ran = handshake_initiator_verify_server_hello(&ini, sh, sh_len) == HANDSHAKE_OK &&
                    handshake_initiator_create_client_auth(&ini, ca, sizeof(ca), &ca_len) == HANDSHAKE_OK;
    CHECK(ran, "v2-5 H1: the initiator completes against a hand-built responder");

    /* The test verifies sig_A itself: the initiator signed a transcript
     * covering the ciphertext it was sent. */
    client_auth_t cam;
    CHECK(ran && decode_client_auth(ca, ca_len, &cam, &consumed) == 0 &&
              transcript_hash_client_auth(ch, ch_len, sh, sh_len, th) == 0 &&
              mldsa_verify(th, sizeof(th), cam.sig, cam.sig_len, g_kp_a.public_key) == 0,
          "v2-5 H1: sig_A verifies against the transcript covering mlkem_ct");

    CHECK(ran && handshake_initiator_finish(&ini) == HANDSHAKE_OK &&
              handshake_get_state(&ini) == HANDSHAKE_STATE_ESTABLISHED,
          "v2-5 H1: initiator finish -> ESTABLISHED");

    /* The keys the test predicts from ITS OWN ss_k and ss_x. */
    if (decode_client_hello(ch, ch_len, &chm, &consumed) != 0 ||
        kex_shared_secret(ss_x, &b_eph, chm.ephemeral_pub) != 0) {
        fatal("H1 secrets");
    }
    expected_keys(ss_x, ss_k, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, want_c2s, want_s2c);

    const uint8_t *c2s = NULL;
    const uint8_t *s2c = NULL;
    const int got = handshake_session_key_c2s(&ini, &c2s) == HANDSHAKE_OK &&
                    handshake_session_key_s2c(&ini, &s2c) == HANDSHAKE_OK;
    CHECK(got && sodium_memcmp(c2s, want_c2s, 32) == 0 && sodium_memcmp(s2c, want_s2c, 32) == 0,
          "v2-5 H1: the initiator's keys equal the INDEPENDENTLY computed hybrid keys (ss_x || ss_k, TH bound)");
    CHECK(hybrid_secrets_wiped(&ini), "v2-5 H1: dk and the retained ciphertext are wiped after finish");

    kex_keypair_free(&b_eph);
    handshake_ctx_wipe(&ini);
}

static void test_v25_h2_manual_initiator(void) {
    static handshake_pending_store_t store;
    static handshake_ctx_t res;
    kex_keypair_t a_eph;
    mlkem_keypair_t a_kem;
    server_hello_t shm;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh[SERVER_HELLO_MAX_ENCODED_LEN],
        ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh_len = 0, ca_len = 0, consumed = 0;
    uint8_t ss_x[32], ss_k[32], sid[16], th[32], th_sb[32];
    uint8_t want_c2s[32], want_s2c[32];
    clock_reset();
    store_fresh(&store, 16);

    if (kex_keypair_generate(&a_eph) != 0 || mlkem_keypair_generate(&a_kem) != 0 ||
        build_client_hello(ID_A, sizeof(ID_A), a_eph.public_key, a_kem.public_key, ch, sizeof(ch), &ch_len) != 0 ||
        handshake_responder_init(&res, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) != HANDSHAKE_OK) {
        fatal("H2 fixture");
    }
    const int made = handshake_responder_accept_client_hello(&res, ch, ch_len) == HANDSHAKE_OK &&
                     handshake_responder_create_server_hello(&res, sh, sizeof(sh), &sh_len) == HANDSHAKE_OK;
    CHECK(made, "v2-5 H2: the responder encapsulates and creates a ServerHello");
    CHECK(made && res.ss_kem != NULL, "v2-5 H2: the responder RETAINS ss_kem in SERVER_HELLO_CREATED");

    /* The test decapsulates with its own dk and checks sig_B itself. */
    const size_t ulen = transcript_server_hello_unsigned_len((uint8_t)sizeof(ID_B));
    if (!made || decode_server_hello(sh, sh_len, &shm, &consumed) != 0 ||
        kex_shared_secret(ss_x, &a_eph, shm.ephemeral_pub) != 0 ||
        mlkem_decaps(ss_k, shm.mlkem_ct, &a_kem) != 0 ||
        transcript_hash_server_auth(ch, ch_len, sh, ulen, th_sb) != 0) {
        fatal("H2 secrets");
    }
    CHECK(mldsa_verify(th_sb, sizeof(th_sb), shm.sig, shm.sig_len, g_kp_b.public_key) == 0,
          "v2-5 H2: sig_B verifies against the transcript covering mlkem_ct");

    if (build_signed_client_auth(ch, ch_len, sh, sh_len, &g_kp_a, ca, sizeof(ca), &ca_len) != 0) {
        fatal("H2 ClientAuth");
    }
    const int done = handshake_responder_verify_client_auth(&res, ca, ca_len) == HANDSHAKE_OK &&
                     handshake_responder_finish(&res) == HANDSHAKE_OK;
    CHECK(done && handshake_get_state(&res) == HANDSHAKE_STATE_ESTABLISHED,
          "v2-5 H2: the responder verifies the hand-built ClientAuth -> ESTABLISHED");

    session_id_of(ch, ch_len, sid);
    if (transcript_hash_client_auth(ch, ch_len, sh, sh_len, th) != 0) {
        fatal("H2 transcript");
    }
    expected_keys(ss_x, ss_k, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, want_c2s, want_s2c);

    const uint8_t *c2s = NULL;
    const uint8_t *s2c = NULL;
    const int got = handshake_session_key_c2s(&res, &c2s) == HANDSHAKE_OK &&
                    handshake_session_key_s2c(&res, &s2c) == HANDSHAKE_OK;
    CHECK(got && sodium_memcmp(c2s, want_c2s, 32) == 0 && sodium_memcmp(s2c, want_s2c, 32) == 0,
          "v2-5 H2: the responder's keys equal the INDEPENDENTLY computed hybrid keys");
    CHECK(hybrid_secrets_wiped(&res), "v2-5 H2: ss_kem is wiped once the keys are derived");

    kex_keypair_free(&a_eph);
    mlkem_keypair_free(&a_kem);
    handshake_ctx_wipe(&res);
    handshake_pending_store_wipe(&store);
}

static void test_v25_h3_tampered_ciphertext(void) {
    static handshake_ctx_t ini;
    kex_keypair_t b_eph;
    client_hello_t chm;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh[SERVER_HELLO_MAX_ENCODED_LEN],
        ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh_len = 0, ca_len = 0, consumed = 0;
    uint8_t ct[WIRE_MLKEM_CT_LEN], ss_k[32], ss_x[32], sid[16], th[32];
    uint8_t want_real[32], want_real_s2c[32], want_zero[32], want_zero_s2c[32];
    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));

    if (handshake_initiator_init(&ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini, ch, sizeof(ch), &ch_len) != HANDSHAKE_OK ||
        kex_keypair_generate(&b_eph) != 0 || encaps_for(ch, ch_len, ct, ss_k) != 0) {
        fatal("H3 fixture");
    }
    /* Tamper BEFORE signing: the ServerHello is validly signed over the
     * altered ciphertext, which is the only way to reach implicit
     * rejection without forging sig_B. */
    ct[0] ^= 0x01;
    session_id_of(ch, ch_len, sid);
    if (build_signed_server_hello(ch, ch_len, ID_B, sizeof(ID_B), &g_kp_b, b_eph.public_key, ct, sid, sh,
                                  sizeof(sh), &sh_len) != 0) {
        fatal("H3 ServerHello");
    }

    const int ok = handshake_initiator_verify_server_hello(&ini, sh, sh_len) == HANDSHAKE_OK &&
                   handshake_initiator_create_client_auth(&ini, ca, sizeof(ca), &ca_len) == HANDSHAKE_OK &&
                   handshake_initiator_finish(&ini) == HANDSHAKE_OK;
    CHECK(ok && handshake_get_state(&ini) == HANDSHAKE_STATE_ESTABLISHED,
          "v2-5 H3: a tampered-but-signed ciphertext still reaches ESTABLISHED -- decapsulation is NOT a "
          "validation signal (Req 4.11)");

    if (decode_client_hello(ch, ch_len, &chm, &consumed) != 0 ||
        kex_shared_secret(ss_x, &b_eph, chm.ephemeral_pub) != 0 ||
        transcript_hash_client_auth(ch, ch_len, sh, sh_len, th) != 0) {
        fatal("H3 secrets");
    }
    expected_keys(ss_x, ss_k, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, want_real, want_real_s2c);
    expected_keys(ss_x, zeros, sid, ID_A, sizeof(ID_A), ID_B, sizeof(ID_B), th, want_zero, want_zero_s2c);

    const uint8_t *c2s = NULL;
    const int got = handshake_session_key_c2s(&ini, &c2s) == HANDSHAKE_OK;
    CHECK(got && sodium_memcmp(c2s, want_real, 32) != 0,
          "v2-5 H3: the initiator's key does NOT match the encapsulator's -- the sides disagree, as designed");
    CHECK(got && sodium_memcmp(c2s, want_zero, 32) != 0,
          "v2-5 H3: ...and it is not the all-zero-ss_k key either (decapsulation really ran)");
    CHECK(hybrid_secrets_wiped(&ini), "v2-5 H3: secrets wiped even on the implicit-rejection path");

    kex_keypair_free(&b_eph);
    handshake_ctx_wipe(&ini);
}

static void test_v25_h4_substitution(void) {
    static handshake_pending_store_t store;
    static handshake_ctx_t ini1, ini2, res;
    kex_keypair_t b_eph;
    uint8_t ch1[CLIENT_HELLO_MAX_ENCODED_LEN], ch2[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t ch1_len = 0, ch2_len = 0, sh_len = 0;
    uint8_t ct1[WIRE_MLKEM_CT_LEN], ct2[WIRE_MLKEM_CT_LEN], ss1[32], ss2[32], sid[16];
    clock_reset();
    store_fresh(&store, 16);

    if (handshake_initiator_init(&ini1, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_initiator_init(&ini2, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini1, ch1, sizeof(ch1), &ch1_len) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini2, ch2, sizeof(ch2), &ch2_len) != HANDSHAKE_OK ||
        kex_keypair_generate(&b_eph) != 0 || encaps_for(ch1, ch1_len, ct1, ss1) != 0 ||
        encaps_for(ch2, ch2_len, ct2, ss2) != 0) {
        fatal("H4 fixture");
    }

    /* (a) A genuine ServerHello for handshake 1, with handshake 2's
     *     ciphertext spliced in afterwards: sig_B no longer matches. */
    session_id_of(ch1, ch1_len, sid);
    if (build_signed_server_hello(ch1, ch1_len, ID_B, sizeof(ID_B), &g_kp_b, b_eph.public_key, ct1, sid, sh,
                                  sizeof(sh), &sh_len) != 0) {
        fatal("H4 ServerHello");
    }
    memcpy(sh + SH_CT_OFFSET(sizeof(ID_B)), ct2, WIRE_MLKEM_CT_LEN);
    const handshake_status_t a = handshake_initiator_verify_server_hello(&ini1, sh, sh_len);
    CHECK(a == HANDSHAKE_ERR_SIGNATURE && handshake_get_state(&ini1) == HANDSHAKE_STATE_FAILED,
          "v2-5 H4: another handshake's mlkem_ct spliced into a signed ServerHello -> SIGNATURE, FAILED");
    CHECK(hybrid_secrets_wiped(&ini1), "v2-5 H4: initiator secrets wiped after the substitution failure");

    /* (b) The other direction: handshake 2's encapsulation key spliced
     *     into initiator 2's OWN ClientHello in flight. The responder
     *     accepts it and signs over the SPLICED bytes; the reply is
     *     returned to initiator 2, so session_id_echo matches and the
     *     check that fires is the one under test -- sig_B, because that
     *     initiator's transcript contains its own ek, not the spliced one.
     *     (ini2's internal copy of its ClientHello is untouched; only the
     *     bytes handed to the responder are altered.) */
    uint8_t ch2_spliced[CLIENT_HELLO_MAX_ENCODED_LEN];
    memcpy(ch2_spliced, ch2, ch2_len);
    memcpy(ch2_spliced + CH_EK_OFFSET(sizeof(ID_A)), ch1 + CH_EK_OFFSET(sizeof(ID_A)), WIRE_MLKEM_EK_LEN);
    CHECK(memcmp(ch2_spliced, ch2, ch2_len) != 0, "v2-5 H4 (precondition): the spliced ClientHello really differs");
    size_t sh2_len = 0;
    const int b_made = handshake_responder_init(&res, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) == HANDSHAKE_OK &&
                       handshake_responder_accept_client_hello(&res, ch2_spliced, ch2_len) == HANDSHAKE_OK &&
                       handshake_responder_create_server_hello(&res, sh, sizeof(sh), &sh2_len) == HANDSHAKE_OK;
    CHECK(b_made, "v2-5 H4: the responder accepts a ClientHello with a substituted ek (it cannot tell)");
    const handshake_status_t b = handshake_initiator_verify_server_hello(&ini2, sh, sh2_len);
    CHECK(b_made && b == HANDSHAKE_ERR_SIGNATURE && handshake_get_state(&ini2) == HANDSHAKE_STATE_FAILED,
          "v2-5 H4: ...and the reply fails sig_B at the initiator, whose transcript has its own ek");
    CHECK(hybrid_secrets_wiped(&ini2), "v2-5 H4: initiator secrets wiped in the ek-substitution case too");

    kex_keypair_free(&b_eph);
    handshake_ctx_wipe(&ini1);
    handshake_ctx_wipe(&ini2);
    handshake_ctx_wipe(&res);
    handshake_pending_store_wipe(&store);
}

static void test_v25_h5_malformed_ek(void) {
    static handshake_pending_store_t store;
    static handshake_ctx_t res;
    kex_keypair_t a_eph;
    uint8_t bad_ek[WIRE_MLKEM_EK_LEN];
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh_len = 777;
    clock_reset();
    store_fresh(&store, 16);
    memset(bad_ek, 0xFF, sizeof(bad_ek)); /* every coefficient >= q */
    memset(sh, 0xAA, sizeof(sh));

    if (kex_keypair_generate(&a_eph) != 0 ||
        build_client_hello(ID_A, sizeof(ID_A), a_eph.public_key, bad_ek, ch, sizeof(ch), &ch_len) != 0 ||
        handshake_responder_init(&res, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) != HANDSHAKE_OK) {
        fatal("H5 fixture");
    }
    CHECK(handshake_responder_accept_client_hello(&res, ch, ch_len) == HANDSHAKE_OK,
          "v2-5 H5: a malformed encapsulation key passes the wire decoder and identity check");

    const handshake_status_t st = handshake_responder_create_server_hello(&res, sh, sizeof(sh), &sh_len);
    CHECK(st == HANDSHAKE_ERR_KEX && handshake_get_state(&res) == HANDSHAKE_STATE_FAILED,
          "v2-5 H5: encapsulation rejects it (FIPS 203 7.2) -> KEX, FAILED");
    CHECK(sh[0] == 0xAA && sh_len == 777, "v2-5 H5: nothing was written to the output buffer");
    CHECK(handshake_pending_active_count(&store) == 0, "v2-5 H5: no ledger entry was created");
    CHECK(no_keys_exposed(&res) && hybrid_secrets_wiped(&res), "v2-5 H5: no keys, secrets wiped");

    kex_keypair_free(&a_eph);
    handshake_ctx_wipe(&res);
    handshake_pending_store_wipe(&store);
}

static void test_v25_h6_wipe_matrix(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    kex_keypair_t eph;
    uint8_t ct[WIRE_MLKEM_CT_LEN], ss_k[32], sid[16];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN], ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t sh_len = 0, ca_len = 0;

    /* --- presence: the secrets must EXIST while the handshake is live,
     *     or every "wiped" assertion below could pass vacuously. --- */
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);
    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK &&
              p.ini.kem.secret_key != NULL,
          "v2-5 H6: the initiator HOLDS dk from CLIENT_HELLO_CREATED");
    CHECK(handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len) == HANDSHAKE_OK &&
              handshake_responder_create_server_hello(&p.res, p.sh, sizeof(p.sh), &p.sh_len) == HANDSHAKE_OK &&
              p.res.ss_kem != NULL,
          "v2-5 H6: the responder HOLDS ss_kem from SERVER_HELLO_CREATED");
    CHECK(handshake_initiator_verify_server_hello(&p.ini, p.sh, p.sh_len) == HANDSHAKE_OK &&
              handshake_initiator_create_client_auth(&p.ini, p.ca, sizeof(p.ca), &p.ca_len) == HANDSHAKE_OK &&
              p.ini.kem.secret_key != NULL,
          "v2-5 H6: the initiator still holds dk at CLIENT_AUTH_CREATED (it decapsulates at finish)");

    /* A below-limit sig_A failure is RETRYABLE, so ss_kem must SURVIVE. */
    memcpy(ca, p.ca, p.ca_len);
    ca_len = p.ca_len;
    ca[ca_len - 1u] ^= 0x01;
    CHECK(handshake_responder_verify_client_auth(&p.res, ca, ca_len) == HANDSHAKE_ERR_SIGNATURE &&
              p.res.ss_kem != NULL,
          "v2-5 H6: ss_kem SURVIVES a retryable sig_A failure -- the next ClientAuth needs it");
    CHECK(handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len) == HANDSHAKE_OK &&
              p.res.ss_kem == NULL,
          "v2-5 H6: ...and is wiped as soon as the keys are derived");
    CHECK(handshake_responder_finish(&p.res) == HANDSHAKE_OK && handshake_initiator_finish(&p.ini) == HANDSHAKE_OK &&
              hybrid_secrets_wiped(&p.ini) && hybrid_secrets_wiped(&p.res),
          "v2-5 H6: both contexts hold no hybrid secret in ESTABLISHED");
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);

    /* --- wiped on representative TERMINAL failures --- */
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);
    if (handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) != HANDSHAKE_OK ||
        encaps_for(p.ch, p.ch_len, ct, ss_k) != 0 || kex_keypair_generate(&eph) != 0) {
        fatal("H6 fixture");
    }
    session_id_of(p.ch, p.ch_len, sid);
    sid[0] ^= 0x01;
    if (build_signed_server_hello(p.ch, p.ch_len, ID_B, sizeof(ID_B), &g_kp_b, eph.public_key, ct, sid, sh,
                                  sizeof(sh), &sh_len) != 0) {
        fatal("H6 ServerHello");
    }
    CHECK(handshake_initiator_verify_server_hello(&p.ini, sh, sh_len) == HANDSHAKE_ERR_SESSION_ID_MISMATCH &&
              hybrid_secrets_wiped(&p.ini),
          "v2-5 H6: initiator secrets wiped after SESSION_ID_MISMATCH");
    kex_keypair_free(&eph);
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);

    /* Responder: unknown identity, then the auth-failure limit. */
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks_b_only); /* A is not pinned */
    if (handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) != HANDSHAKE_OK) {
        fatal("H6 unknown-id fixture");
    }
    CHECK(handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len) == HANDSHAKE_ERR_UNKNOWN_IDENTITY &&
              hybrid_secrets_wiped(&p.res),
          "v2-5 H6: responder secrets wiped after UNKNOWN_IDENTITY");
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);

    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);
    if (pair_to_client_auth(&p) != HANDSHAKE_OK) {
        fatal("H6 auth-limit fixture");
    }
    memcpy(ca, p.ca, p.ca_len);
    ca_len = p.ca_len;
    ca[ca_len - 1u] ^= 0x01;
    handshake_status_t last = HANDSHAKE_OK;
    for (unsigned i = 0; i < HANDSHAKE_AUTH_FAILURE_LIMIT; i++) {
        last = handshake_responder_verify_client_auth(&p.res, ca, ca_len);
    }
    CHECK(last == HANDSHAKE_ERR_AUTH_FAILURE_LIMIT && handshake_get_state(&p.res) == HANDSHAKE_STATE_FAILED &&
              hybrid_secrets_wiped(&p.res),
          "v2-5 H6: responder secrets wiped after AUTH_FAILURE_LIMIT");
    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

static void test_v25_h7_out_cap_rollback(void) {
    static handshake_pending_store_t store;
    static pair_t p;
    uint8_t tiny[8];
    size_t n = 777;
    clock_reset();
    store_fresh(&store, 16);
    pair_init(&p, &store, &g_ks);

    CHECK(handshake_initiator_create_client_hello(&p.ini, tiny, sizeof(tiny), &n) == HANDSHAKE_ERR_INVALID_ARG &&
              handshake_get_state(&p.ini) == HANDSHAKE_STATE_NEW && p.ini.eph.private_key == NULL &&
              p.ini.kem.secret_key == NULL && n == 777,
          "v2-5 H7: a short ClientHello buffer rolls back BOTH keypairs, state stays NEW");

    CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof(p.ch), &p.ch_len) == HANDSHAKE_OK &&
              handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len) == HANDSHAKE_OK,
          "v2-5 H7: the retried ClientHello is accepted");
    CHECK(handshake_responder_create_server_hello(&p.res, tiny, sizeof(tiny), &n) == HANDSHAKE_ERR_INVALID_ARG &&
              handshake_get_state(&p.res) == HANDSHAKE_STATE_CLIENT_HELLO_ACCEPTED &&
              p.res.eph.private_key == NULL && p.res.ss_kem == NULL &&
              handshake_pending_active_count(&store) == 0,
          "v2-5 H7: a short ServerHello buffer rolls back the ephemeral key AND ss_kem, nothing inserted");

    /* The rolled-back contexts must still complete a normal handshake. */
    CHECK(handshake_responder_create_server_hello(&p.res, p.sh, sizeof(p.sh), &p.sh_len) == HANDSHAKE_OK &&
              handshake_initiator_verify_server_hello(&p.ini, p.sh, p.sh_len) == HANDSHAKE_OK &&
              handshake_initiator_create_client_auth(&p.ini, p.ca, sizeof(p.ca), &p.ca_len) == HANDSHAKE_OK &&
              handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len) == HANDSHAKE_OK &&
              handshake_responder_finish(&p.res) == HANDSHAKE_OK &&
              handshake_initiator_finish(&p.ini) == HANDSHAKE_OK,
          "v2-5 H7: both contexts complete normally after the rollbacks");

    const uint8_t *a = NULL;
    const uint8_t *b = NULL;
    CHECK(handshake_session_key_c2s(&p.ini, &a) == HANDSHAKE_OK &&
              handshake_session_key_c2s(&p.res, &b) == HANDSHAKE_OK && sodium_memcmp(a, b, 32) == 0,
          "v2-5 H7: ...and agree on the same key");

    pair_wipe(&p);
    handshake_pending_store_wipe(&store);
}

/* ---- T29 / T32: responder-side low-order X25519 after a valid sig_A --- */

static void test_step4_responder_low_order(int expire_mid_failure) {
    static handshake_pending_store_t store;
    static handshake_ctx_t r;
    static pair_t fresh;
    static uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN], sh[SERVER_HELLO_MAX_ENCODED_LEN],
        ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len = 0, sh_len = 0, ca_len = 0;
    uint8_t hid[16];
    pending_slot_state_t slot;
    uint8_t count = 0;
    const char *t = expire_mid_failure ? "T32" : "T29";
    char name[200];
    mlkem_keypair_t ini_kem; /* valid ek: the X25519 half is the defect under test */
    clock_reset();
    store_fresh(&store, 1); /* capacity 1: reclamation proven by behaviour */

    /* (a) malicious-but-authentic initiator: real A identity, low-order ephemeral */
    if (mlkem_keypair_generate(&ini_kem) != 0 ||
        build_client_hello(ID_A, sizeof(ID_A), SMALL_ORDER_POINT, ini_kem.public_key, ch, sizeof(ch),
                           &ch_len) != 0 ||
        handshake_responder_init(&r, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &store) != HANDSHAKE_OK) {
        fatal("T29 fixture");
    }
    /* (b) */
    const int b_ok = handshake_responder_accept_client_hello(&r, ch, ch_len) == HANDSHAKE_OK &&
                     handshake_responder_create_server_hello(&r, sh, sizeof(sh), &sh_len) == HANDSHAKE_OK;
    snprintf(name, sizeof(name), "step4 %s(b): low-order ClientHello accepted, ServerHello created, store now full", t);
    CHECK(b_ok && handshake_pending_active_count(&store) == 1, name);
    /* (c) a genuinely valid sig_A over the correct transcript */
    if (!b_ok || build_signed_client_auth(ch, ch_len, sh, sh_len, &g_kp_a, ca, sizeof(ca), &ca_len) != 0) {
        fatal("T29 ClientAuth fixture");
    }
    hid_of(ch, ch_len, sh, sh_len, hid);

    if (expire_mid_failure) {
        clock_arm_expiry_after(1); /* live at get_digest, expired by cancel */
    }
    /* (d) */
    const handshake_status_t st = handshake_responder_verify_client_auth(&r, ca, ca_len);
    snprintf(name, sizeof(name), "step4 %s(d): valid sig_A + low-order ephemeral -> KEX (the root cause)", t);
    CHECK(st == HANDSHAKE_ERR_KEX, name);
    /* (e) */
    snprintf(name, sizeof(name), "step4 %s(e): responder FAILED, no keys, not peer-confirmed", t);
    CHECK(handshake_get_state(&r) == HANDSHAKE_STATE_FAILED && no_keys_exposed(&r) &&
              !handshake_is_peer_confirmed(&r),
          name);
    /* (f) */
    snprintf(name, sizeof(name), "step4 %s(f): entry physically removed (inspect -> NOT_FOUND), not left ACTIVE", t);
    CHECK(handshake_pending_inspect(&store, hid, &slot, &count) == PENDING_ERR_NOT_FOUND, name);
    /* (g) */
    snprintf(name, sizeof(name), "step4 %s(g): active_count == 0", t);
    CHECK(handshake_pending_active_count(&store) == 0, name);
    /* (h) */
    pair_init(&fresh, &store, &g_ks);
    snprintf(name, sizeof(name), "step4 %s(h): capacity reclaimed -- a fresh handshake on the capacity-1 store "
                                 "reaches SERVER_HELLO_CREATED", t);
    CHECK(pair_to_server_hello(&fresh) == HANDSHAKE_OK &&
              handshake_get_state(&fresh.res) == HANDSHAKE_STATE_SERVER_HELLO_CREATED,
          name);

    pair_wipe(&fresh);
    handshake_ctx_wipe(&r);
    mlkem_keypair_free(&ini_kem);
    handshake_pending_store_wipe(&store);
}

/* ---- T30: explicit cancellation via handshake_ctx_wipe --------------- */

static void test_step4_wipe_cancels(void) {
    static handshake_pending_store_t store;
    static pair_t p, q;
    uint8_t hid_p[16], hid_q[16];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&store, 4);

    pair_init(&p, &store, &g_ks);
    CHECK(pair_to_server_hello(&p) == HANDSHAKE_OK && handshake_pending_active_count(&store) == 1,
          "step4 T30: responder in SERVER_HELLO_CREATED owns one active entry");
    hid_of(p.ch, p.ch_len, p.sh, p.sh_len, hid_p);
    handshake_ctx_wipe(&p.res);
    CHECK(handshake_pending_inspect(&store, hid_p, &slot, &count) == PENDING_ERR_NOT_FOUND &&
              handshake_pending_active_count(&store) == 0,
          "step4 T30: wiping it cancels the entry immediately (NOT_FOUND, active_count 0)");
    handshake_ctx_wipe(&p.ini);

    pair_init(&q, &store, &g_ks);
    CHECK(pair_to_client_auth(&q) == HANDSHAKE_OK && pair_finish_both(&q) == HANDSHAKE_OK,
          "step4 T30: second pair completes to ESTABLISHED");
    hid_of(q.ch, q.ch_len, q.sh, q.sh_len, hid_q);
    handshake_ctx_wipe(&q.res);
    CHECK(handshake_pending_inspect(&store, hid_q, &slot, &count) == PENDING_ERR_CONSUMED &&
              slot == PENDING_SLOT_CONSUMED,
          "step4 T30: wiping an ESTABLISHED responder leaves its CONSUMED tombstone intact");
    handshake_ctx_wipe(&q.ini);
    handshake_pending_store_wipe(&store);
}

/* ---- T31: cancel semantics, every row of the table ------------------- */

static void test_step4_cancel_semantics(void) {
    static handshake_pending_store_t s;
    uint8_t h[6][16], th[32];
    pending_slot_state_t slot;
    uint8_t count = 0;
    clock_reset();
    store_fresh(&s, 8);
    memset(th, 0x44, sizeof(th));
    for (int i = 0; i < 6; i++) {
        memset(h[i], 0x70 + i, 16);
    }

    handshake_pending_insert(&s, h[0], th);
    CHECK(handshake_pending_cancel(&s, h[0]) == PENDING_OK &&
              handshake_pending_inspect(&s, h[0], &slot, &count) == PENDING_ERR_NOT_FOUND,
          "step4 T31: live ACTIVE -> OK, then NOT_FOUND");

    handshake_pending_insert(&s, h[1], th);
    handshake_pending_consume_success(&s, h[1]);
    CHECK(handshake_pending_cancel(&s, h[1]) == PENDING_ERR_CONSUMED &&
              handshake_pending_inspect(&s, h[1], &slot, &count) == PENDING_ERR_CONSUMED &&
              slot == PENDING_SLOT_CONSUMED,
          "step4 T31: live CONSUMED tombstone -> CONSUMED, and it is still a tombstone");

    handshake_pending_insert(&s, h[2], th);
    for (int i = 0; i < 3; i++) {
        handshake_pending_record_failure(&s, h[2]);
    }
    CHECK(handshake_pending_cancel(&s, h[2]) == PENDING_ERR_AUTH_LIMIT &&
              handshake_pending_inspect(&s, h[2], &slot, &count) == PENDING_ERR_AUTH_LIMIT &&
              slot == PENDING_SLOT_AUTH_LIMITED,
          "step4 T31: live AUTH_LIMITED tombstone -> AUTH_LIMIT, and it is still a tombstone");

    CHECK(handshake_pending_cancel(&s, h[5]) == PENDING_ERR_NOT_FOUND, "step4 T31: absent -> NOT_FOUND");

    handshake_pending_insert(&s, h[3], th);
    g_clock.now += TEST_TTL_MS; /* h[1], h[2], h[3] all expire */
    CHECK(handshake_pending_cancel(&s, h[3]) == PENDING_ERR_EXPIRED &&
              handshake_pending_inspect(&s, h[3], &slot, &count) == PENDING_ERR_NOT_FOUND,
          "step4 T31: expired ACTIVE -> EXPIRED, and the slot is physically freed NOW");
    CHECK(handshake_pending_cancel(&s, h[1]) == PENDING_ERR_EXPIRED &&
              handshake_pending_inspect(&s, h[1], &slot, &count) == PENDING_ERR_NOT_FOUND,
          "step4 T31: expired tombstone -> EXPIRED, evicted by ordinary expiry");
    handshake_pending_store_wipe(&s);
}

/* ---- T33 (store API hygiene): invalid init, overflow-safe deadline ---- */

/* ------------------------------------------------- V4-12: external ledger */

/*
 * The store's slots may live in a caller-provided array, so the daemon can
 * exceed the inline HANDSHAKE_PENDING_MAX of 256.
 *
 * WHY THESE TESTS CARRY THE WEIGHT OF THE STEP. The change rewrote nine
 * accessors from `s->entries[i]` to `s->slots[i]`, and every one of them
 * STILL COMPILES if missed -- `entries` is a real array at a real offset.
 * Worse, a missed site is invisible to every pre-existing test, because all
 * of them use the inline path where the two expressions are the same address.
 * Only a store whose slots are somewhere else can tell them apart, which is
 * what Pext-2 and Pext-6 do.
 */
/* A check that only speaks when it fails -- for loops where 200 PASS lines
 * would bury the result they are establishing. */
#define CHECK_QUIET(cond) do { if (!(cond)) { CHECK(0, "step4 Pext-2b: an insert into the caller array failed"); } } while (0)

static void store_fresh_ext(handshake_pending_store_t *s,
                            handshake_pending_entry_t *slots, size_t capacity) {
    if (handshake_pending_store_init_ext(s, slots, capacity, TEST_TTL_MS,
                                         test_clock_fn, &g_clock) != PENDING_OK) {
        fatal("handshake_pending_store_init_ext");
    }
}

static void id_n(uint8_t out[16], size_t n) {
    memset(out, 0, 16);
    out[0] = (uint8_t)(n & 0xFFu);
    out[1] = (uint8_t)((n >> 8) & 0xFFu);
    out[2] = 0xC7u; /* so no id is all-zero, which a FREE slot also is */
}

static void test_step4_external_ledger(void) {
    static handshake_pending_store_t s;
    static handshake_pending_entry_t big[HANDSHAKE_PENDING_EXT_MAX];
    uint8_t h[16], th[32], out[32];
    memset(th, 0x3C, sizeof th);
    clock_reset();

    /* Pext-1a: the bounds of init_ext, from literals. */
    CHECK(handshake_pending_store_init_ext(&s, big, HANDSHAKE_PENDING_EXT_MAX, TEST_TTL_MS,
                                           test_clock_fn, &g_clock) == PENDING_OK,
          "step4 Pext-1a: init_ext accepts capacity 2048");
    CHECK(handshake_pending_store_init_ext(&s, big, HANDSHAKE_PENDING_EXT_MAX + 1u, TEST_TTL_MS,
                                           test_clock_fn, &g_clock) == PENDING_ERR_INVALID_ARG,
          "step4 Pext-1a: init_ext rejects capacity 2049");
    CHECK(handshake_pending_store_init_ext(&s, NULL, 16, TEST_TTL_MS, test_clock_fn, &g_clock) ==
              PENDING_ERR_INVALID_ARG,
          "step4 Pext-1a: init_ext rejects a NULL backing array");
    CHECK(handshake_pending_store_init_ext(&s, big, 0, TEST_TTL_MS, test_clock_fn, &g_clock) ==
              PENDING_ERR_INVALID_ARG,
          "step4 Pext-1a: init_ext rejects capacity 0");
    CHECK(handshake_pending_store_init_ext(&s, big, 16, 0, test_clock_fn, &g_clock) ==
              PENDING_ERR_INVALID_ARG,
          "step4 Pext-1a: init_ext rejects ttl 0");

    /* Pext-1b: a rejected init leaves the store UNUSABLE, not merely unchanged. */
    id_n(h, 1);
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_ERR_INVALID_ARG,
          "step4 Pext-1b: a store whose init_ext was rejected is unusable");

    /* Pext-1c: init_ext zeroes the caller's array. A reused static would
     * otherwise carry stale bytes that read as occupied slots forever. */
    memset(big, 0xAA, sizeof big);
    store_fresh_ext(&s, big, 8);
    CHECK(handshake_pending_active_count(&s) == 0u,
          "step4 Pext-1c: init_ext zeroes the caller's array (0xAA prefill)");
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_OK,
          "step4 Pext-1c: ...and the store is usable afterwards");

    /* Pext-2b: the same distinction at a capacity that FITS INSIDE the inline
     * array. This is the check that catches a lookup still reading entries[]:
     * at 2048 that read runs off the 256-entry inline array and ASan aborts
     * before any check can print, so the abort -- a weaker verdict than a
     * named failure -- is all a campaign would see. At 200 the wrong array is
     * merely the wrong array: in bounds, empty, and the miss is reportable.
     *
     * It therefore runs BEFORE the 2048 case, not after: the abort would
     * otherwise happen first and the named check would never print. */
    {
        static handshake_pending_entry_t small[200];
        clock_reset();
        store_fresh_ext(&s, small, 200);
        for (size_t i = 0; i < 200u; i++) {
            id_n(h, 3000u + i);
            CHECK_QUIET(handshake_pending_insert(&s, h, th) == PENDING_OK);
        }
        CHECK(handshake_pending_active_count(&s) == 200u,
              "step4 Pext-2b: 200 entries land in a caller array that fits inside entries[]");
        id_n(h, 3000u + 199u);
        CHECK(handshake_pending_get_digest(&s, h, out) == PENDING_OK && memcmp(out, th, 32) == 0,
              "step4 Pext-2b: a caller-array entry is found, not one from the inline array");
        handshake_pending_store_wipe(&s);
    }

    /* Pext-2: capacity really is 2048, and the LAST slot is reachable. The
     * 2048th insert landing and the 2049th failing is what a missed
     * entries->slots rewrite cannot fake. */
    clock_reset();
    store_fresh_ext(&s, big, HANDSHAKE_PENDING_EXT_MAX);
    int inserted = 1;
    for (size_t i = 0; i < HANDSHAKE_PENDING_EXT_MAX; i++) {
        id_n(h, i);
        if (handshake_pending_insert(&s, h, th) != PENDING_OK) { inserted = 0; break; }
    }
    CHECK(inserted == 1, "step4 Pext-2: all 2048 inserts succeed");
    CHECK(handshake_pending_active_count(&s) == (size_t)HANDSHAKE_PENDING_EXT_MAX,
          "step4 Pext-2: active_count is 2048");
    id_n(h, HANDSHAKE_PENDING_EXT_MAX);
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_ERR_FULL,
          "step4 Pext-2: the 2049th insert is FULL");
    /* the entry at the last index is still found */
    id_n(h, HANDSHAKE_PENDING_EXT_MAX - 1u);
    CHECK(handshake_pending_get_digest(&s, h, out) == PENDING_OK && memcmp(out, th, 32) == 0,
          "step4 Pext-2: the id at index 2047 is found with its digest");

    /* Pext-3: expiry works past the inline array's 256 entries. */
    clock_arm_expiry_after(0);
    CHECK(handshake_pending_get_digest(&s, h, out) == PENDING_ERR_EXPIRED,
          "step4 Pext-3: an entry past index 256 expires");
    handshake_pending_sweep(&s);
    CHECK(handshake_pending_active_count(&s) == 0u,
          "step4 Pext-3: sweep frees the whole external array");
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_OK,
          "step4 Pext-3: a swept slot is physically free again");

    /* Pext-4: wipe zeroes the EXTERNAL array. Read through the CALLER's
     * pointer -- the store's is NULL by then, which is the whole point. */
    {
        uint8_t known_id[16], known_th[32];
        memset(known_id, 0x9E, sizeof known_id);
        memset(known_th, 0x7D, sizeof known_th);
        clock_reset();
        store_fresh_ext(&s, big, 300);   /* past the inline 256 on purpose */
        for (size_t i = 0; i < 299; i++) { id_n(h, i); (void)handshake_pending_insert(&s, h, th); }
        CHECK(handshake_pending_insert(&s, known_id, known_th) == PENDING_OK,
              "step4 Pext-4: a known id/digest is in the external array");
        handshake_pending_store_wipe(&s);
        int nonzero = 0;
        const uint8_t *raw = (const uint8_t *)big;
        for (size_t i = 0; i < 300u * sizeof(*big); i++) { if (raw[i] != 0) { nonzero++; } }
        CHECK(nonzero == 0, "step4 Pext-4: wipe zeroes every byte of the EXTERNAL array");
    }

    /* Pext-5: the inline path is untouched -- same limits, same behaviour. */
    {
        static handshake_pending_store_t inl;
        clock_reset();
        CHECK(handshake_pending_store_init(&inl, HANDSHAKE_PENDING_MAX, TEST_TTL_MS,
                                           test_clock_fn, &g_clock) == PENDING_OK,
              "step4 Pext-5: the inline store still accepts capacity 256");
        CHECK(handshake_pending_store_init(&inl, HANDSHAKE_PENDING_MAX + 1u, TEST_TTL_MS,
                                           test_clock_fn, &g_clock) == PENDING_ERR_INVALID_ARG,
              "step4 Pext-5: ...and still refuses 257, external limit or not");
        clock_reset();
        store_fresh(&inl, 4);
        id_n(h, 42);
        CHECK(handshake_pending_insert(&inl, h, th) == PENDING_OK &&
                  handshake_pending_get_digest(&inl, h, out) == PENDING_OK &&
                  handshake_pending_consume_success(&inl, h) == PENDING_OK &&
                  handshake_pending_get_digest(&inl, h, out) == PENDING_ERR_CONSUMED,
              "step4 Pext-5: insert/get/consume/replay still behave on the inline path");
        handshake_pending_store_wipe(&inl);
    }
    handshake_pending_store_wipe(&s);
}

/* ------------------------------------------- V4-12: the lookup callback */

/*
 * A responder may resolve the peer's pin through a callback instead of a
 * keystore_t, so a server holding one pin per connection need not carry a
 * 64,552-byte table to do it.
 *
 * What these have to establish, beyond "it works": that ctx->peer_pk really
 * came from the callback (Pcb-3 hands back a WRONG key and requires the
 * signature to fail), and that the callback is asked about the PEER's
 * identity rather than the local one (Pcb-5 records what it was asked).
 */
typedef struct {
    const uint8_t *pk;      /* what to return, or NULL to refuse */
    uint8_t seen_id[64];
    size_t  seen_len;
    int     calls;
} cb_ctx_t;

static const uint8_t *test_lookup(void *ctx, const uint8_t *id, size_t id_len) {
    cb_ctx_t *c = (cb_ctx_t *)ctx;
    /* NULL-safe on purpose: a resolver that dropped lookup_ctx would otherwise
     * crash here, and a crash is a weaker verdict than a named check. */
    if (c == NULL) {
        return NULL;
    }
    c->calls++;
    c->seen_len = (id_len <= sizeof c->seen_id) ? id_len : sizeof c->seen_id;
    memcpy(c->seen_id, id, c->seen_len);
    return c->pk;
}

/* Both directions agree, read through the accessors' out-parameter form. */
static int keys_agree(const handshake_ctx_t *a, const handshake_ctx_t *b) {
    const uint8_t *ac = NULL, *bc = NULL, *as = NULL, *bs = NULL;
    if (handshake_session_key_c2s(a, &ac) != HANDSHAKE_OK ||
        handshake_session_key_c2s(b, &bc) != HANDSHAKE_OK ||
        handshake_session_key_s2c(a, &as) != HANDSHAKE_OK ||
        handshake_session_key_s2c(b, &bs) != HANDSHAKE_OK) {
        return 0;
    }
    return memcmp(ac, bc, 32) == 0 && memcmp(as, bs, 32) == 0;
}

static void test_step4_lookup_callback(void) {
    static handshake_pending_store_t store;
    static handshake_pending_entry_t big[300];
    uint8_t out[32];
    (void)out;

    /* Pcb-4: argument validation, both directions. */
    {
        handshake_ctx_t r;
        cb_ctx_t cb; memset(&cb, 0, sizeof cb); cb.pk = g_kp_a.public_key;
        clock_reset(); store_fresh(&store, 4);
        CHECK(handshake_responder_init_ext(&r, ID_B, sizeof(ID_B), &g_kp_b, NULL, &cb, &store) ==
                  HANDSHAKE_ERR_INVALID_ARG,
              "step4 Pcb-4: responder_init_ext refuses a NULL lookup_fn");
        CHECK(handshake_responder_init_ext(&r, ID_B, sizeof(ID_B), &g_kp_b, test_lookup, &cb,
                                           &store) == HANDSHAKE_OK,
              "step4 Pcb-4: ...and accepts a real one (canary: not always-refuse)");
        handshake_ctx_wipe(&r);
        CHECK(handshake_responder_init(&r, ID_B, sizeof(ID_B), &g_kp_b, NULL, &store) ==
                  HANDSHAKE_ERR_INVALID_ARG,
              "step4 Pcb-4: responder_init still refuses a NULL keystore");
        handshake_pending_store_wipe(&store);
    }

    /* Pcb-1: a full handshake through the callback reaches ESTABLISHED and
     * both peers agree on both directions' keys. */
    {
        pair_t p;
        cb_ctx_t cb; memset(&cb, 0, sizeof cb); cb.pk = g_kp_a.public_key;
        clock_reset(); store_fresh(&store, 4);
        memset(&p, 0, sizeof p);
        if (handshake_initiator_init(&p.ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B,
                                     sizeof(ID_B)) != HANDSHAKE_OK ||
            handshake_responder_init_ext(&p.res, ID_B, sizeof(ID_B), &g_kp_b, test_lookup, &cb,
                                         &store) != HANDSHAKE_OK) {
            fatal("Pcb-1 init");
        }
        CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK && pair_finish_both(&p) == HANDSHAKE_OK,
              "step4 Pcb-1: a handshake resolved by CALLBACK completes");
        CHECK(keys_agree(&p.ini, &p.res),
              "step4 Pcb-1: both peers derive identical c2s and s2c");
        CHECK(cb.calls == 1, "step4 Pcb-1: the callback was asked exactly once");

        /* Pcb-5: it was asked about the PEER's identity, not the local one. */
        CHECK(cb.seen_len == sizeof(ID_A) && memcmp(cb.seen_id, ID_A, sizeof(ID_A)) == 0,
              "step4 Pcb-5: the callback receives the ClientHello's identity");
        pair_wipe(&p);
        handshake_pending_store_wipe(&store);
    }

    /* Pcb-2: a callback that refuses -> UNKNOWN_IDENTITY and NO ledger entry. */
    {
        pair_t p;
        cb_ctx_t cb; memset(&cb, 0, sizeof cb); cb.pk = NULL;
        clock_reset(); store_fresh(&store, 4);
        memset(&p, 0, sizeof p);
        if (handshake_initiator_init(&p.ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B,
                                     sizeof(ID_B)) != HANDSHAKE_OK ||
            handshake_responder_init_ext(&p.res, ID_B, sizeof(ID_B), &g_kp_b, test_lookup, &cb,
                                         &store) != HANDSHAKE_OK) {
            fatal("Pcb-2 init");
        }
        CHECK(handshake_initiator_create_client_hello(&p.ini, p.ch, sizeof p.ch, &p.ch_len) ==
                  HANDSHAKE_OK,
              "step4 Pcb-2: the ClientHello is created");
        CHECK(handshake_responder_accept_client_hello(&p.res, p.ch, p.ch_len) ==
                  HANDSHAKE_ERR_UNKNOWN_IDENTITY,
              "step4 Pcb-2: a callback returning NULL yields UNKNOWN_IDENTITY");
        CHECK(handshake_pending_active_count(&store) == 0u,
              "step4 Pcb-2: ...and no ledger entry was created");
        pair_wipe(&p);
        handshake_pending_store_wipe(&store);
    }

    /* Pcb-3: a callback handing back the WRONG key. This is what proves
     * peer_pk genuinely came from the callback: everything up to sig_A
     * succeeds, and the signature is what refuses. */
    {
        pair_t p;
        cb_ctx_t cb; memset(&cb, 0, sizeof cb); cb.pk = g_kp_c.public_key; /* C, not A */
        clock_reset(); store_fresh(&store, 4);
        memset(&p, 0, sizeof p);
        if (handshake_initiator_init(&p.ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B,
                                     sizeof(ID_B)) != HANDSHAKE_OK ||
            handshake_responder_init_ext(&p.res, ID_B, sizeof(ID_B), &g_kp_b, test_lookup, &cb,
                                         &store) != HANDSHAKE_OK) {
            fatal("Pcb-3 init");
        }
        CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK,
              "step4 Pcb-3: the wrong pin still gets as far as ClientAuth");
        CHECK(handshake_responder_verify_client_auth(&p.res, p.ca, p.ca_len) ==
                  HANDSHAKE_ERR_SIGNATURE,
              "step4 Pcb-3: a callback returning the WRONG key fails at sig_A");
        pair_wipe(&p);
        handshake_pending_store_wipe(&store);
    }

    /* Pext-6 / Pcb-6: the two features composed, which is how the daemon uses
     * them -- a callback-resolved handshake against an EXTERNAL ledger,
     * pre-filled past the inline array so the entry cannot land in entries[]. */
    {
        pair_t p;
        cb_ctx_t cb; memset(&cb, 0, sizeof cb); cb.pk = g_kp_a.public_key;
        uint8_t fid[16], fth[32];
        memset(fth, 0x11, sizeof fth);
        clock_reset();
        store_fresh_ext(&store, big, 300);
        for (size_t i = 0; i < 299; i++) { id_n(fid, i); (void)handshake_pending_insert(&store, fid, fth); }
        CHECK(handshake_pending_active_count(&store) == 299u,
              "step4 Pext-6: the external ledger is filled to 299 of 300");
        memset(&p, 0, sizeof p);
        if (handshake_initiator_init(&p.ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B,
                                     sizeof(ID_B)) != HANDSHAKE_OK ||
            handshake_responder_init_ext(&p.res, ID_B, sizeof(ID_B), &g_kp_b, test_lookup, &cb,
                                         &store) != HANDSHAKE_OK) {
            fatal("Pext-6 init");
        }
        CHECK(pair_to_client_auth(&p) == HANDSHAKE_OK && pair_finish_both(&p) == HANDSHAKE_OK,
              "step4 Pext-6: a responder handshake completes against an EXTERNAL ledger");
        CHECK(keys_agree(&p.ini, &p.res),
              "step4 Pext-6: ...and both peers agree on the key");
        pair_wipe(&p);
        handshake_pending_store_wipe(&store);
    }
}

static void test_step4_store_api(void) {
    static handshake_pending_store_t s;
    uint8_t h[16], th[32];
    memset(h, 0x5A, 16);
    memset(th, 0x5B, 32);
    CHECK(handshake_pending_store_init(&s, 0, TEST_TTL_MS, NULL, NULL) == PENDING_ERR_INVALID_ARG &&
              handshake_pending_store_init(&s, HANDSHAKE_PENDING_MAX + 1u, TEST_TTL_MS, NULL, NULL) ==
                  PENDING_ERR_INVALID_ARG &&
              handshake_pending_store_init(&s, 4, 0, NULL, NULL) == PENDING_ERR_INVALID_ARG,
          "step4 store: capacity 0 / >MAX and ttl 0 rejected at init");
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_ERR_INVALID_ARG,
          "step4 store: a store whose init was rejected is unusable");
    clock_reset();
    store_fresh(&s, 2);
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_OK && handshake_pending_insert(&s, h, th) == PENDING_ERR_INVALID_ARG,
          "step4 store: duplicate handshake_id insert rejected (fail closed)");
    handshake_pending_store_wipe(&s);
    /* An unreadable/end-of-time clock must fail CLOSED, never wrap. */
    clock_reset();
    g_clock.now = UINT64_MAX - 10u;
    store_fresh(&s, 2);
    CHECK(handshake_pending_insert(&s, h, th) == PENDING_OK, "step4 store: insert near UINT64_MAX");
    g_clock.now = UINT64_MAX;
    uint8_t scratch[32];
    CHECK(handshake_pending_get_digest(&s, h, scratch) == PENDING_ERR_EXPIRED,
          "step4 store: saturating deadline -- the entry expires instead of wrapping to 'never'");
    handshake_pending_store_wipe(&s);
}

static void run_step4_tests(void) {
    if (mldsa_keypair_generate(&g_kp_a) != 0 || mldsa_keypair_generate(&g_kp_b) != 0 ||
        mldsa_keypair_generate(&g_kp_c) != 0) {
        fatal("ML-DSA-65 keypair generation");
    }
    keystore_init(&g_ks);
    keystore_init(&g_ks_b_only);
    if (keystore_add(&g_ks, ID_A, sizeof(ID_A), g_kp_a.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ks, ID_B, sizeof(ID_B), g_kp_b.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ks, ID_C, sizeof(ID_C), g_kp_c.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ks_b_only, ID_B, sizeof(ID_B), g_kp_b.public_key) != KEYSTORE_OK) {
        fatal("keystore fixtures");
    }

    test_step4_happy_path();                    /* T1, T15, T20, T21 */
    test_step4_unknown_peer();                  /* T2 */
    test_step4_session_id_echo_mismatch();      /* T3 */
    test_step4_tampered_sig_b();                /* T4 */
    test_step4_peer_identity_mismatch();        /* T5 */
    test_step4_mutated_handshake_id();          /* T6 */
    test_step4_one_forged_then_legit();         /* T7 */
    test_step4_three_forged();                  /* T8 */
    test_step4_replay_after_success();          /* T9 */
    test_step4_duplicate_client_hello();        /* T10 */
    test_step4_expired();                       /* T11 */
    test_step4_capacity_exhaustion();           /* T12 */
    test_step4_wrong_state_matrix();            /* T13 */
    test_step4_initiator_low_order();           /* T14 */
    test_step4_keystore();                      /* T16 */
    test_step4_unsigned_len_helper();           /* T17 */
    test_step4_get_digest_copy_out();           /* T18 */
    test_step4_inspect_expiry();                /* T19 */
    test_step4_commit_fails_after_derivation(); /* T22 */
    test_v24_kdf_v2();                          /* V2-4 D1-D6 */
    test_v25_h1_manual_responder();             /* V2-5 H1 */
    test_v25_h2_manual_initiator();             /* V2-5 H2 */
    test_v25_h3_tampered_ciphertext();          /* V2-5 H3 */
    test_v25_h4_substitution();                 /* V2-5 H4 */
    test_v25_h5_malformed_ek();                 /* V2-5 H5 */
    test_v25_h6_wipe_matrix();                  /* V2-5 H6 */
    test_v25_h7_out_cap_rollback();             /* V2-5 H7 */
    test_step4_responder_low_order(0);          /* T29 */
    test_step4_wipe_cancels();                  /* T30 */
    test_step4_cancel_semantics();              /* T31 */
    test_step4_responder_low_order(1);          /* T32 */
    test_step4_store_api();
    test_step4_external_ledger();
    test_step4_lookup_callback();                     /* store API hygiene */

    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);
    mldsa_keypair_free(&g_kp_c);
    keystore_wipe(&g_ks);
    keystore_wipe(&g_ks_b_only);
}

int main(void) {
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
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

    /* V2-4: the v2 wire format, checked against literal sizes, offsets
     * and v1 message bytes */
    test_v24_wire_constants();      /* W1-W3 */
    test_v24_new_field_binding();   /* W4 */
    test_v24_v1_messages_rejected(); /* W5 */

    /* Step 4 */
    run_step4_tests();

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
