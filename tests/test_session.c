/*
 * Session record layer (spec §6.4): record format, exact nonce/AD layout,
 * contiguous sequence policy, terminal receive failures, initiator key
 * confirmation, rekey/expiry limits, exactly-once key handoff, and the
 * session_t lifecycle. Every session is created from a REAL handshake
 * driven through the public Step 4 API (ML-DSA-65 identities, X25519).
 *
 * Numbering follows the approved Step 5 plan (S1-S26). S22 is the unchanged
 * test_handshake suite, S23 is tests/test_session_alloc.c and S24 is
 * tests/check_session_no_alloc.cmake -- each a separate CTest test.
 *
 * SINGLE-THREADED BY CONSTRUCTION (spec §6.3.6): every context, store and
 * session here is used from this one thread only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sodium.h>

#include "aead.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"
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

static void fatal(const char *what) {
    fprintf(stderr, "FATAL fixture failure: %s\n", what);
    exit(EXIT_FAILURE);
}

/* ---------------------------------------------------------------------
 * Fixture: identities, keystore, pending store, fake session clock
 * ------------------------------------------------------------------- */

static const uint8_t ID_A[] = {'a', 'l', 'i', 'c', 'e'};
static const uint8_t ID_B[] = {'b', 'o', 'b'};

static mldsa_keypair_t g_kp_a, g_kp_b;
static keystore_t g_ks;                  /* pins A and B */
static handshake_pending_store_t g_store; /* real clock, default TTL */

typedef struct {
    uint64_t now;
} fake_clock_t;

static uint64_t fake_clock_fn(void *p) {
    return ((fake_clock_t *)p)->now;
}

#define T0 UINT64_C(1000)

/* ---- Handshake ----------------------------------------------------------- */

typedef struct {
    handshake_ctx_t ini; /* A, dialing B */
    handshake_ctx_t res; /* B */
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len;
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len;
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ca_len;
    uint8_t hid[WIRE_HANDSHAKE_ID_LEN]; /* derived independently from the wire bytes */
    uint8_t c2s[AEAD_KEY_BYTES];        /* copied out BEFORE the handoff */
    uint8_t s2c[AEAD_KEY_BYTES];
} hs_t;

static void hs_init(hs_t *h) {
    memset(h, 0, sizeof(*h));
    if (handshake_initiator_init(&h->ini, ID_A, sizeof(ID_A), &g_kp_a, &g_ks, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_responder_init(&h->res, ID_B, sizeof(ID_B), &g_kp_b, &g_ks, &g_store) != HANDSHAKE_OK) {
        fatal("handshake init");
    }
}

static void hs_establish(hs_t *h) {
    hs_init(h);
    if (handshake_initiator_create_client_hello(&h->ini, h->ch, sizeof(h->ch), &h->ch_len) != HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&h->res, h->ch, h->ch_len) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&h->res, h->sh, sizeof(h->sh), &h->sh_len) != HANDSHAKE_OK ||
        handshake_initiator_verify_server_hello(&h->ini, h->sh, h->sh_len) != HANDSHAKE_OK ||
        handshake_initiator_create_client_auth(&h->ini, h->ca, sizeof(h->ca), &h->ca_len) != HANDSHAKE_OK ||
        handshake_responder_verify_client_auth(&h->res, h->ca, h->ca_len) != HANDSHAKE_OK ||
        handshake_responder_finish(&h->res) != HANDSHAKE_OK ||
        handshake_initiator_finish(&h->ini) != HANDSHAKE_OK) {
        fatal("handshake did not reach ESTABLISHED (pending store full?)");
    }
    if (transcript_handshake_id(h->ch, h->ch_len, h->sh, h->sh_len, h->hid) != 0) {
        fatal("transcript_handshake_id");
    }
    const uint8_t *k = NULL;
    if (handshake_session_key_c2s(&h->ini, &k) != HANDSHAKE_OK) {
        fatal("c2s accessor");
    }
    memcpy(h->c2s, k, AEAD_KEY_BYTES);
    if (handshake_session_key_s2c(&h->ini, &k) != HANDSHAKE_OK) {
        fatal("s2c accessor");
    }
    memcpy(h->s2c, k, AEAD_KEY_BYTES);
}

static void hs_wipe(hs_t *h) {
    handshake_ctx_wipe(&h->ini);
    handshake_ctx_wipe(&h->res);
}

/* True iff the context is ESTABLISHED and still hands out exactly these keys. */
static int hs_keys_intact(const handshake_ctx_t *ctx, const hs_t *h) {
    const uint8_t *c = NULL;
    const uint8_t *s = NULL;
    return handshake_get_state(ctx) == HANDSHAKE_STATE_ESTABLISHED &&
           handshake_session_key_c2s(ctx, &c) == HANDSHAKE_OK &&
           handshake_session_key_s2c(ctx, &s) == HANDSHAKE_OK &&
           memcmp(c, h->c2s, AEAD_KEY_BYTES) == 0 && memcmp(s, h->s2c, AEAD_KEY_BYTES) == 0;
}

/* ---- Session pair --------------------------------------------------------- */

typedef struct {
    hs_t hs;
    session_t a; /* initiator A */
    session_t b; /* responder B */
    fake_clock_t clk;
} sp_t;

static void sp_open(sp_t *p, const session_limits_t *la, const session_limits_t *lb) {
    memset(p, 0, sizeof(*p));
    p->clk.now = T0;
    hs_establish(&p->hs);
    if (session_init_from_handshake(&p->a, &p->hs.ini, la, fake_clock_fn, &p->clk) != SESSION_OK ||
        session_init_from_handshake(&p->b, &p->hs.res, lb, fake_clock_fn, &p->clk) != SESSION_OK) {
        fatal("session_init_from_handshake");
    }
}

static void sp_close(sp_t *p) {
    session_wipe(&p->a);
    session_wipe(&p->b);
    hs_wipe(&p->hs);
}

/* ---- Record buffers --------------------------------------------------------- */

static uint8_t g_pt_in[SESSION_MAX_PLAINTEXT_BYTES + 1];
static uint8_t g_pt_out[SESSION_MAX_PLAINTEXT_BYTES + 1];
static uint8_t g_rec[SESSION_MAX_RECORD_BYTES + 1];
static uint8_t g_rec2[SESSION_MAX_RECORD_BYTES + 1];

/* Seals g_pt_in[0..pt_len) into rec. */
static session_status_t seal_into(session_t *s, size_t pt_len, uint8_t *rec, size_t *rec_len) {
    return session_seal(s, pt_len ? g_pt_in : NULL, pt_len, rec, SESSION_MAX_RECORD_BYTES + 1, rec_len);
}

static session_status_t open_from(session_t *s, const uint8_t *rec, size_t rec_len, size_t *pt_len) {
    return session_open(s, rec, rec_len, g_pt_out, sizeof(g_pt_out), pt_len);
}

/* Seal pt_len bytes on `from`, open on `to`, and compare. */
static int xfer_ok(session_t *from, session_t *to, size_t pt_len) {
    size_t rec_len = 0;
    size_t got = 0;
    if (seal_into(from, pt_len, g_rec, &rec_len) != SESSION_OK) {
        return 0;
    }
    if (open_from(to, g_rec, rec_len, &got) != SESSION_OK) {
        return 0;
    }
    return got == pt_len && (pt_len == 0 || memcmp(g_pt_out, g_pt_in, pt_len) == 0);
}

/* ---- Independent (hand-built) record layout -------------------------------- */

static const uint8_t HAND_LABEL[20] = {'m', 'l', 'd', 's', 'a', '-', 'a', 'u', 't', 'h',
                                       '/', 'v', '2', '/', 'r', 'e', 'c', 'o', 'r', 'd'};

/* The inner plaintext, built from the literal spec-v2 6.4.1 layout:
 * BE16(content_len) || content || zeros to roundup(2 + content_len, bucket).
 * Deliberately independent of session.c's own arithmetic. */
static size_t hand_inner(uint8_t *inner, const uint8_t *content, size_t content_len, unsigned bucket) {
    const size_t need = content_len + 2u;
    const size_t len = ((need + bucket - 1u) / bucket) * bucket;
    inner[0] = (uint8_t)(content_len >> 8);
    inner[1] = (uint8_t)content_len;
    if (content_len != 0) {
        memcpy(inner + 2, content, content_len);
    }
    memset(inner + need, 0, len - need);
    return len;
}

static void hand_be64(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

static void hand_nonce(uint8_t n[12], uint64_t seq) {
    n[0] = n[1] = n[2] = n[3] = 0x00;
    hand_be64(n + 4, seq);
}

static void hand_ad(uint8_t ad[47], const uint8_t hid[16], uint8_t dir, uint8_t type, uint64_t seq) {
    memcpy(ad, HAND_LABEL, 20);
    ad[20] = 0x00;
    memcpy(ad + 21, hid, 16);
    ad[37] = dir;
    ad[38] = type;
    hand_be64(ad + 39, seq);
}

/* rec = hdr_type || BE(hdr_seq) || AEAD(key, nonce, ad, inner), where the
 * inner is the padded layout above. */
static void hand_record_bucket(uint8_t *rec, size_t *rec_len, const uint8_t key[32], const uint8_t ad[47],
                               const uint8_t nonce[12], uint8_t hdr_type, uint64_t hdr_seq,
                               const uint8_t *content, size_t content_len, unsigned bucket) {
    static uint8_t inner[SESSION_MAX_PLAINTEXT_BYTES];
    size_t ct_len = 0;
    const size_t inner_len = hand_inner(inner, content, content_len, bucket);
    rec[0] = hdr_type;
    hand_be64(rec + 1, hdr_seq);
    if (aead_encrypt(rec + 9, &ct_len, inner, inner_len, ad, 47, nonce, key) != 0) {
        fatal("aead_encrypt (hand record)");
    }
    *rec_len = 9 + ct_len;
}

/* Seals RAW inner bytes, valid or not -- the only way to test the receiver's
 * inner-format rules, which sit behind a passing AEAD check. */
static void hand_record_raw_inner(uint8_t *rec, size_t *rec_len, const uint8_t key[32], const uint8_t ad[47],
                                  const uint8_t nonce[12], uint64_t hdr_seq, const uint8_t *inner,
                                  size_t inner_len) {
    size_t ct_len = 0;
    rec[0] = 0x04;
    hand_be64(rec + 1, hdr_seq);
    if (aead_encrypt(rec + 9, &ct_len, inner, inner_len, ad, 47, nonce, key) != 0) {
        fatal("aead_encrypt (raw inner)");
    }
    *rec_len = 9 + ct_len;
}

static void hand_record(uint8_t *rec, size_t *rec_len, const uint8_t key[32], const uint8_t ad[47],
                        const uint8_t nonce[12], uint8_t hdr_type, uint64_t hdr_seq, const uint8_t *pt,
                        size_t pt_len) {
    hand_record_bucket(rec, rec_len, key, ad, nonce, hdr_type, hdr_seq, pt, pt_len,
                       SESSION_PAD_BUCKET_DEFAULT);
}

/* Decrypt a session-produced record with the hand-built layout. */
static int hand_open_ok(const uint8_t *rec, size_t rec_len, const uint8_t key[32], const uint8_t hid[16],
                        uint8_t dir, uint64_t seq, const uint8_t *expect, size_t expect_len) {
    uint8_t nonce[12];
    uint8_t ad[47];
    size_t got = 0;
    hand_nonce(nonce, seq);
    hand_ad(ad, hid, dir, 0x04, seq);
    if (aead_decrypt(g_pt_out, &got, rec + 9, rec_len - 9, ad, sizeof(ad), nonce, key) != 0) {
        return 0;
    }
    /* Parse the inner by hand: length prefix, content, all-zero padding. */
    if (got < 2u) {
        return 0;
    }
    const size_t content_len = ((size_t)g_pt_out[0] << 8) | (size_t)g_pt_out[1];
    if (content_len != expect_len || content_len > got - 2u) {
        return 0;
    }
    for (size_t i = 2u + content_len; i < got; i++) {
        if (g_pt_out[i] != 0x00) {
            return 0;
        }
    }
    return expect_len == 0 || memcmp(g_pt_out + 2, expect, expect_len) == 0;
}

/* ---- Dead-session hygiene (S18) --------------------------------------------- */

static void check_dead(session_t *s, session_state_t want, const char *path) {
    /* Large enough for a 1-byte payload at the LARGEST bucket, so the seal
     * below is refused for the session's state, never for its capacity. */
    static uint8_t out[SESSION_RECORD_LEN(1, SESSION_PAD_BUCKET_MAX)];
    uint8_t pt[8];
    uint8_t rec[SESSION_MIN_RECORD_BYTES];
    size_t out_len = 777;
    size_t pt_len = 777;
    memset(out, 0x5A, sizeof(out));
    memset(pt, 0x5A, sizeof(pt));
    memset(rec, 0, sizeof(rec));
    rec[0] = SESSION_RECORD_TYPE;

    const session_status_t st_seal = session_seal(s, g_pt_in, 1, out, sizeof(out), &out_len);
    const session_status_t st_open = session_open(s, rec, sizeof(rec), pt, sizeof(pt), &pt_len);
    int untouched = out_len == 777 && pt_len == 777;
    for (size_t i = 0; i < sizeof(out); i++) {
        untouched &= (out[i] == 0x5A);
    }
    for (size_t i = 0; i < sizeof(pt); i++) {
        untouched &= (pt[i] == 0x5A);
    }

    char name[200];
    snprintf(name, sizeof(name),
             "S18 (%s): %s, key block zeroed (white-box), seal/open refused writing nothing, "
             "not confirmed, rekey due",
             path, want == SESSION_STATE_EXPIRED ? "EXPIRED" : "FAILED");
    CHECK(session_get_state(s) == want && s->keys != NULL && sodium_is_zero(s->keys, 2u * AEAD_KEY_BYTES) &&
              st_seal == SESSION_ERR_UNEXPECTED_STATE && st_open == SESSION_ERR_UNEXPECTED_STATE &&
              untouched && !session_is_peer_confirmed(s) && session_rekey_due(s),
          name);
}

/* =====================================================================
 * S1 -- round trip
 * =================================================================== */

static void test_s1_round_trip(void) {
    static const size_t sizes[] = {0, 1, 64, 1024, SESSION_MAX_CONTENT_BYTES};
    sp_t p;
    sp_open(&p, NULL, NULL);
    uint64_t sent = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        int ok = 1;
        for (int r = 0; r < 3; r++) {
            ok &= xfer_ok(&p.a, &p.b, sizes[i]);
            ok &= xfer_ok(&p.b, &p.a, sizes[i]);
        }
        sent += 3;
        char name[120];
        snprintf(name, sizeof(name), "S1: %zu-byte payload, 3 records each direction, plaintext recovered",
                 sizes[i]);
        CHECK(ok, name);
    }
    CHECK(session_get_state(&p.a) == SESSION_STATE_ACTIVE && session_get_state(&p.b) == SESSION_STATE_ACTIVE &&
              p.a.send_seq == sent && p.a.recv_seq == sent && p.b.send_seq == sent && p.b.recv_seq == sent,
          "S1: both sides ACTIVE; each direction's sequence advanced by exactly one per record");
    sp_close(&p);
}

/* =====================================================================
 * S2 -- byte-exact nonce and AD; S3 -- record header
 * =================================================================== */

static void test_s2_s3_exact_layout(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    const uint8_t *hid = p.hs.hid;

    /* (a) records the session produced, opened with the hand-built layout. */
    size_t len[3] = {0, 0, 0};
    uint8_t recs[3][SESSION_RECORD_LEN(64, SESSION_PAD_BUCKET_DEFAULT)];
    int a_ok = 1;
    for (uint64_t seq = 0; seq < 3; seq++) {
        if (session_seal(&p.a, g_pt_in, 64, recs[seq], sizeof(recs[seq]), &len[seq]) != SESSION_OK) {
            a_ok = 0;
            continue;
        }
        a_ok &= hand_open_ok(recs[seq], len[seq], p.hs.c2s, hid, 0x43, seq, g_pt_in, 64);
    }
    CHECK(a_ok, "S2(a): initiator records seq 0,1,2 decrypt with the hand-built nonce "
                "(00000000||BE64 seq) and AD (label||00||handshake_id||0x43||0x04||BE64 seq)");

    int hdr_ok = 1;
    for (uint64_t seq = 0; seq < 3; seq++) {
        uint8_t be[8];
        hand_be64(be, seq);
        hdr_ok &= (len[seq] == SESSION_RECORD_LEN(64, SESSION_PAD_BUCKET_DEFAULT)) && recs[seq][0] == 0x04 &&
                  memcmp(recs[seq] + 1, be, 8) == 0;
    }
    CHECK(hdr_ok, "S3: record = 0x04 || BE64 seq || AEAD(inner) || tag; a 64-byte payload at the default bucket is 281 bytes");

    size_t e_len = 0;
    uint8_t e_rec[SESSION_RECORD_LEN(0, SESSION_PAD_BUCKET_DEFAULT)];
    CHECK(session_seal(&p.a, NULL, 0, e_rec, sizeof(e_rec), &e_len) == SESSION_OK &&
              e_len == SESSION_RECORD_LEN(0, SESSION_PAD_BUCKET_DEFAULT) && e_len == 281u &&
              e_rec[0] == 0x04 && e_rec[8] == 3,
          "S3: an empty payload still yields a full padded record (281 bytes at bucket 256) carrying seq 3");

    /* Responder direction. */
    int b_ok = 1;
    for (uint64_t seq = 0; seq < 2; seq++) {
        size_t l = 0;
        uint8_t r[SESSION_RECORD_LEN(64, SESSION_PAD_BUCKET_DEFAULT)];
        b_ok &= session_seal(&p.b, g_pt_in, 64, r, sizeof(r), &l) == SESSION_OK &&
                hand_open_ok(r, l, p.hs.s2c, hid, 0x53, seq, g_pt_in, 64);
    }
    CHECK(b_ok, "S2(a): responder records seq 0,1 decrypt with the hand-built layout (direction 0x53)");

    /* (b) the responder accepts a record sealed entirely by hand. */
    size_t got = 0;
    int deliver_ok = 1;
    for (uint64_t seq = 0; seq < 3; seq++) {
        deliver_ok &= open_from(&p.b, recs[seq], len[seq], &got) == SESSION_OK;
    }
    deliver_ok &= open_from(&p.b, e_rec, e_len, &got) == SESSION_OK;
    uint8_t nonce[12];
    uint8_t ad[47];
    size_t hl = 0;
    hand_nonce(nonce, 4);
    hand_ad(ad, hid, 0x43, 0x04, 4);
    hand_record(g_rec, &hl, p.hs.c2s, ad, nonce, 0x04, 4, g_pt_in, 100);
    CHECK(deliver_ok && open_from(&p.b, g_rec, hl, &got) == SESSION_OK && got == 100 &&
              memcmp(g_pt_out, g_pt_in, 100) == 0,
          "S2(b): session_open accepts a record built and sealed entirely by hand (seq 4)");
    sp_close(&p);

    /* (c) every single-field deviation from the layout is rejected. Each
     * variant needs its own session: the first failure is terminal. */
    typedef enum { V_LABEL, V_SEP, V_HID, V_DIR, V_TYPE, V_AD_SEQ, V_NONCE_LE, V_NONCE_HI } variant_t;
    static const char *names[] = {
        "S2(c): AD label byte altered -> AUTH",
        "S2(c): AD 0x00 separator altered -> AUTH",
        "S2(c): AD handshake_id altered -> AUTH",
        "S2(c): AD direction 0x53 on a c2s record -> AUTH",
        "S2(c): AD record_type 0x05 (header still 0x04) -> AUTH",
        "S2(c): AD seq differs from header/nonce seq -> AUTH",
        "S2(c): nonce with seq little-endian (seq 1) -> AUTH",
        "S2(c): nonce with seq in bytes 0..7 instead of 4..11 (seq 1) -> AUTH",
    };
    for (variant_t v = V_LABEL; v <= V_NONCE_HI; v++) {
        sp_open(&p, NULL, NULL);
        uint64_t seq = 0;
        if (v == V_NONCE_LE || v == V_NONCE_HI) {
            /* seq 0 encodes identically in every byte order: move to seq 1. */
            if (!xfer_ok(&p.a, &p.b, 16)) {
                fatal("S2(c) warm-up record");
            }
            seq = 1;
        }
        hand_nonce(nonce, seq);
        hand_ad(ad, p.hs.hid, 0x43, 0x04, seq);
        switch (v) {
        case V_LABEL: ad[0] ^= 0x01; break;
        case V_SEP: ad[20] = 0x01; break;
        case V_HID: ad[21] ^= 0x80; break;
        case V_DIR: ad[37] = 0x53; break;
        case V_TYPE: ad[38] = 0x05; break;
        case V_AD_SEQ: hand_be64(ad + 39, seq + 1); break;
        case V_NONCE_LE:
            memset(nonce, 0, 12);
            nonce[4] = (uint8_t)seq; /* little-endian placement */
            break;
        case V_NONCE_HI:
            memset(nonce, 0, 12);
            hand_be64(nonce, seq);
            break;
        }
        hand_record(g_rec, &hl, p.hs.c2s, ad, nonce, 0x04, seq, g_pt_in, 32);
        CHECK(open_from(&p.b, g_rec, hl, &got) == SESSION_ERR_AUTH, names[v]);
        sp_close(&p);
    }
}

/* =====================================================================
 * S4-S9 -- sequence policy, tampering, reflection, cross-session, malformed
 * =================================================================== */

static void test_s4_replay(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l0 = 0;
    size_t l1 = 0;
    size_t got = 0;
    seal_into(&p.a, 40, g_rec, &l0);
    seal_into(&p.a, 40, g_rec2, &l1);
    const int first = open_from(&p.b, g_rec, l0, &got) == SESSION_OK;
    CHECK(first && open_from(&p.b, g_rec, l0, &got) == SESSION_ERR_REPLAY &&
              session_get_state(&p.b) == SESSION_STATE_FAILED,
          "S4: re-delivering an accepted record -> REPLAY, session FAILED");
    CHECK(open_from(&p.b, g_rec2, l1, &got) == SESSION_ERR_UNEXPECTED_STATE,
          "S4: the genuine next record is refused afterwards (terminal)");
    check_dead(&p.b, SESSION_STATE_FAILED, "replay");
    sp_close(&p);
}

static void test_s5_out_of_order(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l0 = 0;
    size_t l1 = 0;
    size_t got = 0;
    seal_into(&p.a, 40, g_rec, &l0);
    seal_into(&p.a, 40, g_rec2, &l1);
    CHECK(open_from(&p.b, g_rec2, l1, &got) == SESSION_ERR_OUT_OF_ORDER &&
              session_get_state(&p.b) == SESSION_STATE_FAILED,
          "S5: seq 1 before seq 0 (a gap) -> OUT_OF_ORDER, session FAILED");
    check_dead(&p.b, SESSION_STATE_FAILED, "out-of-order");
    sp_close(&p);
}

static void test_s6_tamper(void) {
    /* 40-byte payload: ciphertext is rec[9..49), tag is rec[49..65). */
    static const struct {
        size_t offset_from_end;
        const char *what;
    } cases[] = {
        {17, "S6: flipped ciphertext bit -> AUTH, FAILED"},
        {1, "S6: flipped tag bit -> AUTH, FAILED"},
    };
    for (size_t i = 0; i < 2; i++) {
        sp_t p;
        sp_open(&p, NULL, NULL);
        size_t l = 0;
        size_t got = 0;
        seal_into(&p.a, 40, g_rec, &l);
        g_rec[l - cases[i].offset_from_end] ^= 0x01;
        CHECK(open_from(&p.b, g_rec, l, &got) == SESSION_ERR_AUTH &&
                  session_get_state(&p.b) == SESSION_STATE_FAILED,
              cases[i].what);
        check_dead(&p.b, SESSION_STATE_FAILED, i == 0 ? "auth failure: ciphertext" : "auth failure: tag");
        sp_close(&p);
    }
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l = 0;
    size_t got = 0;
    seal_into(&p.a, 40, g_rec, &l);
    g_rec[8] ^= 0x01; /* seq 0 -> 1 in the header */
    CHECK(open_from(&p.b, g_rec, l, &got) == SESSION_ERR_OUT_OF_ORDER,
          "S6: flipped seq bit in the header -> rejected by ordering before any AEAD work");
    sp_close(&p);
}

static void test_s7_reflection(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l = 0;
    size_t got = 0;
    seal_into(&p.a, 40, g_rec, &l);
    CHECK(open_from(&p.a, g_rec, l, &got) == SESSION_ERR_AUTH && session_get_state(&p.a) == SESSION_STATE_FAILED,
          "S7: a record reflected back to its own sender -> AUTH (wrong key and direction)");
    sp_close(&p);
}

static void test_s8_cross_session(void) {
    sp_t p1;
    sp_t p2;
    sp_open(&p1, NULL, NULL);
    sp_open(&p2, NULL, NULL);
    size_t l = 0;
    size_t got = 0;
    seal_into(&p1.a, 40, g_rec, &l);
    CHECK(open_from(&p2.b, g_rec, l, &got) == SESSION_ERR_AUTH,
          "S8: seq-0 record from handshake 1 delivered to handshake 2's session -> AUTH");
    sp_close(&p1);
    sp_close(&p2);
}

static void test_s9_malformed(void) {
    static const struct {
        size_t len;
        uint8_t type;
        const char *what;
    } cases[] = {
        {0, 0x04, "S9: empty record -> MALFORMED, FAILED"},
        {24, 0x04, "S9: 24-byte record -> MALFORMED"},
        {25, 0x04, "S9: 25-byte record (v1's minimum, too short for a 2-byte inner) -> MALFORMED"},
        {26, 0x04, "S9: 26-byte record (one below the 27-byte minimum) -> MALFORMED"},
        {SESSION_MAX_RECORD_BYTES + 1, 0x04, "S9: record one byte over the maximum -> MALFORMED"},
        {0, 0x01, "S9: record_type 0x01 (ClientHello) -> MALFORMED"},
        {0, 0x03, "S9: record_type 0x03 (ClientAuth) -> MALFORMED"},
        {0, 0x05, "S9: record_type 0x05 (unassigned) -> MALFORMED"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sp_t p;
        sp_open(&p, NULL, NULL);
        size_t l = 0;
        size_t got = 0;
        seal_into(&p.a, 40, g_rec, &l); /* a genuine record to start from */
        if (cases[i].type != 0x04) {
            g_rec[0] = cases[i].type;
        } else {
            l = cases[i].len;
            if (l > 0) {
                g_rec[0] = 0x04;
            }
        }
        const session_status_t st = open_from(&p.b, g_rec, l, &got);
        CHECK(st == SESSION_ERR_MALFORMED && session_get_state(&p.b) == SESSION_STATE_FAILED, cases[i].what);
        if (i == 0) {
            check_dead(&p.b, SESSION_STATE_FAILED, "malformed");
        }
        sp_close(&p);
    }
}

/* =====================================================================
 * S10 -- API misuse: no state change, no seq consumed
 * =================================================================== */

static void test_s10_misuse(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l = 0;
    const size_t need = SESSION_RECORD_LEN(40, SESSION_PAD_BUCKET_DEFAULT);

    int seal_rejected = 1;
    seal_rejected &= session_seal(NULL, g_pt_in, 40, g_rec, need, &l) == SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, g_pt_in, 40, NULL, need, &l) == SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, g_pt_in, 40, g_rec, need, NULL) == SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, NULL, 40, g_rec, need, &l) == SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, g_pt_in, 40, g_rec, need - 1, &l) == SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, g_pt_in, SESSION_MAX_CONTENT_BYTES + 1, g_rec, sizeof(g_rec), &l) ==
                     SESSION_ERR_INVALID_ARG;
    seal_rejected &= session_seal(&p.a, g_pt_in, SESSION_MAX_PLAINTEXT_BYTES, g_rec, sizeof(g_rec), &l) ==
                     SESSION_ERR_INVALID_ARG; /* 65536: the inner bound, not a content bound */
    seal_rejected &= session_seal(&p.a, g_rec + 5, 40, g_rec, need, &l) == SESSION_ERR_INVALID_ARG; /* overlap */
    CHECK(seal_rejected, "S10: seal misuse (NULLs, out_cap short by 1, content 65535/65536, overlap) -> INVALID_ARG");
    CHECK(session_get_state(&p.a) == SESSION_STATE_ACTIVE && p.a.send_seq == 0,
          "S10: seal misuse changed no state and consumed no seq");
    CHECK(session_seal(&p.a, g_pt_in, 40, g_rec, need, &l) == SESSION_OK && g_rec[8] == 0 && l == need,
          "S10: the next good seal uses seq 0");

    size_t got = 0;
    int open_rejected = 1;
    open_rejected &= session_open(NULL, g_rec, l, g_pt_out, sizeof(g_pt_out), &got) == SESSION_ERR_INVALID_ARG;
    open_rejected &= session_open(&p.b, NULL, l, g_pt_out, sizeof(g_pt_out), &got) == SESSION_ERR_INVALID_ARG;
    open_rejected &= session_open(&p.b, g_rec, l, NULL, sizeof(g_pt_out), &got) == SESSION_ERR_INVALID_ARG;
    open_rejected &= session_open(&p.b, g_rec, l, g_pt_out, sizeof(g_pt_out), NULL) == SESSION_ERR_INVALID_ARG;
    open_rejected &= session_open(&p.b, g_rec, l, g_pt_out, l - SESSION_OVERHEAD_BYTES - 1u, &got) ==
                     SESSION_ERR_INVALID_ARG;
    open_rejected &= session_open(&p.b, g_rec, l, g_rec + 3, sizeof(g_pt_out), &got) ==
                     SESSION_ERR_INVALID_ARG; /* overlap */
    CHECK(open_rejected, "S10: open misuse (NULLs, pt_cap short by 1, overlap) -> INVALID_ARG");
    CHECK(session_get_state(&p.b) == SESSION_STATE_ACTIVE && p.b.recv_seq == 0,
          "S10: open misuse changed no state and consumed no seq");
    CHECK(session_open(&p.b, g_rec, l, g_pt_out, sizeof(g_pt_out), &got) == SESSION_OK && got == 40 &&
              memcmp(g_pt_out, g_pt_in, 40) == 0,
          "S10: the same record then opens with a big-enough buffer");
    sp_close(&p);
}

/* =====================================================================
 * S11 -- initiator key confirmation
 * =================================================================== */

static void test_s11_confirmation(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    CHECK(!session_is_peer_confirmed(&p.a) && session_is_peer_confirmed(&p.b),
          "S11: after init the initiator is unconfirmed and the responder confirmed");
    CHECK(xfer_ok(&p.a, &p.b, 64) && !session_is_peer_confirmed(&p.a),
          "S11: sealing (and the responder accepting it) does not confirm the initiator");

    size_t l = 0;
    size_t got = 99;
    CHECK(session_seal(&p.b, NULL, 0, g_rec, sizeof(g_rec), &l) == SESSION_OK &&
              open_from(&p.a, g_rec, l, &got) == SESSION_OK && got == 0 && session_is_peer_confirmed(&p.a),
          "S11: the initiator is confirmed by its first successfully opened record (empty payload)");
    sp_close(&p);

    sp_open(&p, NULL, NULL);
    seal_into(&p.b, 16, g_rec, &l);
    g_rec[l - 1] ^= 0x01;
    CHECK(open_from(&p.a, g_rec, l, &got) == SESSION_ERR_AUTH && !session_is_peer_confirmed(&p.a) &&
              !p.a.peer_confirmed,
          "S11: a forged responder record never confirms the initiator");
    sp_close(&p);
}

/* =====================================================================
 * S12 -- exactly-once handoff; S13 -- init preconditions
 * =================================================================== */

static void test_s12_handoff(void) {
    hs_t h;
    hs_establish(&h);
    session_t a;
    session_t b;
    session_t again;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&again, 0, sizeof(again));
    const uint8_t *k = NULL;

    CHECK(session_init_from_handshake(&a, &h.ini, NULL, NULL, NULL) == SESSION_OK &&
              handshake_get_state(&h.ini) == HANDSHAKE_STATE_FAILED &&
              handshake_session_key_c2s(&h.ini, &k) != HANDSHAKE_OK && k == NULL,
          "S12: init consumed the initiator handshake (FAILED, key accessors refuse)");
    CHECK(session_init_from_handshake(&again, &h.ini, NULL, NULL, NULL) == SESSION_ERR_UNEXPECTED_STATE &&
              session_get_state(&again) == SESSION_STATE_EMPTY && again.keys == NULL,
          "S12: a second session from the consumed initiator handshake -> UNEXPECTED_STATE");
    CHECK(session_init_from_handshake(&b, &h.res, NULL, NULL, NULL) == SESSION_OK &&
              handshake_get_state(&h.res) == HANDSHAKE_STATE_FAILED &&
              session_init_from_handshake(&again, &h.res, NULL, NULL, NULL) == SESSION_ERR_UNEXPECTED_STATE,
          "S12: the same holds for the responder handshake");

    pending_slot_state_t ps;
    uint8_t fc;
    CHECK(handshake_pending_inspect(&g_store, h.hid, &ps, &fc) == PENDING_ERR_CONSUMED &&
              ps == PENDING_SLOT_CONSUMED,
          "S12: consuming the responder handshake leaves its CONSUMED ledger tombstone intact");
    CHECK(xfer_ok(&a, &b, 32) && xfer_ok(&b, &a, 32), "S12: the handed-off sessions interoperate");
    session_wipe(&a);
    session_wipe(&b);
    hs_wipe(&h);
}

static void expect_init_refused(handshake_ctx_t *ctx, const char *name) {
    session_t s;
    memset(&s, 0, sizeof(s));
    const handshake_state_t before = handshake_get_state(ctx);
    CHECK(session_init_from_handshake(&s, ctx, NULL, NULL, NULL) == SESSION_ERR_UNEXPECTED_STATE &&
              handshake_get_state(ctx) == before && session_get_state(&s) == SESSION_STATE_EMPTY &&
              s.keys == NULL,
          name);
}

static void test_s13_init_preconditions(void) {
    hs_t h;
    hs_init(&h);
    expect_init_refused(&h.ini, "S13: init from initiator NEW -> UNEXPECTED_STATE, handshake untouched");
    expect_init_refused(&h.res, "S13: init from responder NEW -> UNEXPECTED_STATE");
    if (handshake_initiator_create_client_hello(&h.ini, h.ch, sizeof(h.ch), &h.ch_len) != HANDSHAKE_OK) {
        fatal("S13 CH");
    }
    expect_init_refused(&h.ini, "S13: init from CLIENT_HELLO_CREATED -> UNEXPECTED_STATE");
    if (handshake_responder_accept_client_hello(&h.res, h.ch, h.ch_len) != HANDSHAKE_OK) {
        fatal("S13 accept");
    }
    expect_init_refused(&h.res, "S13: init from CLIENT_HELLO_ACCEPTED -> UNEXPECTED_STATE");
    if (handshake_responder_create_server_hello(&h.res, h.sh, sizeof(h.sh), &h.sh_len) != HANDSHAKE_OK) {
        fatal("S13 SH");
    }
    expect_init_refused(&h.res, "S13: init from SERVER_HELLO_CREATED -> UNEXPECTED_STATE (entry not cancelled)");
    if (handshake_initiator_verify_server_hello(&h.ini, h.sh, h.sh_len) != HANDSHAKE_OK) {
        fatal("S13 verify SH");
    }
    expect_init_refused(&h.ini, "S13: init from SERVER_HELLO_VERIFIED -> UNEXPECTED_STATE");
    if (handshake_initiator_create_client_auth(&h.ini, h.ca, sizeof(h.ca), &h.ca_len) != HANDSHAKE_OK) {
        fatal("S13 CA");
    }
    expect_init_refused(&h.ini, "S13: init from CLIENT_AUTH_CREATED -> UNEXPECTED_STATE");
    if (handshake_responder_verify_client_auth(&h.res, h.ca, h.ca_len) != HANDSHAKE_OK) {
        fatal("S13 verify CA");
    }
    expect_init_refused(&h.res, "S13: init from CLIENT_AUTH_VERIFIED -> UNEXPECTED_STATE");
    hs_wipe(&h);
    expect_init_refused(&h.ini, "S13: init from a wiped (FAILED) handshake -> UNEXPECTED_STATE");

    hs_establish(&h);
    const session_limits_t bad[] = {
        {0, 5, 100, 200, SESSION_PAD_BUCKET_DEFAULT},
        {6, 5, 100, 200, SESSION_PAD_BUCKET_DEFAULT},
        {SESSION_REKEY_AFTER_MESSAGES + 1, SESSION_REJECT_AFTER_MESSAGES, 100, 200, SESSION_PAD_BUCKET_DEFAULT},
        {1, SESSION_REJECT_AFTER_MESSAGES + 1, 100, 200, SESSION_PAD_BUCKET_DEFAULT},
        {1, 5, 0, 200, SESSION_PAD_BUCKET_DEFAULT},
        {1, 5, 201, 200, SESSION_PAD_BUCKET_DEFAULT},
        {1, 5, SESSION_REKEY_AFTER_MS + 1, SESSION_REJECT_AFTER_MS, SESSION_PAD_BUCKET_DEFAULT},
        {1, 5, 100, SESSION_REJECT_AFTER_MS + 1, SESSION_PAD_BUCKET_DEFAULT},
        /* Pad buckets outside {1,16,64,256,1024,4096}: 0 is NOT "use the
         * default", and neither is a stray power of two. */
        {1, 5, 100, 200, 0u},
        {1, 5, 100, 200, 2u},
        {1, 5, 100, 200, 32u},
        {1, 5, 100, 200, 8192u},
        {1, 5, 100, 200, 65536u},
        {1, 5, 100, 200, 255u},
    };
    int all_refused = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        session_t s;
        memset(&s, 0, sizeof(s));
        all_refused &= session_init_from_handshake(&s, &h.ini, &bad[i], NULL, NULL) == SESSION_ERR_INVALID_ARG &&
                       session_get_state(&s) == SESSION_STATE_EMPTY && s.keys == NULL;
    }
    CHECK(all_refused, "S13: invalid limits (zero, soft > hard, above any default, and any pad bucket outside the six allowed values) -> INVALID_ARG");
    CHECK(hs_keys_intact(&h.ini, &h), "S13: ...and the ESTABLISHED handshake still hands out the same keys");

    {
        /* ...while every allowed bucket is accepted. */
        static const uint32_t ok_buckets[6] = {1u, 16u, 64u, 256u, 1024u, 4096u};
        int all_ok = 1;
        for (size_t i = 0; i < 6u; i++) {
            hs_t hb;
            session_t s2;
            session_limits_t lim;
            session_default_limits(&lim);
            lim.pad_bucket = ok_buckets[i];
            memset(&s2, 0, sizeof(s2));
            hs_establish(&hb);
            all_ok &= session_init_from_handshake(&s2, &hb.ini, &lim, NULL, NULL) == SESSION_OK &&
                      s2.limits.pad_bucket == ok_buckets[i];
            session_wipe(&s2);
            hs_wipe(&hb);
        }
        CHECK(all_ok, "S13: all six allowed pad buckets (1, 16, 64, 256, 1024, 4096) are accepted");
    }

    session_t s;
    memset(&s, 0, sizeof(s));
    CHECK(session_init_from_handshake(NULL, &h.ini, NULL, NULL, NULL) == SESSION_ERR_INVALID_ARG &&
              session_init_from_handshake(&s, NULL, NULL, NULL, NULL) == SESSION_ERR_INVALID_ARG &&
              hs_keys_intact(&h.ini, &h),
          "S13: NULL session or handshake -> INVALID_ARG");
    hs_wipe(&h);
}

/* =====================================================================
 * S14 -- record limits; S15 -- time limits; S16 -- clock failure
 * =================================================================== */

static void test_s14_record_limits(void) {
    const session_limits_t lim = {3, 5, SESSION_REKEY_AFTER_MS, SESSION_REJECT_AFTER_MS, SESSION_PAD_BUCKET_DEFAULT};
    sp_t p;
    sp_open(&p, &lim, &lim);
    int ok = xfer_ok(&p.a, &p.b, 8) && xfer_ok(&p.a, &p.b, 8);
    CHECK(ok && !session_rekey_due(&p.a) && !session_rekey_due(&p.b),
          "S14: after 2 records neither side is due (soft limit 3)");
    ok = xfer_ok(&p.a, &p.b, 8);
    CHECK(ok && session_rekey_due(&p.a) && session_rekey_due(&p.b),
          "S14: after exactly 3 records the sender is due (send count) and so is the receiver (receive count)");
    CHECK(xfer_ok(&p.a, &p.b, 8) && xfer_ok(&p.a, &p.b, 8), "S14: records 4 and 5 still work (hard limit 5)");
    size_t l = 0;
    CHECK(seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED && session_get_state(&p.a) == SESSION_STATE_EXPIRED,
          "S14: the 6th seal -> EXPIRED");
    check_dead(&p.a, SESSION_STATE_EXPIRED, "seal over the hard record limit");
    sp_close(&p);

    const session_limits_t tight = {1, 2, SESSION_REKEY_AFTER_MS, SESSION_REJECT_AFTER_MS, SESSION_PAD_BUCKET_DEFAULT};
    sp_open(&p, &lim, &tight);
    size_t got = 0;
    size_t l2 = 0;
    ok = xfer_ok(&p.a, &p.b, 8) && xfer_ok(&p.a, &p.b, 8);
    ok &= seal_into(&p.a, 8, g_rec2, &l2) == SESSION_OK;
    CHECK(ok && open_from(&p.b, g_rec2, l2, &got) == SESSION_ERR_LIMIT &&
              session_get_state(&p.b) == SESSION_STATE_FAILED,
          "S14: a peer sending past the receiver's hard limit (2) -> LIMIT, FAILED");
    check_dead(&p.b, SESSION_STATE_FAILED, "peer over the hard record limit");
    sp_close(&p);
}

static void test_s15_time_limits(void) {
    const session_limits_t lim = {SESSION_REKEY_AFTER_MESSAGES, SESSION_REJECT_AFTER_MESSAGES, 100, 200, SESSION_PAD_BUCKET_DEFAULT};
    sp_t p;
    sp_open(&p, &lim, &lim);
    p.clk.now = T0 + 99;
    CHECK(!session_rekey_due(&p.a) && !session_rekey_due(&p.b), "S15: 1 ms before the soft time limit: not due");
    p.clk.now = T0 + 100;
    CHECK(session_rekey_due(&p.a) && session_rekey_due(&p.b) && xfer_ok(&p.a, &p.b, 8),
          "S15: at the soft time limit: due, and records still flow");
    p.clk.now = T0 + 199;
    size_t l = 0;
    size_t got = 0;
    CHECK(xfer_ok(&p.b, &p.a, 8) && seal_into(&p.a, 8, g_rec2, &l) == SESSION_OK,
          "S15: 1 ms before the hard time limit: records still flow");
    p.clk.now = T0 + 200;
    CHECK(seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED, "S15: at the hard time limit seal -> EXPIRED");
    check_dead(&p.a, SESSION_STATE_EXPIRED, "seal at the hard time limit");
    CHECK(open_from(&p.b, g_rec2, SESSION_RECORD_LEN(8, SESSION_PAD_BUCKET_DEFAULT), &got) == SESSION_ERR_EXPIRED,
          "S15: at the hard time limit open -> EXPIRED (even for a record sealed in time)");
    check_dead(&p.b, SESSION_STATE_EXPIRED, "open at the hard time limit");
    sp_close(&p);

    /* The real spec values, via the fake clock. */
    sp_open(&p, NULL, NULL);
    p.clk.now = T0 + 3599999u;
    CHECK(!session_rekey_due(&p.a), "S15: default limits: not due at 3,599,999 ms");
    p.clk.now = T0 + 3600000u;
    CHECK(session_rekey_due(&p.a) && xfer_ok(&p.a, &p.b, 8), "S15: default limits: due at exactly 3,600,000 ms");
    p.clk.now = T0 + 3899999u;
    CHECK(xfer_ok(&p.a, &p.b, 8), "S15: default limits: records still flow at 3,899,999 ms");
    p.clk.now = T0 + 3900000u;
    CHECK(seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED, "S15: default limits: EXPIRED at exactly 3,900,000 ms");
    sp_close(&p);
}

static void test_s16_clock_failure(void) {
    sp_t p;
    size_t l = 0;
    size_t got = 0;

    sp_open(&p, NULL, NULL);
    seal_into(&p.a, 8, g_rec2, &l);
    p.clk.now = UINT64_MAX;
    CHECK(session_rekey_due(&p.a) && seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED &&
              open_from(&p.b, g_rec2, SESSION_RECORD_LEN(8, SESSION_PAD_BUCKET_DEFAULT), &got) ==
                  SESSION_ERR_EXPIRED,
          "S16: an unreadable clock (UINT64_MAX) -> due, and seal/open EXPIRED (fail closed)");
    sp_close(&p);

    sp_open(&p, NULL, NULL);
    p.clk.now = T0 - 1;
    CHECK(session_rekey_due(&p.a) && seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED,
          "S16: a clock that went backwards by 1 ms -> EXPIRED");
    sp_close(&p);

    /* A backwards jump from near the top of the range would wrap to a SMALL
     * age without the now < start guard. */
    sp_open(&p, NULL, NULL);
    session_wipe(&p.a);
    hs_t h;
    hs_establish(&h);
    p.clk.now = UINT64_MAX - 10u;
    if (session_init_from_handshake(&p.a, &h.ini, NULL, fake_clock_fn, &p.clk) != SESSION_OK) {
        fatal("S16 init near UINT64_MAX");
    }
    p.clk.now = 5;
    CHECK(seal_into(&p.a, 8, g_rec, &l) == SESSION_ERR_EXPIRED,
          "S16: a backwards jump from near UINT64_MAX (unsigned age would wrap to 16 ms) -> EXPIRED");
    hs_wipe(&h);
    sp_close(&p);

    hs_establish(&h);
    session_t s;
    memset(&s, 0, sizeof(s));
    fake_clock_t dead = {UINT64_MAX};
    CHECK(session_init_from_handshake(&s, &h.ini, NULL, fake_clock_fn, &dead) == SESSION_ERR_EXPIRED &&
              session_get_state(&s) == SESSION_STATE_EMPTY && s.keys == NULL && hs_keys_intact(&h.ini, &h),
          "S16: init with an unreadable clock -> EXPIRED; session EMPTY, handshake untouched");
    hs_wipe(&h);
}

/* =====================================================================
 * S17 -- defaults; S19 -- plaintext wiped on failure; S20 -- rekey cutover
 * =================================================================== */

static void test_s17_defaults(void) {
    session_limits_t d;
    session_default_limits(&d);
    CHECK(d.rekey_after_messages == UINT64_C(4294967296) && d.reject_after_messages == UINT64_C(8589934592) &&
              d.rekey_after_ms == UINT64_C(3600000) && d.reject_after_ms == UINT64_C(3900000) &&
              d.pad_bucket == 256u,
          "S17: defaults are 2^32 / 2^33 records, 3,600,000 / 3,900,000 ms, and pad bucket 256");
    sp_t p;
    sp_open(&p, NULL, NULL);
    /* Compared field by field: session_limits_t now has trailing padding
     * after its uint32_t, and padding bytes are not guaranteed equal. */
    CHECK(p.a.limits.rekey_after_messages == d.rekey_after_messages &&
              p.a.limits.reject_after_messages == d.reject_after_messages &&
              p.a.limits.rekey_after_ms == d.rekey_after_ms &&
              p.a.limits.reject_after_ms == d.reject_after_ms && p.a.limits.pad_bucket == d.pad_bucket &&
              p.b.limits.rekey_after_messages == d.rekey_after_messages &&
              p.b.limits.reject_after_messages == d.reject_after_messages &&
              p.b.limits.rekey_after_ms == d.rekey_after_ms &&
              p.b.limits.reject_after_ms == d.reject_after_ms && p.b.limits.pad_bucket == d.pad_bucket,
          "S17: NULL limits -> the defaults");
    sp_close(&p);
}

static void test_s19_plaintext_wiped(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    size_t l = 0;
    size_t got = 0;
    seal_into(&p.a, 64, g_rec, &l);
    g_rec[20] ^= 0x01;
    memset(g_pt_out, 0xAA, 64);
    const session_status_t st = open_from(&p.b, g_rec, l, &got);
    CHECK(st == SESSION_ERR_AUTH && sodium_is_zero(g_pt_out, 64),
          "S19: a failed open zeroes the plaintext region of the caller's buffer");
    sp_close(&p);
}

static void test_s20_cutover(void) {
    sp_t old_p;
    sp_t new_p;
    sp_open(&old_p, NULL, NULL);
    sp_open(&new_p, NULL, NULL);
    size_t l = 0;
    size_t got = 0;
    seal_into(&old_p.a, 32, g_rec2, &l); /* old session, c2s, seq 0 */
    CHECK(xfer_ok(&new_p.b, &new_p.a, 32), "S20: the post-rekey session works (responder -> initiator)");
    CHECK(open_from(&new_p.b, g_rec2, l, &got) == SESSION_ERR_AUTH,
          "S20: an old-session seq-0 record is rejected by the new session, which also expects seq 0 "
          "(same seq, different keys)");
    sp_close(&old_p);
    sp_close(&new_p);
}

/* =====================================================================
 * S21 -- new handshake accessors
 * =================================================================== */

static void test_s21_accessors(void) {
    hs_t h;
    hs_init(&h);
    handshake_role_t r1 = (handshake_role_t)0;
    handshake_role_t r2 = (handshake_role_t)0;
    CHECK(handshake_get_role(&h.ini, &r1) == HANDSHAKE_OK && r1 == HANDSHAKE_ROLE_INITIATOR &&
              handshake_get_role(&h.res, &r2) == HANDSHAKE_OK && r2 == HANDSHAKE_ROLE_RESPONDER,
          "S21: handshake_get_role reports each role");
    CHECK(handshake_get_role(NULL, &r1) == HANDSHAKE_ERR_INVALID_ARG &&
              handshake_get_role(&h.ini, NULL) == HANDSHAKE_ERR_INVALID_ARG,
          "S21: handshake_get_role NULL args -> INVALID_ARG");

    uint8_t id[WIRE_HANDSHAKE_ID_LEN];
    memset(id, 0xFF, sizeof(id));
    CHECK(handshake_get_handshake_id(&h.ini, id) == HANDSHAKE_ERR_UNEXPECTED_STATE && sodium_is_zero(id, sizeof(id)),
          "S21: handshake_get_handshake_id before ESTABLISHED -> UNEXPECTED_STATE, output zeroed");
    hs_wipe(&h);
    CHECK(handshake_get_role(&h.ini, &r1) == HANDSHAKE_ERR_UNEXPECTED_STATE,
          "S21: handshake_get_role on a wiped context -> UNEXPECTED_STATE");

    hs_establish(&h);
    uint8_t id_a[WIRE_HANDSHAKE_ID_LEN];
    uint8_t id_b[WIRE_HANDSHAKE_ID_LEN];
    CHECK(handshake_get_handshake_id(&h.ini, id_a) == HANDSHAKE_OK &&
              handshake_get_handshake_id(&h.res, id_b) == HANDSHAKE_OK && memcmp(id_a, h.hid, 16) == 0 &&
              memcmp(id_b, h.hid, 16) == 0,
          "S21: in ESTABLISHED both sides report the handshake_id derived independently from the wire bytes");
    CHECK(handshake_get_handshake_id(NULL, id_a) == HANDSHAKE_ERR_INVALID_ARG &&
              handshake_get_handshake_id(&h.ini, NULL) == HANDSHAKE_ERR_INVALID_ARG,
          "S21: handshake_get_handshake_id NULL args -> INVALID_ARG");
    hs_wipe(&h);

    const uint64_t t1 = handshake_default_clock_ms(NULL);
    const uint64_t t2 = handshake_default_clock_ms(NULL);
    CHECK(t1 != UINT64_MAX && t2 >= t1, "S21: handshake_default_clock_ms reads a monotonic clock");
}

/* =====================================================================
 * S25 -- no reinitialization without wipe; S26 -- idempotent wipe
 * =================================================================== */

static void test_s25_no_reinit(void) {
    sp_t p;
    sp_open(&p, NULL, NULL);
    int warm = xfer_ok(&p.a, &p.b, 16) && xfer_ok(&p.a, &p.b, 16) && xfer_ok(&p.b, &p.a, 16);

    hs_t h2;
    hs_establish(&h2);
    session_t before;
    uint8_t key_copy[2 * AEAD_KEY_BYTES];
    memcpy(&before, &p.a, sizeof(before));
    memcpy(key_copy, p.a.keys, sizeof(key_copy));

    CHECK(warm && session_init_from_handshake(&p.a, &h2.ini, NULL, fake_clock_fn, &p.clk) ==
                      SESSION_ERR_UNEXPECTED_STATE,
          "S25(a): init on an ACTIVE session without wiping -> UNEXPECTED_STATE");
    CHECK(memcmp(&before, &p.a, sizeof(before)) == 0 && memcmp(key_copy, p.a.keys, sizeof(key_copy)) == 0 &&
              p.a.send_seq == 2 && p.a.recv_seq == 1,
          "S25(b): the live session is byte-identical: state, seqs, key pointer and key bytes");
    CHECK(xfer_ok(&p.a, &p.b, 16) && xfer_ok(&p.b, &p.a, 16), "S25(b): ...and still talks to its peer");
    CHECK(hs_keys_intact(&h2.ini, &h2), "S25(c): the second handshake is still ESTABLISHED with the same keys");

    session_wipe(&p.a);
    session_t b2;
    memset(&b2, 0, sizeof(b2));
    CHECK(session_init_from_handshake(&p.a, &h2.ini, NULL, fake_clock_fn, &p.clk) == SESSION_OK &&
              session_init_from_handshake(&b2, &h2.res, NULL, fake_clock_fn, &p.clk) == SESSION_OK &&
              xfer_ok(&p.a, &b2, 16) && xfer_ok(&b2, &p.a, 16),
          "S25(d): after session_wipe the same session_t initializes from the second handshake and works");
    session_wipe(&b2);
    hs_wipe(&h2);

    /* (e) FAILED and EXPIRED sessions still own a (zeroed) key block. */
    size_t l = 0;
    size_t got = 0;
    seal_into(&p.a, 8, g_rec, &l);
    seal_into(&p.a, 8, g_rec2, &l);
    session_t *dead = &p.b; /* p.b still belongs to the first handshake */
    (void)open_from(dead, g_rec2, l, &got); /* wrong session and wrong seq: terminal */
    hs_t h3;
    hs_establish(&h3);
    CHECK(session_get_state(dead) == SESSION_STATE_FAILED && dead->keys != NULL &&
              session_init_from_handshake(dead, &h3.res, NULL, NULL, NULL) == SESSION_ERR_UNEXPECTED_STATE &&
              hs_keys_intact(&h3.res, &h3),
          "S25(e): init on a FAILED session (key block still owned) -> UNEXPECTED_STATE, handshake untouched");
    hs_wipe(&h3);
    sp_close(&p);

    const session_limits_t one = {1, 1, SESSION_REKEY_AFTER_MS, SESSION_REJECT_AFTER_MS, SESSION_PAD_BUCKET_DEFAULT};
    sp_open(&p, &one, NULL);
    seal_into(&p.a, 8, g_rec, &l);
    (void)seal_into(&p.a, 8, g_rec, &l);
    hs_establish(&h3);
    CHECK(session_get_state(&p.a) == SESSION_STATE_EXPIRED && p.a.keys != NULL &&
              session_init_from_handshake(&p.a, &h3.ini, NULL, NULL, NULL) == SESSION_ERR_UNEXPECTED_STATE &&
              hs_keys_intact(&h3.ini, &h3),
          "S25(e): init on an EXPIRED session (key block still owned) -> UNEXPECTED_STATE, handshake untouched");
    hs_wipe(&h3);
    sp_close(&p);
}

static int is_empty_and_inert(session_t *s) {
    size_t l = 0;
    size_t got = 0;
    uint8_t rec[SESSION_MIN_RECORD_BYTES] = {0x04};
    return session_get_state(s) == SESSION_STATE_EMPTY && s->keys == NULL &&
           session_seal(s, NULL, 0, g_rec, sizeof(g_rec), &l) == SESSION_ERR_UNEXPECTED_STATE &&
           session_open(s, rec, sizeof(rec), g_pt_out, sizeof(g_pt_out), &got) == SESSION_ERR_UNEXPECTED_STATE &&
           !session_is_peer_confirmed(s) && session_rekey_due(s);
}

static void test_s26_wipe_idempotent(void) {
    session_t z;
    memset(&z, 0, sizeof(z));
    CHECK(is_empty_and_inert(&z), "S26: a zero-initialized session is EMPTY and every operation is refused");
    session_wipe(&z);
    const int once = is_empty_and_inert(&z);
    session_wipe(&z);
    CHECK(once && is_empty_and_inert(&z), "S26: wiping a zero-initialized session twice is safe");

    sp_t p;
    sp_open(&p, NULL, NULL);
    session_wipe(&p.a);
    /* Asserted BEFORE the second wipe: if the key pointer survived, the
     * second wipe would be a double free and could crash before reporting. */
    CHECK(is_empty_and_inert(&p.a),
          "S26: the first wipe of an initialized session leaves it EMPTY with the key pointer cleared");
    session_wipe(&p.a);
    CHECK(is_empty_and_inert(&p.a),
          "S26: wiping it a second time: no crash or double free, still EMPTY, keys unavailable");
    session_wipe(NULL);
    CHECK(session_get_state(NULL) == SESSION_STATE_EMPTY, "S26: session_wipe(NULL) is a no-op; NULL reads EMPTY");
    sp_close(&p);
}

/* =====================================================================
 * S27 -- the designed failure mode of a KEM key disagreement (V2-5)
 *
 * spec-v2 6.3: a tampered mlkem_ct is implicitly rejected, both sides
 * complete the handshake, and "the disagreement surfaces as the initiator's
 * first record failing to authenticate". That sentence is asserted here
 * with REAL code on both sides.
 *
 * WHITE-BOX BY NECESSITY: ek and ct are both covered by the signatures, so
 * a ciphertext altered on the wire is rejected as SIGNATURE long before any
 * key is derived (test_handshake H4). The only way to reach implicit
 * rejection with two genuine contexts is to alter the ciphertext the
 * initiator has already accepted -- a public field of its context, touched
 * here the way other tests read eph.private_key and keys_committed.
 * =================================================================== */

static void test_s27_kem_disagreement(void) {
    hs_t h;
    session_t a;
    session_t b;
    fake_clock_t clk;
    size_t rec_len = 0;
    size_t got = 0;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&clk, 0, sizeof(clk));
    clk.now = T0;

    hs_init(&h);
    const int upto_sh =
        handshake_initiator_create_client_hello(&h.ini, h.ch, sizeof(h.ch), &h.ch_len) == HANDSHAKE_OK &&
        handshake_responder_accept_client_hello(&h.res, h.ch, h.ch_len) == HANDSHAKE_OK &&
        handshake_responder_create_server_hello(&h.res, h.sh, sizeof(h.sh), &h.sh_len) == HANDSHAKE_OK &&
        handshake_initiator_verify_server_hello(&h.ini, h.sh, h.sh_len) == HANDSHAKE_OK;
    CHECK(upto_sh, "S27: the handshake reaches SERVER_HELLO_VERIFIED normally");

    /* One byte of the ACCEPTED ciphertext: sig_B has already been checked,
     * so nothing downstream can notice. */
    h.ini.peer_mlkem_ct[0] ^= 0x01;

    const int established =
        upto_sh &&
        handshake_initiator_create_client_auth(&h.ini, h.ca, sizeof(h.ca), &h.ca_len) == HANDSHAKE_OK &&
        handshake_responder_verify_client_auth(&h.res, h.ca, h.ca_len) == HANDSHAKE_OK &&
        handshake_responder_finish(&h.res) == HANDSHAKE_OK &&
        handshake_initiator_finish(&h.ini) == HANDSHAKE_OK;
    CHECK(established, "S27: BOTH sides still reach ESTABLISHED -- decapsulation reports no error (Req 4.11)");

    const uint8_t *ik = NULL;
    const uint8_t *rk = NULL;
    CHECK(established && handshake_session_key_c2s(&h.ini, &ik) == HANDSHAKE_OK &&
              handshake_session_key_c2s(&h.res, &rk) == HANDSHAKE_OK &&
              sodium_memcmp(ik, rk, AEAD_KEY_BYTES) != 0,
          "S27: ...but they derived DIFFERENT keys");

    if (!established || session_init_from_handshake(&a, &h.ini, NULL, fake_clock_fn, &clk) != SESSION_OK ||
        session_init_from_handshake(&b, &h.res, NULL, fake_clock_fn, &clk) != SESSION_OK) {
        fatal("S27 sessions");
    }

    /* The initiator's first record cannot be opened by the responder. */
    CHECK(seal_into(&a, 32, g_rec, &rec_len) == SESSION_OK &&
              open_from(&b, g_rec, rec_len, &got) == SESSION_ERR_AUTH &&
              session_get_state(&b) == SESSION_STATE_FAILED,
          "S27: the initiator's first record fails AUTH at the responder, terminally");

    /* And in the other direction the initiator is never confirmed -- which
     * is what applications gate irreversible actions on (6.4.4). */
    session_wipe(&b);
    memset(&b, 0, sizeof(b));
    hs_t h2;
    session_t a2;
    session_t b2;
    memset(&a2, 0, sizeof(a2));
    memset(&b2, 0, sizeof(b2));
    hs_init(&h2);
    const int ok2 = handshake_initiator_create_client_hello(&h2.ini, h2.ch, sizeof(h2.ch), &h2.ch_len) ==
                        HANDSHAKE_OK &&
                    handshake_responder_accept_client_hello(&h2.res, h2.ch, h2.ch_len) == HANDSHAKE_OK &&
                    handshake_responder_create_server_hello(&h2.res, h2.sh, sizeof(h2.sh), &h2.sh_len) ==
                        HANDSHAKE_OK &&
                    handshake_initiator_verify_server_hello(&h2.ini, h2.sh, h2.sh_len) == HANDSHAKE_OK;
    if (!ok2) {
        fatal("S27 second fixture");
    }
    h2.ini.peer_mlkem_ct[WIRE_MLKEM_CT_LEN - 1u] ^= 0x01;
    if (handshake_initiator_create_client_auth(&h2.ini, h2.ca, sizeof(h2.ca), &h2.ca_len) != HANDSHAKE_OK ||
        handshake_responder_verify_client_auth(&h2.res, h2.ca, h2.ca_len) != HANDSHAKE_OK ||
        handshake_responder_finish(&h2.res) != HANDSHAKE_OK ||
        handshake_initiator_finish(&h2.ini) != HANDSHAKE_OK ||
        session_init_from_handshake(&a2, &h2.ini, NULL, fake_clock_fn, &clk) != SESSION_OK ||
        session_init_from_handshake(&b2, &h2.res, NULL, fake_clock_fn, &clk) != SESSION_OK) {
        fatal("S27 second sessions");
    }
    CHECK(seal_into(&b2, 0, g_rec, &rec_len) == SESSION_OK &&
              open_from(&a2, g_rec, rec_len, &got) == SESSION_ERR_AUTH && !session_is_peer_confirmed(&a2),
          "S27: the responder's confirmation record fails AUTH, so the initiator is never confirmed");

    session_wipe(&a);
    session_wipe(&a2);
    session_wipe(&b2);
    hs_wipe(&h);
    hs_wipe(&h2);
}

/* =====================================================================
 * P1-P6 -- record padding (spec-v2 6.4.1)
 *
 * Every expected length here is computed by the test's OWN roundup, and
 * every malformed-inner case is sealed with the hand-built AEAD under the
 * real key -- the receiver's inner-format rules sit behind a passing AEAD
 * check, so a random record can never reach them.
 * =================================================================== */

static const uint32_t P_BUCKETS[6] = {1u, 16u, 64u, 256u, 1024u, 4096u};

/* The test's own arithmetic, independent of SESSION_INNER_LEN. */
static size_t p_roundup(size_t content_len, uint32_t bucket) {
    size_t n = content_len + 2u;
    while (n % bucket != 0u) {
        n++;
    }
    return n;
}

static void p_open_pair(sp_t *p, uint32_t bucket_a, uint32_t bucket_b) {
    session_limits_t la;
    session_limits_t lb;
    session_default_limits(&la);
    session_default_limits(&lb);
    la.pad_bucket = bucket_a;
    lb.pad_bucket = bucket_b;
    sp_open(p, &la, &lb);
}

static void test_p1_exact_lengths(void) {
    static const size_t sizes[13] = {0, 1, 2, 14, 15, 16, 17, 255, 256, 1024, 4095, 4096,
                                     SESSION_MAX_CONTENT_BYTES};
    int all_ok = 1;
    int inner_ok = 1;
    for (size_t b = 0; b < 6u; b++) {
        sp_t p;
        p_open_pair(&p, P_BUCKETS[b], P_BUCKETS[b]);
        for (size_t i = 0; i < 13u; i++) {
            const size_t want = p_roundup(sizes[i], P_BUCKETS[b]) + SESSION_OVERHEAD_BYTES;
            size_t l = 0;
            memset(g_rec, 0xAA, want + 1u); /* a seal that skips its padding is visible */
            const int sealed = seal_into(&p.a, sizes[i], g_rec, &l) == SESSION_OK;
            all_ok &= sealed && l == want && session_sealed_len(&p.a, sizes[i]) == want &&
                      want == SESSION_RECORD_LEN(sizes[i], P_BUCKETS[b]);
            /* The inner really is BE16(len) || content || zeros. */
            inner_ok &= sealed && hand_open_ok(g_rec, l, p.hs.c2s, p.hs.hid, 0x43, p.b.recv_seq, g_pt_in,
                                               sizes[i]);
            size_t got = 0;
            all_ok &= sealed && open_from(&p.b, g_rec, l, &got) == SESSION_OK && got == sizes[i];
        }
        sp_close(&p);
    }
    CHECK(all_ok, "v2-6 P1: record length is roundup(2 + content, bucket) + 25 for 13 content sizes x all six "
                  "buckets, agreeing with session_sealed_len and SESSION_RECORD_LEN");
    CHECK(inner_ok, "v2-6 P1: ...and each inner is exactly BE16(content_len) || content || zero padding");
}

static void test_p2_bucket_one(void) {
    static const size_t sizes[6] = {0, 1, 64, 1024, 65533, SESSION_MAX_CONTENT_BYTES};
    sp_t p;
    p_open_pair(&p, 1u, 1u);
    int ok = 1;
    for (size_t i = 0; i < 6u; i++) {
        size_t l = 0;
        size_t got = 0;
        ok &= seal_into(&p.a, sizes[i], g_rec, &l) == SESSION_OK &&
              l == sizes[i] + SESSION_CONTENT_LEN_BYTES + SESSION_OVERHEAD_BYTES &&
              open_from(&p.b, g_rec, l, &got) == SESSION_OK && got == sizes[i];
    }
    CHECK(ok, "v2-6 P2: bucket 1 adds no padding at all -- every record is content + 27 bytes");
    sp_close(&p);
}

static void test_p3_bucket_independence(void) {
    static const size_t sizes[5] = {0, 1, 100, 4095, 5000};
    int ok = 1;
    for (size_t i = 0; i < 5u; i++) {
        sp_t p;
        size_t l = 0;
        size_t got = 0;
        /* A bucket-1 sender talking to a bucket-4096 receiver, and back. */
        p_open_pair(&p, 1u, SESSION_PAD_BUCKET_MAX);
        ok &= seal_into(&p.a, sizes[i], g_rec, &l) == SESSION_OK && l == sizes[i] + 27u &&
              open_from(&p.b, g_rec, l, &got) == SESSION_OK && got == sizes[i];
        ok &= seal_into(&p.b, sizes[i], g_rec2, &l) == SESSION_OK &&
              l == p_roundup(sizes[i], SESSION_PAD_BUCKET_MAX) + SESSION_OVERHEAD_BYTES &&
              open_from(&p.a, g_rec2, l, &got) == SESSION_OK && got == sizes[i];
        sp_close(&p);
    }
    CHECK(ok, "v2-6 P3: a receiver requires nothing of the sender's bucket -- bucket 1 <-> bucket 4096 "
              "interoperate in both directions at every size");
}

/* Seals raw inner bytes to p->b under the c2s key at its next expected seq. */
static void p_seal_inner(sp_t *p, const uint8_t *inner, size_t inner_len, uint8_t *rec, size_t *rec_len) {
    uint8_t nonce[12];
    uint8_t ad[47];
    const uint64_t seq = p->b.recv_seq;
    hand_nonce(nonce, seq);
    hand_ad(ad, p->hs.hid, 0x43, 0x04, seq);
    hand_record_raw_inner(rec, rec_len, p->hs.c2s, ad, nonce, seq, inner, inner_len);
}

static void test_p4_malformed_inner(void) {
    static uint8_t inner[512];

    /* (a) content_len one past what the inner can hold. */
    {
        sp_t p;
        size_t l = 0;
        size_t got = 0;
        p_open_pair(&p, SESSION_PAD_BUCKET_DEFAULT, SESSION_PAD_BUCKET_DEFAULT);
        memset(inner, 0, 64);
        inner[0] = 0x00;
        inner[1] = 63; /* 63 > 64 - 2 */
        p_seal_inner(&p, inner, 64, g_rec, &l);
        memset(g_pt_out, 0xAA, 64);
        CHECK(open_from(&p.b, g_rec, l, &got) == SESSION_ERR_MALFORMED &&
                  session_get_state(&p.b) == SESSION_STATE_FAILED && sodium_is_zero(g_pt_out, 64),
              "v2-6 P4(a): an authentic inner whose content_len exceeds it -> MALFORMED, FAILED, buffer zeroed");
        check_dead(&p.b, SESSION_STATE_FAILED, "content_len past the inner");
        sp_close(&p);
    }

    /* (b),(c) nonzero padding, first and last byte. */
    static const struct {
        int last;
        const char *what;
    } pad_cases[2] = {
        {0, "v2-6 P4(b): the FIRST padding byte nonzero -> MALFORMED, FAILED, buffer zeroed"},
        {1, "v2-6 P4(c): the LAST padding byte nonzero -> MALFORMED, FAILED, buffer zeroed"},
    };
    for (size_t i = 0; i < 2u; i++) {
        sp_t p;
        size_t l = 0;
        size_t got = 0;
        p_open_pair(&p, SESSION_PAD_BUCKET_DEFAULT, SESSION_PAD_BUCKET_DEFAULT);
        memset(inner, 0, 64);
        inner[1] = 10; /* content_len 10, padding is [12, 64) */
        memcpy(inner + 2, g_pt_in, 10);
        inner[pad_cases[i].last ? 63 : 12] = 0x01;
        p_seal_inner(&p, inner, 64, g_rec, &l);
        memset(g_pt_out, 0xAA, 64);
        CHECK(open_from(&p.b, g_rec, l, &got) == SESSION_ERR_MALFORMED &&
                  session_get_state(&p.b) == SESSION_STATE_FAILED && sodium_is_zero(g_pt_out, 64),
              pad_cases[i].what);
        sp_close(&p);
    }

    /* (d) no padding at all, and (e) the smallest legal inner. */
    {
        sp_t p;
        size_t l = 0;
        size_t got = 0;
        p_open_pair(&p, SESSION_PAD_BUCKET_DEFAULT, SESSION_PAD_BUCKET_DEFAULT);
        memset(inner, 0, 64);
        inner[1] = 62; /* content_len == inner - 2: legal, zero padding bytes */
        memcpy(inner + 2, g_pt_in, 62);
        p_seal_inner(&p, inner, 64, g_rec, &l);
        CHECK(open_from(&p.b, g_rec, l, &got) == SESSION_OK && got == 62 &&
                  memcmp(g_pt_out, g_pt_in, 62) == 0,
              "v2-6 P4(d): content_len == inner_len - 2 (no padding) is legal");
        inner[0] = 0;
        inner[1] = 0;
        p_seal_inner(&p, inner, 2, g_rec, &l);
        CHECK(l == SESSION_MIN_RECORD_BYTES && open_from(&p.b, g_rec, l, &got) == SESSION_OK && got == 0,
              "v2-6 P4(e): a 2-byte inner (empty content) is legal and yields a 27-byte record");
        sp_close(&p);
    }

    /* (f) a 26-byte record is rejected on length, before any AEAD work. */
    {
        sp_t p;
        size_t l = 0;
        size_t got = 0;
        p_open_pair(&p, SESSION_PAD_BUCKET_DEFAULT, SESSION_PAD_BUCKET_DEFAULT);
        seal_into(&p.a, 40, g_rec, &l);
        const uint64_t before = p.b.recv_seq;
        CHECK(open_from(&p.b, g_rec, 26u, &got) == SESSION_ERR_MALFORMED && p.b.recv_seq == before,
              "v2-6 P4(f): a 26-byte record -> MALFORMED (length, not AUTH), recv_seq unchanged");
        sp_close(&p);
    }
}

static void test_p5_buffer_hygiene(void) {
    sp_t p;
    size_t l = 0;
    size_t got = 0;
    p_open_pair(&p, SESSION_PAD_BUCKET_MAX, SESSION_PAD_BUCKET_MAX);
    memset(g_pt_out, 0xAA, 4096);
    seal_into(&p.a, 10, g_rec, &l);
    const int opened = open_from(&p.b, g_rec, l, &got) == SESSION_OK;
    const size_t inner = l - SESSION_OVERHEAD_BYTES;
    CHECK(opened && got == 10 && memcmp(g_pt_out, g_pt_in, 10) == 0,
          "v2-6 P5: the content lands at offset 0 with the length prefix stripped");
    CHECK(opened && sodium_is_zero(g_pt_out + 10, inner - 10),
          "v2-6 P5: ...and everything after it is zeroed -- no stale prefix or padding in the caller's buffer");
    sp_close(&p);
}

static void test_p6_bounds(void) {
    sp_t p;
    size_t l = 0;
    size_t got = 0;

    p_open_pair(&p, 1u, 1u);
    CHECK(seal_into(&p.a, 0, g_rec, &l) == SESSION_OK && l == 27u,
          "v2-6 P6: empty content at bucket 1 -> a 27-byte record (the frame table's minimum)");
    sp_close(&p);

    p_open_pair(&p, SESSION_PAD_BUCKET_MAX, SESSION_PAD_BUCKET_MAX);
    CHECK(seal_into(&p.a, 0, g_rec, &l) == SESSION_OK && l == 4121u,
          "v2-6 P6: empty content at bucket 4096 -> a 4121-byte record (the frame table's confirmation maximum)");
    sp_close(&p);

    int max_ok = 1;
    for (size_t b = 0; b < 6u; b++) {
        sp_t q;
        p_open_pair(&q, P_BUCKETS[b], P_BUCKETS[b]);
        max_ok &= seal_into(&q.a, SESSION_MAX_CONTENT_BYTES, g_rec, &l) == SESSION_OK &&
                  l == SESSION_MAX_RECORD_BYTES &&
                  open_from(&q.b, g_rec, l, &got) == SESSION_OK && got == SESSION_MAX_CONTENT_BYTES;
        sp_close(&q);
    }
    CHECK(max_ok, "v2-6 P6: 65534 bytes of content seal to exactly 65561 bytes at EVERY bucket (rounding never "
                  "exceeds the inner bound)");

    p_open_pair(&p, SESSION_PAD_BUCKET_DEFAULT, SESSION_PAD_BUCKET_DEFAULT);
    l = 777;
    CHECK(session_seal(&p.a, g_pt_in, SESSION_MAX_CONTENT_BYTES + 1u, g_rec, sizeof(g_rec), &l) ==
              SESSION_ERR_INVALID_ARG &&
              l == 777 && p.a.send_seq == 0,
          "v2-6 P6: 65535 bytes of content -> INVALID_ARG, nothing written, no seq consumed");
    CHECK(session_sealed_len(&p.a, SESSION_MAX_CONTENT_BYTES + 1u) == 0 && session_sealed_len(NULL, 0) == 0,
          "v2-6 P6: session_sealed_len reports 0 for content it cannot seal");
    sp_close(&p);
}

int main(void) {
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return EXIT_FAILURE;
    }
    if (mldsa_keypair_generate(&g_kp_a) != 0 || mldsa_keypair_generate(&g_kp_b) != 0) {
        fatal("mldsa_keypair_generate");
    }
    keystore_init(&g_ks);
    if (keystore_add(&g_ks, ID_A, sizeof(ID_A), g_kp_a.public_key) != KEYSTORE_OK ||
        keystore_add(&g_ks, ID_B, sizeof(ID_B), g_kp_b.public_key) != KEYSTORE_OK) {
        fatal("keystore_add");
    }
    if (handshake_pending_store_init(&g_store, HANDSHAKE_PENDING_MAX, HANDSHAKE_PENDING_TTL_MS_DEFAULT, NULL,
                                     NULL) != PENDING_OK) {
        fatal("handshake_pending_store_init");
    }
    randombytes_buf(g_pt_in, sizeof(g_pt_in));

    test_s1_round_trip();
    test_s2_s3_exact_layout();
    test_s4_replay();
    test_s5_out_of_order();
    test_s6_tamper();
    test_s7_reflection();
    test_s8_cross_session();
    test_s9_malformed();
    test_s10_misuse();
    test_s11_confirmation();
    test_s12_handoff();
    test_s13_init_preconditions();
    test_s14_record_limits();
    test_s15_time_limits();
    test_s16_clock_failure();
    test_s17_defaults();
    test_s19_plaintext_wiped();
    test_s20_cutover();
    test_s21_accessors();
    test_s25_no_reinit();
    test_s26_wipe_idempotent();
    test_s27_kem_disagreement();
    test_p1_exact_lengths();
    test_p2_bucket_one();
    test_p3_bucket_independence();
    test_p4_malformed_inner();
    test_p5_buffer_hygiene();
    test_p6_bounds();

    handshake_pending_store_wipe(&g_store);
    keystore_wipe(&g_ks);
    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
