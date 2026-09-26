/*
 * V4-13b: the wasm export shim (apps/authd/client_wasm.c), compiled NATIVELY
 * and driven exactly as the JavaScript transport drives it -- flat calls,
 * caller-allocated buffers, 32-bit lengths -- against tests/cc_fake_server.h.
 *
 * What the shim adds to client_core, and therefore what is tested here:
 *   - a login cannot begin until the caller has set the clock, and the clock
 *     it sets is monotonic, finite and non-negative;
 *   - identities are sealed at the BROWSER's Argon2id parameters, whatever the
 *     caller wanted;
 *   - ccw_init routes liboqs to libsodium's generator (proven with a
 *     deterministic generator installed first: two identities from the same
 *     generator state must be byte-identical, which liboqs's own generator
 *     would never produce);
 *   - lengths reported back equal the bytes written, and a refused record
 *     leaves no login code in the caller's buffer.
 * The protocol itself is client_core's and is tested by test_client_core.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cc_fake_server.h"
#include "client_wasm.h"
#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"
#include "passphrase.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { printf("PASS: %s\n", msg); } \
    else { printf("FAIL: %s\n", msg); g_fail = 1; } } while (0)

/* ---- deterministic generator (TEST ONLY), installed before ccw_init ------- */
static const char KEY_TEXT[] = "mldsa-auth/v1/ccw-test-drbg/only"; /* public, test-only */
_Static_assert(sizeof(KEY_TEXT) - 1u == crypto_stream_chacha20_KEYBYTES, "DRBG key is 32 bytes");
static uint64_t g_counter = 0;
static void drbg_fill(uint8_t *out, size_t n)
{
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    const uint64_t v = g_counter++;
    for (size_t i = 0; i < sizeof nonce; i++) { nonce[i] = (uint8_t)(v >> (8u * i)); }
    if (n != 0u) { (void)crypto_stream_chacha20(out, n, nonce, (const unsigned char *)KEY_TEXT); }
}
static const char *det_name(void) { return "ccw-test-deterministic-TEST-ONLY"; }
static uint32_t det_random(void) { uint8_t b[4]; drbg_fill(b, 4); return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }
static void det_stir(void) {}
static void det_buf(void *const buf, const size_t size) { drbg_fill((uint8_t *)buf, size); }
static int det_close(void) { return 0; }
static randombytes_implementation g_det = { det_name, det_random, det_stir, NULL, det_buf, det_close };

static const uint8_t SID[] = { 'a', 'u', 't', 'h', 'd' };
static const char PASS[] = "correct horse battery staple";
static uint8_t g_out[FRAME_BUF_BYTES], g_in[FRAME_BUF_BYTES];

typedef struct {
    char hid[CC_HANDLE_BUF];
    uint8_t ek[8192]; uint32_t ek_len;
    uint8_t pub[4096]; uint32_t pub_len;
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
} wdev_t;

static int make_dev(wdev_t *d)
{
    if (ccw_new_handle(d->hid) != CC_OK) { return -1; }
    if (ccw_seal_new_identity((const uint8_t *)d->hid, CC_HANDLE_LEN, PASS, (uint32_t)strlen(PASS),
                              d->ek, sizeof d->ek, &d->ek_len, d->pub, sizeof d->pub, &d->pub_len) != CC_OK) {
        return -1;
    }
    return demo_keys_parse_public(d->pub, d->pub_len, (const uint8_t *)d->hid, CC_HANDLE_LEN, d->pk) ==
                   DEMO_KEYS_OK ? 0 : -1;
}

/* The server's MLDSAPK1, as a browser would hold it. */
static uint32_t server_pub(const fs_t *fs, uint8_t *out, size_t cap)
{
    return demo_keys_build_public_image(out, cap, SID, sizeof SID, fs->kp.public_key) == DEMO_KEYS_OK
               ? (uint32_t)demo_keys_public_image_len(sizeof SID) : 0u;
}

/* A fresh handle logged in against `fs` up to (not including) the first
 * record. Returns the status of the first failing step. */
static int login_to_record(ccw_t *h, fs_t *fs, const wdev_t *d, int keep)
{
    uint8_t spub[4096];
    uint32_t n = 0;
    size_t m = 0;
    const uint32_t sl = server_pub(fs, spub, sizeof spub);
    int st = ccw_pin_server_pub(h, spub, sl, SID, sizeof SID);
    if (st != CC_OK) { return st; }
    st = ccw_login_begin(h, (const uint8_t *)d->hid, CC_HANDLE_LEN, d->ek, d->ek_len, PASS, (uint32_t)strlen(PASS),
                         keep, g_out, sizeof g_out, &n);
    if (st != CC_OK) { return st; }
    if (n < 4u || fs_get_len(g_out) != n - 4u) { return 1000; }            /* length reported == bytes written */
    if (fs_on_client_hello(fs, g_out, n, g_in, sizeof g_in, &m) != 0) { return 1001; }
    st = ccw_on_server_hello(h, g_in, (uint32_t)m, g_out, sizeof g_out, &n);
    if (st != CC_OK) { return st; }
    if (n < 4u || fs_get_len(g_out) != n - 4u) { return 1002; }
    return fs_on_client_auth(fs, g_out, n) == 0 ? CC_OK : 1003;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(ccw_new() == NULL, "init: no handle before ccw_init");
    if (randombytes_set_implementation(&g_det) != 0) { puts("FAIL: generator"); return 2; }
    CHECK(ccw_init() == 0 && ccw_init() == 0, "init: ccw_init succeeds, and again (idempotent)");

    /* ccw_init routed liboqs: two identities from one generator state match. */
    { wdev_t a, b;
      g_counter = 0; const int ra = make_dev(&a);
      g_counter = 0; const int rb = make_dev(&b);
      CHECK(ra == 0 && rb == 0 && memcmp(a.pk, b.pk, sizeof a.pk) == 0 && a.pub_len == b.pub_len &&
                memcmp(a.pub, b.pub, a.pub_len) == 0,
            "init: after ccw_init, ML-DSA keygen draws from libsodium's generator (same state, same key)"); }
    g_counter = 1000;

    wdev_t d;
    CHECK(make_dev(&d) == 0, "seal: the shim makes an identity");
    CHECK(d.ek_len == ccw_sealed_len(CC_HANDLE_LEN) && d.pub_len == ccw_public_len(CC_HANDLE_LEN),
          "seal: the lengths reported are the sizes the shim tells JavaScript to allocate");
    { keyfile_header_t hd;
      CHECK(keyfile_parse_header(d.ek, d.ek_len, &hd) == KEYFILE_OK && hd.opslimit == 3u &&
                hd.memlimit == 64u * 1024u * 1024u,
            "seal: sealed at the browser's Argon2id parameters, ops 3 and 64 MiB (spec 12)"); }
    CHECK(ccw_frame_buf_bytes() == FRAME_BUF_BYTES, "sizes: the frame buffer size is the transport's");

    /* ---- the passphrase policy, through the shim (V4-13c) ---- */
    { uint32_t cps = 0, bits = 0, reasons = 0;
      CHECK(ccw_passphrase_check("password1234", 12u, &cps, &bits, &reasons) == PP_COMMON && cps == 12u,
            "policy: the shim reports the policy's verdict (common) and counts");
      CHECK(ccw_passphrase_check(PASS, (uint32_t)strlen(PASS), NULL, NULL, NULL) == PP_OK,
            "policy: the test passphrase itself is acceptable");
      wdev_t w;
      memset(&w, 0, sizeof w);
      w.ek_len = 77u; w.pub_len = 77u;
      CHECK(ccw_seal_new_identity((const uint8_t *)"d1weak", 6u, "zzzzzzzzzzzz", 12u, w.ek, sizeof w.ek, &w.ek_len,
                                  w.pub, sizeof w.pub, &w.pub_len) == CC_ERR_PASSPHRASE &&
                w.ek_len == 0u && w.pub_len == 0u && sodium_is_zero(w.ek, sizeof w.ek),
            "policy: sealing under a refused passphrase is CC_ERR_PASSPHRASE and produces nothing"); }

    /* ---- the clock ---- */
    { ccw_t *h = ccw_new();
      fs_t fs;
      uint32_t n = 77u;
      uint8_t spub[4096];
      (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
      (void)ccw_pin_server_pub(h, spub, server_pub(&fs, spub, sizeof spub), SID, sizeof SID);
      CHECK(ccw_login_begin(h, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.ek, d.ek_len, PASS, (uint32_t)strlen(PASS),
                            0, g_out, sizeof g_out, &n) == CC_ERR_STATE && n == 0u,
            "clock: a login cannot begin before the caller has set the clock");
      CHECK(ccw_set_now_ms(h, -1.0) == -1 && ccw_set_now_ms(h, 0.0 / 0.0) == -1 &&
                ccw_set_now_ms(h, 1.0 / 0.0) == -1,
            "clock: a negative, NaN or infinite time is refused");
      CHECK(ccw_set_now_ms(h, 5000.0) == 0 && ccw_set_now_ms(h, 4999.0) == -1 && ccw_set_now_ms(h, 5000.0) == 0,
            "clock: time may stand still but never run backwards");
      ccw_free(h); fs_wipe(&fs); }

    /* ---- the server pin ---- */
    { ccw_t *h = ccw_new();
      fs_t fs;
      uint8_t spub[4096];
      (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
      const uint32_t sl = server_pub(&fs, spub, sizeof spub);
      CHECK(ccw_pin_server_pub(h, spub, sl, (const uint8_t *)"authx", 5) == CC_ERR_KEYS &&
                strcmp(ccw_diag_detail(h), demo_keys_status_name(DEMO_KEYS_ERR_ID_MISMATCH)) == 0,
            "pin: a server public key naming a different id is refused, named id-mismatch");
      CHECK(ccw_pin_server_pub(h, spub, sl, SID, sizeof SID) == CC_OK && ccw_state(h) == CC_STATE_PINNED,
            "pin: the right one pins");
      ccw_free(h); fs_wipe(&fs); }

    /* ---- a whole login ---- */
    { ccw_t *h = ccw_new();
      fs_t fs;
      (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
      (void)ccw_set_now_ms(h, 1000.0);
      CHECK(login_to_record(h, &fs, &d, 0) == CC_OK, "login: ClientHello and ClientAuth through the shim");
      CHECK(h->cc.kp == NULL && h->cc.own_kp.secret_key == NULL,
            "login: the key the shim opened is freed once ClientAuth is built");
      CHECK(ccw_recv_max(h) == FRAME_CONFIRM_MAX, "login: the next frame's bound is the login code's");
      size_t m = 0;
      uint8_t code[32]; uint32_t flags = 99u; double exp = -1.0;
      (void)fs_send_login_code(&fs, 1u, 0x42, 1700000060u, g_in, sizeof g_in, &m);
      CHECK(ccw_on_record(h, g_in, (uint32_t)m, code, &flags, &exp) == CC_OK && code[0] == 0x42 && code[31] == 0x42 &&
                flags == 1u && exp == 1700000060.0,
            "login: the login code, its flags and its expiry come back to the caller");
      uint32_t n = 0;
      CHECK(ccw_bye(h, g_out, sizeof g_out, &n) == CC_OK && n > 4u && fs_get_len(g_out) == n - 4u,
            "login: BYE, with its length reported exactly");
      ccw_free(h); fs_wipe(&fs); }

    /* ---- refusals ---- */
    { ccw_t *h = ccw_new();
      fs_t fs;
      uint32_t n = 0;
      uint8_t spub[4096];
      (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
      (void)ccw_set_now_ms(h, 1000.0);
      (void)ccw_pin_server_pub(h, spub, server_pub(&fs, spub, sizeof spub), SID, sizeof SID);
      CHECK(ccw_login_begin(h, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.ek, d.ek_len, "wrong", 5u, 0, g_out,
                            sizeof g_out, &n) == CC_ERR_KEYFILE && n == 0u && ccw_state(h) == CC_STATE_PINNED &&
                strncmp(ccw_diag_detail(h), "decryption-failed", 17) == 0,
            "refuse: a wrong passphrase sends nothing, says decryption-failed, and may be retried");
      ccw_free(h); fs_wipe(&fs); }
    { ccw_t *h = ccw_new();
      fs_t fs;
      (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
      (void)ccw_set_now_ms(h, 1000.0);
      (void)login_to_record(h, &fs, &d, 0);
      size_t m = 0;
      /* A failed login upstream leaves no record (m == 0): never index
       * g_in[m - 1] then -- v54 WA7 crashed here before this guard. */
      if (fs_send_login_code(&fs, 0u, 0x42, 1u, g_in, sizeof g_in, &m) != 0 || m == 0u) { m = 1u; g_in[0] = 0u; }
      g_in[m - 1u] ^= 0x01u;   /* the tag no longer authenticates */
      uint8_t code[32]; uint32_t flags = 7u; double exp = 7.0;
      memset(code, 0xA5, sizeof code);
      CHECK(ccw_on_record(h, g_in, (uint32_t)m, code, &flags, &exp) == CC_ERR_SESSION &&
                sodium_is_zero(code, sizeof code) && flags == 0u && exp == 0.0 && ccw_state(h) == CC_STATE_FAILED,
            "refuse: a record that does not authenticate leaves no code, flags or expiry in the caller's buffers");
      ccw_free(h); fs_wipe(&fs); }

    /* ---- the injected clock governs the session ---- */
    for (int jump = 0; jump <= 1; jump++) {
        ccw_t *h = ccw_new();
        fs_t fs;
        (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
        (void)ccw_set_now_ms(h, 1000.0);
        (void)login_to_record(h, &fs, &d, 0);
        size_t m = 0;
        uint8_t code[32]; uint32_t flags = 0; double exp = 0;
        (void)fs_send_login_code(&fs, 0u, 1, 1u, g_in, sizeof g_in, &m);
        (void)ccw_on_record(h, g_in, (uint32_t)m, code, &flags, &exp);
        if (jump) { (void)ccw_set_now_ms(h, 1000.0 + (double)SESSION_REJECT_AFTER_MS + 1.0); }
        uint32_t n = 0;
        const int st = ccw_bye(h, g_out, sizeof g_out, &n);
        if (jump) {
            CHECK(st == CC_ERR_SESSION, "clock: past the caller's clock's hard limit the session refuses to seal");
        } else {
            CHECK(st == CC_OK, "clock: control -- with the clock held, the same seal succeeds");
        }
        ccw_free(h); fs_wipe(&fs);
    }

    /* ---- rotation through the shim ---- */
    for (int ackok = 1; ackok >= 0; ackok--) {
        ccw_t *h = ccw_new();
        fs_t fs;
        wdev_t nx;
        memcpy(nx.hid, d.hid, sizeof nx.hid);
        (void)ccw_seal_new_identity((const uint8_t *)nx.hid, CC_HANDLE_LEN, PASS, (uint32_t)strlen(PASS),
                                    nx.ek, sizeof nx.ek, &nx.ek_len, nx.pub, sizeof nx.pub, &nx.pub_len);
        (void)demo_keys_parse_public(nx.pub, nx.pub_len, (const uint8_t *)nx.hid, CC_HANDLE_LEN, nx.pk);
        (void)fs_init(&fs, SID, sizeof SID, (const uint8_t *)d.hid, CC_HANDLE_LEN, d.pk);
        (void)ccw_set_now_ms(h, 1000.0);
        (void)login_to_record(h, &fs, &d, 1);
        size_t m = 0;
        uint8_t code[32]; uint32_t flags = 0; double exp = 0;
        (void)fs_send_login_code(&fs, 0u, 1, 1u, g_in, sizeof g_in, &m);
        (void)ccw_on_record(h, g_in, (uint32_t)m, code, &flags, &exp);
        uint32_t n = 0;
        const int bs = ccw_rotate_build(h, nx.ek, nx.ek_len, PASS, (uint32_t)strlen(PASS), g_out, sizeof g_out, &n);
        uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES];
        size_t pl = 0;
        authmsg_rotate_t rot;
        const int carries = bs == CC_OK && fs_open(&fs, g_out, n, pt, sizeof pt, &pl) == 0 &&
                            authmsg_decode_rotate(pt, pl, &rot) == AUTHMSG_OK &&
                            memcmp(rot.pk_new, nx.pk, MLDSA_PUBLIC_KEY_BYTES) == 0;
        (void)fs_send_rotate_ack(&fs, (const uint8_t *)d.hid, CC_HANDLE_LEN, ackok ? nx.pk : d.pk, 9u,
                                 g_in, sizeof g_in, &m);
        uint32_t ec = 7u;
        const int rs = ccw_rotate_on_reply(h, g_in, (uint32_t)m, &ec);
        if (ackok) {
            CHECK(carries && h->cc.kp == NULL && h->cc.own_kp.secret_key == NULL && rs == CC_OK && ec == 0u,
                  "rotate: ROTATE carries the new key, the old key is freed with it, and the ACK is accepted");
        } else {
            CHECK(rs == CC_ERR_ACK_MISMATCH, "rotate: an ACK naming the OLD key is refused");
        }
        ccw_free(h); fs_wipe(&fs);
    }

    CHECK(ccw_key_plan(0, 1, 0) == KEY_PLAN_REFUSE && ccw_key_plan(0, 1, 1) == KEY_PLAN_PROMOTE_NEXT &&
              strcmp(ccw_status_name(CC_ERR_KEYFILE), "key-envelope") == 0,
          "state: the .ek.next decision and the status names are reachable through the shim");
    ccw_free(NULL);

    printf(g_fail ? "\nFAILED\n" : "\nAll checks passed\n");
    return g_fail;
}
