/*
 * V4-13a: the client core's known-answer test.
 *
 * With a deterministic generator substituted for libsodium's (TEST ONLY) and
 * liboqs routed to it through cc_use_sodium_rng_for_oqs() -- the very
 * function the wasm module's init will call -- every byte the client core
 * produces is a function of the generator alone. This test runs one complete
 * device lifetime against tests/cc_fake_server.h (keygen, seal at two
 * parameter sets, login, rotation, BYE), prints the SHA-256 of each artefact,
 * and requires them to equal tests/golden/client_core_kat.txt.
 *
 * THE GOLDEN IS A CONTRACT FOR 13b: the same core compiled to wasm must print
 * the same lines. Native macOS (arm64) and native Linux (x86_64) already
 * differ in liboqs's backend, so CI running this on both is a first
 * cross-backend check before the wasm one.
 *
 * Two runs in one process, each from a reset generator, must agree with each
 * other as well as with the golden: if any randomness escaped the generator
 * -- liboqs not routed, most likely -- the runs differ even before the golden
 * is consulted, and the failure says which artefact moved first.
 *
 *   test_client_core_kat GOLDEN            compare
 *   test_client_core_kat --write GOLDEN    regenerate (review the diff!)
 *
 * Only hashes are printed or committed; no key, passphrase-derived value or
 * plaintext ever leaves the process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cc_fake_server.h"
#include "client_core.h"
#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"

/* ---- the deterministic generator (TEST ONLY) ------------------------------ */

static const char KAT_KEY_TEXT[] = "mldsa-auth/v1/cckat-drbg/tstonly"; /* public, test-only */
_Static_assert(sizeof(KAT_KEY_TEXT) - 1u == crypto_stream_chacha20_KEYBYTES, "DRBG key is 32 bytes");
static uint64_t g_counter = 0;

static void drbg_fill(uint8_t *out, size_t n)
{
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    const uint64_t v = g_counter++;
    for (size_t i = 0; i < sizeof nonce; i++) { nonce[i] = (uint8_t)(v >> (8u * i)); }
    if (n != 0u) { (void)crypto_stream_chacha20(out, n, nonce, (const unsigned char *)KAT_KEY_TEXT); }
}
static const char *det_name(void) { return "mldsa-auth-cc-kat-deterministic-TEST-ONLY"; }
static uint32_t det_random(void)
{
    uint8_t b[4];
    drbg_fill(b, sizeof b);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void det_stir(void) {}
static void det_buf(void *const buf, const size_t size) { drbg_fill((uint8_t *)buf, size); }
static int det_close(void) { return 0; }
static randombytes_implementation g_det_impl = { det_name, det_random, det_stir, NULL, det_buf, det_close };

/* ---- one device lifetime -------------------------------------------------- */

#define KAT_MAX 16
typedef struct { char name[32]; char hex[65]; } kat_line_t;
typedef struct { kat_line_t l[KAT_MAX]; int n; } kat_t;

static void rec(kat_t *k, const char *name, const uint8_t *p, size_t len)
{
    if (k->n >= KAT_MAX) { return; }
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, p, len);
    snprintf(k->l[k->n].name, sizeof k->l[k->n].name, "%s", name);
    (void)sodium_bin2hex(k->l[k->n].hex, sizeof k->l[k->n].hex, h, sizeof h);
    k->n++;
}

static uint8_t g_out[FRAME_BUF_BYTES];
static uint8_t g_in[FRAME_BUF_BYTES];
static cc_t g_cc;
static const uint8_t SID[] = { 'a', 'u', 't', 'h', 'd' };
static const char PASS[] = "kat passphrase, test only";

#define STEP(cond) do { if (!(cond)) { printf("KAT step failed at line %d\n", __LINE__); return -1; } } while (0)

static int lifetime(kat_t *k)
{
    memset(k, 0, sizeof *k);
    g_counter = 0;   /* every run starts from the same generator state */

    char hid[CC_HANDLE_BUF];
    cc_new_handle(hid);
    rec(k, "handle", (const uint8_t *)hid, CC_HANDLE_LEN);

    static uint8_t ek[8192], ek2[8192], pub[4096];
    size_t el = 0, el2 = 0, pl = 0;
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    STEP(cc_seal_new_identity((const uint8_t *)hid, CC_HANDLE_LEN, PASS, strlen(PASS), 1u, 8u * 1024u * 1024u,
                              ek, sizeof ek, &el, pub, sizeof pub, &pl, pk, NULL) == CC_OK);
    rec(k, "sealed-ops1-8mib", ek, el);
    rec(k, "pubfile", pub, pl);

    /* The browser's parameters (spec 12): the one KDF setting 13b will use. */
    static uint8_t pubb[4096];
    size_t plb = 0;
    STEP(cc_seal_new_identity((const uint8_t *)hid, CC_HANDLE_LEN, PASS, strlen(PASS), CC_KDF_OPS_BROWSER,
                              CC_KDF_MEM_BROWSER, ek2, sizeof ek2, &el2, pubb, sizeof pubb, &plb, NULL, NULL) == CC_OK);
    rec(k, "sealed-browser", ek2, el2);

    fs_t fs;
    STEP(fs_init(&fs, SID, sizeof SID, (const uint8_t *)hid, CC_HANDLE_LEN, pk) == 0);
    size_t n = 0, m = 0;
    cc_init(&g_cc, NULL, NULL);
    STEP(cc_pin_server(&g_cc, SID, sizeof SID, fs.kp.public_key) == CC_OK);
    STEP(cc_login_begin_sealed(&g_cc, (const uint8_t *)hid, CC_HANDLE_LEN, ek, el, PASS, strlen(PASS),
                               CC_KEEP_FOR_ROTATE, g_out, sizeof g_out, &n) == CC_OK);
    rec(k, "client-hello", g_out, n);
    STEP(fs_on_client_hello(&fs, g_out, n, g_in, sizeof g_in, &m) == 0);
    rec(k, "server-hello", g_in, m);
    STEP(cc_login_on_server_hello(&g_cc, g_in, m, g_out, sizeof g_out, &n) == CC_OK);
    rec(k, "client-auth", g_out, n);
    STEP(fs_on_client_auth(&fs, g_out, n) == 0);
    STEP(fs_send_login_code(&fs, 0u, 0x5A, 1700000060u, g_in, sizeof g_in, &m) == 0);
    rec(k, "login-code", g_in, m);
    authmsg_login_code_t code;
    STEP(cc_login_on_record(&g_cc, g_in, m, &code) == CC_OK);

    /* rotation: a second identity for the same handle */
    static uint8_t ekn[8192], pubn[4096];
    size_t eln = 0, pln = 0;
    uint8_t pkn[MLDSA_PUBLIC_KEY_BYTES];
    STEP(cc_seal_new_identity((const uint8_t *)hid, CC_HANDLE_LEN, PASS, strlen(PASS), 1u, 8u * 1024u * 1024u,
                              ekn, sizeof ekn, &eln, pubn, sizeof pubn, &pln, pkn, NULL) == CC_OK);
    mldsa_keypair_t nkp;
    STEP(cc_open_sealed(ekn, eln, (const uint8_t *)hid, CC_HANDLE_LEN, PASS, strlen(PASS), &nkp, NULL) == CC_OK);
    STEP(cc_rotate_build(&g_cc, &nkp, 0u, g_out, sizeof g_out, &n) == CC_OK);
    rec(k, "rotate", g_out, n);
    mldsa_keypair_free(&nkp);
    STEP(fs_send_rotate_ack(&fs, (const uint8_t *)hid, CC_HANDLE_LEN, pkn, 1700000100u, g_in, sizeof g_in, &m) == 0);
    rec(k, "rotate-ack", g_in, m);
    STEP(cc_rotate_on_reply(&g_cc, g_in, m, NULL) == CC_OK);
    STEP(cc_bye(&g_cc, g_out, sizeof g_out, &n) == CC_OK);
    rec(k, "bye", g_out, n);

    cc_wipe(&g_cc);
    fs_wipe(&fs);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const int write_mode = (argc == 3 && strcmp(argv[1], "--write") == 0);
    const char *golden = write_mode ? argv[2] : (argc == 2 ? argv[1] : NULL);
    if (golden == NULL) {
        fprintf(stderr, "usage: %s [--write] GOLDEN\n", argv[0]);
        return 2;
    }
    /* Must precede sodium_init(). */
    if (randombytes_set_implementation(&g_det_impl) != 0 || sodium_init() < 0) {
        puts("FAIL: the deterministic generator could not be installed");
        return 2;
    }
    cc_use_sodium_rng_for_oqs();
    fprintf(stderr, "DETERMINISTIC RNG - TEST ONLY: every key below is reproducible and worthless\n");

    static kat_t a, b;
    if (lifetime(&a) != 0 || lifetime(&b) != 0) {
        puts("FAIL: the KAT lifetime did not complete");
        return 1;
    }
    int fail = 0;
    for (int i = 0; i < a.n; i++) {
        if (strcmp(a.l[i].hex, b.l[i].hex) != 0) {
            printf("FAIL: two runs from the same generator state differ first at '%s' -- randomness "
                   "escaped the generator\n", a.l[i].name);
            fail = 1;
            break;
        }
    }
    if (!fail) { printf("PASS: two runs from the same generator state are byte-identical (%d artefacts)\n", a.n); }

    if (write_mode) {
        FILE *f = fopen(golden, "w");
        if (f == NULL) { perror(golden); return 2; }
        fprintf(f, "# client_core KAT (tests/test_client_core_kat.c): SHA-256 of each artefact.\n"
                   "# A contract for the wasm build (V4-13b), which must reproduce every line.\n");
        for (int i = 0; i < a.n; i++) { fprintf(f, "%s %s\n", a.l[i].name, a.l[i].hex); }
        fclose(f);
        printf("wrote %d lines to %s\n", a.n, golden);
        return fail;
    }

    FILE *f = fopen(golden, "r");
    if (f == NULL) { perror(golden); return 2; }
    char line[256];
    int i = 0, bad = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (line[0] == '#' || line[0] == '\n') { continue; }
        char name[64], hex[80];
        if (sscanf(line, "%63s %79s", name, hex) != 2) { bad = 1; break; }
        if (i >= a.n || strcmp(name, a.l[i].name) != 0 || strcmp(hex, a.l[i].hex) != 0) {
            printf("FAIL: artefact %d: golden says '%s %s', this build made '%s %s'\n", i, name, hex,
                   i < a.n ? a.l[i].name : "(none)", i < a.n ? a.l[i].hex : "");
            bad = 1;
        } else {
            printf("PASS: %s matches the golden\n", name);
        }
        i++;
    }
    fclose(f);
    if (i != a.n) {
        printf("FAIL: the golden has %d artefacts, this build made %d\n", i, a.n);
        bad = 1;
    }
    if (!bad) { printf("PASS: all %d artefacts reproduce the golden byte-for-byte\n", a.n); }
    return (fail || bad) ? 1 : 0;
}
