/* V4-6: the MLDSAEK1 key envelope (apps/authd/keyfile.c).
 *
 * Independent checks, in the project's fail-loud style: a round trip through
 * seal/open recovers the identity; a wrong passphrase is rejected; every
 * mutable header byte and the ciphertext are tamper-evident (the header is the
 * AEAD's associated data); parameter bounds are enforced; the output is never
 * clobbered and never written in place; and -- the point of reusing the shared
 * validator -- a decrypted image with a wrong id or a corrupted digest is
 * refused exactly as the file loader would refuse it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sodium.h>
#include "keyfile.h"
#include "demo_keys.h"
#include "mldsa_wrap.h"
#include "secure_mem.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { printf("PASS: %s\n", msg); } \
    else { printf("FAIL: %s\n", msg); g_fail = 1; } } while (0)

static const uint8_t ID_A[] = {'a','l','i','c','e'};
#define IDLEN 5u
static const char PASS[] = "correct horse battery staple";
/* keep tests fast: minimum accepted KDF work, not the per-role production values */
#define OPS 1u
#define MEM (8u * 1024u * 1024u)

static char g_dir[256];
/* The return IS checked. gcc at -O2 -D_FORTIFY_SOURCE=2 cannot prove
 * "%s/%s" fits when g_dir is as large as the destination, and promotes it to
 * -Werror=format-truncation; clang does not, and CI builds gcc at -O0, so no
 * gate saw it until a Release+gcc sweep did (audit finding F19). A truncated
 * fixture path is a test bug, so it aborts rather than proceeding on a
 * silently shortened name. */
static void path(char *out, size_t cap, const char *name) {
    const int n = snprintf(out, cap, "%s/%s", g_dir, name);
    if (n < 0 || (size_t)n >= cap) { fprintf(stderr, "fixture path truncated\n"); abort(); }
}

/* Build a fresh, valid MLDSASK2 image in secure memory. */
static uint8_t *fresh_image(size_t *len_out) {
    mldsa_keypair_t kp;
    if (mldsa_keypair_generate(&kp) != 0) { return NULL; }
    const size_t len = demo_keys_sk2_image_len(IDLEN);
    uint8_t *img = secure_mem_alloc(len);
    if (img == NULL || demo_keys_build_sk2_image(img, len, ID_A, IDLEN, &kp) != DEMO_KEYS_OK) {
        mldsa_keypair_free(&kp); return NULL;
    }
    mldsa_keypair_free(&kp);
    *len_out = len; return img;
}

static long fsize(const char *p) { struct stat st; return stat(p, &st) == 0 ? (long)st.st_size : -1; }
static int fmode(const char *p) { struct stat st; return stat(p, &st) == 0 ? (int)(st.st_mode & 0777) : -1; }

int main(void) {
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { puts("sodium_init failed"); return 2; }
    snprintf(g_dir, sizeof(g_dir), "/tmp/authd_kf_%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) { perror("mkdir"); return 2; }

    size_t ilen = 0; uint8_t *img = fresh_image(&ilen);
    if (img == NULL) { puts("fixture failed"); return 2; }

    char ek[256]; path(ek, sizeof(ek), "alice.ek");

    /* round trip */
    CHECK(keyfile_seal(ek, img, ilen, PASS, strlen(PASS), OPS, MEM) == KEYFILE_OK,
          "seal writes an MLDSAEK1 file");
    CHECK(fmode(ek) == 0600, "the sealed file is mode 0600");
    CHECK(fsize(ek) == (long)(KEYFILE_HEADER_LEN + ilen + crypto_aead_xchacha20poly1305_ietf_ABYTES),
          "file size = header + image + AEAD tag");
    { uint8_t magic[8]; FILE *f = fopen(ek, "rb"); size_t n = f ? fread(magic, 1, 8, f) : 0; if (f) fclose(f);
      CHECK(n == 8 && memcmp(magic, KEYFILE_MAGIC, 8) == 0, "file begins with the MLDSAEK1 magic"); }

    mldsa_keypair_t kp;
    uint8_t kek[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t kek2[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    memset(kek, 0xAA, sizeof(kek));
    CHECK(keyfile_open(ek, ID_A, IDLEN, PASS, strlen(PASS), &kp, kek) == KEYFILE_OK,
          "open recovers the identity with the right passphrase");
    /* V4-7: the KEK out-param. It must be filled on success (not left at the
     * 0xAA pre-fill, and not all-zero), and it must be DETERMINISTIC for the
     * same passphrase+salt -- the store's audit key is derived from it. */
    { int all_aa = 1, all_00 = 1;
      for (size_t i = 0; i < sizeof(kek); i++) { if (kek[i] != 0xAA) all_aa = 0; if (kek[i] != 0) all_00 = 0; }
      CHECK(!all_aa && !all_00, "open fills the KEK out-param on success"); }
    /* the recovered key really works */
    { uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES]; size_t sl = 0; const uint8_t m[3] = {1,2,3};
      CHECK(kp.secret_key != NULL && mldsa_sign(sig, &sl, m, 3, &kp) == 0 &&
            mldsa_verify(m, 3, sig, sl, kp.public_key) == 0, "the recovered keypair signs and verifies");
      mldsa_keypair_free(&kp); }

    memset(kek2, 0xAA, sizeof(kek2));
    CHECK(keyfile_open(ek, ID_A, IDLEN, PASS, strlen(PASS), &kp, kek2) == KEYFILE_OK &&
          memcmp(kek, kek2, sizeof(kek)) == 0,
          "the KEK is re-derived identically from the same passphrase and salt");
    mldsa_keypair_free(&kp);

    /* wrong passphrase */
    memset(kek2, 0xAA, sizeof(kek2));
    CHECK(keyfile_open(ek, ID_A, IDLEN, "wrong pass", 10, &kp, kek2) == KEYFILE_ERR_DECRYPT,
          "a wrong passphrase is rejected (DECRYPT), no keypair");
    CHECK(kp.secret_key == NULL, "no secret key is returned on a failed open");
    { int zeroed = 1; for (size_t i = 0; i < sizeof(kek2); i++) { if (kek2[i] != 0) zeroed = 0; }
      CHECK(zeroed, "a failed open zeroes the KEK out-param"); }

    /* wrong expected id -> the shared validator rejects the decrypted image */
    { const uint8_t bob[] = {'b','o','b'};
      CHECK(keyfile_open(ek, bob, 3, PASS, strlen(PASS), &kp, NULL) == KEYFILE_ERR_IMAGE,
            "the right passphrase but a wrong expected id -> IMAGE (validator rejects)");
      CHECK(kp.secret_key == NULL, "no key returned on an id mismatch"); }

    /* never clobbers, never in place */
    CHECK(keyfile_seal(ek, img, ilen, PASS, strlen(PASS), OPS, MEM) == KEYFILE_ERR_EXISTS,
          "sealing over an existing file -> EXISTS, not overwritten");

    /* parameter bounds -- exercised with opslimit, whose over-ceiling value
       (11) is a handful of iterations even if a bound is removed, so a mutation
       kills cleanly instead of triggering a multi-gigabyte Argon2 allocation. */
    { char ek2[256]; path(ek2, sizeof(ek2), "toobig.ek");
      CHECK(keyfile_seal(ek2, img, ilen, PASS, strlen(PASS), KEYFILE_OPSLIMIT_MAX + 1u, MEM) == KEYFILE_ERR_PARAMS,
            "seal opslimit over the ceiling -> PARAMS");
      CHECK(keyfile_seal(ek2, img, ilen, PASS, strlen(PASS), OPS, KEYFILE_MEMLIMIT_MAX + 1u) == KEYFILE_ERR_PARAMS,
            "seal memlimit over the ceiling -> PARAMS");
      CHECK(fsize(ek2) == -1, "no file is written when parameters are rejected");
      /* open-side bound: craft a header whose opslimit exceeds the ceiling.
         params_ok fires before derive_key, so this is PARAMS, not a slow KDF. */
      long total = fsize(ek);
      uint8_t *b = malloc((size_t)total); FILE *f = fopen(ek, "rb"); size_t rn = fread(b,1,(size_t)total,f); fclose(f); (void)rn;
      b[10] = 0; b[11] = 0; b[12] = 0; b[13] = (uint8_t)(KEYFILE_OPSLIMIT_MAX + 1u); /* opslimit BE32 @ off 10 */
      char bad[256]; path(bad, sizeof(bad), "badops.ek"); (void)unlink(bad);
      FILE *g = fopen(bad, "wb"); fwrite(b,1,(size_t)total,g); fclose(g); chmod(bad, 0600); free(b);
      CHECK(keyfile_open(bad, ID_A, IDLEN, PASS, strlen(PASS), &kp, NULL) == KEYFILE_ERR_PARAMS,
            "open rejects a header opslimit over the ceiling -> PARAMS (before the KDF)");
      (void)unlink(bad); }

    /* tamper-evidence: flip each header field and the ciphertext; every flip
       must fail to open (the header is the AEAD's associated data). */
    { long total = fsize(ek);
      /* opslimit (off 10) and memlimit (off 14) are deliberately NOT flipped:
         they set the Argon2 work factor, so under a mutation that dropped the
         bound, reaching the KDF with a corrupted work factor would burn
         minutes/gigabytes. They are covered by the PARAMS checks and by being
         AEAD associated data. */
      const size_t spots[] = {8,9,22,38,39,63, (size_t)total - 1u}; /* version,kdf,salt,aead,nonce,ctlen,ct */
      const char *names[] = {"version","kdf_alg","salt","aead_alg","nonce","ct_len","ciphertext"};
      int all = 1;
      for (size_t i = 0; i < sizeof(spots)/sizeof(spots[0]); i++) {
          uint8_t *b = malloc((size_t)total); FILE *f = fopen(ek, "rb"); size_t n = fread(b,1,(size_t)total,f); fclose(f);
          (void)n; b[spots[i]] ^= 0x01u;
          char t[256]; path(t, sizeof(t), "tampered.ek");
          (void)unlink(t); FILE *g = fopen(t, "wb"); fwrite(b,1,(size_t)total,g); fclose(g); chmod(t, 0600);
          keyfile_status_t s = keyfile_open(t, ID_A, IDLEN, PASS, strlen(PASS), &kp, NULL);
          if (s == KEYFILE_OK) { printf("  (tamper at %s opened!)\n", names[i]); all = 0; if (kp.secret_key) mldsa_keypair_free(&kp); }
          free(b); (void)unlink(t);
      }
      CHECK(all, "flipping any header field or the ciphertext makes open fail"); }

    /* symlink is refused (O_NOFOLLOW) */
    { char lnk[256]; path(lnk, sizeof(lnk), "link.ek");
      if (symlink(ek, lnk) == 0) {
          CHECK(keyfile_open(lnk, ID_A, IDLEN, PASS, strlen(PASS), &kp, NULL) == KEYFILE_ERR_IO,
                "a symlinked envelope is refused (O_NOFOLLOW)");
          (void)unlink(lnk);
      } }

    secure_mem_free(img, ilen);
    { char cmd[300]; snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
      /* see the note in test_authd_conn.c: (void) does not silence gcc here */
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf(g_fail ? "\nFAILED\n" : "\nAll checks passed\n");
    return g_fail;
}
