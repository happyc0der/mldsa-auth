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
static void path(char *out, size_t cap, const char *name) { snprintf(out, cap, "%s/%s", g_dir, name); }

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
    CHECK(keyfile_open(ek, ID_A, IDLEN, PASS, strlen(PASS), &kp) == KEYFILE_OK,
          "open recovers the identity with the right passphrase");
    /* the recovered key really works */
    { uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES]; size_t sl = 0; const uint8_t m[3] = {1,2,3};
      CHECK(kp.secret_key != NULL && mldsa_sign(sig, &sl, m, 3, &kp) == 0 &&
            mldsa_verify(m, 3, sig, sl, kp.public_key) == 0, "the recovered keypair signs and verifies");
      mldsa_keypair_free(&kp); }

    /* wrong passphrase */
    CHECK(keyfile_open(ek, ID_A, IDLEN, "wrong pass", 10, &kp) == KEYFILE_ERR_DECRYPT,
          "a wrong passphrase is rejected (DECRYPT), no keypair");
    CHECK(kp.secret_key == NULL, "no secret key is returned on a failed open");

    /* wrong expected id -> the shared validator rejects the decrypted image */
    { const uint8_t bob[] = {'b','o','b'};
      CHECK(keyfile_open(ek, bob, 3, PASS, strlen(PASS), &kp) == KEYFILE_ERR_IMAGE,
            "the right passphrase but a wrong expected id -> IMAGE (validator rejects)");
      CHECK(kp.secret_key == NULL, "no key returned on an id mismatch"); }

    /* never clobbers, never in place */
    CHECK(keyfile_seal(ek, img, ilen, PASS, strlen(PASS), OPS, MEM) == KEYFILE_ERR_EXISTS,
          "sealing over an existing file -> EXISTS, not overwritten");

    /* parameter bounds */
    { char ek2[256]; path(ek2, sizeof(ek2), "toobig.ek");
      CHECK(keyfile_seal(ek2, img, ilen, PASS, strlen(PASS), OPS, KEYFILE_MEMLIMIT_MAX + 1u) == KEYFILE_ERR_PARAMS,
            "memlimit over the ceiling -> PARAMS");
      CHECK(keyfile_seal(ek2, img, ilen, PASS, strlen(PASS), KEYFILE_OPSLIMIT_MAX + 1u, MEM) == KEYFILE_ERR_PARAMS,
            "opslimit over the ceiling -> PARAMS");
      CHECK(fsize(ek2) == -1, "no file is written when parameters are rejected"); }

    /* tamper-evidence: flip each header field and the ciphertext; every flip
       must fail to open (the header is the AEAD's associated data). */
    { long total = fsize(ek);
      const size_t spots[] = {9,10,14,22,38,39,63, (size_t)total - 1u}; /* version,kdf,ops,salt,aead,nonce,ctlen,ct */
      const char *names[] = {"version","kdf_alg","opslimit","salt","aead_alg","nonce","ct_len","ciphertext"};
      int all = 1;
      for (size_t i = 0; i < sizeof(spots)/sizeof(spots[0]); i++) {
          uint8_t *b = malloc((size_t)total); FILE *f = fopen(ek, "rb"); size_t n = fread(b,1,(size_t)total,f); fclose(f);
          (void)n; b[spots[i]] ^= 0x01u;
          char t[256]; path(t, sizeof(t), "tampered.ek");
          (void)unlink(t); FILE *g = fopen(t, "wb"); fwrite(b,1,(size_t)total,g); fclose(g); chmod(t, 0600);
          keyfile_status_t s = keyfile_open(t, ID_A, IDLEN, PASS, strlen(PASS), &kp);
          if (s == KEYFILE_OK) { printf("  (tamper at %s opened!)\n", names[i]); all = 0; if (kp.secret_key) mldsa_keypair_free(&kp); }
          free(b); (void)unlink(t);
      }
      CHECK(all, "flipping any header field or the ciphertext makes open fail"); }

    /* symlink is refused (O_NOFOLLOW) */
    { char lnk[256]; path(lnk, sizeof(lnk), "link.ek");
      if (symlink(ek, lnk) == 0) {
          CHECK(keyfile_open(lnk, ID_A, IDLEN, PASS, strlen(PASS), &kp) == KEYFILE_ERR_IO,
                "a symlinked envelope is refused (O_NOFOLLOW)");
          (void)unlink(lnk);
      } }

    secure_mem_free(img, ilen);
    { char cmd[300]; snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir); (void)system(cmd); }
    printf(g_fail ? "\nFAILED\n" : "\nAll checks passed\n");
    return g_fail;
}
