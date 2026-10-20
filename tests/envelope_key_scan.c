/*
 * V4-27 (CLAIMS D10): is a browser's identity key anywhere on its disk in the
 * clear?
 *
 *   envelope_key_scan --dir DIR --envelope HEXFILE --pass FILE --handle H [--plant FILE]
 *   envelope_key_scan --dir DIR --needle HEXFILE
 *
 * The browser's pages never see a key: it is made, sealed and opened inside
 * the wasm module, and IndexedDB is handed only the sealed MLDSAEK1 envelope.
 * browser_e2e checks that against what Chromium actually wrote. It reads an
 * envelope back from IndexedDB, and this opens it -- natively, with the test's
 * passphrase, through the same keyfile_open_buf the module runs -- and looks
 * under DIR (the browser's profile) for any 16-byte window of the secret key
 * made wholly of secret bytes (key_windows.h, F105's rule).
 *
 * --needle looks for every 16-byte window of arbitrary bytes instead: the
 * canary, which shows the scan can see what IndexedDB writes at all, and the
 * passphrase.
 *
 * --plant FILE is the key path's own proof that it can see: before the scan
 * it writes the opened secret key, in the clear, to FILE (which must be under
 * DIR and must not exist), and removes it after. Every secret window must
 * then be found. Nothing else in the tree writes a key in the clear; this
 * does it to a throwaway test key, in a profile about to be deleted.
 *
 * Every regular file under DIR is read, whatever its size. Symlinks and other
 * non-regular entries (a profile has a lock symlink and a socket) are counted
 * and not followed. A regular file that cannot be read is an error, not a
 * pass (F86's rule: a path the scan cannot hold must not look clean).
 *
 * The output is positions and counts, never a byte of the key:
 *   hit: FILE at OFFSET holds window W
 *   found N of M windows; scanned F files, B bytes; skipped S non-regular entries
 * Exit 0 when the scan completed, whatever it found -- the caller judges N;
 * 2 when it could not (bad arguments, an envelope that does not open, an
 * unreadable file).
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "key_windows.h"
#include "keyfile.h"
#include "mldsa_wrap.h"

#define WIN 16u
#define MAX_HITS_PRINTED 20u

/* The windows looked for, indexed by their first 8 bytes so each file
 * position costs one binary search rather than one memcmp per window. */
typedef struct {
    uint64_t prefix;
    size_t w; /* offset of the window in the needle */
} win_t;

static const uint8_t *g_needle;
static win_t *g_wins;
static size_t g_nwins;
static uint8_t *g_seen; /* per window: found anywhere yet */
static size_t g_files, g_skipped, g_hits_printed;
static unsigned long long g_bytes;

static uint64_t load64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static int cmp_win(const void *a, const void *b)
{
    const uint64_t x = ((const win_t *)a)->prefix, y = ((const win_t *)b)->prefix;
    return (x > y) - (x < y);
}

/* Index the windows of needle[0..len) that `keep` accepts (all, when NULL). */
static int index_windows(const uint8_t *needle, size_t len, int (*keep)(size_t, size_t))
{
    g_needle = needle;
    g_wins = calloc(len, sizeof *g_wins);
    g_seen = calloc(len, 1u);
    if (g_wins == NULL || g_seen == NULL || len < WIN) { return -1; }
    for (size_t w = 0; w + WIN <= len; w++) {
        if (keep != NULL && !keep(w, WIN)) { continue; }
        g_wins[g_nwins].prefix = load64(needle + w);
        g_wins[g_nwins].w = w;
        g_nwins++;
    }
    qsort(g_wins, g_nwins, sizeof *g_wins, cmp_win);
    return 0;
}

static void scan_buf(const char *path, const uint8_t *buf, size_t n)
{
    for (size_t off = 0; off + WIN <= n; off++) {
        const uint64_t p = load64(buf + off);
        size_t lo = 0, hi = g_nwins;
        while (lo < hi) { /* first entry with prefix >= p */
            const size_t mid = lo + (hi - lo) / 2u;
            if (g_wins[mid].prefix < p) { lo = mid + 1u; } else { hi = mid; }
        }
        for (size_t i = lo; i < g_nwins && g_wins[i].prefix == p; i++) {
            const size_t w = g_wins[i].w;
            if (memcmp(buf + off, g_needle + w, WIN) != 0) { continue; }
            if (!g_seen[w] && g_hits_printed < MAX_HITS_PRINTED) {
                printf("hit: %s at %zu holds window %zu\n", path, off, w);
                g_hits_printed++;
            }
            g_seen[w] = 1u;
        }
    }
}

static int scan_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (d == NULL) { fprintf(stderr, "cannot open directory %s: %s\n", dir, strerror(errno)); return -1; }
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) { continue; }
        char p[4096];
        const int pn = snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        if (pn < 0 || (size_t)pn >= sizeof p) { fprintf(stderr, "path too long under %s\n", dir); rc = -1; break; }
        struct stat st;
        if (lstat(p, &st) != 0) {
            if (errno == ENOENT) { continue; } /* gone since readdir: a live profile changes */
            fprintf(stderr, "cannot stat %s: %s\n", p, strerror(errno));
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) { rc = scan_dir(p); continue; }
        if (!S_ISREG(st.st_mode)) { g_skipped++; continue; }
        FILE *f = fopen(p, "rb");
        if (f == NULL) {
            if (errno == ENOENT) { continue; }
            fprintf(stderr, "cannot read %s: %s\n", p, strerror(errno));
            rc = -1;
            break;
        }
        const size_t n = (size_t)st.st_size;
        uint8_t *buf = malloc(n > 0u ? n : 1u);
        const size_t got = (buf != NULL) ? fread(buf, 1u, n, f) : 0u;
        (void)fclose(f);
        if (buf == NULL) { fprintf(stderr, "out of memory for %s\n", p); rc = -1; break; }
        /* A file that shrank since lstat is scanned as it is now. */
        scan_buf(p, buf, got);
        g_files++;
        g_bytes += got;
        free(buf);
    }
    (void)closedir(d);
    return rc;
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    size_t cap = 4096u, n = 0u;
    uint8_t *b = malloc(cap);
    while (b != NULL) {
        n += fread(b + n, 1u, cap - n, f);
        if (n < cap) { break; }
        uint8_t *nb = realloc(b, cap * 2u);
        if (nb == NULL) { free(b); b = NULL; break; }
        b = nb;
        cap *= 2u;
    }
    (void)fclose(f);
    *len = n;
    return b;
}

/* Hex text (whitespace ignored) to bytes, in place of the text. */
static uint8_t *read_hex(const char *path, size_t *len)
{
    size_t n = 0u;
    uint8_t *t = read_file(path, &n);
    if (t == NULL) { return NULL; }
    size_t out = 0u;
    int hi = -1;
    for (size_t i = 0; i < n; i++) {
        const int c = t[i];
        int v;
        if (c >= '0' && c <= '9') { v = c - '0'; }
        else if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; }
        else if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; }
        else if (c == ' ' || c == '\n' || c == '\r' || c == '\t') { continue; }
        else { free(t); return NULL; }
        if (hi < 0) { hi = v; } else { t[out++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    if (hi >= 0) { free(t); return NULL; }
    *len = out;
    return t;
}

static int usage(void)
{
    fputs("usage: envelope_key_scan --dir DIR --envelope HEXFILE --pass FILE --handle H [--plant FILE]\n"
          "       envelope_key_scan --dir DIR --needle HEXFILE\n", stderr);
    return 2;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *dir = NULL, *env = NULL, *pass = NULL, *handle = NULL, *needle = NULL, *plant = NULL;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--dir") == 0) { dir = argv[i + 1]; }
        else if (strcmp(argv[i], "--envelope") == 0) { env = argv[i + 1]; }
        else if (strcmp(argv[i], "--pass") == 0) { pass = argv[i + 1]; }
        else if (strcmp(argv[i], "--handle") == 0) { handle = argv[i + 1]; }
        else if (strcmp(argv[i], "--needle") == 0) { needle = argv[i + 1]; }
        else if (strcmp(argv[i], "--plant") == 0) { plant = argv[i + 1]; }
        else { return usage(); }
    }
    if (argc % 2 != 1 || dir == NULL || (needle == NULL) == (env == NULL) ||
        (env != NULL && (pass == NULL || handle == NULL)) || (plant != NULL && env == NULL)) {
        return usage();
    }
    if (sodium_init() < 0) { fputs("sodium_init failed\n", stderr); return 2; }

    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    uint8_t *nb = NULL;
    int rc = 2;
    if (needle != NULL) {
        size_t nlen = 0u;
        nb = read_hex(needle, &nlen);
        if (nb == NULL || index_windows(nb, nlen, NULL) != 0) { fprintf(stderr, "bad needle %s\n", needle); goto out; }
    } else {
        size_t elen = 0u, plen = 0u;
        uint8_t *eb = read_hex(env, &elen);
        uint8_t *pb = read_file(pass, &plen);
        keyfile_status_t st = KEYFILE_ERR_FORMAT;
        if (eb != NULL && pb != NULL) {
            st = keyfile_open_buf(eb, elen, (const uint8_t *)handle, strlen(handle), (const char *)pb, plen, &kp, NULL);
        }
        free(eb);
        if (pb != NULL) { sodium_memzero(pb, plen); free(pb); }
        if (st != KEYFILE_OK || kp.secret_key == NULL) {
            fprintf(stderr, "the envelope did not open: %s\n", keyfile_status_name(st));
            goto out;
        }
        if (index_windows(kp.secret_key, MLDSA_SECRET_KEY_BYTES, sk_window_is_secret) != 0) { goto out; }
    }
    int planted = 0;
    if (plant != NULL) {
        const int fd = open(plant, O_WRONLY | O_CREAT | O_EXCL, 0600);
        const ssize_t wr = (fd >= 0) ? write(fd, kp.secret_key, MLDSA_SECRET_KEY_BYTES) : -1;
        if (fd >= 0) { (void)close(fd); planted = 1; }
        if (wr != (ssize_t)MLDSA_SECRET_KEY_BYTES) { fprintf(stderr, "cannot plant %s\n", plant); goto unplant; }
    }
    if (scan_dir(dir) != 0) { goto unplant; }
    size_t found = 0u;
    for (size_t i = 0; i < g_nwins; i++) { found += g_seen[g_wins[i].w] ? 1u : 0u; }
    printf("found %zu of %zu windows; scanned %zu files, %llu bytes; skipped %zu non-regular entries\n",
           found, g_nwins, g_files, g_bytes, g_skipped);
    rc = 0;
unplant:
    if (planted && unlink(plant) != 0) { fprintf(stderr, "cannot remove %s\n", plant); rc = 2; }
out:
    mldsa_keypair_free(&kp);
    free(nb);
    free(g_wins);
    free(g_seen);
    return rc;
}
