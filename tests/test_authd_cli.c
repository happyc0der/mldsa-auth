/*
 * V4-9b: the two command-line tools (spec mldsa-authd 13).
 *
 * The subcommands are library functions (authd_cli.h), so this test drives
 * every refusal path directly instead of forking a binary and parsing prose --
 * the demo_cli_keygen() precedent. tests/authd_e2e.sh covers the other half:
 * the SHIPPED binaries as real processes against a real daemon.
 *
 * What is pinned here is mostly what must NOT happen: no plaintext secret key
 * on disk (Req 10), no second config validator, no trusting a .pub file's own
 * label, no init over an existing store, and one authoritative answer to "does
 * this command's reply end with END?".
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/ioctl.h>
#include <linux/sockios.h>
#endif

#include "authd_cli.h"
#include "authd_config.h"
#include "authd_harness.h"
#include <sodium.h>

#include "sdnotify.h"
#include "authd_secret.h"
#include "stdfds.h"
#include "child_exit.h"
#include "key_windows.h"
#include "keyfile.h"
#include "localcli.h"
#include "net_io.h"
#include "secure_mem.h"

static int g_fail = 0;
static int g_checks = 0;
static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) { printf("FAIL: %s\n", what); g_fail = 1; }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

static char g_dir[192];

/* argv builder: authd_cli_* take (argc, argv) exactly as main() would. */
#define RUN_ADMIN(...) run_cli(authd_cli_admin, (char *[]){ "authd_admin", __VA_ARGS__, NULL })
#define RUN_CLIENT(...) run_cli(authd_cli_client, (char *[]){ "authd_client", __VA_ARGS__, NULL })

static int run_cli(int (*fn)(int, char **), char **argv)
{
    int argc = 0;
    while (argv[argc] != NULL) { argc++; }
    return fn(argc, argv);
}

/* Runs a CLI with one of its streams captured into `buf`. Used where the
 * MESSAGE is the thing under test, not just the exit code. */
static int run_tool_capture_stream(int (*tool)(int, char **), char **argv, char *buf, size_t cap,
                                   FILE *stream, int fd)
{
    char tmp[256];
    (void)snprintf(tmp, sizeof tmp, "%s/captured.txt", g_dir);
    (void)fflush(stream);
    const int saved = dup(fd);
    FILE *f = freopen(tmp, "w", stream);
    const int rc = (f != NULL) ? run_cli(tool, argv) : -1;
    (void)fflush(stream);
    if (saved >= 0) {
        (void)dup2(saved, fd);
        (void)close(saved);
        clearerr(stream);
    }
    buf[0] = '\0';
    FILE *r = fopen(tmp, "r");
    if (r != NULL) {
        const size_t n = fread(buf, 1u, cap - 1u, r);
        buf[n] = '\0';
        (void)fclose(r);
    }
    (void)unlink(tmp);
    return rc;
}

static int run_admin_capture_stream(char **argv, char *buf, size_t cap, FILE *stream, int fd)
{
    return run_tool_capture_stream(authd_cli_admin, argv, buf, cap, stream, fd);
}

/* V4-327 (F608): how many bytes written to `fd` its peer has not read yet,
 * where the platform can say. Linux can (measured in a container: 768 after
 * an 11-byte write to a Unix socket, 0 once the peer has read). macOS's
 * SO_NWRITE answers 0 for a Unix socket whatever is unread, so there this
 * returns 0 and the caller keeps its sleep; the nightly, which is the
 * authority for a campaign's kills, runs on Linux. */
static int unread_bytes(int fd)
{
    int n = 0;
#if defined(__linux__)
    if (ioctl(fd, SIOCOUTQ, &n) != 0) { n = 0; }
#else
    (void)fd;
#endif
    return n;
}

static int run_client_capture(char **argv, char *buf, size_t cap)
{
    return run_tool_capture_stream(authd_cli_client, argv, buf, cap, stderr, 2);
}

static int run_admin_capture(char **argv, char *buf, size_t cap)
{
    return run_admin_capture_stream(argv, buf, cap, stderr, 2);
}

static int run_admin_capture_stdout(char **argv, char *buf, size_t cap)
{
    return run_admin_capture_stream(argv, buf, cap, stdout, 1);
}

static int write_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { return -1; }
    (void)fputs(text, f);
    (void)fclose(f);
    return chmod(path, mode);
}

static mode_t mode_of(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) ? (st.st_mode & 07777) : 0;
}

static int file_size(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) ? (int)st.st_size : -1;
}

static void sha256_file(const char *path, uint8_t out[32])
{
    memset(out, 0, 32);
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return; }
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1u, sizeof buf, f)) > 0u) {
        crypto_hash_sha256_update(&st, buf, n);
    }
    (void)fclose(f);
    crypto_hash_sha256_final(&st, out);
}

/* Recursively: does any regular file under `dir` begin with `magic`? */
static int any_file_starts_with(const char *dir, const char *magic)
{
    DIR *d = opendir(dir);
    if (d == NULL) { return 0; }
    struct dirent *e;
    int found = 0;
    while (!found && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) { continue; }
        char p[512];
        /* Every caller asserts that NOTHING matches, so a path this scan cannot
         * hold counts as found: an absence check that skipped what it could
         * not read would pass vacuously (F86; gcc 16 on macOS, where d_name is
         * 1,024 bytes, asks for exactly this). */
        const int pn = snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        if (pn < 0 || (size_t)pn >= sizeof p) { found = 1; continue; }
        struct stat st;
        if (stat(p, &st) != 0) { continue; }
        if (S_ISDIR(st.st_mode)) {
            found = any_file_starts_with(p, magic);
            continue;
        }
        FILE *f = fopen(p, "rb");
        if (f == NULL) { continue; }
        char head[16] = { 0 };
        const size_t got = fread(head, 1u, strlen(magic), f);
        (void)fclose(f);
        if (got == strlen(magic) && memcmp(head, magic, got) == 0) { found = 1; }
    }
    (void)closedir(d);
    return found;
}

/* sk_window_is_secret, F105's rule for which key windows count, is in
 * key_windows.h, shared with test_authd_conn and envelope_key_scan (V4-27). */

/* Recursively: does any regular file under `dir`, other than `exempt` (may be
 * NULL), hold a 16-byte window of the ML-DSA-65 secret key `sk` made wholly of
 * secret bytes? The header scan above finds only files that BEGIN with
 * MLDSASK; this finds key bytes anywhere, headed or not (V4-15c, CLAIMS D10).
 * As there, a path the scan cannot hold counts as found (F86). A hit says
 * which file and which window, so a failure explains itself. */
static int any_file_has_key_window(const char *dir, const uint8_t *sk, const char *exempt)
{
    DIR *d = opendir(dir);
    if (d == NULL) { return 0; }
    struct dirent *e;
    int found = 0;
    while (!found && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) { continue; }
        char p[512];
        const int pn = snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        if (pn < 0 || (size_t)pn >= sizeof p) { found = 1; continue; }
        struct stat st;
        if (stat(p, &st) != 0) { continue; }
        if (S_ISDIR(st.st_mode)) { found = any_file_has_key_window(p, sk, exempt); continue; }
        if (exempt != NULL && strcmp(p, exempt) == 0) { continue; }
        if (st.st_size <= 0 || st.st_size > (off_t)(1 << 20)) { continue; }
        FILE *f = fopen(p, "rb");
        if (f == NULL) { found = 1; continue; }
        uint8_t *buf = (uint8_t *)malloc((size_t)st.st_size);
        const size_t got = (buf != NULL) ? fread(buf, 1u, (size_t)st.st_size, f) : 0u;
        (void)fclose(f);
        if (buf == NULL || got != (size_t)st.st_size) { free(buf); found = 1; continue; }
        for (size_t w = 0; !found && w + 16u <= MLDSA_SECRET_KEY_BYTES; w++) {
            if (!sk_window_is_secret(w, 16u)) { continue; }
            if (memmem(buf, got, sk + w, 16u) != NULL) {
                printf("  (scan: %s holds sk[%zu..%zu))\n", p, w, w + 16u);
                found = 1;
            }
        }
        free(buf);
    }
    (void)closedir(d);
    return found;
}

/* ---------------------------------------------------------------- init */

static void test_init(void)
{
    char dir[256], pass[256], ek[256], pub[256], db[256];
    (void)snprintf(dir, sizeof dir, "%s/i1", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/i1/pass", g_dir);
    (void)snprintf(ek, sizeof ek, "%s/i1/server.ek", g_dir);
    (void)snprintf(pub, sizeof pub, "%s/i1/server.pub", g_dir);
    (void)snprintf(db, sizeof db, "%s/i1/store.sqlite3", g_dir);

    char said[2048];
    CHECK(run_admin_capture_stdout((char *[]){ "authd_admin", "init", "--dir", dir, "--server-id", "authd",
                                               "--passphrase-file", pass, NULL }, said, sizeof said) == 0,
          "init: creates a server key, a store and a passphrase file");
    CHECK(strstr(said, "init: created ") != NULL && strstr(said, "/i1 (mode 0700)") != NULL &&
          strstr(said, "used the existing") == NULL,
          "init: says it created the directory, mode 0700, when it did");

    CHECK(mode_of(dir) == 0700, "init: the data directory is 0700 (spec 16)");
    CHECK(mode_of(ek) == 0600, "init: server.ek is 0600");
    CHECK(mode_of(pass) == 0600, "init: the passphrase file is 0600");
    /* store_open creates the database with the CALLER'S umask -- 0022 in an
     * operator's shell -- so without an explicit chmod this is 0644 and every
     * token hash and public key in it is world-readable. */
    CHECK(mode_of(db) == 0600, "init: store.sqlite3 is 0600, not the umask's opinion");
    CHECK(file_size(pub) == 1961 + 5, "init: server.pub is MLDSAPK1 of the right length");

    /* Spec 12: server parameters are ops=4, mem=256 MiB, and they live in the
     * header where anyone can read them back. Offsets 10 and 14, big-endian. */
    FILE *f = fopen(ek, "rb");
    CHECK(f != NULL, "init: server.ek is readable");
    if (f != NULL) {
        uint8_t hdr[22];
        CHECK(fread(hdr, 1u, sizeof hdr, f) == sizeof hdr, "init: header readable");
        (void)fclose(f);
        const uint32_t ops = ((uint32_t)hdr[10] << 24) | ((uint32_t)hdr[11] << 16) |
                             ((uint32_t)hdr[12] << 8) | (uint32_t)hdr[13];
        uint64_t mem = 0;
        for (int i = 0; i < 8; i++) { mem = (mem << 8) | hdr[14 + i]; }
        CHECK(ops == 4u, "init: server opslimit is 4 (spec 12)");
        CHECK(mem == 256ull * 1024ull * 1024ull, "init: server memlimit is 256 MiB (spec 12)");
    }

    /* THE binding that matters: the key must open with the passphrase EXACTLY
     * as the file holds it. The reader strips one trailing newline, so a key
     * sealed under the in-memory random bytes rather than the bytes read back
     * is unopenable whenever the last byte happens to be 0x0A -- one time in
     * 256, reported as success. */
    uint8_t *p = NULL;
    size_t plen = 0;
    CHECK(authd_secret_read(pass, &p, &plen) == AUTHD_SECRET_OK, "init: passphrase file reads back");
    if (p != NULL) {
        mldsa_keypair_t kp;
        memset(&kp, 0, sizeof kp);
        const keyfile_status_t ks = keyfile_open(ek, (const uint8_t *)"authd", 5u,
                                                 (const char *)p, plen, &kp, NULL);
        CHECK(ks == KEYFILE_OK,
              "init: server.ek opens with the passphrase AS WRITTEN to the file");
        mldsa_keypair_free(&kp);
        authd_secret_free(p, plen);
    }

    /* A second init must refuse and change NOTHING. store_open() would
     * otherwise succeed on the existing store and re-derive key_audit from a
     * different KEK, breaking the audit chain permanently with no error at the
     * moment of damage. */
    uint8_t h_ek[32], h_db[32], h_ek2[32], h_db2[32];
    sha256_file(ek, h_ek);
    sha256_file(db, h_db);
    CHECK(RUN_ADMIN("init", "--dir", dir, "--server-id", "authd", "--passphrase-file", pass) != 0,
          "init: a second init into the same directory is refused");
    sha256_file(ek, h_ek2);
    sha256_file(db, h_db2);
    CHECK(memcmp(h_ek, h_ek2, 32) == 0 && memcmp(h_db, h_db2, 32) == 0,
          "init: the refused second init left server.ek and store.sqlite3 byte-identical");

    /* The dangerous case, and the one the existence check actually exists for.
     *
     * Refusing a second init when the PASSPHRASE file is still there proves
     * little: write_secret_file uses O_EXCL, so it would refuse anyway. The
     * state that matters is the one an operator creates when they decide to
     * start the server identity over: every piece of key material removed, the
     * STORE left behind. Without the check init would seal a brand new key and
     * then store_open the existing store with a DIFFERENT KEK, re-deriving
     * key_audit and breaking the audit chain permanently -- and it would
     * report SUCCESS, because nothing downstream notices.
     *
     * (This is what a mutation surviving on Linux revealed: the refusal had
     * only ever been "killed" by a compile error on the unused helper, which
     * V4-9c removed by giving that helper a second caller.) */
    {
        char db2[256], ek2[256], pass2[256], pub2[256];
        (void)snprintf(db2, sizeof db2, "%s/i2/store.sqlite3", g_dir);
        (void)snprintf(ek2, sizeof ek2, "%s/i2/server.ek", g_dir);
        (void)snprintf(pass2, sizeof pass2, "%s/i2/pass", g_dir);
        (void)snprintf(pub2, sizeof pub2, "%s/i2/server.pub", g_dir);
        char dir2[256];
        (void)snprintf(dir2, sizeof dir2, "%s/i2", g_dir);
        CHECK(RUN_ADMIN("init", "--dir", dir2, "--server-id", "authd",
                        "--passphrase-file", pass2) == 0, "init: a second directory for the store check");
        uint8_t before[32], after[32];
        sha256_file(db2, before);
        /* the operator's tidy-up: credential stored, plaintext gone */
        CHECK(unlink(pass2) == 0 && unlink(ek2) == 0 && unlink(pub2) == 0,
              "init: remove ALL key material, keep the store");
        CHECK(RUN_ADMIN("init", "--dir", dir2, "--server-id", "authd",
                        "--passphrase-file", pass2) != 0,
              "init: an EXISTING STORE is refused even when all key material is gone");
        sha256_file(db2, after);
        CHECK(memcmp(before, after, 32) == 0,
              "init: the refused init left the existing store byte-identical");
    }

    /* V4-109, F195: a public key left behind is found BEFORE anything is
     * written, and named. It used to be found after the passphrase file and
     * the sealed key were on disk, with a message that named neither. */
    {
        char dir3[256], pub3[256], ek3[256], db3[256], pass3[256], err[1024];
        (void)snprintf(dir3, sizeof dir3, "%s/i3", g_dir);
        (void)snprintf(pub3, sizeof pub3, "%s/i3/server.pub", g_dir);
        (void)snprintf(ek3, sizeof ek3, "%s/i3/server.ek", g_dir);
        (void)snprintf(db3, sizeof db3, "%s/i3/store.sqlite3", g_dir);
        (void)snprintf(pass3, sizeof pass3, "%s/i3/pass", g_dir);
        CHECK(mkdir(dir3, 0700) == 0 && write_file(pub3, "left over\n", 0644) == 0,
              "init: a directory holding only an old server.pub");
        CHECK(run_admin_capture((char *[]){ "authd_admin", "init", "--dir", dir3, "--server-id", "authd",
                                            "--passphrase-file", pass3, NULL }, err, sizeof err) == 1 &&
              strstr(err, "refusing") != NULL && strstr(err, "/i3/server.pub already exists") != NULL,
              "init: an existing server.pub is refused up front, by name (F195)");
        CHECK(access(pass3, F_OK) != 0 && access(ek3, F_OK) != 0 && access(db3, F_OK) != 0 &&
              file_size(pub3) == 10,
              "init: and that refusal wrote nothing: no passphrase, key or store (F195)");
    }

    /* V4-157, F233: an init that fails AFTER it has written something says
     * exactly what it left. The store is made to fail by a directory where
     * SQLite wants its write-ahead log. The message used to name the key and
     * the passphrase file and not server.pub, so an operator who removed the
     * two it named was refused on the retry. */
    {
        char dirw[256], pubw[256], ekw[256], dbw[256], walw[256], passw[256], err[2048];
        (void)snprintf(dirw, sizeof dirw, "%s/iw", g_dir);
        (void)snprintf(pubw, sizeof pubw, "%s/iw/server.pub", g_dir);
        (void)snprintf(ekw, sizeof ekw, "%s/iw/server.ek", g_dir);
        (void)snprintf(dbw, sizeof dbw, "%s/iw/store.sqlite3", g_dir);
        (void)snprintf(walw, sizeof walw, "%s/iw/store.sqlite3-wal", g_dir);
        (void)snprintf(passw, sizeof passw, "%s/iw/pass", g_dir);
        CHECK(mkdir(dirw, 0700) == 0 && mkdir(walw, 0700) == 0, "init: a directory where the store's log must go");
        const int rcw = run_admin_capture((char *[]){ "authd_admin", "init", "--dir", dirw, "--server-id", "authd",
                                                      "--passphrase-file", passw, NULL }, err, sizeof err);
        CHECK(rcw == 1 && access(ekw, F_OK) == 0 && access(pubw, F_OK) == 0 && access(passw, F_OK) == 0,
              "init: a store that cannot be made fails (1) after the key, its public half and the passphrase were written");
        CHECK(strstr(err, "left behind:") != NULL && strstr(err, "/iw/server.ek") != NULL &&
              strstr(err, "/iw/pass") != NULL && strstr(err, "/iw/server.pub") != NULL &&
              (access(dbw, F_OK) != 0 || strstr(err, "/iw/store.sqlite3 --") != NULL),
              "init: a failure after writing names every file it left, server.pub among them (F233)");
    }

    /* V4-109, F195: a directory that was already there keeps its mode, and
     * init says what that mode is instead of "created ... (mode 0700)". */
    {
        char dir4[256], pass4[256], out[2048];
        (void)snprintf(dir4, sizeof dir4, "%s/i4", g_dir);
        (void)snprintf(pass4, sizeof pass4, "%s/i4/pass", g_dir);
        CHECK(mkdir(dir4, 0750) == 0 && chmod(dir4, 0750) == 0, "init: an empty directory of mode 0750");
        CHECK(run_admin_capture_stdout((char *[]){ "authd_admin", "init", "--dir", dir4, "--server-id", "authd",
                                                   "--passphrase-file", pass4, NULL }, out, sizeof out) == 0 &&
              mode_of(dir4) == 0750,
              "init: runs in an existing empty directory and leaves its mode alone");
        CHECK(strstr(out, "init: used the existing ") != NULL && strstr(out, "/i4 (mode 0750)") != NULL &&
              strstr(out, "init: created ") == NULL,
              "init: says it used the existing directory and reports its real mode (F195)");
    }

    /* V4-109, F193: the offline commands read a store, they do not make one.
     * A mistyped --store used to create an empty store there (mode 0644) and
     * report "0 entries verified" with exit 0. */
    {
        char typo[256], wal[300], err[1024];
        (void)snprintf(typo, sizeof typo, "%s/i1/store.sqlite", g_dir);
        (void)snprintf(wal, sizeof wal, "%s-wal", typo);
        CHECK(run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", typo, "--key", ek,
                                            "--passphrase-file", pass, "--server-id", "authd", NULL },
                                err, sizeof err) == 1 && strstr(err, "store.sqlite: io") != NULL,
              "audit-verify: a --store that names no file fails (1) as io (F193)");
        CHECK(access(typo, F_OK) != 0 && access(wal, F_OK) != 0,
              "audit-verify: and creates nothing at that path (F193)");
        CHECK(run_admin_capture((char *[]){ "authd_admin", "pseudonym", "--store", typo, "--key", ek,
                                            "--passphrase-file", pass, "--server-id", "authd", "--id", "alice",
                                            NULL }, err, sizeof err) == 1 && strstr(err, "store.sqlite: io") != NULL,
              "pseudonym: a --store that names no file fails (1) as io (F193)");
        CHECK(access(typo, F_OK) != 0, "pseudonym: and creates nothing at that path (F193)");
        CHECK(RUN_ADMIN("audit-verify", "--store", db, "--key", ek, "--passphrase-file", pass,
                        "--server-id", "authd") == 0,
              "audit-verify: the store init made verifies (0)");
    }

    CHECK(RUN_ADMIN("init", "--dir", dir, "--server-id") == 2, "init: a missing value is usage (2)");
    CHECK(RUN_ADMIN("init", "--dir", dir, "--bogus", "x") == 2, "init: an unknown option is usage (2)");

    /* V4-13d: pseudonym, offline against the store init just made. Its VALUE
     * is authd_e2e's to check against a real daemon's journal; these are its
     * refusals, which decide whether an operator's typo is told apart from a
     * wrong key. */
    CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", ek, "--passphrase-file", pass,
                    "--server-id", "authd", "--id", "alice") == 0,
          "pseudonym: prints a pseudonym for an id (0)");
    CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", ek, "--passphrase-file", pass,
                    "--server-id", "authd") == 2, "pseudonym: no --id is usage (2)");
    CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", ek, "--passphrase-file", pass,
                    "--server-id", "authd", "--id", "") == 2, "pseudonym: an empty --id is usage (2)");
    CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", ek, "--passphrase-file", pass,
                    "--server-id", "authd", "--id", "a", "--bogus", "x") == 2,
          "pseudonym: an unknown option is usage (2)");
    {
        char wrong[256];
        (void)snprintf(wrong, sizeof wrong, "%s/wrong-pass", g_dir);
        CHECK(write_file(wrong, "not the server passphrase\n", 0600) == 0, "pseudonym: wrong passphrase fixture");
        CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", ek, "--passphrase-file", wrong,
                        "--server-id", "authd", "--id", "alice") == 3,
              "pseudonym: a wrong passphrase is a configuration error (3): no pseudonym without the key (F196)");
        /* F196 (V4-112): a --key that cannot be used is the operator's file
         * to fix, 3, as a --passphrase-file already was -- missing, unsafe or
         * not opened by the passphrase. 1 is left for an operation that ran
         * and failed: a chain that does not verify. */
        char nokey[256], gkey[256], err[512];
        (void)snprintf(nokey, sizeof nokey, "%s/no-such.ek", g_dir);
        (void)snprintf(gkey, sizeof gkey, "%s/group.ek", g_dir);
        CHECK(run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", db, "--key", nokey,
                                            "--passphrase-file", pass, "--server-id", "authd", NULL },
                                err, sizeof err) == 3 &&
              strstr(err, "/no-such.ek: io-error") != NULL,
              "audit-verify: a --key that names no file is a configuration error (3), by name (F196)");
        CHECK(run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", db, "--key", ek,
                                            "--passphrase-file", wrong, "--server-id", "authd", NULL },
                                err, sizeof err) == 3 &&
              strstr(err, "decryption-failed") != NULL,
              "audit-verify: a wrong passphrase is a configuration error (3) (F196)");
        CHECK(RUN_ADMIN("pseudonym", "--store", db, "--key", nokey, "--passphrase-file", pass,
                        "--server-id", "authd", "--id", "alice") == 3,
              "pseudonym: a --key that names no file is a configuration error (3) (F196)");
        { uint8_t buf[8192];
          size_t n = 0;
          FILE *f = fopen(ek, "rb");
          if (f != NULL) { n = fread(buf, 1, sizeof buf, f); (void)fclose(f); }
          f = fopen(gkey, "wb");
          if (f != NULL) { (void)fwrite(buf, 1, n, f); (void)fclose(f); }
          CHECK(n > 0 && chmod(gkey, 0640) == 0 &&
                run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", db, "--key", gkey,
                                              "--passphrase-file", pass, "--server-id", "authd", NULL },
                                  err, sizeof err) == 3 &&
                strstr(err, "unsafe-permissions") != NULL,
                "audit-verify: a group-readable --key is a configuration error (3) (F196)");
          (void)unlink(gkey); }
        /* V4-276 (F443): the right passphrase and another identity's key
         * name: id-mismatch, not a damaged image. */
        CHECK(run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", db, "--key", ek,
                                            "--passphrase-file", pass, "--server-id", "not-authd", NULL },
                                err, sizeof err) == 3 &&
              strstr(err, "id-mismatch") != NULL && strstr(err, "decrypted-image-invalid") == NULL,
              "audit-verify: a --server-id the key is not is id-mismatch, not decrypted-image-invalid (F443)");
        /* V4-276 (F445): a socket that is not there is told apart from one
         * this user may not reach. */
        { char nosock[256];
          (void)snprintf(nosock, sizeof nosock, "%s/no-such.sock", g_dir);
          CHECK(run_admin_capture((char *[]){ "authd_admin", "list-users", "--socket", nosock, NULL }, err, sizeof err) == 1 &&
                strstr(err, "cannot-connect") != NULL && strstr(err, "there is no socket at that path") != NULL,
                "admin: a socket path with nothing there says so, beside cannot-connect (F445)"); }
        CHECK(RUN_ADMIN("rewrap", "--id", "authd", "--in", nokey, "--out", gkey,
                        "--old-passphrase-file", pass, "--new-passphrase-file", wrong) == 3 &&
              file_size(gkey) < 0,
              "rewrap: an --in that names no file is a configuration error (3), and nothing is written (F196)");
    }
}

/* ------------------------------------------------------- keys and rewrap */

static void test_keys(void)
{
    char dir[256], pass[256], pass2[256], bad[256], ek[256], pub[256], ek2[256];
    (void)snprintf(dir, sizeof dir, "%s/k1", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/k1/p1", g_dir);
    (void)snprintf(pass2, sizeof pass2, "%s/k1/p2", g_dir);
    (void)snprintf(bad, sizeof bad, "%s/k1/p644", g_dir);
    (void)snprintf(ek, sizeof ek, "%s/k1/a.ek", g_dir);
    (void)snprintf(pub, sizeof pub, "%s/k1/a.pub", g_dir);
    (void)snprintf(ek2, sizeof ek2, "%s/k1/b.ek", g_dir);
    (void)mkdir(dir, 0700);
    CHECK(write_file(pass, "passphrase-one\n", 0600) == 0, "keys: fixture passphrase");
    CHECK(write_file(pass2, "passphrase-two\n", 0600) == 0, "keys: fixture passphrase 2");
    CHECK(write_file(bad, "world readable\n", 0644) == 0, "keys: fixture 0644 passphrase");

    /* A passphrase any other user can read is not a passphrase. Spec 13 calls
     * that a CONFIGURATION error, exit 3 -- distinct from 1, so an operator's
     * script can tell "you set this up wrong" from "the operation failed". */
    CHECK(RUN_ADMIN("keygen-server", "--key", ek, "--pub", pub, "--server-id", "srv",
                    "--passphrase-file", bad) == 3,
          "keygen-server: a 0644 passphrase file is a configuration error (3)");
    CHECK(file_size(ek) < 0, "keygen-server: nothing was written after that refusal");

    CHECK(RUN_ADMIN("keygen-server", "--key", ek, "--pub", pub, "--server-id", "srv",
                    "--passphrase-file", pass) == 0, "keygen-server: writes a sealed key");
    CHECK(mode_of(ek) == 0600, "keygen-server: the sealed key is 0600");
    /* V4-157, F232: a --pub that cannot be written is found BEFORE a key is
     * made. keygen-server sealed the key first and then failed on the public
     * half, leaving a secret key with no public key beside it, and a retry
     * was refused on the key it had just orphaned. */
    {
        char ek5[512], err[1024];
        (void)snprintf(ek5, sizeof ek5, "%s/orphan.ek", dir);
        CHECK(run_admin_capture((char *[]){ "authd_admin", "keygen-server", "--key", ek5, "--pub", pub,
                                            "--server-id", "srv", "--passphrase-file", pass, NULL },
                                err, sizeof err) == 1 &&
              strstr(err, "refusing") != NULL && strstr(err, "already exists") != NULL,
              "keygen-server: a --pub that already exists is refused up front, by name (F232)");
        CHECK(file_size(ek5) < 0, "keygen-server: and that refusal sealed no key (F232)");
    }
    /* V4-314, F547: two spellings of one path are not caught by F538's
     * comparison. The key is sealed, the public half finds it there, and
     * the run used to end without saying that a key had been left. */
    {
        char k7[512], p7[512], err[1024];
        (void)snprintf(k7, sizeof k7, "%s/two.ek", dir);
        (void)snprintf(p7, sizeof p7, "%s/./two.ek", dir);
        CHECK(run_admin_capture((char *[]){ "authd_admin", "keygen-server", "--key", k7, "--pub", p7,
                                            "--server-id", "srv", "--passphrase-file", pass, NULL },
                                err, sizeof err) == 1 &&
              strstr(err, "was written and its public half was not; remove it before retrying") != NULL,
              "keygen-server: a key left without its public half is named, two spellings of one path included (F547)");
        (void)unlink(k7);
    }

    /* Req 10: no plaintext secret key is written to disk by any daemon or CLI
     * command. demo_keys_generate_files() writes one, which is exactly why the
     * authd paths cannot use it -- and every functional check would still pass
     * if they did. */
    CHECK(!any_file_starts_with(dir, "MLDSASK2") && !any_file_starts_with(dir, "MLDSASK1"),
          "keygen-server: no plaintext MLDSASK file was written anywhere (Req 10)");
    /* ...and by content, not just by header: no 16-byte window of the secret
     * key in any file under the directory (V4-15c, CLAIMS D10). */
    {
        mldsa_keypair_t k;
        memset(&k, 0, sizeof k);
        CHECK(keyfile_open(ek, (const uint8_t *)"srv", 3u, "passphrase-one", 14u, &k, NULL) == KEYFILE_OK,
              "keygen-server: the sealed key opens (the scan needs to know what to look for)");
        CHECK(k.secret_key != NULL && !any_file_has_key_window(dir, k.secret_key, NULL),
              "keygen-server: no window of the server's secret key is in any file under its directory (Req 10)");
        mldsa_keypair_free(&k);
    }

    CHECK(RUN_ADMIN("keygen-server", "--key", ek, "--pub", pub, "--server-id", "srv",
                    "--passphrase-file", pass) == 1,
          "keygen-server: an existing key is never overwritten");

    /* rewrap: the OLD passphrase must actually be checked, and --out equal to
     * --in must be impossible rather than merely discouraged. */
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek2,
                    "--old-passphrase-file", pass2, "--new-passphrase-file", pass) == 3,
          "rewrap: the wrong old passphrase is refused, as a configuration error (3) (F196)");
    CHECK(file_size(ek2) < 0, "rewrap: nothing was written after a wrong passphrase");
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek,
                    "--old-passphrase-file", pass, "--new-passphrase-file", pass2) == 1,
          "rewrap: --out equal to --in is refused, so rewrap is never in place");
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek2,
                    "--old-passphrase-file", pass, "--new-passphrase-file", pass2) == 0,
          "rewrap: writes a new file under the new passphrase");
    /* V4-108, F190: the V4-104 warning is gone with its cause. What rewrap
     * says now is that the store's keys carry over, and on stderr nothing. */
    { char ek3[400], err[4096], outb[4096];
      (void)snprintf(ek3, sizeof ek3, "%s.f190", ek2);
      char *wa[] = { "authd_admin", "rewrap", "--id", "srv", "--in", ek, "--out", ek3,
                     "--old-passphrase-file", pass, "--new-passphrase-file", pass2, NULL };
      CHECK(run_admin_capture(wa, err, sizeof err) == 0 && err[0] == '\0',
            "rewrap: a successful rewrap prints no warning (the F190 warning went with its cause)");
      (void)unlink(ek3);
      CHECK(run_admin_capture_stdout(wa, outb, sizeof outb) == 0 && strstr(outb, "version 2") != NULL &&
            strstr(outb, "carry over") != NULL && strstr(outb, "same store root key") != NULL,
            "rewrap: says the new file is version 2 and that the store's audit chain and pseudonyms carry over");
      (void)unlink(ek3); }
    {
        mldsa_keypair_t a, b;
        memset(&a, 0, sizeof a);
        memset(&b, 0, sizeof b);
        CHECK(keyfile_open(ek, (const uint8_t *)"srv", 3u, "passphrase-one", 14u, &a, NULL) == KEYFILE_OK,
              "rewrap: the original still opens under the old passphrase");
        CHECK(keyfile_open(ek2, (const uint8_t *)"srv", 3u, "passphrase-two", 14u, &b, NULL) == KEYFILE_OK,
              "rewrap: the rewrapped file opens under the new one");
        CHECK(memcmp(a.public_key, b.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
              "rewrap: it is the SAME identity, re-sealed");
        CHECK(a.secret_key != NULL && !any_file_has_key_window(dir, a.secret_key, NULL),
              "rewrap: no window of the secret key in either sealed file or anywhere else (Req 10)");
        mldsa_keypair_free(&a);
        mldsa_keypair_free(&b);
    }
}

/* ------------------------------------------- rewrap keeps the store (F190) */

static int version_byte(const char *path)
{
    uint8_t h[9];
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return -1; }
    const size_t n = fread(h, 1u, sizeof h, f);
    (void)fclose(f);
    return (n == sizeof h) ? (int)h[8] : -1;
}

/* Opens the store at `db` with the root key of `ek`, optionally writes two
 * audit entries, and returns the pseudonym of "alice". 0 on success. */
static int store_with_key(const char *db, const char *ek, const char *id, const char *pass, size_t pass_len,
                          int write_entries, uint8_t root_out[KEYFILE_ROOT_BYTES],
                          uint8_t ps_out[STORE_PSEUDONYM_BYTES])
{
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    /* Every failure names its step and status: a bare "!= 0" here once left a
     * one-off failure with nothing to read (V4-108). */
    const keyfile_status_t ks = keyfile_open(ek, (const uint8_t *)id, strlen(id), pass, pass_len, &kp, root_out);
    if (ks != KEYFILE_OK) {
        printf("store_with_key: keyfile_open(%s) -> %d\n", ek, (int)ks);
        return -1;
    }
    mldsa_keypair_free(&kp);
    store_t *st = NULL;
    const store_status_t so = store_open(db, root_out, &st);
    if (so != STORE_OK) {
        printf("store_with_key: store_open(%s) -> %d\n", db, (int)so);
        return -2;
    }
    int rc = 0;
    if (write_entries) {
        const store_status_t sa = store_add_user(st, (const uint8_t *)"alice", 5u, STORE_ROLE_USER);
        const store_status_t sd = (sa == STORE_OK)
            ? store_disable_user(st, (const uint8_t *)"alice", 5u, "test", (const uint8_t *)"f190", 4u) : sa;
        if (sa != STORE_OK || sd != STORE_OK) {
            printf("store_with_key: add_user -> %d, disable_user -> %d\n", (int)sa, (int)sd);
            rc = -3;
        }
    }
    if (rc == 0) {
        const store_status_t sv = store_audit_verify(st);
        if (sv != STORE_OK) { printf("store_with_key: audit_verify -> %d\n", (int)sv); rc = -4; }
    }
    if (rc == 0) {
        const store_status_t sp = store_log_pseudonym(st, (const uint8_t *)"alice", 5u, ps_out);
        if (sp != STORE_OK) { printf("store_with_key: log_pseudonym -> %d\n", (int)sp); rc = -5; }
    }
    store_close(st);
    return rc;
}

/* V4-108, audit F190, spec erratum 79. Before this step the store's audit-MAC
 * and pseudonym keys were derived from the envelope KEK, so a passphrase
 * change left a store that failed audit-verify and whose every idh= had
 * changed. Now they come from a root key sealed in the key file, and rewrap
 * carries it over. Both starting points are driven: a version-2 file from
 * init, and a version-1 file with a store keyed from its KEK -- what every
 * deployment made before this step has. */
static void test_rewrap_keeps_store(void)
{
    char dir[256], pass[256], p2[256], p3[256], ek[256], db[256], next[300], third[300], other[300], opub[300];
    (void)snprintf(dir, sizeof dir, "%s/rw1", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/rw1/pass", g_dir);
    (void)snprintf(p2, sizeof p2, "%s/rw-p2", g_dir);
    (void)snprintf(p3, sizeof p3, "%s/rw-p3", g_dir);
    (void)snprintf(ek, sizeof ek, "%s/rw1/server.ek", g_dir);
    (void)snprintf(db, sizeof db, "%s/rw1/store.sqlite3", g_dir);
    (void)snprintf(next, sizeof next, "%s.next", ek);
    (void)snprintf(third, sizeof third, "%s.third", ek);
    (void)snprintf(other, sizeof other, "%s/rw-other.ek", g_dir);
    (void)snprintf(opub, sizeof opub, "%s/rw-other.pub", g_dir);
    CHECK(write_file(p2, "the second passphrase\n", 0600) == 0 && write_file(p3, "the third passphrase\n", 0600) == 0,
          "rewrap/store: fixture passphrases");

    CHECK(RUN_ADMIN("init", "--dir", dir, "--server-id", "authd", "--passphrase-file", pass) == 0,
          "rewrap/store: init");
    CHECK(version_byte(ek) == 2 && file_size(ek) == 6140 + 5,
          "init: server.ek is MLDSAEK1 version 2, 6140 + id_len bytes (spec 12)");

    /* The passphrase exactly as authd_admin reads it -- through its own
     * reader. init writes 32 RANDOM bytes, and the reader strips one trailing
     * newline and nothing else; a reader of this test's own that stripped
     * every trailing CR and LF derived a different key whenever the last
     * byte was 0x0D, about one run in 256 (seen once, in a campaign's clean
     * suite). */
    uint8_t *pw = NULL;
    size_t pwl = 0u;
    (void)authd_secret_read(pass, &pw, &pwl);
    uint8_t root0[KEYFILE_ROOT_BYTES], root1[KEYFILE_ROOT_BYTES], root2[KEYFILE_ROOT_BYTES];
    uint8_t ps0[STORE_PSEUDONYM_BYTES], ps1[STORE_PSEUDONYM_BYTES], ps2[STORE_PSEUDONYM_BYTES];
    CHECK(pwl > 0u && store_with_key(db, ek, "authd", (const char *)pw, pwl, 1, root0, ps0) == 0,
          "rewrap/store: two audit entries written under the key init made, and the chain verifies");
    CHECK(RUN_ADMIN("audit-verify", "--store", db, "--key", ek, "--passphrase-file", pass,
                    "--server-id", "authd") == 0,
          "rewrap/store: audit-verify passes before the passphrase change");

    CHECK(RUN_ADMIN("rewrap", "--id", "authd", "--in", ek, "--out", next,
                    "--old-passphrase-file", pass, "--new-passphrase-file", p2) == 0 &&
              version_byte(next) == 2 && file_size(next) == 6140 + 5 && mode_of(next) == 0600,
          "rewrap/store: a version-2 key is rewrapped to a version-2 key, mode 0600");
    CHECK(RUN_ADMIN("audit-verify", "--store", db, "--key", next, "--passphrase-file", p2,
                    "--server-id", "authd") == 0,
          "F190: after a passphrase change the store's audit chain still verifies (audit-verify 0)");
    CHECK(store_with_key(db, next, "authd", "the second passphrase", 21u, 0, root1, ps1) == 0 &&
              memcmp(root0, root1, sizeof root0) == 0 && memcmp(ps0, ps1, sizeof ps0) == 0,
          "F190: after a passphrase change the root key and a user's pseudonym are unchanged");
    CHECK(RUN_ADMIN("audit-verify", "--store", db, "--key", next, "--passphrase-file", pass,
                    "--server-id", "authd") == 3,
          "rewrap/store: the old passphrase does not open the new file (audit-verify 3, F196)");
    CHECK(RUN_ADMIN("rewrap", "--id", "authd", "--in", next, "--out", third,
                    "--old-passphrase-file", p2, "--new-passphrase-file", p3) == 0 &&
              RUN_ADMIN("audit-verify", "--store", db, "--key", third, "--passphrase-file", p3,
                        "--server-id", "authd") == 0,
          "F190: a second passphrase change, and the chain still verifies");

    /* the control: the chain is keyed, and a different root key fails it. A
     * check above that passed for an empty or unkeyed chain would pass here too. */
    CHECK(RUN_ADMIN("keygen-server", "--key", other, "--pub", opub, "--server-id", "authd",
                    "--passphrase-file", p2) == 0 && version_byte(other) == 2,
          "keygen-server: writes MLDSAEK1 version 2");
    { char aerr[1024];
      /* V4-276 (F446): ...at entry 1, and the tool says the key is the
       * likelier cause than the chain. */
      CHECK(run_admin_capture((char *[]){ "authd_admin", "audit-verify", "--store", db, "--key", other,
                                          "--passphrase-file", p2, "--server-id", "authd", NULL },
                              aerr, sizeof aerr) == 1 &&
            strstr(aerr, "FAILED at entry 1") != NULL && strstr(aerr, "--key is not") != NULL,
            "control: a key file with a different root key fails audit-verify (1, not 3: the key opened) on the same store, "
            "and says the key is the likelier cause (F446)"); }

    /* ---- the legacy path: a version-1 server key, a store keyed from its KEK */
    char ldir[256], l1[300], l2[300], ldb[300], lp[300];
    (void)snprintf(ldir, sizeof ldir, "%s/rw-legacy", g_dir);
    (void)snprintf(l1, sizeof l1, "%s/server.ek", ldir);
    (void)snprintf(l2, sizeof l2, "%s/server.ek.next", ldir);
    (void)snprintf(ldb, sizeof ldb, "%s/store.sqlite3", ldir);
    (void)snprintf(lp, sizeof lp, "%s/pass", ldir);
    (void)mkdir(ldir, 0700);
    static const char LPASS[] = "a passphrase from before V4-108";
    {
        mldsa_keypair_t kp;
        memset(&kp, 0, sizeof kp);
        const size_t il = demo_keys_sk2_image_len(5u);
        uint8_t *img = secure_mem_alloc(il);
        const int made = img != NULL && mldsa_keypair_generate(&kp) == 0 &&
                         demo_keys_build_sk2_image(img, il, (const uint8_t *)"authd", 5u, &kp) == DEMO_KEYS_OK &&
                         keyfile_seal(l1, img, il, LPASS, strlen(LPASS), 1u, 8u * 1024u * 1024u) == KEYFILE_OK;
        if (kp.secret_key != NULL) { mldsa_keypair_free(&kp); }
        if (img != NULL) { secure_mem_free(img, il); }
        CHECK(made && version_byte(l1) == 1 && file_size(l1) == 6108 + 5 &&
                  write_file(lp, "a passphrase from before V4-108\n", 0600) == 0,
              "legacy: a version-1 server key, as every key file before V4-108 is");
    }
    CHECK(store_with_key(ldb, l1, "authd", LPASS, strlen(LPASS), 1, root0, ps0) == 0,
          "legacy: a store keyed from the version-1 file's KEK, with two audit entries");
    CHECK(RUN_ADMIN("audit-verify", "--store", ldb, "--key", l1, "--passphrase-file", lp,
                    "--server-id", "authd") == 0,
          "legacy: an existing store still verifies under its version-1 key (no forced migration)");
    CHECK(RUN_ADMIN("rewrap", "--id", "authd", "--in", l1, "--out", l2,
                    "--old-passphrase-file", lp, "--new-passphrase-file", p2) == 0 &&
              version_byte(l2) == 2 && file_size(l2) == 6140 + 5,
          "legacy: rewrap turns the version-1 key into a version-2 key");
    CHECK(RUN_ADMIN("audit-verify", "--store", ldb, "--key", l2, "--passphrase-file", p2,
                    "--server-id", "authd") == 0,
          "F190, legacy: the store verifies under the rewrapped key and its new passphrase");
    CHECK(store_with_key(ldb, l2, "authd", "the second passphrase", 21u, 0, root2, ps2) == 0 &&
              memcmp(root0, root2, sizeof root0) == 0 && memcmp(ps0, ps2, sizeof ps0) == 0,
          "F190, legacy: the old KEK became the root key, and the pseudonym is unchanged");
    CHECK(RUN_ADMIN("audit-verify", "--store", ldb, "--key", other, "--passphrase-file", p2,
                    "--server-id", "authd") == 1,
          "control, legacy: a different key fails audit-verify (1) on the legacy store");
    authd_secret_free(pw, pwl);
    sodium_memzero(root0, sizeof root0); sodium_memzero(root1, sizeof root1); sodium_memzero(root2, sizeof root2);
}

/* -------------------------------------------------------- client keygen */

static void test_client_keygen(void)
{
    char dir[256], pass[256];
    (void)snprintf(dir, sizeof dir, "%s/c1", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/c1pass", g_dir);
    CHECK(write_file(pass, "device passphrase\n", 0600) == 0, "client: fixture passphrase");

    CHECK(RUN_CLIENT("keygen", "--dir", dir, "--passphrase-file", pass) == 0,
          "client keygen: generates a handle and a sealed key");
    CHECK(!any_file_starts_with(dir, "MLDSASK2") && !any_file_starts_with(dir, "MLDSASK1"),
          "client keygen: no plaintext MLDSASK file was written anywhere (Req 10)");

    /* Spec 3.1: handle = "d1" || 32 lowercase hex characters. */
    DIR *d = opendir(dir);
    CHECK(d != NULL, "client keygen: the directory exists");
    char handle[64] = { 0 };
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            const size_t n = strlen(e->d_name);
            if (n > 3u && strcmp(e->d_name + n - 3u, ".ek") == 0) {
                (void)snprintf(handle, sizeof handle, "%.*s", (int)(n - 3u), e->d_name);
            }
        }
        (void)closedir(d);
    }
    CHECK(strlen(handle) == 34u && handle[0] == 'd' && handle[1] == '1',
          "client keygen: the handle is d1 + 32 hex (spec 3.1)");
    int hexish = 1;
    for (size_t i = 2; i < strlen(handle); i++) {
        if (!((handle[i] >= '0' && handle[i] <= '9') || (handle[i] >= 'a' && handle[i] <= 'f'))) {
            hexish = 0;
        }
    }
    CHECK(hexish, "client keygen: the handle's 32 characters are lowercase hex");

    char ek[512];
    (void)snprintf(ek, sizeof ek, "%s/%s.ek", dir, handle);
    CHECK(mode_of(ek) == 0600, "client keygen: the device key is 0600");
    {
        mldsa_keypair_t k;
        memset(&k, 0, sizeof k);
        CHECK(keyfile_open(ek, (const uint8_t *)handle, strlen(handle), "device passphrase", 17u, &k, NULL)
                  == KEYFILE_OK, "client keygen: the sealed device key opens");
        CHECK(k.secret_key != NULL && !any_file_has_key_window(dir, k.secret_key, NULL),
              "client keygen: no window of the device's secret key is in any file under its directory (Req 10)");
        mldsa_keypair_free(&k);
    }

    /* Spec 12: operator parameters are ops=3, distinct from the server's 4. */
    FILE *f = fopen(ek, "rb");
    if (f != NULL) {
        uint8_t hdr[14];
        /* gcc's warn_unused_result is NOT silenced by a (void) cast -- the F0
         * lesson, and a short read here would compare uninitialised bytes. */
        const size_t got = fread(hdr, 1u, sizeof hdr, f);
        (void)fclose(f);
        CHECK(got == sizeof hdr, "client keygen: the envelope header is readable");
        const uint32_t ops = ((uint32_t)hdr[10] << 24) | ((uint32_t)hdr[11] << 16) |
                             ((uint32_t)hdr[12] << 8) | (uint32_t)hdr[13];
        CHECK(ops == 3u, "client keygen: operator opslimit is 3, not the server's 4 (spec 12)");
    }

    /* enroll-operator must believe --handle, not the file. A .pub whose
     * embedded id differs is ID_MISMATCH -- the V2-9 rule that a file's own
     * label is never the authority, applied to enrollment. */
    char pub[512], other[512];
    (void)snprintf(pub, sizeof pub, "%s/%s.pub", dir, handle);
    (void)snprintf(other, sizeof other, "%s/sock-does-not-exist", g_dir);
    char err[1024];
    char *argv[] = { "authd_admin", "enroll-operator", "--socket", other, "--user", "u1",
                     "--handle", "d1deadbeef", "--pub", pub, NULL };
    const int rc = run_admin_capture(argv, err, sizeof err);
    CHECK(rc == 1 && strstr(err, "id-mismatch") != NULL,
          "enroll-operator: a .pub whose embedded id differs from --handle is id-mismatch");
}

/* --------------------------------------------------------- migrate-key */

/* The first test ever to run migrate-key (V4-15c, CLAIMS D10). Its input is a
 * plaintext MLDSASK2 file BY DESIGN -- the legacy form it exists to replace --
 * and the command leaves it in place, printing a warning, because it cannot
 * know what else references it. So the scan exempts that one file by name, and
 * the canary is that the exempt file really does hold the key. */
static void test_migrate_key(void)
{
    char dir[256], legacy[256], out[256], pass[256];
    (void)snprintf(dir, sizeof dir, "%s/m1", g_dir);
    (void)snprintf(legacy, sizeof legacy, "%s/m1/mig.sk", g_dir);
    (void)snprintf(out, sizeof out, "%s/m1/mig.ek", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/m1pass", g_dir);
    CHECK(write_file(pass, "migrate passphrase\n", 0600) == 0, "migrate: fixture passphrase");
    CHECK(demo_keys_generate_files(dir, (const uint8_t *)"mig", 3u) == DEMO_KEYS_OK,
          "migrate: a legacy plaintext identity (mig.sk, mig.pub)");
    CHECK(RUN_ADMIN("migrate-key", "--id", "mig", "--in", legacy, "--out", out,
                    "--passphrase-file", pass) == 0,
          "migrate-key: seals the legacy identity into an envelope");
    CHECK(version_byte(out) == 2 && file_size(out) == 6140 + 3,
          "migrate-key: writes MLDSAEK1 version 2, 6140 + id_len bytes");
    mldsa_keypair_t old_k, new_k;
    memset(&old_k, 0, sizeof old_k);
    memset(&new_k, 0, sizeof new_k);
    CHECK(demo_keys_load_identity(legacy, (const uint8_t *)"mig", 3u, &old_k) == DEMO_KEYS_OK &&
              keyfile_open(out, (const uint8_t *)"mig", 3u, "migrate passphrase", 18u, &new_k, NULL) == KEYFILE_OK &&
              memcmp(old_k.public_key, new_k.public_key, MLDSA_PUBLIC_KEY_BYTES) == 0,
          "migrate-key: the envelope holds the SAME identity as the legacy file");
    CHECK(new_k.secret_key != NULL && any_file_has_key_window(dir, new_k.secret_key, NULL),
          "migrate-key: the plaintext input itself holds the key -- the scan's canary");
    CHECK(new_k.secret_key != NULL && !any_file_has_key_window(dir, new_k.secret_key, legacy),
          "migrate-key: no window of the secret key outside its plaintext input (Req 10)");
    mldsa_keypair_free(&old_k);
    mldsa_keypair_free(&new_k);
}

/* --------------------------------------------------- one config validator */

/* authd_admin --check-config must be the DAEMON's validator, reached through a
 * second entry point -- not a second implementation. Two validators drift, and
 * the one an operator runs before starting the service would then approve a
 * configuration the one that matters rejects.
 *
 * Several DIFFERENT malformed inputs, and the exact status name compared, so a
 * second parser cannot pass by agreeing accidentally on one of them. */
static void test_check_config(void)
{
    static const struct { const char *name; const char *text; } cases[] = {
        { "unknown-key",    "store_path = /a\nnope = 1\n" },
        { "duplicate-key",  "store_path = /a\nstore_path = /b\n" },
        { "syntax",         "store_path\n" },
        { "range",          "store_path = /a\nkey_path = /b\nkey_passphrase_file = /c\n"
                            "server_id = s\nlisten_port = 1\nmax_slots = 99999\n" },
        { "missing-key",    "store_path = /a\n" },
        { "value",          "store_path = /a\nkey_path = /b\nkey_passphrase_file = /c\n"
                            "server_id = s\nlisten_port = 1\npad_bucket = 32\n" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char path[256];
        (void)snprintf(path, sizeof path, "%s/cfg%zu.conf", g_dir, i);
        CHECK(write_file(path, cases[i].text, 0600) == 0, "check-config: fixture written");

        authd_config_t cfg;
        size_t line = 0;
        const authd_config_status_t direct = authd_config_load(path, &cfg, &line);
        CHECK(direct != AUTHD_CFG_OK, "check-config: the fixture really is malformed");

        char err[1024];
        char *argv[] = { "authd_admin", "--check-config", "--config", path, NULL };
        const int rc = run_admin_capture(argv, err, sizeof err);
        CHECK(rc == 3, "check-config: a malformed config is exit 3, not 1 (spec 13)");
        CHECK(strstr(err, authd_config_status_name(direct)) != NULL,
              "check-config: admin reports the SAME status name the shared parser returned");
    }

    /* V4-101, F187: "io" now says why. A missing file, a directory, and --
     * when not root, which reads anything -- a file this user cannot read,
     * the shape that stopped the rehearsed daemon (F180). */
    { char missing[256], unreadable[256], err[1024];
      (void)snprintf(missing, sizeof missing, "%s/absent.conf", g_dir);
      char *a1[] = { "authd_admin", "--check-config", "--config", missing, NULL };
      CHECK(run_admin_capture(a1, err, sizeof err) == 3 && strstr(err, ": io (") != NULL &&
            strstr(err, strerror(ENOENT)) != NULL,
            "check-config: a missing configuration says io and why (No such file or directory)");
      char *a2[] = { "authd_admin", "--check-config", "--config", g_dir, NULL };
      CHECK(run_admin_capture(a2, err, sizeof err) == 3 && strstr(err, ": io (not a regular file)") != NULL,
            "check-config: a directory as the configuration says io (not a regular file)");
      (void)snprintf(unreadable, sizeof unreadable, "%s/unreadable.conf", g_dir);
      CHECK(write_file(unreadable, "store_path = /a\n", 0000) == 0, "check-config: an unreadable fixture");
      if (geteuid() != 0) {
          char *a3[] = { "authd_admin", "--check-config", "--config", unreadable, NULL };
          CHECK(run_admin_capture(a3, err, sizeof err) == 3 && strstr(err, strerror(EACCES)) != NULL,
                "check-config: an unreadable configuration says io (Permission denied) -- F180's shape");
      }
      (void)unlink(unreadable); }

    /* V4-101, F186: a socket that closes without a byte -- the daemon's
     * refusal of a uid outside the allowlist -- is explained, not just
     * named. A child accepts one connection and closes it. */
    { char sp[sizeof g_dir + 16u], err[2048];
      (void)snprintf(sp, sizeof sp, "%s/refuse.sock", g_dir);
      const int ls = socket(AF_UNIX, SOCK_STREAM, 0);
      struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
      const size_t spn = strlen(sp);
      const int fits = spn < sizeof a.sun_path;
      if (fits) { memcpy(a.sun_path, sp, spn + 1u); }
      const int ok = fits && ls >= 0 && bind(ls, (struct sockaddr *)&a, sizeof a) == 0 && listen(ls, 1) == 0;
      CHECK(ok, "refused peer: a listening socket that will close at accept");
      const pid_t kid = ok ? fork() : -1;
      if (kid == 0) { const int c = accept(ls, NULL, NULL); if (c >= 0) { (void)close(c); } _exit(0); }
      if (kid > 0) {
          char *av[] = { "authd_admin", "list-users", "--socket", sp, NULL };
          const int rc = run_admin_capture(av, err, sizeof err);
          (void)waitpid(kid, NULL, 0);
          CHECK(rc != 0 && strstr(err, "closed the connection without answering") != NULL &&
                strstr(err, "admin_uids") != NULL,
                "refused peer: a connection closed without a byte says the uid allowlist is the likely cause (F186)");
      }
      if (ls >= 0) { (void)close(ls); }
      (void)unlink(sp); }

    /* And a valid one, whose files exist, passes both halves. */
    char dir[256], cpath[256], text[1024];
    int n = 0;
    (void)snprintf(dir, sizeof dir, "%s/i1", g_dir);
    (void)snprintf(cpath, sizeof cpath, "%s/good.conf", g_dir);
    (void)snprintf(text, sizeof text,
                   "store_path = %s/store.sqlite3\nkey_path = %s/server.ek\n"
                   "key_passphrase_file = %s/pass\nserver_id = authd\nlisten_port = 18443\n",
                   dir, dir, dir);
    CHECK(write_file(cpath, text, 0600) == 0, "check-config: valid fixture written");
    CHECK(RUN_ADMIN("--check-config", "--config", cpath) == 0, "check-config: a valid config is 0");

    /* The check that only exists because AUTHD_PATH_MAX (255) is roughly 2.5x
     * sun_path: a socket path every byte-level check accepts, which the daemon
     * then cannot bind. Catching it here is the difference between a clear
     * refusal and a service that will not start. */
    char longsock[160];
    memcpy(longsock, "/tmp/", 5u);
    memset(longsock + 5, 'z', 120u);
    memcpy(longsock + 125, "/x.sock", 8u);   /* 132 bytes: over sun_path, under AUTHD_PATH_MAX */
    /* snprintf's return is CHECKED, not discarded. gcc at -O0 refuses the
     * discard outright (-Werror=format-truncation) and is right to: a
     * truncated fixture would test something other than what it names. */
    n = snprintf(text, sizeof text,
                 "store_path = %s/store.sqlite3\nkey_path = %s/server.ek\n"
                 "key_passphrase_file = %s/pass\nserver_id = authd\nlisten_unix = %s\n",
                 dir, dir, dir, longsock);
    CHECK(n > 0 && (size_t)n < sizeof text, "check-config: the long-socket fixture fits");
    (void)snprintf(cpath, sizeof cpath, "%s/longsock.conf", g_dir);
    CHECK(write_file(cpath, text, 0600) == 0, "check-config: long-socket fixture written");
    char err[1024];
    char *argv[] = { "authd_admin", "--check-config", "--config", cpath, NULL };
    CHECK(run_admin_capture(argv, err, sizeof err) == 3 &&
          strstr(err, "too long for a Unix socket") != NULL,
          "check-config: a socket path that cannot fit sun_path is refused, not deferred to bind");
}

/* ------------------------------------------------- the one framing rule */

/* localcli_is_list_command() decides whether to read until a line "END".
 * Nothing in a reply can decide it: REVOKE-TOKENS answers `OK count=N` on ONE
 * line, exactly like a list HEADER. This measures what each command's reply
 * ACTUALLY looks like -- via h_local_drain, which applies no rule at all -- and
 * requires the table to agree with reality for every command.
 *
 * Measuring with h_local_cmd would compare the table against itself. */
static int ends_with_end_line(const char *s)
{
    const size_t n = strlen(s);
    return n >= 4u && memcmp(s + n - 4u, "END\n", 4u) == 0;
}

static void test_framing_rule(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "cli.sqlite3", 1) == 0, "framing: daemon starts");
    int fd = h_dial_unix(d.admin_path);
    CHECK(fd >= 0, "framing: connect to admin.sock");

    static const uint8_t U[] = { 'u', '1' };
    static const uint8_t H[] = { 'd', '1', 'a', 'a' };
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    CHECK(mldsa_keypair_generate(&kp) == 0, "framing: device key");
    CHECK(store_add_user(d.store, U, sizeof U, STORE_ROLE_USER) == STORE_OK, "framing: user");
    CHECK(store_enroll_device(d.store, H, sizeof H, U, sizeof U, kp.public_key,
                              "site", "test", NULL, 0) == STORE_OK, "framing: device");

    char uhex[8];
    h_hex(uhex, sizeof uhex, U, sizeof U);

    char req[256];
    static char resp[LOCALCLI_RESP_MAX + 1u];
    struct { const char *cmd; const char *args; } cases[] = {
        { "PING",          "" },
        { "LIST-USERS",    "" },
        { "LIST-DEVICES",  NULL },   /* filled in below: needs the hex user id */
        { "AUDIT-TAIL",    "n=5" },
        { "REVOKE-TOKENS", NULL },   /* the ambiguous one: OK count=N, ONE line */
        { "ENABLE-USER",   NULL },
    };
    char ld[64], rt[64], eu[64];
    (void)snprintf(ld, sizeof ld, "user=%s", uhex);
    (void)snprintf(rt, sizeof rt, "user=%s", uhex);
    (void)snprintf(eu, sizeof eu, "user=%s", uhex);
    cases[2].args = ld;
    cases[4].args = rt;
    cases[5].args = eu;

    int saw_count_with_end = 0, saw_count_without_end = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        (void)snprintf(req, sizeof req, "%s%s%s", cases[i].cmd,
                       (cases[i].args[0] != '\0') ? " " : "", cases[i].args);
        CHECK(h_local_drain(&d, fd, req, resp, sizeof resp) == 0, "framing: a reply arrived");
        CHECK(strncmp(resp, "OK", 2) == 0, "framing: every probe command succeeded");
        const int actual = ends_with_end_line(resp);
        CHECK(localcli_is_list_command(cases[i].cmd) == actual,
              "framing: the list table matches what the daemon actually sends");
        if (strncmp(resp, "OK count=", 9) == 0) {
            if (actual) { saw_count_with_end = 1; } else { saw_count_without_end = 1; }
        }
    }
    /* Non-vacuity: unless BOTH shapes were observed, the table could be a
     * constant and this test would still pass. saw_count_without_end is
     * REVOKE-TOKENS, the reply that makes the prefix useless as a signal. */
    CHECK(saw_count_with_end && saw_count_without_end,
          "framing: both `OK count=` shapes were observed, so the prefix really is ambiguous");

    /* A list must be read to its END, not truncated at the header. */
    (void)snprintf(req, sizeof req, "LIST-DEVICES user=%s", uhex);
    CHECK(h_local_drain(&d, fd, req, resp, sizeof resp) == 0, "framing: list-devices replies");
    CHECK(strstr(resp, "DEVICE handle=") != NULL && ends_with_end_line(resp),
          "framing: a list carries its rows between the header and END");

    (void)close(fd);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* Every combination of the .ek.next decision, without a network round trip.
 *
 * The rule under test is deliberately NOT spec 10.2's wording: that says "if
 * it is unknown, the server never committed", and Req 6 guarantees a client
 * cannot tell unknown from revoked from bad-signature. Only .ek
 * authenticating proves the server did not commit -- there is one active key
 * per handle -- so that is the only case in which discarding .ek.next is safe.
 * The asymmetry is the point: a stale file costs a confusing directory entry,
 * a wrong delete costs the identity. */
/* The CLIENT's reader, not the harness's (V4-14a, F79). The framing check
 * above drains replies with h_local_drain, so localcli_call's own
 * response_complete -- the code authd_admin actually runs -- was never on the
 * path of any test; v49b's L2 mutates it and was only ever "killed" by the
 * compiler. A real daemon writes a list in one go and the first read gets all
 * of it, so a reader that stops at the header still looks right. This server
 * sends the header, waits, then the rows and END: only a reader that waits
 * for END sees the row. */
static void test_localcli_split_list(void)
{
    char path[400];
    (void)snprintf(path, sizeof path, "%s/split.sock", g_dir);
    (void)unlink(path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    const int sn = snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);   /* checked: F86 */
    CHECK(sn > 0 && (size_t)sn < sizeof sa.sun_path && lfd >= 0 &&
          bind(lfd, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(lfd, 1) == 0,
          "split: a fake daemon listens");
    const pid_t pid = fork();
    if (pid == 0) {
        const int c = accept(lfd, NULL, NULL);
        char req[256];
        (void)!read(c, req, sizeof req);
        static const char head[] = "OK count=1\n";
        static const char rest[] = "DEVICE handle=6431 label=- via=site\nEND\n";
        (void)!write(c, head, sizeof head - 1u);
        /* The rows arrive in a second write, and only once the header has
         * been READ (V4-327, F608). It was a 200 ms sleep: a reader stalled
         * past it took both writes in one read, and a client that stops at
         * the first line (campaign v49b, L2) returned the whole list. */
        if (unread_bytes(c) > 0) {
            for (int spin = 0; spin < 5000 && unread_bytes(c) > 0; spin++) { usleep(1000); }
            usleep(20000);
        } else {
            usleep(200000);                     /* this platform cannot say (macOS): the old sleep */
        }
        (void)!write(c, rest, sizeof rest - 1u);
        usleep(100000);
        (void)close(c);
        child_exit(0);
    }
    char out[4096];
    size_t n = 0;
    const localcli_status_t st = localcli_call(path, "LIST-DEVICES", "user=75", 5000u, out, sizeof out, &n);
    int ws = 0;
    (void)waitpid(pid, &ws, 0);
    (void)close(lfd);
    (void)unlink(path);
    CHECK(st == LOCALCLI_OK && strncmp(out, "OK count=1\n", 11) == 0,
          "split: localcli_call returns the list's header");
    CHECK(st == LOCALCLI_OK && strstr(out, "DEVICE handle=6431") != NULL && strstr(out, "\nEND\n") != NULL,
          "split: a list that arrives in two writes is read to its END, rows included");
}

/* V4-52: localcli_call against a daemon that misbehaves. It is the local-API
 * client authd_admin uses, and V4-44's coverage showed none of its refusals had
 * run: a reply larger than the caller's buffer, a reply cut off before it is
 * complete, a daemon that never answers, a request over spec 8's line cap.
 * Each fake daemon is a forked child that accepts once and plays a script. */
static int lc_listen(const char *path)
{
    (void)unlink(path);
    const int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    const int sn = snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    if (lfd < 0 || sn <= 0 || (size_t)sn >= sizeof sa.sun_path ||
        bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 1) != 0) {
        if (lfd >= 0) { (void)close(lfd); }
        return -1;
    }
    return lfd;
}

/* The child: accept, read the request, write `reply`, then wait `hold_us`
 * before closing (a long hold is a daemon that never finishes). */
static pid_t lc_daemon(int lfd, const char *reply, size_t n, useconds_t hold_us)
{
    const pid_t pid = fork();
    if (pid == 0) {
        const int c = accept(lfd, NULL, NULL);
        char req[512];
        (void)!read(c, req, sizeof req);
        if (n > 0u) { (void)!write(c, reply, n); }
        usleep(hold_us);
        (void)close(c);
        child_exit(0);
    }
    return pid;
}

static void test_localcli_robustness(void)
{
    char path[400];
    (void)snprintf(path, sizeof path, "%s/lc.sock", g_dir);
    int ws = 0;

    /* the canary: a one-line reply is OK */
    { const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, "OK\n", 3u, 50000);
      char out[256]; size_t n = 0;
      const localcli_status_t st = localcli_call(path, "PING", NULL, 5000u, out, sizeof out, &n);
      (void)waitpid(pid, &ws, 0); (void)close(lfd);
      CHECK(lfd >= 0 && st == LOCALCLI_OK && strcmp(out, "OK\n") == 0,
            "localcli: a one-line reply is OK -- the canary"); }

    /* a reply larger than the buffer, never complete: refused, and nothing is
     * written past the buffer (guard bytes after it) */
    { static char big[600];
      memcpy(big, "OK count=9\n", 11u);
      for (size_t i = 11; i < sizeof big; i++) { big[i] = (i % 40u == 39u) ? '\n' : 'r'; }
      const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, big, sizeof big, 300000);
      char out[64 + 16]; memset(out, 0x5a, sizeof out);
      size_t n = 0;
      const localcli_status_t st = localcli_call(path, "LIST-USERS", NULL, 5000u, out, 64u, &n);
      (void)waitpid(pid, &ws, 0); (void)close(lfd);
      int intact = 1; for (size_t i = 64; i < sizeof out; i++) { if ((unsigned char)out[i] != 0x5au) { intact = 0; } }
      CHECK(st == LOCALCLI_ERR_RESPONSE && n < 64u && memchr(out, '\0', 64u) != NULL && intact,
            "localcli: a reply larger than the caller's buffer is refused, NUL-terminated inside it, and nothing is written past it"); }

    /* half a list, then the daemon closes: a truncation, not a list */
    { static const char half[] = "OK count=2\nUSER user=75 role=user\n";
      const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, half, sizeof half - 1u, 0);
      char out[512]; size_t n = 0;
      const localcli_status_t st = localcli_call(path, "LIST-USERS", NULL, 5000u, out, sizeof out, &n);
      (void)waitpid(pid, &ws, 0); (void)close(lfd);
      CHECK(st == LOCALCLI_ERR_RESPONSE,
            "localcli: a list the daemon closes before its END is refused as a truncation, not returned"); }

    /* a daemon that never answers: TIMEOUT, at the deadline */
    { const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, NULL, 0u, 2000000);
      char out[256]; size_t n = 0;
      const uint64_t t0 = net_now_ms();
      const localcli_status_t st = localcli_call(path, "PING", NULL, 300u, out, sizeof out, &n);
      const uint64_t took = net_now_ms() - t0;
      (void)kill(pid, SIGKILL); (void)waitpid(pid, &ws, 0); (void)close(lfd);
      CHECK(st == LOCALCLI_ERR_TIMEOUT && took >= 250u && took < 1500u,
            "localcli: a daemon that never answers is a TIMEOUT at the deadline"); }

    /* Spec 8's 8192-byte line cap, LF included, from both sides (V4-55). A
     * request ONE byte over it is refused before any byte is sent -- the fake
     * daemon sees no connection -- and one exactly AT it is sent. "PING " and
     * the LF are 6 bytes, so the arguments are the cap minus 5 and minus 6.
     * One byte over, not thousands: V4-52's 8197-byte request overflowed the
     * client's 8194-byte line buffer once the check was mutated away, and
     * ASan, not this check, then caught it on Linux (F128). */
    { const int lfd = lc_listen(path);
      static char args[AUTHD_LINE_MAX];
      memset(args, 'a', AUTHD_LINE_MAX - 5u); args[AUTHD_LINE_MAX - 5u] = '\0';
      char out[256]; size_t n = 0;
      const localcli_status_t st = localcli_call(path, "PING", args, 1000u, out, sizeof out, &n);
      struct pollfd pf = { lfd, POLLIN, 0 };
      const int pending = poll(&pf, 1, 100);
      (void)close(lfd);
      CHECK(strlen("PING ") + strlen(args) + 1u == AUTHD_LINE_MAX + 1u,
            "localcli: the over-cap request is exactly one byte over the 8192-byte cap");
      CHECK(lfd >= 0 && st == LOCALCLI_ERR_TOO_LONG && pending == 0,
            "localcli: a request over the 8192-byte line cap is refused before it connects"); }
    { const int lfd = lc_listen(path);
      static char args[AUTHD_LINE_MAX];
      memset(args, 'a', AUTHD_LINE_MAX - 6u); args[AUTHD_LINE_MAX - 6u] = '\0';
      char out[256]; size_t n = 0;
      const localcli_status_t st = localcli_call(path, "PING", args, 300u, out, sizeof out, &n);
      struct pollfd pf = { lfd, POLLIN, 0 };
      const int pending = poll(&pf, 1, 100);
      (void)close(lfd);
      CHECK(strlen("PING ") + strlen(args) + 1u == AUTHD_LINE_MAX,
            "localcli: the at-cap request is exactly 8192 bytes");
      CHECK(lfd >= 0 && st != LOCALCLI_ERR_TOO_LONG && pending == 1,
            "localcli: a request of exactly 8192 bytes is not refused: the client connects to send it"); }

    /* no daemon at all */
    { (void)unlink(path);
      char out[256]; size_t n = 0;
      CHECK(localcli_call(path, "PING", NULL, 1000u, out, sizeof out, &n) == LOCALCLI_ERR_CONNECT,
            "localcli: a socket path with no daemon is cannot-connect"); }
    (void)unlink(path);
}

static void test_key_plan(void)
{
    /* V4-263 (F402): which failed login is the daemon refusing the key. */
    CHECK(client_failure_is_refusal(1, 1000u, 20000u) == 1,
          "refusal: a failure after ClientAuth and before the deadline is the daemon's answer");
    CHECK(client_failure_is_refusal(1, 20000u, 20000u) == 0 && client_failure_is_refusal(1, 20001u, 20000u) == 0,
          "refusal: a wait that ran to the deadline is a daemon that did not answer, not a refusal (F402)");
    CHECK(client_failure_is_refusal(0, 1000u, 20000u) == 0,
          "refusal: a failure before ClientAuth was sent is never one");
    CHECK(client_failure_is_refusal(1, UINT64_MAX, 20000u) == 0,
          "refusal: with a clock that cannot be read nothing is called a refusal");
    CHECK(client_key_plan(1, 0, 0) == KEY_PLAN_USE_EK,
          "key-plan: no .ek.next and .ek works -- use it");
    CHECK(client_key_plan(1, 1, 0) == KEY_PLAN_USE_EK,
          "key-plan: .ek works, so .ek.next was never committed");
    CHECK(client_key_plan(1, 1, 1) == KEY_PLAN_USE_EK,
          "key-plan: .ek works, so .ek.next is stale even if it also opens");
    CHECK(client_key_plan(0, 1, 1) == KEY_PLAN_PROMOTE_NEXT,
          "key-plan: .ek is dead and .ek.next lives -- complete the rename");
    CHECK(client_key_plan(0, 1, 0) == KEY_PLAN_REFUSE,
          "key-plan: an unreadable .ek never causes .ek.next to be deleted");
    CHECK(client_key_plan(0, 0, 0) == KEY_PLAN_REFUSE,
          "key-plan: nothing works and there is nothing to promote -- refuse");
    /* next_ok without next_present is nonsense; it must not promote. */
    CHECK(client_key_plan(0, 0, 1) == KEY_PLAN_REFUSE,
          "key-plan: a missing .ek.next is never promoted");
}

/* ----------------------------------------------- rotation on disk (V4-24c) */

/* The CLI blocks on its socket and the harness daemon is pumped from this
 * thread, so a CLI run is a child process while the parent pumps. Returns the
 * child's exit status, or -1 if it did not exit within 60 s. The child's
 * stdout -- a login code, a path -- goes nowhere; its stderr stays visible. */
/* V4-35: called after every tick, so a test can act on the daemon at a chosen
 * moment of a CLI run -- between two loop turns, which is where nothing on the
 * wire can interleave. */
typedef void (*pump_hook_fn)(h_daemon_t *d, void *ctx);

static int run_client_pumped_hook(h_daemon_t *d, char **argv, pump_hook_fn hook, void *ctx);

static int run_client_pumped(h_daemon_t *d, char **argv)
{
    return run_client_pumped_hook(d, argv, NULL, NULL);
}

/* F298: something for the CHILD to do before it becomes the client -- the
 * one place a test can know the pid the client will run as. */
static void (*g_child_pre)(void);
static char g_stale_base[512];
static void plant_stale_newpub(void)
{
    char p[600];
    /* The name rotate itself builds, inside this test's mkdtemp directory: not
     * a scratch name of the test's own choosing (F114's gate, scratch_dirs). */
    const long me = (long)getpid();
    (void)snprintf(p, sizeof p, "%s.newpub.%ld", g_stale_base, me);
    if (write_file(p, "left by a killed rotation\n", 0600) != 0) { child_exit(124); }
}

/* V4-324: the pumped client's stderr, to a file the test then reads (the
 * client talks to the harness daemon, so it cannot be run by the capturing
 * runner, which does not pump it). */
static char g_child_err_path[600];
static void child_err_to_file(void)
{
    if (freopen(g_child_err_path, "w", stderr) == NULL) { child_exit(123); }
}

static int run_client_pumped_hook(h_daemon_t *d, char **argv, pump_hook_fn hook, void *ctx)
{
    fflush(stdout);
    fflush(stderr);
    const pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL) { child_exit(125); }
        if (g_child_pre != NULL) { g_child_pre(); }
        const int rc = run_cli(authd_cli_client, argv);
        fflush(stderr);
        child_exit(rc & 0xff);
    }
    const time_t start = time(NULL);
    int ws = 0;
    for (;;) {
        h_tick(d);
        if (hook != NULL) { hook(d, ctx); }
        const pid_t r = waitpid(pid, &ws, WNOHANG);
        if (r == pid) { break; }
        if (r < 0 || time(NULL) - start > 60) {
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &ws, 0);
            return -1;
        }
    }
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : -1;
}

static int read_bytes(const char *path, uint8_t *buf, size_t cap, size_t *n);

/* V4-282 (F467): the stale rotation now removes the .ek.next it sealed, so
 * the test keeps a copy of it while it exists to scan that key's windows.
 * Not a race: the file is published (link, complete) before the client
 * connects, and the session cannot be refused until the daemon -- which
 * runs only in this loop's h_tick -- has answered at least once. */
typedef struct { const char *path; uint8_t buf[8192]; size_t n; } next_copy_t;
static void copy_next_hook(h_daemon_t *d, void *ctx)
{
    (void)d;
    next_copy_t *c = (next_copy_t *)ctx;
    size_t n = 0;
    if (c->n == 0u && read_bytes(c->path, c->buf, sizeof c->buf, &n) == 0) { c->n = n; }
}

static int read_bytes(const char *path, uint8_t *buf, size_t cap, size_t *n)
{
    *n = 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return -1; }
    *n = fread(buf, 1u, cap, f);
    const int more = (fgetc(f) != EOF);
    (void)fclose(f);
    return (*n > 0u && !more) ? 0 : -1;
}

static int write_bytes(const char *path, const uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) { return -1; }
    const size_t put = fwrite(buf, 1u, n, f);
    const int closed = fclose(f);
    return (put == n && closed == 0 && chmod(path, 0600) == 0) ? 0 : -1;
}

static int same_bytes(const char *path, const uint8_t *buf, size_t n)
{
    static uint8_t got[8192];
    size_t m = 0;
    return read_bytes(path, got, sizeof got, &m) == 0 && m == n && memcmp(got, buf, n) == 0;
}

/* Does any entry directly under `dir` have `part` in its name? */
static int any_name_contains(const char *dir, const char *part)
{
    DIR *d = opendir(dir);
    if (d == NULL) { return 1; }
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (strstr(e->d_name, part) != NULL) {
            printf("  (left behind: %s/%s)\n", dir, e->d_name);
            found = 1;
        }
    }
    (void)closedir(d);
    return found;
}

/* D10 for the keys keygen does not make. The header scan of authd_e2e.sh is
 * all that ever looked at rotation's files, and it reads only a file's first
 * eight bytes -- a raw secret key carries no magic, so it would pass. Here the
 * CLI's own rotate and login run against the in-process daemon, every key the
 * device ever held is opened from its sealed file, and every file under the
 * device's and the daemon's directories is searched for it: after an
 * acknowledged rotation, after the login that completes an interrupted one,
 * and after a rotation attempted from a key the daemon has superseded. */
/* V4-218, F296: a backup destination longer than the daemon holds is refused
 * by the tool, with the bound, before anything is sent. It used to go out and
 * come back as `refused: malformed`. No daemon is needed: the socket named
 * here does not exist, and the check comes first. */
static void test_backup_path_bound(void)
{
    static char longp[AUTHD_BACKUP_PATH_MAX + 2u], okp[AUTHD_BACKUP_PATH_MAX + 1u], err[1024];
    memset(longp, 'a', sizeof longp - 1u);
    longp[0] = '/';
    longp[sizeof longp - 1u] = '\0';
    memset(okp, 'a', sizeof okp - 1u);
    okp[0] = '/';
    okp[sizeof okp - 1u] = '\0';
    char sock[256];
    (void)snprintf(sock, sizeof sock, "%s/no-such.sock", g_dir);
    int rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", longp, NULL },
                               err, sizeof err);
    CHECK(rc == 2 && strstr(err, "--path is at most 511 bytes") != NULL,
          "backup: a destination of 512 bytes is refused as usage, with the bound named (F296)");
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", okp, NULL },
                           err, sizeof err);
    CHECK(rc == 1 && strstr(err, "at most") == NULL,
          "backup: one of 511 bytes passes the check and fails only at the socket that is not there");
    /* F345: the daemon refuses a path with a byte outside printable ASCII,
     * and answered it `malformed`, naming nothing. */
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/var/backups/caf\xc3\xa9.db", NULL },
                           err, sizeof err);
    const int utf8_ok = (rc == 2 && strstr(err, "--path is printable ASCII only") != NULL);
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/var/backups/a\tb", NULL },
                           err, sizeof err);
    CHECK(utf8_ok && rc == 2 && strstr(err, "--path is printable ASCII only") != NULL,
          "backup: a destination with a byte outside printable ASCII is usage, and says so (F345)");
    /* V4-332 (F624): a destination in /tmp or /var/tmp is the daemon's own
     * under the shipped unit. Said before the request goes out; and not said
     * of a path that only begins alike. */
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/tmp/b.sqlite3", NULL },
                           err, sizeof err);
    const int tmp_said = (rc == 1 && strstr(err, "PrivateTmp") != NULL);
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/var/tmp/b.sqlite3", NULL },
                           err, sizeof err);
    CHECK(tmp_said && rc == 1 && strstr(err, "PrivateTmp") != NULL,
          "backup: a destination under /tmp or /var/tmp is warned of: the daemon's is its own under the shipped unit (F624)");
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/tmpfiles/b.sqlite3", NULL },
                           err, sizeof err);
    const int alike = (strstr(err, "PrivateTmp") == NULL);
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/var/lib/mldsa-authd/backups/b.sqlite3", NULL },
                           err, sizeof err);
    CHECK(alike && rc == 1 && strstr(err, "PrivateTmp") == NULL && strstr(err, "/run is not kept") == NULL,
          "backup: and no other destination is (F624)");
    /* V4-333 (F631): by where the path leads, not how it is spelled. */
    { static const char *const SPELT[] = { "//tmp/b.sqlite3", "/./tmp/b.sqlite3", "/var//tmp/b.sqlite3",
                                           "/var/./tmp/b.sqlite3", "/tmp/../tmp/b.sqlite3", "/var/lib/../tmp/b.sqlite3" };
      int all = 1;
      for (size_t i = 0; i < sizeof SPELT / sizeof SPELT[0]; i++) {
          rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", (char *)SPELT[i], NULL },
                                 err, sizeof err);
          if (rc != 1 || strstr(err, "PrivateTmp") == NULL) { all = 0; printf("  not warned of: %s\n", SPELT[i]); }
      }
      CHECK(all, "backup: /tmp and /var/tmp are warned of however the path is spelled (F631)");
      rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/tmp/../var/lib/mldsa-authd/backups/b", NULL },
                             err, sizeof err);
      CHECK(rc == 1 && strstr(err, "warning") == NULL,
            "backup: and a path that only passes through /tmp is not (F631)"); }
    /* The runtime directory: the one other place the sandboxed daemon can
     * write, removed by systemd at every stop. */
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/run/mldsa-authd/pre-upgrade.sqlite3", NULL },
                           err, sizeof err);
    CHECK(rc == 1 && strstr(err, "/run is not kept") != NULL && strstr(err, "PrivateTmp") == NULL,
          "backup: a destination under /run is warned of: it is removed when the service stops (F631)");
    rc = run_admin_capture((char *[]){ "authd_admin", "backup", "--socket", sock, "--path", "/runs/b.sqlite3", NULL },
                           err, sizeof err);
    CHECK(rc == 1 && strstr(err, "warning") == NULL,
          "backup: and /runs is not /run (F631)");
}

/* V4-245, F352: authd_client options that could not take effect were dropped
 * in silence. --state and --proxy-v2 travel on a WebSocket connection; over
 * the raw listener (--port without --ws) the login went through, exit 0,
 * with a code bound to the empty state. Nothing here reaches a daemon or a
 * key: the arguments are judged first. */
static void test_client_ws_only_options(void)
{
    char err[1024], key[300], pass[300], pub[300], sock[300];
    (void)snprintf(key, sizeof key, "%s/absent.ek", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/absent.pass", g_dir);
    (void)snprintf(pub, sizeof pub, "%s/absent.pub", g_dir);
    (void)snprintf(sock, sizeof sock, "%s/absent.sock", g_dir);
#define CLIENT_LOGIN(...) run_client_capture((char *[]){ "authd_client", "login", "--handle", "d1aa", \
        "--key", key, "--passphrase-file", pass, "--server-id", "authd", "--server-pub", pub, \
        __VA_ARGS__, NULL }, err, sizeof err)
    int rc = CLIENT_LOGIN("--port", "9", "--state", "s1");
    CHECK(rc == 2 && strstr(err, "with --port, add --ws") != NULL,
          "client: --state over the raw listener is usage, not a login bound to the empty state (F352)");
    rc = CLIENT_LOGIN("--port", "9", "--proxy-v2");
    CHECK(rc == 2 && strstr(err, "with --port, add --ws") != NULL,
          "client: --proxy-v2 over the raw listener is usage, not ignored (F352)");
    rc = CLIENT_LOGIN("--port", "9", "--ws", "--state", "a&b");
    const int amp = (rc == 2 && strstr(err, "--state is 1 to 64 printable ASCII characters") != NULL);
    rc = CLIENT_LOGIN("--port", "9", "--ws", "--state", "a b");
    const int space = (rc == 2 && strstr(err, "--state is 1 to 64 printable ASCII characters") != NULL);
    rc = CLIENT_LOGIN("--port", "9", "--ws", "--state", "");
    const int empty = (rc == 2 && strstr(err, "--state is 1 to 64 printable ASCII characters") != NULL);
    char s65[66], s64[65];
    memset(s65, 'z', 65u); s65[65] = '\0';
    memset(s64, 'z', 64u); s64[64] = '\0';
    rc = CLIENT_LOGIN("--unix", sock, "--state", s65);
    CHECK(amp && space && empty && rc == 2 && strstr(err, "--state is 1 to 64 printable ASCII characters") != NULL,
          "client: a --state the daemon would refuse or cut short is usage, with the rule named (F352)");
    /* The controls: the same options where they do apply get past the
     * arguments and fail later, at a file that is not there: not usage (2).
     * Since V4-317 (F551) that is the server's public key, exit 3. */
    rc = CLIENT_LOGIN("--port", "9", "--ws", "--state", s64, "--proxy-v2");
    const int tcp_ok = (rc == 3 && strstr(err, "--state") == NULL);
    rc = CLIENT_LOGIN("--unix", sock, "--state", "s~1", "--proxy-v2");
    const int unix_ok = (rc == 3 && strstr(err, "--state") == NULL);
    /* F550: '%', '+' and '#' are the daemon's to refuse too (F478). */
    int url_chars = 1;
    { static char b0[] = "a%b", b1[] = "a+b", b2[] = "a#b";
      char *const bad[] = { b0, b1, b2 };
      for (size_t b = 0; b < 3u; b++) {
          const int brc = CLIENT_LOGIN("--unix", sock, "--state", bad[b]);
          if (!(brc == 2 && strstr(err, "none of '&', '%', '+', '#'") != NULL)) { url_chars = 0; }
      } }
    CHECK(url_chars, "client: a --state with '%', '+' or '#' is usage, as the daemon refuses it in the URL (F550)");
    rc = CLIENT_LOGIN("--port", "9");
    /* The exact status (review 70): "not 2 and not 0" let anything else by. */
    CHECK(tcp_ok && unix_ok && rc == 3 && strstr(err, "--ws") == NULL,
          "client: with --ws or --unix a 64-byte --state and --proxy-v2 pass the arguments, and a bare --port still does");
#undef CLIENT_LOGIN
}

/* F297: a FIFO where a file is expected. open() without O_NONBLOCK waits for a
 * writer that never comes, so each reader runs in a child with a deadline:
 * the answer is its exit status, or 99 for "still blocked after 3 s". */
static int fifo_child(int which, const char *p)
{
    fflush(stdout);
    fflush(stderr);
    const pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        int out = 0;
        if (which == 0) {
            uint8_t *s = NULL; size_t n = 0;
            out = (int)authd_secret_read(p, &s, &n);
        } else if (which == 1) {
            mldsa_keypair_t kp;
            memset(&kp, 0, sizeof kp);
            out = (int)keyfile_open(p, (const uint8_t *)"h", 1u, "x", 1u, &kp, NULL);
        } else if (which == 2) {
            char to[600];
            (void)snprintf(to, sizeof to, "%s.to", p);
            out = (int)keyfile_promote(p, to);
        } else if (which == 4) {        /* V4-265, F407: a public key, as --server-pub and --pub read one */
            uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
            out = (int)demo_keys_load_public(p, (const uint8_t *)"h", 1u, pk);
        } else if (which == 5) {        /* ...and a plaintext secret key, as migrate-key --in reads one */
            mldsa_keypair_t kp;
            memset(&kp, 0, sizeof kp);
            out = (int)demo_keys_load_identity(p, (const uint8_t *)"h", 1u, &kp);
        } else {
            static authd_config_t cfg;
            size_t line = 0;
            out = (int)authd_config_load(p, &cfg, &line);
        }
        child_exit(out & 0x7f);
    }
    int ws = 0;
    for (int i = 0; i < 300; i++) {
        if (waitpid(pid, &ws, WNOHANG) == pid) {
            return WIFEXITED(ws) ? WEXITSTATUS(ws) : -1;
        }
        usleep(10000);
    }
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, &ws, 0);
    return 99;
}

static void test_fifo_refused(void)
{
    char p[300];
    (void)snprintf(p, sizeof p, "%s/a-fifo", g_dir);
    CHECK(mkfifo(p, 0600) == 0, "fifo: a FIFO with no writer exists");
    CHECK(fifo_child(0, p) == (int)AUTHD_SECRET_ERR_NOT_REGULAR,
          "fifo: a passphrase path that is a FIFO is refused as not-a-regular-file, not waited on (F297)");
    CHECK(fifo_child(1, p) == (int)KEYFILE_ERR_IO,
          "fifo: a sealed-key path that is a FIFO is refused, not waited on (F297)");
    CHECK(fifo_child(2, p) == (int)KEYFILE_ERR_IO,
          "fifo: a key to promote that is a FIFO is refused, not waited on (F297)");
    CHECK(fifo_child(3, p) == (int)AUTHD_CFG_ERR_IO,
          "fifo: a configuration path that is a FIFO is refused, not waited on (F297)");
    CHECK(fifo_child(4, p) == (int)DEMO_KEYS_ERR_IO,
          "fifo: a public-key path that is a FIFO is refused, not waited on (F407)");
    CHECK(fifo_child(5, p) == (int)DEMO_KEYS_ERR_IO,
          "fifo: a plaintext secret-key path that is a FIFO is refused, not waited on (F407)");
    (void)unlink(p);
}

/* F299: a reply that is neither form of spec 8's response. */
static void test_reply_not_protocol(void)
{
    static const char *const bad[] = { "ERR\n", "ERR internal\n", "ERRx code=y\n", "err code=x\n", "\n",
                                       "HTTP/1.1 400 Bad Request\r\n", "OKAY\n" };
    char path[400], err[1024];
    (void)snprintf(path, sizeof path, "%s/np.sock", g_dir);
    int ws = 0, all = 1;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const int lfd = lc_listen(path);
        const pid_t pid = lc_daemon(lfd, bad[i], strlen(bad[i]), 50000);
        const int rc = run_admin_capture((char *[]){ "authd_admin", "enable-user", "--socket", path,
                                                     "--user", "u", NULL }, err, sizeof err);
        (void)waitpid(pid, &ws, 0); (void)close(lfd);
        if (lfd < 0 || rc != 1 || strstr(err, "not one this protocol has") == NULL) {
            printf("  reply %zu: rc %d, stderr: %s\n", i, rc, err);
            all = 0;
        }
    }
    CHECK(all, "reply: a first line that is neither OK nor ERR code= fails the command and says so (F299)");
    { const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, "OK\n", 3u, 50000);
      const int rc = run_admin_capture((char *[]){ "authd_admin", "enable-user", "--socket", path,
                                                   "--user", "u", NULL }, err, sizeof err);
      (void)waitpid(pid, &ws, 0); (void)close(lfd);
      CHECK(lfd >= 0 && rc == 0 && err[0] == '\0', "reply: a bare OK is agreement -- the canary"); }
    { const int lfd = lc_listen(path);
      const pid_t pid = lc_daemon(lfd, "OK count=0\nEND\n", 15u, 50000);
      const int rc = run_admin_capture((char *[]){ "authd_admin", "list-users", "--socket", path, NULL },
                                       err, sizeof err);
      (void)waitpid(pid, &ws, 0); (void)close(lfd);
      CHECK(lfd >= 0 && rc == 0 && err[0] == '\0', "reply: OK followed by a space is agreement too"); }
    CHECK(localcli_reply_ok("OK\n") && localcli_reply_ok("OK a=b\n") && !localcli_reply_ok("OK") &&
          !localcli_reply_ok("") && !localcli_reply_ok(NULL) && !localcli_reply_ok("O"),
          "reply: localcli_reply_ok takes OK then a space or the line's end, and nothing shorter");
    (void)unlink(path);
}

/* F300: the daemon's bounds on --user and --reason, named by the tool. */
static void test_online_bounds(void)
{
    char sock[256], err[1024];
    static char u65[66], u64[65], r257[258], r256[257];
    memset(u65, 'u', 65u); memset(u64, 'u', 64u); memset(r257, 'r', 257u); memset(r256, 'r', 256u);
    (void)snprintf(sock, sizeof sock, "%s/no-such.sock", g_dir);
    static const char *const subs[] = { "enable-user", "list-devices" };
    int all = 1;
    for (size_t i = 0; i < 2u; i++) {
        static const char *bad_users[3];
        bad_users[0] = u65; bad_users[1] = ""; bad_users[2] = "jos\xc3\xa9";
        for (size_t k = 0; k < 3u; k++) {
            const int rc = run_admin_capture((char *[]){ "authd_admin", (char *)subs[i], "--socket", sock,
                                                         "--user", (char *)bad_users[k], NULL }, err, sizeof err);
            if (rc != 2 || strstr(err, "--user is 1 to 64 bytes of printable ASCII") == NULL) {
                printf("  %s user case %zu: rc %d, stderr: %s\n", subs[i], k, rc, err);
                all = 0;
            }
        }
    }
    CHECK(all, "bounds: --user of 65 bytes, of none, or with a byte outside printable ASCII is usage, "
               "with the bound named (F300)");
    /* F344: enroll-operator reads its own arguments, and checked the length
     * alone. Refused before the .pub is opened: the file named here is not
     * there, and is never asked for. */
    int op = 1;
    {
        static const char *bad_users[2];
        bad_users[0] = ""; bad_users[1] = "jos\xc3\xa9";
        for (size_t k = 0; k < 2u; k++) {
            const int rc2 = run_admin_capture((char *[]){ "authd_admin", "enroll-operator", "--socket", sock,
                                                          "--user", (char *)bad_users[k], "--handle", "h1",
                                                          "--pub", "/no/such/h1.pub", NULL }, err, sizeof err);
            if (rc2 != 2 || strstr(err, "--user is 1 to 64 bytes of printable ASCII") == NULL) {
                printf("  enroll-operator user case %zu: rc %d, stderr: %s\n", k, rc2, err);
                op = 0;
            }
        }
    }
    CHECK(op, "bounds: enroll-operator --user of none, or with a byte outside printable ASCII, is usage, "
              "with the bound named (F344)");
    int rc = run_admin_capture((char *[]){ "authd_admin", "enable-user", "--socket", sock, "--user", u64, NULL },
                               err, sizeof err);
    CHECK(rc == 1 && strstr(err, "--user is") == NULL,
          "bounds: --user of 64 bytes passes and fails only at the socket that is not there");
    rc = run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", sock, "--user", "u",
                                       "--reason", r257, NULL }, err, sizeof err);
    const int long_ok = (rc == 2 && strstr(err, "--reason is 1 to 256 bytes") != NULL);
    rc = run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", sock, "--user", "u",
                                       "--reason", "", NULL }, err, sizeof err);
    CHECK(long_ok && rc == 2 && strstr(err, "--reason is 1 to 256 bytes") != NULL,
          "bounds: --reason of 257 bytes or of none is usage, with the bound named (F300)");
    rc = run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", sock, "--user", "u",
                                       "--reason", r256, NULL }, err, sizeof err);
    CHECK(rc == 1 && strstr(err, "--reason is") == NULL,
          "bounds: --reason of 256 bytes passes and fails only at the socket that is not there");
}

static void test_rotate_on_disk(void)
{
    static const uint8_t RU[] = { 'r', 'u' };
    static const char PASS[] = "rotation passphrase";
    char root[256], dev[288], dd[288], pass[256], spub[320];
    (void)snprintf(root, sizeof root, "%s/rot", g_dir);
    (void)snprintf(dev, sizeof dev, "%s/dev", root);
    (void)snprintf(dd, sizeof dd, "%s/d", root);
    (void)snprintf(pass, sizeof pass, "%s/rotpass", g_dir);
    (void)snprintf(spub, sizeof spub, "%s/server.pub", dd);
    CHECK(mkdir(root, 0700) == 0 && mkdir(dd, 0700) == 0 &&
          write_file(pass, "rotation passphrase\n", 0600) == 0, "rotate: fixture directories and passphrase");

    CHECK(RUN_CLIENT("keygen", "--dir", dev, "--passphrase-file", pass) == 0,
          "rotate: the device's first key is generated");
    char handle[64] = { 0 };
    DIR *dh = opendir(dev);
    if (dh != NULL) {
        struct dirent *e;
        while ((e = readdir(dh)) != NULL) {
            const size_t n = strlen(e->d_name);
            if (n > 3u && strcmp(e->d_name + n - 3u, ".ek") == 0) {
                (void)snprintf(handle, sizeof handle, "%.*s", (int)(n - 3u), e->d_name);
            }
        }
        (void)closedir(dh);
    }
    const size_t hlen = strlen(handle);
    char ek[400], next[408], pubp[400];
    (void)snprintf(ek, sizeof ek, "%s/%s.ek", dev, handle);
    (void)snprintf(next, sizeof next, "%s.next", ek);
    (void)snprintf(pubp, sizeof pubp, "%s/%s.pub", dev, handle);

    mldsa_keypair_t a, b, c;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    memset(&c, 0, sizeof c);
    CHECK(hlen == 34u && keyfile_open(ek, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &a, NULL)
              == KEYFILE_OK, "rotate: the first key opens");

    h_daemon_t d;
    CHECK(h_start(&d, dd, "rot.sqlite3", 0) == 0, "rotate: the daemon starts");
    (void)store_add_user(d.store, RU, sizeof RU, STORE_ROLE_USER);
    CHECK(a.public_key != NULL &&
          store_enroll_device(d.store, (const uint8_t *)handle, hlen, RU, sizeof RU, a.public_key,
                              "site", "test", NULL, 0) == STORE_OK, "rotate: the device is enrolled");
    CHECK(demo_keys_write_public(spub, H_SERVER_ID, sizeof H_SERVER_ID, d.server_kp.public_key)
              == DEMO_KEYS_OK, "rotate: the daemon's public key is pinned");
    char port[8];
    (void)snprintf(port, sizeof port, "%u", (unsigned)d.port);

    static uint8_t sealed_a[8192], sealed_b[8192];
    size_t na = 0, nb = 0;
    CHECK(read_bytes(ek, sealed_a, sizeof sealed_a, &na) == 0, "rotate: the first sealed key is saved");

    /* 1. An acknowledged rotation: A -> B. F298: it runs with the temp file
     * of a rotation that was killed under the SAME pid already in place. */
    (void)snprintf(g_stale_base, sizeof g_stale_base, "%s", next);
    g_child_pre = plant_stale_newpub;
    int rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                               "--passphrase-file", pass, "--server-id", "authd",
                                               "--server-pub", spub, "--port", port, NULL });
    g_child_pre = NULL;
    { int left = 0;
      DIR *dl = opendir(dev);
      if (dl != NULL) {
          struct dirent *e;
          while ((e = readdir(dl)) != NULL) {
              if (strstr(e->d_name, ".newpub.") != NULL) { left++; }
          }
          (void)closedir(dl);
      }
      CHECK(rc == 0 && left == 0,
            "rotate: a temp file left by a killed rotation with this pid does not stop the next one, "
            "and none is left (F298)"); }
    uint8_t pub_pk[MLDSA_PUBLIC_KEY_BYTES];
    const int b_ok = keyfile_open(ek, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &b, NULL)
                     == KEYFILE_OK;
    CHECK(rc == 0 && b_ok && a.public_key != NULL &&
          memcmp(b.public_key, a.public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 &&
          demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, pub_pk) == DEMO_KEYS_OK &&
          memcmp(pub_pk, b.public_key, sizeof pub_pk) == 0 && access(next, F_OK) != 0,
          "rotate: the daemon acknowledged; .ek and .pub now name a new key, and no .ek.next is left");
    CHECK(a.secret_key != NULL && b_ok &&
          !any_file_has_key_window(root, a.secret_key, NULL) &&
          !any_file_has_key_window(root, b.secret_key, NULL),
          "rotate: no window of the old or the new secret key in any file under the device's or the daemon's directory (Req 10)");
    {
        char canary[320];
        (void)snprintf(canary, sizeof canary, "%s/canary.raw", dev);
        CHECK(b_ok && write_bytes(canary, b.secret_key, MLDSA_SECRET_KEY_BYTES) == 0 &&
                  any_file_has_key_window(root, b.secret_key, NULL),
              "rotate: a raw copy of the new key, planted beside it, IS found (the canary)");
        (void)unlink(canary);
    }
    /* V4-217, F293: a --key path so long that "<key>.next" does not fit.
     * The name was built with an unchecked snprintf; at PATH_MAX - 1 bytes it
     * came out EQUAL to the key's own path, the "leftover .ek.next" was the
     * live key, and rotate deleted it. The same file through a path padded
     * with "/." segments: the rotation is refused and the key stays. */
    {
        static char longp[PATH_MAX + 8];
        /* The resolved directory: on macOS /tmp is a link, and the kernel
         * counts the name it expands to against the same limit. */
        static char realdev[PATH_MAX];
        if (realpath(dev, realdev) == NULL) { (void)snprintf(realdev, sizeof realdev, "%s", dev); }
        size_t at = (size_t)snprintf(longp, sizeof longp, "%s", realdev);
        const size_t tail = 1u + hlen + 3u;            /* "/<handle>.ek" */
        const size_t want = (size_t)PATH_MAX - 1u;
        if ((want - tail - at) % 2u != 0u) { longp[at++] = '/'; }
        while (at + tail < want) { longp[at++] = '/'; longp[at++] = '.'; }
        (void)snprintf(longp + at, sizeof longp - at, "/%s.ek", handle);
        static uint8_t before[8192], after[8192];
        size_t n0 = 0, n1 = 0;
        const int have = read_bytes(ek, before, sizeof before, &n0) == 0;
        const int named = strlen(longp) == want && access(longp, F_OK) == 0;
        rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", longp,
                                               "--passphrase-file", pass, "--server-id", "authd",
                                               "--server-pub", spub, "--port", port, NULL });
        CHECK(named,
              "long path: the padded path is PATH_MAX - 1 bytes and names the key");
        /* An exact status, the refusal (V4-270, F427): `rc != 0` was also
         * met by -1, which the runner returns for a client that crashed or
         * was killed after 60 seconds, and the key file is untouched then
         * too. 3 since V4-318 (F558): a --key whose names do not fit is a
         * path that cannot be used; it was 1. */
        CHECK(have && rc == 3 && read_bytes(ek, after, sizeof after, &n1) == 0 && n1 == n0 &&
              memcmp(before, after, n0) == 0,
              "long path: a rotation whose .ek.next name does not fit is refused and the key file is untouched (F293)");
    }

    CHECK(read_bytes(ek, sealed_b, sizeof sealed_b, &nb) == 0, "rotate: the new sealed key is saved");

    /* 2. The rename was interrupted: .ek is still A, the daemon holds B, and
     *    .ek.next is B. The next login must complete it (PROMOTE_NEXT). */
    CHECK(write_bytes(ek, sealed_a, na) == 0 && write_bytes(next, sealed_b, nb) == 0,
          "interrupted rotation: .ek is the superseded key and .ek.next the live one");
    rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                           "--passphrase-file", pass, "--server-id", "authd",
                                           "--server-pub", spub, "--port", port, NULL });
    CHECK(rc == 0 && access(next, F_OK) != 0 && same_bytes(ek, sealed_b, nb),
          "interrupted rotation: the next login completes it -- .ek.next is gone and .ek holds the new key");
    CHECK(a.secret_key != NULL && b_ok &&
          !any_file_has_key_window(root, a.secret_key, NULL) &&
          !any_file_has_key_window(root, b.secret_key, NULL),
          "interrupted rotation: after the login that completes it, no window of either key in any file (Req 10)");

    /* 3. A device that still holds the superseded key tries to rotate: the new
     *    key C is sealed to .ek.next first (spec 10.2) and the daemon refuses
     *    A. No ROTATE can have been sent on a session that never opened, so
     *    .ek.next is REMOVED (V4-282, F467, erratum 126); it used to be kept.
     *    A copy taken while it existed is scanned with the other two. */
    CHECK(write_bytes(ek, sealed_a, na) == 0, "stale rotate: .ek is the superseded key again");
    static next_copy_t seen;
    memset(&seen, 0, sizeof seen);
    seen.path = next;
    rc = run_client_pumped_hook(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                                "--passphrase-file", pass, "--server-id", "authd",
                                                "--server-pub", spub, "--port", port, NULL },
                                copy_next_hook, &seen);
    CHECK(rc != 0 && rc != -1 && access(next, F_OK) != 0 && same_bytes(ek, sealed_a, na),
          "stale rotate: the session is refused, .ek is as it was and no .ek.next is left (F467)");
    char seen_path[512];
    (void)snprintf(seen_path, sizeof seen_path, "%s/stale-next-copy", g_dir);
    const int c_ok = seen.n > 0u && write_bytes(seen_path, seen.buf, seen.n) == 0 &&
                     keyfile_open(seen_path, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &c, NULL)
                     == KEYFILE_OK;
    (void)unlink(seen_path);
    CHECK(c_ok && a.public_key != NULL && b_ok &&
          memcmp(c.public_key, a.public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 &&
          memcmp(c.public_key, b.public_key, MLDSA_PUBLIC_KEY_BYTES) != 0,
          "stale rotate: the key it staged, copied while it existed, is a third key, sealed (not vacuous)");
    CHECK(a.secret_key != NULL && b_ok && c_ok &&
          !any_file_has_key_window(root, a.secret_key, NULL) &&
          !any_file_has_key_window(root, b.secret_key, NULL) &&
          !any_file_has_key_window(root, c.secret_key, NULL),
          "stale rotate: no window of any of the three keys in any file (Req 10)");
    CHECK(!any_name_contains(dev, ".newpub."), "stale rotate: no .newpub temp file is left behind (F118)");

    /* V4-273 (F438): a rotation that reaches no daemon at all writes its
     * .ek.next and then cannot send ROTATE; that file cannot be live, and is
     * not kept. (Since V4-282 neither is the stale leg's, refused after
     * ClientAuth, F467.) */
    { (void)unlink(next);
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", "1", NULL });
      CHECK(rc == 1 && access(next, F_OK) != 0 && same_bytes(ek, sealed_a, na),
            "no daemon: a rotation that reaches no daemon fails, keeps .ek as it was and leaves no .ek.next (F438)"); }

    /* V4-282 (F466): the login that completes an interrupted rotation
     * replaces the .pub BEFORE it promotes the key, as rotate does (erratum
     * 119). Here the promote is made to fail -- .ek is a directory, so the
     * rename over it is refused -- after the probe has proved .ek.next (B)
     * live. The .pub, set to name the old key A, must already name B, and
     * .ek.next must still be there for the next run, which completes it. */
    { uint8_t got[MLDSA_PUBLIC_KEY_BYTES];
      (void)unlink(pubp);
      (void)unlink(ek);
      CHECK(a.public_key != NULL && b_ok &&
            demo_keys_write_public(pubp, (const uint8_t *)handle, hlen, a.public_key) == DEMO_KEYS_OK &&
            write_bytes(next, sealed_b, nb) == 0 && mkdir(ek, 0700) == 0,
            "promote order: .pub names the old key, .ek.next the live one, and .ek is a directory (F466)");
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      CHECK(rc == 1 && access(next, F_OK) == 0 &&
            demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, got) == DEMO_KEYS_OK &&
            memcmp(got, b.public_key, sizeof got) == 0,
            "promote order: a promote that fails leaves .ek.next, and the .pub already names the live key (F466)");
      (void)rmdir(ek);
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      CHECK(rc == 0 && access(next, F_OK) != 0 && same_bytes(ek, sealed_b, nb) &&
            demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, got) == DEMO_KEYS_OK &&
            memcmp(got, b.public_key, sizeof got) == 0,
            "promote order: the next login completes it -- .ek holds the live key and .pub names it (F466)"); }

    /* V4-323 (F583): a .pub that cannot be replaced stops the promotion. The
     * key was promoted all the same, .ek.next was gone, and nothing ever
     * published the .pub again: the file an administrator enrols from named
     * a dead key for good, and `rotate` exited 0. Here the .pub is a
     * directory with a file in it, which a rename cannot replace.
     *
     * The login that finds .ek.next live: it logs in with that key, and
     * leaves .ek and .ek.next as they are for the next run. */
    { char inside[600];
      uint8_t got[MLDSA_PUBLIC_KEY_BYTES];
      /* The harness's clock stands still, so the tombstone of every
       * handshake this function has had ACCEPTED is still in the daemon's
       * ledger, which holds one a slot (a refused one is cancelled when its
       * connection closes; review 75 corrected this comment). Six came
       * before; each login here adds two, the accepted probe and the login.
       * The clock is moved past the ledger's ten seconds before each leg. */
#define PUB_BLOCKED_FRESH_LEDGER() do { d.app.now_ms += 20000u; h_tick(&d); } while (0)
      PUB_BLOCKED_FRESH_LEDGER();
      (void)snprintf(inside, sizeof inside, "%s/x", pubp);
      (void)unlink(pubp);
      CHECK(write_bytes(ek, sealed_a, na) == 0 && write_bytes(next, sealed_b, nb) == 0 &&
            mkdir(pubp, 0700) == 0 && write_bytes(inside, (const uint8_t *)"x", 1u) == 0,
            "pub blocked: .ek is the superseded key, .ek.next the live one, and .pub cannot be replaced (F583)");
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      CHECK(rc == 0 && same_bytes(next, sealed_b, nb) && same_bytes(ek, sealed_a, na),
            "pub blocked: the login succeeds with the live key and promotes nothing: .ek.next is kept (F583)");
      /* V4-324 (F591): and a rotation in that state stops before it makes
       * anything. It used to seal a new key and fail at the name .ek.next
       * with `already-exists`, on the file that holds the live key. */
      PUB_BLOCKED_FRESH_LEDGER();
      { uint8_t rerr[4096];
        size_t rn = 0;
        memset(rerr, 0, sizeof rerr);
        (void)snprintf(g_child_err_path, sizeof g_child_err_path, "%s/rotate-kept.err", g_dir);
        g_child_pre = child_err_to_file;
        rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                               "--passphrase-file", pass, "--server-id", "authd",
                                               "--server-pub", spub, "--port", port, NULL });
        g_child_pre = NULL;
        (void)read_bytes(g_child_err_path, rerr, sizeof rerr - 1u, &rn);
        (void)unlink(g_child_err_path);
        CHECK(rc == 1 && same_bytes(next, sealed_b, nb) && same_bytes(ek, sealed_a, na) &&
              strstr((const char *)rerr, "not rotating") != NULL &&
              strstr((const char *)rerr, "holds the LIVE key") != NULL &&
              strstr((const char *)rerr, "already-exists") == NULL,
              "pub blocked: a rotation while .ek.next holds the live key stops, says so and changes neither file (F591)"); }
      (void)unlink(inside);
      (void)rmdir(pubp);
      PUB_BLOCKED_FRESH_LEDGER();
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      CHECK(rc == 0 && access(next, F_OK) != 0 && same_bytes(ek, sealed_b, nb) &&
            demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, got) == DEMO_KEYS_OK &&
            memcmp(got, b.public_key, sizeof got) == 0,
            "pub blocked: with the .pub replaceable again the next login completes it (the canary)");
      PUB_BLOCKED_FRESH_LEDGER();

      /* rotate, with the same obstacle. The daemon takes the new key; the
       * run fails, and the new key stays in .ek.next for the next login. */
      CHECK(unlink(pubp) == 0 && mkdir(pubp, 0700) == 0 && write_bytes(inside, (const uint8_t *)"x", 1u) == 0,
            "pub blocked: the .pub cannot be replaced again");
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      CHECK(rc == 1 && access(next, F_OK) == 0 && same_bytes(ek, sealed_b, nb),
            "pub blocked: a rotation whose .pub cannot be replaced fails, promotes nothing and keeps .ek.next (F583)");
      (void)unlink(inside);
      (void)rmdir(pubp);
      PUB_BLOCKED_FRESH_LEDGER();
      rc = run_client_pumped(&d, (char *[]){ "authd_client", "login", "--handle", handle, "--key", ek,
                                             "--passphrase-file", pass, "--server-id", "authd",
                                             "--server-pub", spub, "--port", port, NULL });
      /* Review 75: the .pub must name the key that is IN .ek, not merely
       * some key that is not B. */
      mldsa_keypair_t now_kp;
      memset(&now_kp, 0, sizeof now_kp);
      const int opened = keyfile_open(ek, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &now_kp, NULL) == KEYFILE_OK;
      CHECK(rc == 0 && access(next, F_OK) != 0 && !same_bytes(ek, sealed_b, nb) && opened &&
            demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, got) == DEMO_KEYS_OK &&
            memcmp(got, b.public_key, sizeof got) != 0 &&
            memcmp(got, now_kp.public_key, sizeof got) == 0,
            "pub blocked: the next login completes that rotation -- .ek holds the new key and .pub names it (F583)");
      mldsa_keypair_free(&now_kp);
      /* V4-326 (review 76): the other side of F591's stop. A rotation that
       * finds .ek.next live and CAN promote it does so and then rotates; a
       * stop that fired whenever .ek.next was promoted, blocked or not,
       * passed every check above. .ek.next is given the live key and .ek
       * the superseded one, with nothing in the way. */
      { static uint8_t live[16384];
        size_t ln = 0;
        PUB_BLOCKED_FRESH_LEDGER();
        CHECK(read_bytes(ek, live, sizeof live, &ln) == 0 && ln > 0u && write_bytes(next, live, ln) == 0 &&
              write_bytes(ek, sealed_a, na) == 0,
              "promotable: .ek.next holds the live key, .ek the superseded one, and the .pub can be replaced");
        rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                               "--passphrase-file", pass, "--server-id", "authd",
                                               "--server-pub", spub, "--port", port, NULL });
        /* Review 77: and the .pub names the key that is now in .ek. */
        mldsa_keypair_t after_kp;
        memset(&after_kp, 0, sizeof after_kp);
        const int o2 = keyfile_open(ek, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &after_kp, NULL) == KEYFILE_OK;
        CHECK(rc == 0 && access(next, F_OK) != 0 && !same_bytes(ek, live, ln) && !same_bytes(ek, sealed_a, na) && o2 &&
              demo_keys_load_public(pubp, (const uint8_t *)handle, hlen, got) == DEMO_KEYS_OK &&
              memcmp(got, after_kp.public_key, sizeof got) == 0,
              "promotable: a rotation that can complete the earlier one does, and then rotates to a new key (F591)");
        mldsa_keypair_free(&after_kp); }
#undef PUB_BLOCKED_FRESH_LEDGER
    }

    mldsa_keypair_free(&a);
    mldsa_keypair_free(&b);
    mldsa_keypair_free(&c);
    h_stop(&d);
}

/* --------------------------- V4-282 (F465): a CRLF passphrase file at keygen */

static void test_keygen_crlf(void)
{
    char dir[256], pass[256], err[2048];
    (void)snprintf(dir, sizeof dir, "%s/crlf", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/crlfpass", g_dir);
    CHECK(write_file(pass, "device passphrase words\r\n", 0600) == 0, "crlf: a passphrase file with a CRLF ending");
    const int rc = run_client_capture((char *[]){ "authd_client", "keygen", "--dir", dir,
                                                  "--passphrase-file", pass, NULL }, err, sizeof err);
    CHECK(rc == 3 && strstr(err, "passphrase-ends-in-cr") != NULL && !any_name_contains(dir, ".ek"),
          "crlf: keygen refuses a NEW passphrase ending in a carriage return, by name, and writes no key (F465)");
    CHECK(write_file(pass, "device passphrase words\n", 0600) == 0 &&
          RUN_CLIENT("keygen", "--dir", dir, "--passphrase-file", pass) == 0 && any_name_contains(dir, ".ek"),
          "crlf: the same words with a plain newline make a key (the control)");
}

/* --------------------------- a rotation whose reply is refused or lost (V4-35) */

/* CLAIMS D10 said "a CLI rotation whose session opens but whose reply is lost
 * or refused is not scanned". cmd_client_rotate has two answers to that after
 * ROTATE is SENT -- "the daemon refused" and "no reply" -- and keeps .ek.next,
 * sealed, on both, "so the next run can resolve it". These are those two runs,
 * against the in-process daemon, each followed by the same scan as the others:
 * every key the device held, in any file. */
enum { ROT_REFUSE = 1, ROT_LOSE = 2 };
typedef struct {
    int mode, fired;
    const uint8_t *handle;
    size_t hlen;
    uint8_t old_pk[MLDSA_PUBLIC_KEY_BYTES];   /* the key the CLI's session opens with */
    uint8_t other_pk[MLDSA_PUBLIC_KEY_BYTES]; /* ROT_REFUSE: rotated to behind the session's back */
    size_t closed;
} rot_hook_t;

static void rot_hook(h_daemon_t *d, void *vctx)
{
    rot_hook_t *h = (rot_hook_t *)vctx;
    if (h->fired) { return; }
    if (h->mode == ROT_REFUSE) {
        /* The session is open and its login code queued: rotate the store's key
         * now, before ROTATE can arrive. The daemon's own store_rotate_key then
         * finds its pk_old no longer active and refuses -- a real refusal, on
         * the wire, for a session that did open. */
        for (size_t i = 0; i < d->nslots; i++) {
            const authd_conn_t *c = &d->conns[i];
            if (c->stage == CONN_STAGE_SERVING && c->handle_len == h->hlen &&
                memcmp(c->handle, h->handle, h->hlen) == 0) {
                static const uint8_t hsid[16] = { 0 };
                int64_t at = 0;
                size_t dropped = 0;
                if (store_rotate_key(d->store, h->handle, h->hlen, h->other_pk, h->old_pk, hsid, sizeof hsid,
                                     0, d->app.now_unix, &at, &dropped) == STORE_OK) {
                    h->fired = 1;
                }
                return;
            }
        }
    } else {
        /* The daemon committed (the handle's active key moved) and queued its
         * ACK in the same turn; the ACK goes out on a LATER turn's POLLOUT.
         * Closing the session now loses it, as a crash or a dropped link would. */
        uint8_t now_pk[MLDSA_PUBLIC_KEY_BYTES];
        if (store_lookup_active(d->store, h->handle, h->hlen, now_pk, NULL, 0, NULL, NULL) == STORE_OK &&
            memcmp(now_pk, h->old_pk, sizeof now_pk) != 0) {
            h->closed = authd_app_close_handle(&d->app, h->handle, h->hlen);
            h->fired = 1;
        }
    }
}

static void test_rotate_reply_refused_or_lost(void)
{
    static const uint8_t RU[] = { 'r', 'l' };
    static const char PASS[] = "rotation passphrase";
    char root[256], dd[288], pass[256], spub[320], port[8];
    (void)snprintf(root, sizeof root, "%s/rotrl", g_dir);
    (void)snprintf(dd, sizeof dd, "%s/d", root);
    (void)snprintf(pass, sizeof pass, "%s/rotrlpass", g_dir);
    (void)snprintf(spub, sizeof spub, "%s/server.pub", dd);
    CHECK(mkdir(root, 0700) == 0 && mkdir(dd, 0700) == 0 &&
          write_file(pass, "rotation passphrase\n", 0600) == 0, "rotate-reply: fixture directories and passphrase");
    h_daemon_t d;
    CHECK(h_start(&d, dd, "rotrl.sqlite3", 0) == 0, "rotate-reply: the daemon starts");
    (void)store_add_user(d.store, RU, sizeof RU, STORE_ROLE_USER);
    CHECK(demo_keys_write_public(spub, H_SERVER_ID, sizeof H_SERVER_ID, d.server_kp.public_key) == DEMO_KEYS_OK,
          "rotate-reply: the daemon's public key is pinned");
    (void)snprintf(port, sizeof port, "%u", (unsigned)d.port);

    for (int mode = ROT_REFUSE; mode <= ROT_LOSE; mode++) {
        const char *what = (mode == ROT_REFUSE) ? "refused" : "lost";
        char dev[320];
        (void)snprintf(dev, sizeof dev, "%s/dev-%s", root, what);
        CHECK(RUN_CLIENT("keygen", "--dir", dev, "--passphrase-file", pass) == 0,
              mode == ROT_REFUSE ? "rotate-reply: a device for the refused case" : "rotate-reply: a device for the lost case");
        char handle[64] = { 0 };
        DIR *dh = opendir(dev);
        if (dh != NULL) {
            struct dirent *e;
            while ((e = readdir(dh)) != NULL) {
                const size_t n = strlen(e->d_name);
                if (n > 3u && strcmp(e->d_name + n - 3u, ".ek") == 0) {
                    (void)snprintf(handle, sizeof handle, "%.*s", (int)(n - 3u), e->d_name);
                }
            }
            (void)closedir(dh);
        }
        const size_t hlen = strlen(handle);
        char ek[400], next[408];
        (void)snprintf(ek, sizeof ek, "%s/%s.ek", dev, handle);
        (void)snprintf(next, sizeof next, "%s.next", ek);
        mldsa_keypair_t a, n, other;
        memset(&a, 0, sizeof a);
        memset(&n, 0, sizeof n);
        memset(&other, 0, sizeof other);
        const int a_ok = hlen == 34u &&
            keyfile_open(ek, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &a, NULL) == KEYFILE_OK;
        CHECK(a_ok && store_enroll_device(d.store, (const uint8_t *)handle, hlen, RU, sizeof RU, a.public_key,
                                          "site", "test", NULL, 0) == STORE_OK &&
              mldsa_keypair_generate(&other) == 0,
              mode == ROT_REFUSE ? "rotate-reply: the refused case's device is enrolled" : "rotate-reply: the lost case's device is enrolled");
        static uint8_t sealed_a[8192];
        size_t na = 0;
        (void)read_bytes(ek, sealed_a, sizeof sealed_a, &na);

        rot_hook_t hk;
        memset(&hk, 0, sizeof hk);
        hk.mode = mode;
        hk.handle = (const uint8_t *)handle;
        hk.hlen = hlen;
        if (a_ok) { memcpy(hk.old_pk, a.public_key, sizeof hk.old_pk); }
        if (other.secret_key != NULL) { memcpy(hk.other_pk, other.public_key, sizeof hk.other_pk); }
        const int rc = run_client_pumped_hook(&d, (char *[]){ "authd_client", "rotate", "--handle", handle,
                                                              "--key", ek, "--passphrase-file", pass,
                                                              "--server-id", "authd", "--server-pub", spub,
                                                              "--port", port, NULL }, rot_hook, &hk);
        const int n_ok = keyfile_open(next, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &n, NULL)
                         == KEYFILE_OK;
        uint8_t now_pk[MLDSA_PUBLIC_KEY_BYTES];
        const int looked = store_lookup_active(d.store, (const uint8_t *)handle, hlen, now_pk, NULL, 0, NULL, NULL)
                           == STORE_OK;
        if (mode == ROT_REFUSE) {
            /* The canary that this IS the refused path: the store moved to the
             * key the test chose, never to the one the CLI sealed. */
            CHECK(hk.fired && rc != 0 && rc != -1 && n_ok && looked && same_bytes(ek, sealed_a, na) &&
                      memcmp(now_pk, other.public_key, sizeof now_pk) == 0 &&
                      memcmp(n.public_key, now_pk, sizeof now_pk) != 0,
                  "rotate refused: the session opened, the daemon refused ROTATE, .ek is unchanged and .ek.next kept, sealed");
            CHECK(a_ok && n_ok && !any_file_has_key_window(root, a.secret_key, NULL) &&
                      !any_file_has_key_window(root, n.secret_key, NULL),
                  "rotate refused: no window of the old or the new secret key in any file (Req 10)");
        } else {
            /* The canary that this IS the lost path: the daemon committed the
             * key the CLI sealed, and the session was closed before its ACK. */
            CHECK(hk.fired && hk.closed >= 1u && rc != 0 && rc != -1 && n_ok && looked &&
                      same_bytes(ek, sealed_a, na) && memcmp(now_pk, n.public_key, sizeof now_pk) == 0,
                  "rotate lost: the daemon committed, the ACK never arrived, .ek is unchanged and .ek.next kept, sealed");
            CHECK(a_ok && n_ok && !any_file_has_key_window(root, a.secret_key, NULL) &&
                      !any_file_has_key_window(root, n.secret_key, NULL),
                  "rotate lost: no window of the old or the new secret key in any file (Req 10)");
        }
        mldsa_keypair_free(&a);
        mldsa_keypair_free(&n);
        mldsa_keypair_free(&other);
    }
    h_stop(&d);
}

/* V4-48: the passphrase file's custody. authd_secret_read is how the daemon
 * and both CLIs read a passphrase, and V4-40/44's coverage found that only its
 * mode refusal had ever run. Each case below needs its own status AND no
 * buffer back; the canaries are a file of exactly AUTHD_PASSPHRASE_MAX bytes
 * and the one-trailing-newline rule. The owner refusal needs a file another
 * user owns that the reader can still open -- only root can arrange that, so
 * it is authd_e2e's privileged Linux leg. */
static int pc_write(const char *path, const void *b, size_t n, mode_t mode)
{
    (void)unlink(path);
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { return -1; }
    const int ok = (n == 0u || write(fd, b, n) == (ssize_t)n) && fchmod(fd, mode) == 0;
    (void)close(fd);
    return ok ? 0 : -1;
}

static int refused_as(const char *path, authd_secret_status_t want)
{
    uint8_t *p = (uint8_t *)1;      /* must come back NULL */
    size_t n = 99u;
    const authd_secret_status_t st = authd_secret_read(path, &p, &n);
    if (st == AUTHD_SECRET_OK) { authd_secret_free(p, n); }
    return st == want && p == NULL && n == 0u;
}

static void test_passphrase_custody(void)
{
    char d[256], f[300], lnk[300], big[300], nl[300];
    (void)snprintf(d, sizeof d, "%s/pc", g_dir);
    CHECK(mkdir(d, 0700) == 0, "passphrase custody: a scratch directory");
    (void)snprintf(f, sizeof f, "%s/pass", d);
    (void)snprintf(lnk, sizeof lnk, "%s/pass.lnk", d);
    (void)snprintf(big, sizeof big, "%s/big", d);
    (void)snprintf(nl, sizeof nl, "%s/nl", d);

    CHECK(pc_write(f, "correct horse\n", 14u, 0600) == 0 && symlink(f, lnk) == 0,
          "passphrase custody: a 0600 passphrase file and a symlink to it");
    { uint8_t *p = NULL; size_t n = 0;
      CHECK(authd_secret_read(f, &p, &n) == AUTHD_SECRET_OK && n == 13u && p != NULL && memcmp(p, "correct horse", 13u) == 0,
            "passphrase custody: the 0600 file reads back without its one trailing newline -- the canary");
      authd_secret_free(p, n); }
    CHECK(refused_as(lnk, AUTHD_SECRET_ERR_OPEN),
          "passphrase custody: a symlink to a good passphrase file is refused (O_NOFOLLOW)");
    { char missing[320]; (void)snprintf(missing, sizeof missing, "%s/absent", d);
      CHECK(refused_as(missing, AUTHD_SECRET_ERR_OPEN), "passphrase custody: a missing file is refused as cannot-open"); }
    CHECK(refused_as(d, AUTHD_SECRET_ERR_NOT_REGULAR),
          "passphrase custody: a directory is refused as not-a-regular-file");
    { const mode_t bad[] = {0640, 0620, 0610, 0604, 0602, 0601};
      int all = 1;
      for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
          if (chmod(f, bad[i]) != 0 || !refused_as(f, AUTHD_SECRET_ERR_PERMISSIONS)) { all = 0; }
      }
      (void)chmod(f, 0600);
      CHECK(all, "passphrase custody: a file with any one group or other bit set is refused as unsafe-permissions"); }
    CHECK(pc_write(f, "", 0u, 0600) == 0 && refused_as(f, AUTHD_SECRET_ERR_SIZE),
          "passphrase custody: an empty file is refused as empty-or-too-large");
    CHECK(pc_write(nl, "\n", 1u, 0600) == 0 && refused_as(nl, AUTHD_SECRET_ERR_SIZE),
          "passphrase custody: a file holding only a newline is refused as empty");
    /* F337: the probe --check-config uses answers what the read would, on
     * every file above, without reading. The one stated difference is a file
     * holding only a newline: its size is in range, and only the read sees
     * that nothing is left of it. */
    { char missing[320]; (void)snprintf(missing, sizeof missing, "%s/absent", d);
      int all = (pc_write(f, "correct horse\n", 14u, 0600) == 0);
      all = all && authd_secret_probe(f) == AUTHD_SECRET_OK;
      all = all && authd_secret_probe(lnk) == AUTHD_SECRET_ERR_OPEN;
      all = all && authd_secret_probe(missing) == AUTHD_SECRET_ERR_OPEN;
      all = all && authd_secret_probe(d) == AUTHD_SECRET_ERR_NOT_REGULAR;
      const mode_t bad[] = {0640, 0620, 0610, 0604, 0602, 0601};
      for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
          if (chmod(f, bad[i]) != 0 || authd_secret_probe(f) != AUTHD_SECRET_ERR_PERMISSIONS) { all = 0; }
      }
      (void)chmod(f, 0600);
      CHECK(all, "passphrase probe: the good file, a symlink, a missing file, a directory and each unsafe mode are answered as the read answers them");
      CHECK(pc_write(f, "", 0u, 0600) == 0 && authd_secret_probe(f) == AUTHD_SECRET_ERR_SIZE,
            "passphrase probe: an empty file is refused as empty-or-too-large");
      CHECK(authd_secret_probe(nl) == AUTHD_SECRET_ERR_SIZE && refused_as(nl, AUTHD_SECRET_ERR_SIZE),
            "passphrase probe: a file holding only a newline is refused by the probe as the read refuses it (F400)");
      CHECK(pc_write(f, "x", 1u, 0600) == 0 && authd_secret_probe(f) == AUTHD_SECRET_OK,
            "passphrase probe: a file of one byte that is not a newline is in range (the control)");
      CHECK(pc_write(f, "correct horse\n", 14u, 0600) == 0, "passphrase probe: the file is put back"); }
    { static uint8_t b[AUTHD_PASSPHRASE_MAX + 1u];
      memset(b, 'x', sizeof b);
      CHECK(pc_write(big, b, sizeof b, 0600) == 0 && refused_as(big, AUTHD_SECRET_ERR_SIZE),
            "passphrase custody: a file one byte over AUTHD_PASSPHRASE_MAX is refused as empty-or-too-large");
      uint8_t *p = NULL; size_t n = 0;
      CHECK(pc_write(big, b, AUTHD_PASSPHRASE_MAX, 0600) == 0 &&
            authd_secret_read(big, &p, &n) == AUTHD_SECRET_OK && n == AUTHD_PASSPHRASE_MAX,
            "passphrase custody: a file of exactly AUTHD_PASSPHRASE_MAX bytes reads whole -- the canary");
      authd_secret_free(p, n); }
    { uint8_t *p = NULL; size_t n = 0;
      CHECK(pc_write(f, "pw\n\n", 4u, 0600) == 0 && authd_secret_read(f, &p, &n) == AUTHD_SECRET_OK &&
            n == 3u && memcmp(p, "pw\n", 3u) == 0,
            "passphrase custody: only ONE trailing newline is stripped; a second is part of the passphrase");
      authd_secret_free(p, n); }
    (void)unlink(lnk); (void)unlink(f); (void)unlink(big); (void)unlink(nl); (void)rmdir(d);
}

/* V4-99 (erratum 74): systemd's credential, as MEASURED on Ubuntu 26.04 --
 * root:root, 0440, read by the service user through an ACL -- is accepted
 * only DIRECTLY inside $CREDENTIALS_DIRECTORY, and only with no group write
 * and no other bit. The decision is a pure function so the root-owned cases
 * run without root; the rehearsal (tools/rehearse_runbook.py) is where real
 * systemd delivers one to the real daemon. */
static void test_credential_custody(void)
{
    const char *cd = "/run/credentials/mldsa-authd.service";
    const char *in = "/run/credentials/mldsa-authd.service/passphrase";
    const uid_t me = (uid_t)997;
#define CC(p, u, g, m, dir) authd_secret_custody((p), (uid_t)(u), (gid_t)(g), (mode_t)(m), me, (dir))
    CHECK(CC(in, 0, 0, 0100440, cd) == AUTHD_SECRET_OK,
          "credential custody: systemd's root:root 0440 file in $CREDENTIALS_DIRECTORY is accepted -- the canary");
    CHECK(CC(in, 0, 0, 0100400, cd) == AUTHD_SECRET_OK && CC(in, 0, 0, 0100600, cd) == AUTHD_SECRET_OK,
          "credential custody: 0400 and 0600 root:root credentials are accepted");
    CHECK(CC(in, 0, 0, 0100440, "/run/credentials/mldsa-authd.service/") == AUTHD_SECRET_OK,
          "credential custody: a trailing slash on $CREDENTIALS_DIRECTORY changes nothing");
    CHECK(CC(in, 0, 0, 0100440, NULL) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: without $CREDENTIALS_DIRECTORY a root-owned file is not-owned-by-this-user");
    CHECK(CC("/etc/mldsa-authd/pass", 0, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: a root-owned file OUTSIDE the credentials directory is refused as before");
    CHECK(CC("/run/credentials/mldsa-authd.serviceX/passphrase", 0, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: a sibling directory sharing the prefix is not the credentials directory");
    CHECK(CC("/run/credentials/mldsa-authd.serviceXpassphrase", 0, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: a NAME sharing the prefix, with no '/' after it, is not inside the directory");
    CHECK(CC("/run/credentials/mldsa-authd.service/sub/passphrase", 0, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: a subdirectory of the credentials directory is not the credentials directory");
    CHECK(CC("/run/credentials/mldsa-authd.service/", 0, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: the directory itself names no file");
    CHECK(CC("run/credentials/x.service/passphrase", 0, 0, 0100440, "run/credentials/x.service") == AUTHD_SECRET_ERR_OWNER,
          "credential custody: a relative $CREDENTIALS_DIRECTORY is never trusted");
    CHECK(CC(in, 0, 5, 0100440, cd) == AUTHD_SECRET_ERR_OWNER && CC(in, 5, 0, 0100440, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: only root:root earns the exception -- another owner or group does not");
    CHECK(CC(in, 0, 0, 0100460, cd) == AUTHD_SECRET_ERR_PERMISSIONS,
          "credential custody: a group-writable credential is refused as unsafe-permissions");
    { const mode_t other[] = {0100444, 0100442, 0100441};
      int all = 1;
      for (size_t i = 0; i < sizeof other / sizeof other[0]; i++) {
          if (CC(in, 0, 0, other[i], cd) != AUTHD_SECRET_ERR_PERMISSIONS) { all = 0; }
      }
      CHECK(all, "credential custody: any 'other' bit on a credential is refused as unsafe-permissions"); }
    CHECK(CC(in, me, 0, 0100400, cd) == AUTHD_SECRET_OK && CC(in, me, 0, 0100440, cd) == AUTHD_SECRET_ERR_PERMISSIONS,
          "credential custody: a credential chowned to the service user keeps the ordinary 0600-or-tighter rule");
    CHECK(CC("/home/u/pass", (uid_t)5, me, 0100600, cd) == AUTHD_SECRET_ERR_OWNER,
          "credential custody: another user's 0600 file is not-owned-by-this-user, credentials directory or not");
    CHECK(CC("/home/u/pass", me, me, 0100600, cd) == AUTHD_SECRET_OK && CC("/home/u/pass", me, me, 0100640, cd) == AUTHD_SECRET_ERR_PERMISSIONS,
          "credential custody: an ordinary own file is unchanged -- 0600 accepted, 0640 refused");
#undef CC
}

/* V4-104: readiness for systemd's Type=notify. A datagram socket stands in
 * for systemd's: READY=1 must arrive, verbatim, at the path $NOTIFY_SOCKET
 * names; unset is "not under systemd" (0, nothing sent); a relative path and
 * an over-long one are refused, not guessed at. Linux also gets the abstract
 * namespace, which is what systemd actually uses there. */
static void test_sd_notify(void)
{
    char sp[sizeof g_dir + 16u];
    (void)snprintf(sp, sizeof sp, "%s/notify.sock", g_dir);
    struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
    const size_t spn = strlen(sp);
    const int fits = spn < sizeof a.sun_path;
    if (fits) { memcpy(a.sun_path, sp, spn + 1u); }
    const int rs = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(fits && rs >= 0 && bind(rs, (struct sockaddr *)&a, sizeof a) == 0,
          "sd_notify: a datagram socket standing in for systemd's");
    (void)unsetenv("NOTIFY_SOCKET");
    CHECK(authd_sd_notify("READY=1") == 0, "sd_notify: without NOTIFY_SOCKET it does nothing and says so (0)");
    (void)setenv("NOTIFY_SOCKET", "", 1);
    CHECK(authd_sd_notify("READY=1") == 0, "sd_notify: an empty NOTIFY_SOCKET is the same as none");
    (void)setenv("NOTIFY_SOCKET", sp, 1);
    CHECK(authd_sd_notify("READY=1") == 1, "sd_notify: with NOTIFY_SOCKET set, the datagram is sent (1)");
    { char got[64] = {0};
      const ssize_t n = rs >= 0 ? recv(rs, got, sizeof got - 1u, MSG_DONTWAIT) : -1;
      CHECK(n == 7 && memcmp(got, "READY=1", 7u) == 0, "sd_notify: systemd's socket receives exactly READY=1"); }
    /* F437 (V4-309): the socket READY=1 opened is KEPT, so a ping still goes
     * out when no descriptor can be opened. Staged with RLIMIT_NOFILE at 0:
     * the canary is that socket() itself now fails. */
    { struct rlimit saved, none;
      if (getrlimit(RLIMIT_NOFILE, &saved) == 0) {
          none = saved; none.rlim_cur = 0;
          if (setrlimit(RLIMIT_NOFILE, &none) == 0) {
              const int probe = socket(AF_UNIX, SOCK_DGRAM, 0);
              const int probe_errno = errno;
              const int sent = authd_sd_notify("WATCHDOG=1");
              (void)setrlimit(RLIMIT_NOFILE, &saved);
              if (probe >= 0) { (void)close(probe); }
              CHECK(probe < 0 && (probe_errno == EMFILE || probe_errno == ENFILE),
                    "sd_notify: with RLIMIT_NOFILE at 0 no socket can be opened (the canary)");
              CHECK(sent == 1, "sd_notify: a ping is still sent when no descriptor can be opened: the socket is kept (F437)");
              char got[64] = {0};
              const ssize_t n = rs >= 0 ? recv(rs, got, sizeof got - 1u, MSG_DONTWAIT) : -1;
              CHECK(n == 10 && memcmp(got, "WATCHDOG=1", 10u) == 0,
                    "sd_notify: and systemd's socket receives exactly WATCHDOG=1 (F437)");
          } else {
              printf("SKIP: sd_notify: this platform will not lower RLIMIT_NOFILE to 0; the kept socket is not staged (F437)\n");
          }
      } }
    /* Closed, the next notification opens one again. */
    authd_sd_notify_close();
    authd_sd_notify_close();                    /* twice is harmless */
    CHECK(authd_sd_notify("READY=1") == 1, "sd_notify: after authd_sd_notify_close the next call opens a socket again");
    { char got[64] = {0};
      const ssize_t n = rs >= 0 ? recv(rs, got, sizeof got - 1u, MSG_DONTWAIT) : -1;
      CHECK(n == 7, "sd_notify: and that READY=1 arrives"); }
    (void)setenv("NOTIFY_SOCKET", "relative/notify", 1);
    CHECK(authd_sd_notify("READY=1") == -1, "sd_notify: a relative NOTIFY_SOCKET is refused (-1), not guessed at");
    { char longp[200]; memset(longp, 'x', sizeof longp - 1u); longp[0] = '/'; longp[sizeof longp - 1u] = '\0';
      (void)setenv("NOTIFY_SOCKET", longp, 1);
      CHECK(authd_sd_notify("READY=1") == -1, "sd_notify: a NOTIFY_SOCKET longer than sun_path is refused (-1)"); }
#ifdef __linux__
    { const int as = socket(AF_UNIX, SOCK_DGRAM, 0);
      struct sockaddr_un b; memset(&b, 0, sizeof b); b.sun_family = AF_UNIX;
      /* A random name, not a pid one: scratch_dirs (F114) refuses those. */
      uint8_t rnd[8]; randombytes_buf(rnd, sizeof rnd);
      char hex[2u * sizeof rnd + 1u]; (void)sodium_bin2hex(hex, sizeof hex, rnd, sizeof rnd);
      char name[64]; (void)snprintf(name, sizeof name, "mldsa-notify-%s", hex);
      const size_t nl = strlen(name);
      memcpy(b.sun_path + 1, name, nl);           /* sun_path[0] = 0: abstract */
      const socklen_t bl = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1u + nl);
      char env[80]; (void)snprintf(env, sizeof env, "@%s", name);
      (void)setenv("NOTIFY_SOCKET", env, 1);
      char got[64] = {0};
      const int ok = as >= 0 && bind(as, (struct sockaddr *)&b, bl) == 0 && authd_sd_notify("READY=1") == 1 &&
                     recv(as, got, sizeof got - 1u, MSG_DONTWAIT) == 7 && memcmp(got, "READY=1", 7u) == 0;
      CHECK(ok, "sd_notify: an abstract NOTIFY_SOCKET (@name), as systemd uses on Linux, receives READY=1");
      if (as >= 0) { (void)close(as); } }
#endif
    (void)unsetenv("NOTIFY_SOCKET");
    authd_sd_notify_close();
    if (rs >= 0) { (void)close(rs); }
    (void)unlink(sp);
}

/* V4-311, review 67: what authd_admin's argument handling let through. */
static void test_admin_arguments(void)
{
    char err[1024];
    char nosock[sizeof g_dir + 32u];
    (void)snprintf(nosock, sizeof nosock, "%s/no-such.sock", g_dir);

    /* F537: a flag given twice is a usage error, not "the last one wins". */
    int rc = run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", nosock, "--user", "alice",
                                           "--user", "bob", "--reason", "x", NULL }, err, sizeof err);
    CHECK(rc == 2 && strstr(err, "disable-user: --user is given more than once") != NULL,
          "args: disable-user with --user twice is refused as usage, naming the flag (F537)");
    rc = run_admin_capture((char *[]){ "authd_admin", "list-users", "--socket", nosock, "--socket", nosock, NULL },
                           err, sizeof err);
    CHECK(rc == 2 && strstr(err, "--socket is given more than once") != NULL,
          "args: --socket twice is refused too (F537)");
    {
        char d2[sizeof g_dir + 32u], pf[sizeof g_dir + 32u];
        (void)snprintf(d2, sizeof d2, "%s/twice-init", g_dir);
        (void)snprintf(pf, sizeof pf, "%s/no-such-pass", g_dir);
        rc = run_admin_capture((char *[]){ "authd_admin", "init", "--dir", d2, "--dir", d2, "--server-id", "authd",
                                           "--passphrase-file", pf, NULL }, err, sizeof err);
        struct stat st;
        CHECK(rc == 2 && strstr(err, "init: --dir is given more than once") != NULL && stat(d2, &st) != 0,
              "args: an offline command refuses a doubled flag before it makes anything (F537)");
    }
    /* The canary: a VALUE that looks like a flag is not a repeat. This is
     * past the usage checks and fails at the socket that is not there. */
    rc = run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", nosock, "--user", "alice",
                                       "--reason", "--user", NULL }, err, sizeof err);
    CHECK(rc == 1 && strstr(err, "more than once") == NULL && strstr(err, "cannot-connect") != NULL,
          "args: a value spelled like a flag is a value: the request goes on to the socket (F537 canary)");

    /* F538: one path for the key and its public half. */
    {
        char same[sizeof g_dir + 32u], pf[sizeof g_dir + 32u];
        (void)snprintf(same, sizeof same, "%s/same.ek", g_dir);
        (void)snprintf(pf, sizeof pf, "%s/no-such-pass", g_dir);
        rc = run_admin_capture((char *[]){ "authd_admin", "keygen-server", "--key", same, "--pub", same,
                                           "--server-id", "authd", "--passphrase-file", pf, NULL }, err, sizeof err);
        struct stat st;
        CHECK(rc == 2 && strstr(err, "--key and --pub name the same file; nothing was written") != NULL &&
              stat(same, &st) != 0,
              "args: keygen-server with one path for both halves is refused as usage and writes nothing (F538)");
    }

    /* F539: pseudonym --id is held to the daemon's bound for an identifier. */
    {
        char id64[65], id65[66];
        memset(id64, 'a', 64u); id64[64] = '\0';
        memset(id65, 'a', 65u); id65[65] = '\0';
        char no[sizeof g_dir + 32u];
        (void)snprintf(no, sizeof no, "%s/no-such-file", g_dir);
        rc = run_admin_capture((char *[]){ "authd_admin", "pseudonym", "--store", no, "--key", no,
                                           "--passphrase-file", no, "--server-id", "authd", "--id", id65, NULL },
                               err, sizeof err);
        CHECK(rc == 2 && strstr(err, "pseudonym: --id is 1 to 64 bytes of printable ASCII") != NULL,
              "args: pseudonym refuses a 65-byte --id as usage, naming the bound (F539)");
        rc = run_admin_capture((char *[]){ "authd_admin", "pseudonym", "--store", no, "--key", no,
                                           "--passphrase-file", no, "--server-id", "authd", "--id", "a\tb", NULL },
                               err, sizeof err);
        CHECK(rc == 2 && strstr(err, "--id is 1 to 64 bytes of printable ASCII") != NULL,
              "args: and one with a tab in it (F539)");
        rc = run_admin_capture((char *[]){ "authd_admin", "pseudonym", "--store", no, "--key", no,
                                           "--passphrase-file", no, "--server-id", "authd", "--id", id64, NULL },
                               err, sizeof err);
        CHECK(rc != 2 && strstr(err, "--id is 1 to") == NULL,
              "args: a 64-byte --id passes that check and fails later, on the files (F539 canary)");
    }

    /* V4-321, F569: a command that is sent and not answered says so. A bare
     * `timeout` read as "nothing happened"; a daemon that is busy carries the
     * request out when it is free. The listener here takes the connection
     * into its queue and never answers: ten seconds, the tool's own wait. */
    {
        char sp[sizeof g_dir + 32u];
        (void)snprintf(sp, sizeof sp, "%s/silent.sock", g_dir);
        struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
        const size_t spn = strlen(sp);
        const int fits = spn < sizeof sa.sun_path;
        if (fits) { memcpy(sa.sun_path, sp, spn + 1u); }
        const int ls = socket(AF_UNIX, SOCK_STREAM, 0);
        const int up = fits && ls >= 0 && bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 4) == 0;
        rc = up ? run_admin_capture((char *[]){ "authd_admin", "disable-user", "--socket", sp, "--user", "u",
                                               "--reason", "r", NULL }, err, sizeof err) : -2;
        CHECK(rc == 1 && strstr(err, ": timeout") != NULL &&
              strstr(err, "the request was sent and not answered in time") != NULL &&
              strstr(err, "check the result before running this again") != NULL,
              "args: a command sent to a daemon that does not answer says it WAS sent and may still be carried out (F569)");
        if (ls >= 0) { (void)close(ls); }
        (void)unlink(sp);
    }

    /* F533: BACKUP is given ten minutes, everything else ten seconds, and a
     * timed-out backup says the daemon may still finish it. Named here; a
     * test that waited for either would be the slowest in the tree. */
    CHECK(authd_cli_timeout_ms("BACKUP") == 600000u, "args: BACKUP waits ten minutes for its answer (F533)");
    CHECK(authd_cli_timeout_ms("LIST-USERS") == 10000u && authd_cli_timeout_ms("ENROLL-OPERATOR") == 10000u &&
          authd_cli_timeout_ms(NULL) == 10000u,
          "args: every other command waits ten seconds (the canary)");
    CHECK(authd_cli_timeout_hint("BACKUP") != NULL &&
          strstr(authd_cli_timeout_hint("BACKUP"), "the daemon may still be writing the backup") != NULL,
          "args: a timed-out backup says the daemon may still be writing it (F533)");
    CHECK(authd_cli_timeout_hint("LIST-USERS") == NULL && authd_cli_timeout_hint(NULL) == NULL,
          "args: and no other command claims that");
}

/* F209 (V4-126): the watchdog interval. systemd hands a service with
 * WatchdogSec= the timeout in $WATCHDOG_USEC (and, when the variable is meant
 * for one process only, that process in $WATCHDOG_PID). The daemon pings at a
 * quarter of it, at most once a second -- its loop turns at least that often
 * -- and not at all unless all of it is there and well-formed: a ping nobody
 * asked for is harmless, but a period computed from garbage is not. */
static uint64_t tick_clock(void) { return 2000u; }

#ifdef __linux__
/* V4-318, F561: on Linux a non-blocking connect to a Unix socket whose
 * backlog is full fails at once with EAGAIN. The tools read that as nothing
 * listening. It is a listener that is busy: the connect is tried until its
 * deadline and is then a timeout, and it succeeds once the listener takes a
 * connection. Linux only, because only Linux answers so: macOS refuses the
 * connection, as it does when nothing is there. */
static void test_unix_backlog_full(void)
{
    char sp[600];
    (void)snprintf(sp, sizeof sp, "%s/backlog.sock", g_dir);
    struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
    const size_t spn = strlen(sp);
    if (spn >= sizeof a.sun_path) { CHECK(0, "backlog: the socket path fits"); return; }
    memcpy(a.sun_path, sp, spn + 1u);
    const int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(ls >= 0 && bind(ls, (struct sockaddr *)&a, sizeof a) == 0 && listen(ls, 1) == 0,
          "backlog: a listener that accepts nothing");
    /* Fill the backlog with raw non-blocking connects until one is EAGAIN. */
    int held[64], nheld = 0, full = 0;
    for (int i = 0; i < 64 && !full; i++) {
        const int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (c < 0) { break; }
        (void)fcntl(c, F_SETFL, O_NONBLOCK);
        if (connect(c, (struct sockaddr *)&a, sizeof a) != 0) {
            full = (errno == EAGAIN);
            (void)close(c);
        } else {
            held[nheld++] = c;
        }
    }
    CHECK(full, "backlog: the backlog fills and a raw connect is refused EAGAIN (the staging)");
    net_conn_t conn;
    const uint64_t t0 = net_now_ms();
    const net_status_t busy = net_connect_unix(sp, net_deadline_in(300u), &conn);
    const uint64_t waited = net_now_ms() - t0;
    CHECK(busy == NET_TIMEOUT && waited >= 250u,
          "backlog: a connect to a full backlog waits for its deadline and is a timeout, not an I/O error (F561)");
    if (busy == NET_OK) { net_close(&conn); }
    /* F566 (V4-320): and the administrator's tool says which wait ended.
     * `timeout` is a request that was sent and not answered; here nothing
     * was sent, and the status says so. */
    { char out[64];
      size_t on = 0;
      const localcli_status_t ls = localcli_call(sp, "PING", NULL, 300u, out, sizeof out, &on);
      CHECK(ls == LOCALCLI_ERR_BUSY && strcmp(localcli_status_name(ls), "daemon-busy") == 0,
            "backlog: authd_admin's call to a full backlog is daemon-busy, not timeout: nothing was sent (F566)"); }
    /* The listener takes one: there is room, and the same call connects. */
    const int got = accept(ls, NULL, NULL);
    const net_status_t then = net_connect_unix(sp, net_deadline_in(2000u), &conn);
    CHECK(got >= 0 && then == NET_OK, "backlog: once the listener takes a connection the connect succeeds (F561)");
    if (then == NET_OK) { net_close(&conn); }
    if (got >= 0) { (void)close(got); }
    for (int i = 0; i < nheld; i++) { (void)close(held[i]); }
    (void)close(ls);
    (void)unlink(sp);
}
#endif

static void test_sd_watchdog(void)
{
    char pid[32];
    (void)setenv("NOTIFY_SOCKET", "/run/systemd/notify", 1);
    (void)unsetenv("WATCHDOG_PID");
    (void)unsetenv("WATCHDOG_USEC");
    CHECK(authd_sd_watchdog_period_ms() == 0u, "sd_watchdog: without WATCHDOG_USEC there is no watchdog (0)");
    (void)setenv("WATCHDOG_USEC", "30000000", 1);
    CHECK(authd_sd_watchdog_period_ms() == 1000u, "sd_watchdog: a 30 s watchdog is pinged every second, the loop's own longest turn");
    (void)setenv("WATCHDOG_USEC", "2000000", 1);
    CHECK(authd_sd_watchdog_period_ms() == 500u, "sd_watchdog: a 2 s watchdog is pinged every 500 ms, a quarter of it");
    (void)setenv("WATCHDOG_USEC", "100000", 1);
    CHECK(authd_sd_watchdog_period_ms() == 25u, "sd_watchdog: a 100 ms watchdog is pinged every 25 ms");
    (void)setenv("WATCHDOG_USEC", "3999", 1);
    CHECK(authd_sd_watchdog_period_ms() == 1u, "sd_watchdog: a watchdog shorter than 4 ms is pinged every millisecond, never every 0");
    static const char *const bad[] = { "", "0", "-5", "abc", "12x", " 30000000", "+30000000",
                                       "99999999999999999999999999" };
    int all_zero = 1;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        (void)setenv("WATCHDOG_USEC", bad[i], 1);
        if (authd_sd_watchdog_period_ms() != 0u) { all_zero = 0; }
    }
    CHECK(all_zero, "sd_watchdog: an empty, zero, signed, non-numeric, padded or overflowing WATCHDOG_USEC is no watchdog (0)");
    (void)setenv("WATCHDOG_USEC", "18446744073709551615", 1);
    CHECK(authd_sd_watchdog_period_ms() == 1000u, "sd_watchdog: the largest 64-bit WATCHDOG_USEC is still one ping a second");
    /* F340: the loop's idle wait never runs past the next ping. */
    CHECK(authd_sd_watchdog_wait_ms(1000u, 0u, 1000) == 1000 && authd_sd_watchdog_wait_ms(300u, 0u, 1000) == 300,
          "sd_watchdog wait: just after a ping the loop may sleep one period, or its idle wait if that is shorter");
    CHECK(authd_sd_watchdog_wait_ms(1000u, 999u, 1000) == 1 && authd_sd_watchdog_wait_ms(300u, 120u, 1000) == 180,
          "sd_watchdog wait: woken early, the loop sleeps only what is left until the ping is due, not a whole wait more (F340)");
    CHECK(authd_sd_watchdog_wait_ms(1000u, 1000u, 1000) == 0 && authd_sd_watchdog_wait_ms(300u, 5000u, 1000) == 0,
          "sd_watchdog wait: a ping that is due or overdue is not slept on at all");
    CHECK(authd_sd_watchdog_wait_ms(0u, 123456u, 1000) == 1000,
          "sd_watchdog wait: with no watchdog the idle wait is the loop's own");
    /* V4-315, F541: the ping from inside one long turn (a BACKUP). The
     * decision with the time as an argument, against a socket standing in
     * for systemd's. */
    {
        char tp[600], keep[600] = {0};
        const char *was = getenv("NOTIFY_SOCKET");
        if (was != NULL) { (void)snprintf(keep, sizeof keep, "%s", was); }
        (void)snprintf(tp, sizeof tp, "%s/tick.sock", g_dir);
        struct sockaddr_un ta; memset(&ta, 0, sizeof ta); ta.sun_family = AF_UNIX;
        const size_t tn = strlen(tp);
        const int tfits = tn < sizeof ta.sun_path;
        if (tfits) { memcpy(ta.sun_path, tp, tn + 1u); }
        const int ts = socket(AF_UNIX, SOCK_DGRAM, 0);
        const int bound = tfits && ts >= 0 && bind(ts, (struct sockaddr *)&ta, sizeof ta) == 0;
        authd_sd_notify_close();
        (void)setenv("NOTIFY_SOCKET", tp, 1);
        char got[32];
        authd_wd_tick_t t = { .period_ms = 0u, .last_ms = 1000u, .clock_ms = tick_clock };
        CHECK(bound && authd_sd_watchdog_tick_at(&t, 999999u) == 0 && recv(ts, got, sizeof got, MSG_DONTWAIT) < 0,
              "sd_watchdog tick: with no watchdog nothing is sent, however long the turn (F541)");
        t.period_ms = 500u;
        CHECK(authd_sd_watchdog_tick_at(&t, 1499u) == 0 && recv(ts, got, sizeof got, MSG_DONTWAIT) < 0,
              "sd_watchdog tick: a millisecond before a ping is due, none is sent (F541)");
        memset(got, 0, sizeof got);
        CHECK(authd_sd_watchdog_tick_at(&t, 1500u) == 1 && recv(ts, got, sizeof got - 1u, MSG_DONTWAIT) == 10 &&
              memcmp(got, "WATCHDOG=1", 10u) == 0 && t.last_ms == 1500u,
              "sd_watchdog tick: when a ping is due inside a turn, WATCHDOG=1 is sent and the time noted (F541)");
        CHECK(authd_sd_watchdog_tick_at(&t, 1501u) == 0 && recv(ts, got, sizeof got, MSG_DONTWAIT) < 0,
              "sd_watchdog tick: and the next call sends nothing until a period has passed (F541)");
        memset(got, 0, sizeof got);
        authd_sd_watchdog_tick(&t);                     /* the store's callback: the clock says 2000 */
        CHECK(recv(ts, got, sizeof got - 1u, MSG_DONTWAIT) == 10 && t.last_ms == 2000u,
              "sd_watchdog tick: the store's callback reads the clock it was given and pings (F541)");
        authd_sd_notify_close();
        if (ts >= 0) { (void)close(ts); }
        (void)unlink(tp);
        if (was != NULL) { (void)setenv("NOTIFY_SOCKET", keep, 1); } else { (void)unsetenv("NOTIFY_SOCKET"); }
    }
    (void)setenv("WATCHDOG_USEC", "2000000", 1);
    /* The pid as systemd would write it -- an environment value, not a name
     * (tests/scratch_dirs.sh forbids the latter, F114). */
    const long self = (long)getpid();
    (void)snprintf(pid, sizeof pid, "%ld", self);
    (void)setenv("WATCHDOG_PID", pid, 1);
    CHECK(authd_sd_watchdog_period_ms() == 500u, "sd_watchdog: WATCHDOG_PID naming this process keeps the watchdog");
    const long parent = (long)getppid();
    (void)snprintf(pid, sizeof pid, "%ld", parent);
    (void)setenv("WATCHDOG_PID", pid, 1);
    CHECK(authd_sd_watchdog_period_ms() == 0u, "sd_watchdog: WATCHDOG_PID naming another process means the watchdog is not this one's (0)");
    (void)setenv("WATCHDOG_PID", "junk", 1);
    CHECK(authd_sd_watchdog_period_ms() == 0u, "sd_watchdog: a WATCHDOG_PID that is not a number is not this process (0)");
    (void)unsetenv("WATCHDOG_PID");
    (void)unsetenv("NOTIFY_SOCKET");
    CHECK(authd_sd_watchdog_period_ms() == 0u, "sd_watchdog: with nowhere to send a ping there is no watchdog (0)");
    (void)unsetenv("WATCHDOG_USEC");
}

/* V4-201, F280: stdfds_ensure_open, in a child whose descriptors this test
 * may close. The child reports through its exit status: 0, or 10 plus what
 * went wrong. */
static int stdfds_child(int close_mask, int want_mask)
{
    const pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        for (int fd = 0; fd <= 2; fd++) {
            if ((close_mask & (1 << fd)) != 0) { (void)close(fd); }
        }
        const int got = stdfds_ensure_open();
        if (got != want_mask) { _exit(10); }
        for (int fd = 0; fd <= 2; fd++) {
            if (fcntl(fd, F_GETFD) == -1) { _exit(11 + fd); }
        }
        /* the next descriptor opened is none of the three */
        const int next = open("/dev/null", O_RDONLY);
        if (next <= 2) { _exit(20); }
        /* a closed 1 or 2 became write-only /dev/null; a closed 0 read-only */
        if ((close_mask & 2) != 0 && write(1, "x", 1) != 1) { _exit(21); }
        if ((close_mask & 1) != 0) { char ch; if (read(0, &ch, 1) != 0) { _exit(22); } }
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) { return -1; }
    return WEXITSTATUS(st);
}

static void test_stdfds(void)
{
    CHECK(stdfds_child(0, 0) == 0, "stdfds: with all three open nothing is changed and the mask is 0 (the canary)");
    CHECK(stdfds_child(7, 7) == 0,
          "stdfds: with 0, 1 and 2 closed all three are opened on /dev/null, and the next descriptor is 3 or more (F280)");
    CHECK(stdfds_child(2, STDFDS_STDOUT_WAS_CLOSED) == 0,
          "stdfds: standard output alone closed is reported as that, and is writable afterwards (F280)");
    CHECK(stdfds_child(4, STDFDS_STDERR_WAS_CLOSED) == 0 && stdfds_child(1, STDFDS_STDIN_WAS_CLOSED) == 0 &&
              stdfds_child(5, STDFDS_STDIN_WAS_CLOSED | STDFDS_STDERR_WAS_CLOSED) == 0,
          "stdfds: standard error, standard input, and the two together are each reported exactly (F280)");
}

int main(void)
{
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }
    /* mkdtemp, not a pid-keyed name (audit F114): a run that crashes leaves its
     * directory behind, and a later run that drew the same pid stopped at once. */
    (void)snprintf(g_dir, sizeof g_dir, "/tmp/authd-cli-XXXXXX");
    if (mkdtemp(g_dir) == NULL) { printf("FAIL: mkdtemp %s\n", g_dir); return 1; }

    test_init();
    test_keys();
    test_rewrap_keeps_store();
    test_client_keygen();
    test_migrate_key();
    test_check_config();
    test_framing_rule();
    test_localcli_split_list();
    test_localcli_robustness();
    test_key_plan();
    test_backup_path_bound();
    test_client_ws_only_options();
    test_fifo_refused();
    test_reply_not_protocol();
    test_online_bounds();
    test_rotate_on_disk();
    test_rotate_reply_refused_or_lost();
    test_passphrase_custody();
    test_credential_custody();
    test_stdfds();
    test_sd_notify();
    test_sd_watchdog();
#ifdef __linux__
    test_unix_backlog_full();
#endif
    test_admin_arguments();
    test_keygen_crlf();

    char cmd[512];
    (void)snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { printf("FAIL: could not remove %s\n", g_dir); g_fail = 1; }

    if (g_fail) { printf("FAILED (%d checks)\n", g_checks); return 1; }
    printf("PASS: test_authd_cli (%d checks)\n", g_checks);
    return 0;
}
