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

#include "authd_cli.h"
#include "authd_config.h"
#include "authd_harness.h"
#include <sodium.h>

#include "sdnotify.h"
#include "authd_secret.h"
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
static int run_admin_capture_stream(char **argv, char *buf, size_t cap, FILE *stream, int fd)
{
    char tmp[256];
    (void)snprintf(tmp, sizeof tmp, "%s/captured.txt", g_dir);
    (void)fflush(stream);
    const int saved = dup(fd);
    FILE *f = freopen(tmp, "w", stream);
    const int rc = (f != NULL) ? run_cli(authd_cli_admin, argv) : -1;
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
    CHECK(RUN_ADMIN("audit-verify", "--store", db, "--key", other, "--passphrase-file", p2,
                    "--server-id", "authd") == 1,
          "control: a key file with a different root key fails audit-verify (1, not 3: the key opened) on the same store");

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
        usleep(200000);                         /* the rows arrive in a second write */
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

static int run_client_pumped_hook(h_daemon_t *d, char **argv, pump_hook_fn hook, void *ctx)
{
    fflush(stdout);
    fflush(stderr);
    const pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL) { child_exit(125); }
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

    /* 1. An acknowledged rotation: A -> B. */
    int rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                               "--passphrase-file", pass, "--server-id", "authd",
                                               "--server-pub", spub, "--port", port, NULL });
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
     *    key C is sealed to .ek.next first (spec 10.2), the daemon refuses A,
     *    and .ek.next must be KEPT -- still sealed. */
    CHECK(write_bytes(ek, sealed_a, na) == 0, "stale rotate: .ek is the superseded key again");
    rc = run_client_pumped(&d, (char *[]){ "authd_client", "rotate", "--handle", handle, "--key", ek,
                                           "--passphrase-file", pass, "--server-id", "authd",
                                           "--server-pub", spub, "--port", port, NULL });
    const int c_ok = keyfile_open(next, (const uint8_t *)handle, hlen, PASS, sizeof PASS - 1u, &c, NULL)
                     == KEYFILE_OK;
    CHECK(rc != 0 && rc != -1 && c_ok && a.public_key != NULL && b_ok &&
          memcmp(c.public_key, a.public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 &&
          memcmp(c.public_key, b.public_key, MLDSA_PUBLIC_KEY_BYTES) != 0 && same_bytes(ek, sealed_a, na),
          "stale rotate: the session is refused and .ek.next is kept, sealed");
    CHECK(a.secret_key != NULL && b_ok && c_ok &&
          !any_file_has_key_window(root, a.secret_key, NULL) &&
          !any_file_has_key_window(root, b.secret_key, NULL) &&
          !any_file_has_key_window(root, c.secret_key, NULL),
          "stale rotate: no window of any of the three keys in any file (Req 10)");
    CHECK(!any_name_contains(dev, ".newpub."), "stale rotate: no .newpub temp file is left behind (F118)");

    mldsa_keypair_free(&a);
    mldsa_keypair_free(&b);
    mldsa_keypair_free(&c);
    h_stop(&d);
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
    if (rs >= 0) { (void)close(rs); }
    (void)unlink(sp);
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
    test_rotate_on_disk();
    test_rotate_reply_refused_or_lost();
    test_passphrase_custody();
    test_credential_custody();
    test_sd_notify();

    char cmd[512];
    (void)snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { printf("FAIL: could not remove %s\n", g_dir); g_fail = 1; }

    if (g_fail) { printf("FAILED (%d checks)\n", g_checks); return 1; }
    printf("PASS: test_authd_cli (%d checks)\n", g_checks);
    return 0;
}
