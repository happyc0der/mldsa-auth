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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "authd_cli.h"
#include "authd_config.h"
#include "authd_harness.h"
#include "authd_secret.h"
#include "keyfile.h"

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

/* Runs a CLI with stderr captured into `buf`. Used where the MESSAGE is the
 * thing under test, not just the exit code. */
static int run_admin_capture(char **argv, char *buf, size_t cap)
{
    char tmp[256];
    (void)snprintf(tmp, sizeof tmp, "%s/stderr.txt", g_dir);
    const int saved = dup(2);
    fflush(stderr);
    FILE *f = freopen(tmp, "w", stderr);
    const int rc = (f != NULL) ? run_cli(authd_cli_admin, argv) : -1;
    fflush(stderr);
    if (saved >= 0) {
        (void)dup2(saved, 2);
        (void)close(saved);
        clearerr(stderr);
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
        (void)snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
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

/* ---------------------------------------------------------------- init */

static void test_init(void)
{
    char dir[256], pass[256], ek[256], pub[256], db[256];
    (void)snprintf(dir, sizeof dir, "%s/i1", g_dir);
    (void)snprintf(pass, sizeof pass, "%s/i1/pass", g_dir);
    (void)snprintf(ek, sizeof ek, "%s/i1/server.ek", g_dir);
    (void)snprintf(pub, sizeof pub, "%s/i1/server.pub", g_dir);
    (void)snprintf(db, sizeof db, "%s/i1/store.sqlite3", g_dir);

    CHECK(RUN_ADMIN("init", "--dir", dir, "--server-id", "authd", "--passphrase-file", pass) == 0,
          "init: creates a server key, a store and a passphrase file");

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

    CHECK(RUN_ADMIN("init", "--dir", dir, "--server-id") == 2, "init: a missing value is usage (2)");
    CHECK(RUN_ADMIN("init", "--dir", dir, "--bogus", "x") == 2, "init: an unknown option is usage (2)");
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

    CHECK(RUN_ADMIN("keygen-server", "--key", ek, "--pub", pub, "--server-id", "srv",
                    "--passphrase-file", pass) == 1,
          "keygen-server: an existing key is never overwritten");

    /* rewrap: the OLD passphrase must actually be checked, and --out equal to
     * --in must be impossible rather than merely discouraged. */
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek2,
                    "--old-passphrase-file", pass2, "--new-passphrase-file", pass) == 1,
          "rewrap: the wrong old passphrase is refused");
    CHECK(file_size(ek2) < 0, "rewrap: nothing was written after a wrong passphrase");
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek,
                    "--old-passphrase-file", pass, "--new-passphrase-file", pass2) == 1,
          "rewrap: --out equal to --in is refused, so rewrap is never in place");
    CHECK(RUN_ADMIN("rewrap", "--id", "srv", "--in", ek, "--out", ek2,
                    "--old-passphrase-file", pass, "--new-passphrase-file", pass2) == 0,
          "rewrap: writes a new file under the new passphrase");
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
        mldsa_keypair_free(&a);
        mldsa_keypair_free(&b);
    }
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

int main(void)
{
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }
    (void)snprintf(g_dir, sizeof g_dir, "/tmp/authd-cli-%ld", (long)getpid());
    if (mkdir(g_dir, 0700) != 0) { printf("FAIL: mkdir %s\n", g_dir); return 1; }

    test_init();
    test_keys();
    test_client_keygen();
    test_check_config();
    test_framing_rule();
    test_key_plan();

    char cmd[512];
    (void)snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { printf("FAIL: could not remove %s\n", g_dir); g_fail = 1; }

    if (g_fail) { printf("FAILED (%d checks)\n", g_checks); return 1; }
    printf("PASS: test_authd_cli (%d checks)\n", g_checks);
    return 0;
}
