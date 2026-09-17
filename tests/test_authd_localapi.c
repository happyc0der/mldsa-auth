/*
 * V4-9a: the local socket protocol (spec §8), tokens (§11) and the revocation
 * that reaches live sessions (Req 9).
 *
 * The daemon runs in-process via tests/authd_harness.h -- the same assembly
 * authd_main.c performs -- so the test owns the clock and can drive token
 * expiry, idle windows and the sweep exactly rather than by sleeping.
 *
 * The habits that earned their place in V4-8: pump-until-condition, never a
 * fixed count; and a present canary before every absence check.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "authd_harness.h"

static int g_fail = 0;
static int g_checks = 0;
static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) { printf("FAIL: %s\n", what); g_fail = 1; }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

static char g_dir[256];

static const uint8_t U1[]      = { 'u','1' };
static const uint8_t HANDLE1[] = { 'd','1','a','a' };

/* hex helpers for building request lines */
static void hx(char *out, size_t cap, const uint8_t *p, size_t n) { h_hex(out, cap, p, n); }

static int starts(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

/* Enrolls a device through the store directly (the API path is tested
 * separately) and returns its keypair. */
static void enroll_direct(h_daemon_t *d, const uint8_t *handle, size_t hl, mldsa_keypair_t *kp)
{
    CHECK(mldsa_keypair_generate(kp) == 0, "fixture: device key");
    (void)store_add_user(d->store, U1, sizeof U1, STORE_ROLE_USER);
    CHECK(store_enroll_device(d->store, handle, hl, U1, sizeof U1,
                              kp->public_key, "site", "test", NULL, 0) == STORE_OK,
          "fixture: enroll");
}

/* ------------------------------------------------------------- grammar */

static void test_grammar(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "grammar.sqlite3", 1) == 0, "grammar: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "grammar: connect to site.sock");

    char resp[16384];
    CHECK(h_local_cmd(&d, fd, "PING", resp, sizeof resp) == 0 && starts(resp, "OK version=1 schema=1"),
          "grammar: PING answers OK with version and schema");

    CHECK(h_local_cmd(&d, fd, "NOSUCHCOMMAND", resp, sizeof resp) == 0 &&
          starts(resp, "ERR code=not-permitted"),
          "grammar: an unknown command is refused");
    CHECK(h_local_cmd(&d, fd, "PING extra=1", resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "grammar: a key on a command that takes none is malformed");
    CHECK(h_local_cmd(&d, fd, "VERIFY", resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "grammar: a missing required key is malformed");
    CHECK(h_local_cmd(&d, fd, "VERIFY token=zz", resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "grammar: a non-hex value is malformed");
    CHECK(h_local_cmd(&d, fd, "VERIFY token=abc", resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "grammar: an odd-length hex value is malformed");
    /* Both of the next two use a WELL-FORMED token, so the duplication (resp.
     * the unknown key) is the only thing wrong with the request. With a short
     * value the answer would be `malformed` for the value's sake and the check
     * would pass even if the rule were removed -- which is exactly what the
     * first version did, and both mutations survived it. */
    {
        static const char T64[] = "VERIFY token="
            "0000000000000000000000000000000000000000000000000000000000000000";
        char line[512];
        snprintf(line, sizeof line, "%s token="
                 "1111111111111111111111111111111111111111111111111111111111111111", T64);
        CHECK(h_local_cmd(&d, fd, line, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
              "grammar: a duplicate key is malformed");
        /* the same request WITHOUT the duplicate is refused for a different
         * reason, which is what makes the check above discriminating */
        CHECK(h_local_cmd(&d, fd, T64, resp, sizeof resp) == 0 && starts(resp, "ERR code=unknown"),
              "grammar: the same token alone is merely unknown (canary for the check above)");

        snprintf(line, sizeof line, "%s nosuchkey=aa", T64);
        CHECK(h_local_cmd(&d, fd, line, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
              "grammar: an unknown key is malformed, not ignored");
    }
    CHECK(h_local_cmd(&d, fd, "LOGOUT token=", resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "grammar: an empty value is refused where the key requires bytes");

    /* The 8192-byte line cap, from both sides. */
    {
        char big[9000];
        memset(big, 'a', sizeof big);
        /* a line that is long but still terminates under the cap */
        size_t under = 8000;
        big[under] = '\0';
        char req[9100];
        snprintf(req, sizeof req, "VERIFY token=%s", big);
        CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
              "grammar: a long-but-legal line is parsed (and refused on its value)");
        (void)close(fd);

        /* over the cap: the connection is dropped rather than answered */
        fd = h_dial_unix(d.site_path);
        CHECK(fd >= 0, "grammar: reconnect for the over-cap case");
        memset(big, 'a', sizeof big);
        const size_t over = 8600;
        CHECK(h_write_all(&d, fd, "VERIFY token=", 13) == 0, "grammar: send the over-cap prefix");
        CHECK(h_write_all(&d, fd, big, over) == 0, "grammar: send over-cap bytes with no LF");
        CHECK(H_PUMP_UNTIL(&d, evloop_local_active(&d.ev) == 0u),
              "grammar: a line over 8192 bytes closes the connection");
    }
    (void)close(fd);
    h_stop(&d);
}

/* --------------------------------------------- the two sockets and Req 11 */

static void test_two_tables(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "tables.sqlite3", 1) == 0, "tables: daemon starts");
    char resp[16384];

    int site = h_dial_unix(d.site_path);
    int adm  = h_dial_unix(d.admin_path);
    CHECK(site >= 0 && adm >= 0, "tables: both sockets accept a connection");

    /* Present canary: the site socket DOES serve its own table. */
    CHECK(h_local_cmd(&d, site, "PING", resp, sizeof resp) == 0 && starts(resp, "OK"),
          "tables: the site socket serves site commands (canary)");

    CHECK(h_local_cmd(&d, site, "LIST-USERS", resp, sizeof resp) == 0 &&
          starts(resp, "ERR code=not-permitted"),
          "tables: an ADMIN command on site.sock is refused (Req 11, by construction)");
    CHECK(h_local_cmd(&d, adm, "LIST-USERS", resp, sizeof resp) == 0 && starts(resp, "OK count="),
          "tables: the same command on admin.sock is served");
    CHECK(h_local_cmd(&d, site, "ENROLL-OPERATOR", resp, sizeof resp) == 0 &&
          starts(resp, "ERR code=not-permitted"),
          "tables: ENROLL-OPERATOR is unreachable from the site socket");

    /* Refusal is indistinguishable from an unknown command, so the site socket
     * is not an oracle for which admin commands exist. */
    char a[64], b[64];
    CHECK(h_local_cmd(&d, site, "LIST-USERS", a, sizeof a) == 0 &&
          h_local_cmd(&d, site, "NOSUCHTHING", b, sizeof b) == 0 && strcmp(a, b) == 0,
          "tables: an admin command and a nonsense command give the SAME answer");

    (void)close(site); (void)close(adm);
    h_stop(&d);
}

/* ------------------------------------------------- exchange, verify, tokens */

static void test_exchange_verify(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "exch.sqlite3", 1) == 0, "exch: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "exch: login");
    CHECK(h_get_login_code(&d, &c, code) == 0, "exch: login code received");

    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "exch: connect to site.sock");

    char hexcode[80], req[512], resp[16384];
    hx(hexcode, sizeof hexcode, code, sizeof code);

    /* wrong state first: the code must survive a failed exchange */
    snprintf(req, sizeof req, "EXCHANGE code=%s state=6f74686572", hexcode);   /* "other" */
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=state-mismatch"),
          "exch: a code presented with the WRONG state is refused (login-CSRF binding)");

    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hexcode);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK token="),
          "exch: the right (empty) state yields a token");

    /* pull the token out of the reply */
    char token_hex[80] = {0};
    { const char *p = strstr(resp, "token=");
      CHECK(p != NULL, "exch: the reply carries a token");
      if (p != NULL) { sscanf(p + 6, "%79[0-9a-f]", token_hex); } }
    CHECK(strlen(token_hex) == 64u, "exch: the token is 32 bytes of hex");
    CHECK(strstr(resp, "role=user") != NULL, "exch: the reply names the role");

    /* single use */
    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hexcode);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=used"),
          "exch: a code is single-use, and says so");

    /* an unknown code is distinguishable from a used one */
    { uint8_t other[32]; memset(other, 0xAB, sizeof other);
      char oh[80]; hx(oh, sizeof oh, other, sizeof other);
      snprintf(req, sizeof req, "EXCHANGE code=%s state=", oh);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=unknown"),
            "exch: an unknown code is reported as unknown, not as used"); }

    /* VERIFY */
    snprintf(req, sizeof req, "VERIFY token=%s", token_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK user="),
          "verify: a fresh token verifies");
    CHECK(strstr(resp, "handle=") != NULL && strstr(resp, "expires=") != NULL,
          "verify: the reply carries the handle and expiry");

    /* The idle window, with its lower bound -- and, crucially, a point that
     * ONLY a token whose window was actually slid can survive.
     *
     * Advancing past the original window and asserting expiry proves nothing:
     * an unrefreshed token expires there too. The distinguishing moment is
     * AFTER the original window but INSIDE the refreshed one. */
    d.app.now_unix += (int64_t)TOKEN_IDLE_TTL_USER_S - 5;
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK user="),
          "verify: the token is STILL valid just before its idle window ends");
    d.app.now_unix += 100;   /* past the ORIGINAL window, inside the refreshed one */
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK user="),
          "verify: the token survives past its ORIGINAL idle window, so VERIFY really slid it");
    d.app.now_unix += (int64_t)TOKEN_IDLE_TTL_USER_S + 5;   /* past the refreshed window too */
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=idle-expired"),
          "verify: once the idle window passes, the token is idle-expired");

    /* LOGOUT reports what it did */
    CHECK(h_local_cmd(&d, fd, "LOGOUT token=00", resp, sizeof resp) == 0 &&
          starts(resp, "ERR code=malformed"), "logout: a short token is malformed");
    { char lo[512];
      snprintf(lo, sizeof lo, "LOGOUT token=%s", token_hex);
      CHECK(h_local_cmd(&d, fd, lo, resp, sizeof resp) == 0 && starts(resp, "OK deleted=1"),
            "logout: deletes the token and reports deleted=1");
      CHECK(h_local_cmd(&d, fd, lo, resp, sizeof resp) == 0 && starts(resp, "OK deleted=0"),
            "logout: a second logout reports deleted=0"); }

    (void)close(fd);
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* ------------------------------------------- revocation reaches live sessions */

static void test_revocation_closes_sessions(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "revoke.sqlite3", 1) == 0, "revoke: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "revoke: login");
    CHECK(h_get_login_code(&d, &c, code) == 0, "revoke: code received");

    /* Present canary: the session really is live and SERVING. */
    int serving = 0;
    for (size_t i = 0; i < d.nslots; i++) {
        if (d.conns[i].stage == CONN_STAGE_SERVING) { serving = 1; }
    }
    CHECK(serving, "revoke: a live SERVING connection exists before the revoke (canary)");

    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "revoke: connect to site.sock");
    char req[512], resp[16384], hh[160];
    hx(hh, sizeof hh, HANDLE1, sizeof HANDLE1);
    snprintf(req, sizeof req, "REVOKE-DEVICE handle=%s reason=6c656166", hh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK"),
          "revoke: REVOKE-DEVICE succeeds");

    int still = 0;
    for (size_t i = 0; i < d.nslots; i++) {
        if (d.conns[i].stage != CONN_STAGE_FREE) { still = 1; }
    }
    CHECK(!still, "revoke: the live session was CLOSED, not just the row updated (Req 9)");

    snprintf(req, sizeof req, "REVOKE-DEVICE handle=%s reason=00", hh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK"),
          "revoke: revoking again is still OK (idempotent at the API)");

    (void)close(fd);
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* ------------------------------------------------------- enroll via the API */

static void test_enroll(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp, kp2;
    CHECK(h_start(&d, g_dir, "enroll.sqlite3", 1) == 0, "enroll: daemon starts");
    CHECK(mldsa_keypair_generate(&kp) == 0 && mldsa_keypair_generate(&kp2) == 0, "enroll: keys");

    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "enroll: connect");
    char req[9000], resp[16384], uh[160], hh[160], pkh[4000], pk2h[4000];
    hx(uh, sizeof uh, U1, sizeof U1);
    hx(hh, sizeof hh, HANDLE1, sizeof HANDLE1);
    hx(pkh, sizeof pkh, kp.public_key, sizeof kp.public_key);
    hx(pk2h, sizeof pk2h, kp2.public_key, sizeof kp2.public_key);

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, hh, pkh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK fp="),
          "enroll: a new device enrolls and returns its fingerprint");
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && strstr(resp, "idempotent=1") != NULL,
          "enroll: a byte-identical re-enrollment is idempotent");

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, hh, pk2h);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=exists-different-key"),
          "enroll: the same handle with a DIFFERENT key is refused (Req 7)");

    { uint8_t h2[] = { 'd','1','b','b' }; char h2h[160];
      hx(h2h, sizeof h2h, h2, sizeof h2);
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, h2h, pkh);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=pk-in-use"),
            "enroll: a public key already in use cannot be enrolled elsewhere"); }

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery", uh, hh, pkh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=not-permitted"),
          "enroll: via=recovery is refused until V4-9c, not silently accepted");

    /* an operator cannot be created from the site socket, and the role of an
     * existing user is never silently changed */
    int adm = h_dial_unix(d.admin_path);
    CHECK(adm >= 0, "enroll: connect to admin.sock");
    { uint8_t h3[] = { 'd','1','c','c' }; char h3h[160]; mldsa_keypair_t kp3;
      CHECK(mldsa_keypair_generate(&kp3) == 0, "enroll: third key");
      char pk3h[4000]; hx(pk3h, sizeof pk3h, kp3.public_key, sizeof kp3.public_key);
      hx(h3h, sizeof h3h, h3, sizeof h3);
      snprintf(req, sizeof req, "ENROLL-OPERATOR user=%s handle=%s pk=%s via=site", uh, h3h, pk3h);
      CHECK(h_local_cmd(&d, adm, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=role-mismatch"),
            "enroll: an existing `user` is not silently promoted to operator");
      mldsa_keypair_free(&kp3); }

    (void)close(fd); (void)close(adm);
    mldsa_keypair_free(&kp); mldsa_keypair_free(&kp2);
    h_stop(&d);
}

/* ------------------------------------------------------------------ sweep */

static void test_sweep(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "sweep.sqlite3", 1) == 0, "sweep: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "sweep: login");
    CHECK(h_get_login_code(&d, &c, code) == 0, "sweep: code received");

    /* Present canary: the unexpired code is NOT swept. */
    authd_app_maybe_sweep(&d.app);
    CHECK(d.app.swept_codes == 0u, "sweep: an unexpired login code is left alone (canary)");

    /* past the code's 60 s life, and past the sweep interval */
    d.app.now_unix += 120;
    d.app.now_ms += (uint64_t)TOKEN_SWEEP_INTERVAL_MS + 1000u;
    authd_app_maybe_sweep(&d.app);
    CHECK(d.app.swept_codes == 1u, "sweep: an expired login code is removed and counted");

    /* the interval is honoured: an immediate second sweep does nothing */
    const uint64_t before = d.app.swept_codes + d.app.swept_tokens;
    authd_app_maybe_sweep(&d.app);
    CHECK(d.app.swept_codes + d.app.swept_tokens == before,
          "sweep: it does not run again before its interval elapses");

    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* ------------------------------------------------- logging: uid/pid, no secrets */

static void test_log_hygiene(void)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (f == NULL) { printf("SKIP: open_memstream unavailable\n"); return; }

    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "loghyg.sqlite3", 1) == 0, "log: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "log: login");
    CHECK(h_get_login_code(&d, &c, code) == 0, "log: code received");

    authd_log_init(f, AUTHD_LOG_INFO);          /* capture from here on */

    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "log: connect");
    char hexcode[80], req[512], resp[16384];
    hx(hexcode, sizeof hexcode, code, sizeof code);
    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hexcode);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK token="),
          "log: exchange succeeds");
    fflush(f);

    /* PRESENT CANARY: the request IS logged, with the peer's uid. */
    CHECK(strstr(buf, "event=local-request") != NULL && strstr(buf, "cmd=EXCHANGE") != NULL,
          "log: the request is logged with its command name (canary)");
    { char uidpat[64];
      snprintf(uidpat, sizeof uidpat, "uid=%lu", (unsigned long)getuid());
      CHECK(strstr(buf, uidpat) != NULL, "log: the peer's uid is logged (spec 8)"); }
    CHECK(strstr(buf, "pid=") != NULL, "log: the peer's pid is logged (spec 8)");

    /* ...and the secrets are NOT. */
    CHECK(strstr(buf, hexcode) == NULL, "log: the login code never appears in the log");
    { char *tk = strstr(resp, "token=");
      char token_hex[80] = {0};
      if (tk != NULL) { sscanf(tk + 6, "%79[0-9a-f]", token_hex); }
      CHECK(strlen(token_hex) == 64u && strstr(buf, token_hex) == NULL,
            "log: the issued token never appears in the log"); }

    authd_log_init(stderr, AUTHD_LOG_ERROR);
    (void)close(fd);
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
    fclose(f);
    free(buf);
}

int main(void)
{
    if (sodium_init() < 0) { printf("FAIL: sodium_init\n"); return 1; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);
    snprintf(g_dir, sizeof g_dir, "/tmp/authd-localapi-%ld", (long)getpid());
    if (mkdir(g_dir, 0700) != 0) { printf("FAIL: mkdir\n"); return 1; }

    test_grammar();
    test_two_tables();
    test_exchange_verify();
    test_revocation_closes_sessions();
    test_enroll();
    test_sweep();
    test_log_hygiene();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf("%s: test_authd_localapi (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
