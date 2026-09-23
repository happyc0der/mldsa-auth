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
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "enroll: via=recovery without a ticket is malformed (the ticket is the authorisation)");

    /* F47: a REFUSED enrollment must leave the store exactly as it was. The
     * original order created the user first and checked the handle after, so
     * naming a fresh user with an already-taken handle answered
     * `exists-different-key` and left that user behind. Both refusals are
     * checked, because they refuse at different points. */
    { uint8_t fresh1[] = { 'n','e','w','1' }, fresh2[] = { 'n','e','w','2' };
      char f1h[160], f2h[160], h9h[160];
      uint8_t h9[] = { 'd','1','z','z' };
      hx(f1h, sizeof f1h, fresh1, sizeof fresh1);
      hx(f2h, sizeof f2h, fresh2, sizeof fresh2);
      hx(h9h, sizeof h9h, h9, sizeof h9);
      char users_before[16384], users_after[16384];
      int adm0 = h_dial_unix(d.admin_path);
      CHECK(adm0 >= 0, "enroll: connect to admin.sock for the user census");
      CHECK(h_local_cmd(&d, adm0, "LIST-USERS", users_before, sizeof users_before) == 0,
            "enroll: user census before the refusals");

      /* (a) a known handle, a different key -- Req 7 */
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", f1h, hh, pk2h);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=exists-different-key"),
            "enroll: a fresh user with an already-enrolled handle is refused (Req 7)");
      /* (b) a fresh handle, but a key already in use elsewhere */
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", f2h, h9h, pkh);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=pk-in-use"),
            "enroll: a fresh user with an already-used public key is refused");

      /* A fresh connection for the second census: the slot the first one used
       * has since been reclaimed, and reusing it would measure the transport
       * rather than the store. */
      (void)close(adm0);
      int adm1 = h_dial_unix(d.admin_path);
      CHECK(adm1 >= 0, "enroll: connect to admin.sock for the second census");
      CHECK(h_local_cmd(&d, adm1, "LIST-USERS", users_after, sizeof users_after) == 0,
            "enroll: user census after the refusals");
      CHECK(strcmp(users_before, users_after) == 0,
            "enroll: NEITHER refusal created a user -- a refused request changes nothing (F47)");
      (void)close(adm1); }

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

    /* F47, the case the fuzzer actually found: a FRESH user name plus a handle
     * whose USER has been disabled. The daemon's pre-check is the three-join
     * active lookup and the store's Req 7 check is the key row alone, so this
     * is exactly where the two disagree -- the pre-check misses, and the old
     * code created the user before the store refused. */
    { snprintf(req, sizeof req, "DISABLE-USER user=%s", uh);
      CHECK(h_local_cmd(&d, adm, req, resp, sizeof resp) == 0 && starts(resp, "OK"),
            "enroll: the handle's user is disabled");
      char before[16384], after[16384];
      int a1 = h_dial_unix(d.admin_path);
      CHECK(a1 >= 0 && h_local_cmd(&d, a1, "LIST-USERS", before, sizeof before) == 0,
            "enroll: census before the disabled-user refusal");
      (void)close(a1);

      mldsa_keypair_t kp4;
      CHECK(mldsa_keypair_generate(&kp4) == 0, "enroll: a fourth, unused key");
      char pk4h[4000], f3h[160];
      uint8_t fresh3[] = { 'n','e','w','3' };
      hx(pk4h, sizeof pk4h, kp4.public_key, sizeof kp4.public_key);
      hx(f3h, sizeof f3h, fresh3, sizeof fresh3);
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", f3h, hh, pk4h);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code="),
            "enroll: a fresh user with a DISABLED user's handle is refused");

      int a2 = h_dial_unix(d.admin_path);
      CHECK(a2 >= 0 && h_local_cmd(&d, a2, "LIST-USERS", after, sizeof after) == 0,
            "enroll: census after the disabled-user refusal");
      CHECK(strcmp(before, after) == 0,
            "enroll: that refusal created no user either -- the pre-check and the store may disagree, the store may not be left half-changed (F47)");
      (void)close(a2);
      mldsa_keypair_free(&kp4); }

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

/* ------------------------------------------------------------- recovery */

/* Pulls the first code out of an `OK codes=c1,c2,...` reply. */
static void first_code(const char *resp, char out[BASE32_CODE_CHARS + 1u])
{
    memset(out, 0, BASE32_CODE_CHARS + 1u);
    const char *p = strstr(resp, "codes=");
    if (p == NULL) { return; }
    p += 6;
    size_t i = 0;
    while (i < BASE32_CODE_CHARS && p[i] != '\0' && p[i] != ',' && p[i] != '\n') { out[i] = p[i]; i++; }
}

static size_t count_codes(const char *resp)
{
    const char *p = strstr(resp, "codes=");
    if (p == NULL) { return 0u; }
    size_t n = 1u;
    for (p += 6; *p != '\0' && *p != '\n'; p++) { if (*p == ',') { n++; } }
    return n;
}

/* The Crockford codec, pinned against LITERAL vectors. A round trip cannot
 * catch a wrong alphabet -- encode and decode would agree with each other -- so
 * the expected strings here are computed by hand from the 5-bit groups. */
static void test_base32(void)
{
    char out[40];

    /* 0x00.. -> all zeros; 0xff.. -> all Z (value 31). */
    { const uint8_t z[BASE32_CODE_BYTES] = {0};
      CHECK(base32_encode(z, sizeof z, out, sizeof out) == 0 &&
            strcmp(out, "0000000000000000") == 0, "base32: ten zero bytes encode to sixteen '0'"); }
    { uint8_t f[BASE32_CODE_BYTES]; memset(f, 0xff, sizeof f);
      CHECK(base32_encode(f, sizeof f, out, sizeof out) == 0 &&
            strcmp(out, "ZZZZZZZZZZZZZZZZ") == 0, "base32: ten 0xff bytes encode to sixteen 'Z'"); }
    /* 0x00 0x44 0x32 0x14 0xc7 = 00000 00001 00010 00011 00100 00101 00110 00111
     *                          =   0     1     2     3     4     5     6     7  */
    { const uint8_t v[5] = { 0x00, 0x44, 0x32, 0x14, 0xc7 };
      CHECK(base32_encode(v, sizeof v, out, sizeof out) == 0 && strcmp(out, "01234567") == 0,
            "base32: the literal five-byte vector encodes to 01234567"); }
    /* The alphabet itself, so a single wrong symbol is named rather than
     * hidden inside a longer string: values 0..31 in order. */
    { const uint8_t all[20] = { 0x00,0x44,0x32,0x14,0xc7,0x42,0x54,0xb6,0x35,0xcf,
                                0x84,0x65,0x3a,0x56,0xd7,0xc6,0x75,0xbe,0x77,0xdf };
      CHECK(base32_encode(all, sizeof all, out, sizeof out) == 0 &&
            strcmp(out, "0123456789ABCDEFGHJKMNPQRSTVWXYZ") == 0,
            "base32: values 0..31 render as Crockford's alphabet, in order"); }

    char n[BASE32_CODE_CHARS + 1u];
    CHECK(base32_normalize("0123456789ABCDEF", 16, n) == 0 && strcmp(n, "0123456789ABCDEF") == 0,
          "base32: a canonical code normalises to itself");
    CHECK(base32_normalize("0123456789abcdef", 16, n) == 0 && strcmp(n, "0123456789ABCDEF") == 0,
          "base32: lower case normalises to upper");
    CHECK(base32_normalize("0123-4567-89AB-CDEF", 19, n) == 0 && strcmp(n, "0123456789ABCDEF") == 0,
          "base32: grouping hyphens are ignored");
    CHECK(base32_normalize("O123456789ABCDEi", 16, n) == 0 && strcmp(n, "0123456789ABCDE1") == 0,
          "base32: the confusables O and i normalise to 0 and 1");
    CHECK(base32_normalize("0123456789ABCDEl", 16, n) == 0 && strcmp(n, "0123456789ABCDE1") == 0,
          "base32: the confusable l normalises to 1");
    CHECK(base32_normalize("0123456789ABCDEU", 16, n) != 0, "base32: U is not in the alphabet");
    CHECK(base32_normalize("0123456789ABCDE", 15, n) != 0, "base32: fifteen symbols is not a code");
    CHECK(base32_normalize("0123456789ABCDEFG", 17, n) != 0, "base32: seventeen symbols is not a code");
    CHECK(base32_normalize("0123456789ABCDE!", 16, n) != 0, "base32: a character outside the set is refused");
    { char dirty[BASE32_CODE_CHARS + 1u];
      memset(dirty, 'X', sizeof dirty);
      CHECK(base32_normalize("0123456789ABCDE!", 16, dirty) != 0 && dirty[0] == '\0',
            "base32: a refused code leaves no partial result in the output"); }
}

static void test_recovery(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "recovery.sqlite3", 1) == 0, "recovery: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "recovery: connect to site.sock");

    mldsa_keypair_t kp;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    char uh[160], req[8192], resp[16384];
    hx(uh, sizeof uh, U1, sizeof U1);

    /* --- issue --- */
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=0", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "recovery: count=0 is malformed");
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=17", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "recovery: count above the §10.3 maximum of 16 is malformed");
    { uint8_t nobody[] = { 'n','o' }; char nh[160]; hx(nh, sizeof nh, nobody, sizeof nobody);
      snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=2", nh);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=invalid"),
            "recovery: issuing for an unknown user is refused"); }

    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=3", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "recovery: RECOVERY-ISSUE returns codes");
    CHECK(count_codes(resp) == 3u, "recovery: exactly `count` codes come back");
    char gen1[BASE32_CODE_CHARS + 1u];
    first_code(resp, gen1);
    CHECK(strlen(gen1) == BASE32_CODE_CHARS, "recovery: a code is sixteen base32 characters");
    { char norm[BASE32_CODE_CHARS + 1u];
      CHECK(base32_normalize(gen1, strlen(gen1), norm) == 0 && strcmp(norm, gen1) == 0,
            "recovery: an issued code is already canonical"); }

    /* The plaintext is returned once and stored only as an Argon2id hash. */
    /* WAL mode: a just-written row is in the -wal file, not the database, so
     * scanning only the database would be a vacuous pass. The canary below is
     * what makes that impossible -- it failed exactly this way when written. */
    { static char blob[8u * 1024u * 1024u];
      size_t got = 0;
      const char *sfx[] = { "", "-wal" };
      for (size_t k = 0; k < 2u; k++) {
          char path[512];
          snprintf(path, sizeof path, "%s/recovery.sqlite3%s", g_dir, sfx[k]);
          FILE *f = fopen(path, "rb");
          if (f == NULL) { continue; }
          got += fread(blob + got, 1, sizeof blob - got - 1u, f);
          fclose(f);
      }
      blob[got] = '\0';
      CHECK(memmem(blob, got, "$argon2id$", 10) != NULL,
            "recovery: the store holds an Argon2id hash (the present canary)");
      CHECK(memmem(blob, got, gen1, BASE32_CODE_CHARS) == NULL,
            "recovery: the plaintext code is NOT in the store (Req 4)"); }

    /* --- use --- */
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, "0000000000000000");
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=invalid"),
          "recovery: a wrong code is invalid");

    /* A code typed the way a human would get it wrong still works: lower case,
     * hyphenated, and with the letter O for the digit zero. */
    char typed[64];
    { size_t j = 0;
      for (size_t i = 0; i < BASE32_CODE_CHARS; i++) {
          if (i > 0u && (i % 4u) == 0u) { typed[j++] = '-'; }
          char ch = gen1[i];
          if (ch >= 'A' && ch <= 'Z') { ch = (char)(ch + ('a' - 'A')); }
          if (ch == '0') { ch = 'o'; }
          if (ch == '1') { ch = 'l'; }
          typed[j++] = ch;
      }
      typed[j] = '\0'; }
    CHECK(strcmp(typed, gen1) != 0, "recovery: the mistyped form really does differ from the issued one");

    const uint64_t kdf_before = d.app.recovery_kdf_calls;
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, typed);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
          "recovery: a lower-case, hyphenated, O-for-0 code is ACCEPTED");
    CHECK(d.app.recovery_kdf_calls > kdf_before,
          "recovery: a verification attempt performs Argon2id (the canary for the locked case)");

    char ticket_hex[80] = {0};
    { const char *t = strstr(resp, "ticket=");
      if (t != NULL) { sscanf(t + 7, "%79[0-9a-f]", ticket_hex); } }
    CHECK(strlen(ticket_hex) == 64u, "recovery: the ticket is 32 bytes of hex");
    long long expires = 0;
    { const char *e = strstr(resp, "expires=");
      if (e != NULL) { sscanf(e + 8, "%lld", &expires); } }
    CHECK(expires == d.app.now_unix + RECOVERY_TICKET_TTL_S,
          "recovery: the ticket expires ten minutes out (§10.3)");

    /* §15's never-list, for the one entry the logging API cannot enforce by
     * shape: a ticket hash is 32 bytes, the exact width authd_log_fp takes, so
     * `authd_log_fp(..., thash)` would compile and leak it. The present canary
     * is that identities DO appear. */
    { char logp[512]; snprintf(logp, sizeof logp, "%s/reclog.txt", g_dir);
      FILE *lf = fopen(logp, "w+");
      CHECK(lf != NULL, "recovery: log capture opens");
      if (lf != NULL) {
          authd_log_init(lf, AUTHD_LOG_INFO);
          char req2[8192], resp2[16384];
          snprintf(req2, sizeof req2, "RECOVERY-ISSUE user=%s count=1", uh);
          (void)h_local_cmd(&d, fd, req2, resp2, sizeof resp2);
          char c2[BASE32_CODE_CHARS + 1u];
          first_code(resp2, c2);
          snprintf(req2, sizeof req2, "RECOVERY-USE user=%s code=%s", uh, c2);
          (void)h_local_cmd(&d, fd, req2, resp2, sizeof resp2);
          char t2[80] = {0};
          { const char *t = strstr(resp2, "ticket=");
            if (t != NULL) { sscanf(t + 7, "%79[0-9a-f]", t2); } }
          authd_log_init(stderr, AUTHD_LOG_ERROR);
          fflush(lf);
          long n = ftell(lf); if (n < 0) { n = 0; }
          rewind(lf);
          char *buf = (char *)calloc((size_t)n + 1u, 1u);
          if (buf != NULL) { if (fread(buf, 1, (size_t)n, lf) != (size_t)n) { buf[0] = '\0'; } }
          CHECK(buf != NULL && strstr(buf, "recovery-issue") != NULL &&
                strstr(buf, "recovery-use") != NULL,
                "recovery: issue and use ARE logged (§15, the present canary)");
          /* authd_log_slot_id renders an identity as printable text, not hex. */
          CHECK(buf != NULL && strstr(buf, "id=u1") != NULL,
                "recovery: the user id IS logged (identities are not secret)");
          CHECK(buf != NULL && strlen(c2) == BASE32_CODE_CHARS && strstr(buf, c2) == NULL,
                "recovery: the recovery CODE never appears in the log (§15)");
          CHECK(buf != NULL && strlen(t2) == 64u && strstr(buf, t2) == NULL,
                "recovery: the enrollment TICKET never appears in the log (§15)");
          free(buf); fclose(lf); } }

    /* single use */
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, gen1);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=invalid"),
          "recovery: a code cannot be used twice");

    /* --- enroll against the ticket --- */
    mldsa_keypair_t kp2;
    CHECK(mldsa_keypair_generate(&kp2) == 0, "recovery: replacement device key");
    char pk2h[4000], h2h[160];
    const uint8_t HANDLE2[] = { 'd','1','n','e','w' };
    hx(pk2h, sizeof pk2h, kp2.public_key, sizeof kp2.public_key);
    hx(h2h, sizeof h2h, HANDLE2, sizeof HANDLE2);

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site ticket=%s", uh, h2h, pk2h, ticket_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "enroll: via=site with a ticket is malformed, not silently ignored");
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery", uh, h2h, pk2h);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "enroll: via=recovery without a ticket is malformed");
    { char bogus[80]; memset(bogus, '0', 64); bogus[64] = '\0';
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s", uh, h2h, pk2h, bogus);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=ticket-invalid"),
            "enroll: an unknown ticket is ticket-invalid"); }

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s", uh, h2h, pk2h, ticket_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK fp="),
          "enroll: via=recovery with a valid ticket enrolls the new device");
    { uint8_t seen[STORE_PK_BYTES];
      CHECK(store_lookup_active(d.store, HANDLE2, sizeof HANDLE2, seen, NULL, 0, NULL, NULL) == STORE_OK &&
            memcmp(seen, kp2.public_key, STORE_PK_BYTES) == 0,
            "enroll: the recovered device is active with the NEW key"); }

    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s", uh, h2h, pk2h, ticket_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=ticket-invalid"),
          "enroll: a ticket is single-use");

    (void)close(fd);
    mldsa_keypair_free(&kp);
    mldsa_keypair_free(&kp2);
    h_stop(&d);
}

/* Supersede, lockout and its expiry: each needs its own store, because they
 * are about counters that the happy path deliberately clears. */
static void test_recovery_policy(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "recovery2.sqlite3", 1) == 0, "policy: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "policy: connect to site.sock");

    mldsa_keypair_t kp;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    char uh[160], req[8192], resp[16384];
    hx(uh, sizeof uh, U1, sizeof U1);

    /* --- superseding bounds the verify loop --- */
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=2", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "policy: first generation issued");
    char old_code[BASE32_CODE_CHARS + 1u];
    first_code(resp, old_code);

    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=2", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "policy: second generation issued");
    char new_code[BASE32_CODE_CHARS + 1u];
    first_code(resp, new_code);

    const uint64_t before = d.app.recovery_kdf_calls;
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, old_code);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=invalid"),
          "policy: a code from the PREVIOUS generation is refused after re-issue");
    CHECK(d.app.recovery_kdf_calls - before == 2u,
          "policy: only the current generation is tried -- the loop stays bounded at `count`");

    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, new_code);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
          "policy: the current generation still works");

    /* --- lockout --- */
    char wrong[BASE32_CODE_CHARS + 1u];
    memset(wrong, '0', BASE32_CODE_CHARS); wrong[BASE32_CODE_CHARS] = '\0';
    for (int i = 0; i < RECOVERY_LOCK_THRESHOLD; i++) {
        snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, wrong);
        CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=invalid"),
              "policy: each of the first five wrong codes answers `invalid`");
    }
    const uint64_t kdf_at_lock = d.app.recovery_kdf_calls;
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, wrong);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=locked"),
          "policy: the sixth attempt is refused with `locked` (§10.3)");
    CHECK(d.app.recovery_kdf_calls == kdf_at_lock,
          "policy: a LOCKED user's attempt performs ZERO Argon2id -- the lockout is checked first");

    /* Even the right code is refused while locked. */
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "policy: issuing still works while recovery is locked");
    char fresh[BASE32_CODE_CHARS + 1u];
    first_code(resp, fresh);
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, fresh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=locked"),
          "policy: issuing new codes does NOT lift the lockout");

    /* ...and it lifts on its own clock, with a lower bound so "it expired"
     * cannot pass for "it was never enforced". */
    d.app.now_unix += RECOVERY_LOCK_SECONDS - 1;
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, fresh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=locked"),
          "policy: one second before the hour is up, still locked");
    d.app.now_unix += 1;
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, fresh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
          "policy: an hour later the lock has lifted and the code works");

    /* --- an operator's recovery is administrative (Req 11) --- */
    int adm = h_dial_unix(d.admin_path);
    CHECK(adm >= 0, "policy: connect to admin.sock");
    { const uint8_t OP[] = { 'o','p' }; char oph[160];
      hx(oph, sizeof oph, OP, sizeof OP);
      CHECK(store_add_user(d.store, OP, sizeof OP, STORE_ROLE_OPERATOR) == STORE_OK,
            "policy: an operator user exists");
      snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", oph);
      CHECK(h_local_cmd(&d, adm, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
            "policy: an operator CAN be issued recovery codes from admin.sock (present canary)");
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=not-permitted"),
            "policy: an operator's recovery codes are NOT mintable from site.sock (Req 11)");
      snprintf(req, sizeof req, "RECOVERY-USE user=%s code=0000000000000000", oph);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=not-permitted"),
            "policy: an operator cannot be recovered from site.sock either"); }

    /* --- a disabled user --- */
    snprintf(req, sizeof req, "DISABLE-USER user=%s", uh);
    CHECK(h_local_cmd(&d, adm, req, resp, sizeof resp) == 0 && starts(resp, "OK"),
          "policy: the user is disabled");
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=user-disabled"),
          "policy: a disabled user cannot be issued codes");
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, fresh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=user-disabled"),
          "policy: a disabled user cannot recover");

    (void)close(fd); (void)close(adm);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* `revoke=all` is the stolen-device case: the most destructive thing the site
 * socket can do, so it gets a present canary on both sides. */
static void test_recovery_revoke_all(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "recovery3.sqlite3", 1) == 0, "revoke-all: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "revoke-all: connect to site.sock");

    mldsa_keypair_t kp;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    char uh[160], req[8192], resp[16384];
    hx(uh, sizeof uh, U1, sizeof U1);

    { uint8_t seen[STORE_PK_BYTES];
      CHECK(store_lookup_active(d.store, HANDLE1, sizeof HANDLE1, seen, NULL, 0, NULL, NULL) == STORE_OK,
            "revoke-all: the old device is active BEFORE recovery (present canary)"); }

    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "revoke-all: codes issued");
    char code[BASE32_CODE_CHARS + 1u];
    first_code(resp, code);

    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s revoke=bogus", uh, code);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=malformed"),
          "revoke-all: an unknown revoke= value is malformed, not treated as `none`");

    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s revoke=all", uh, code);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
          "revoke-all: recovery with revoke=all succeeds");
    { uint8_t seen[STORE_PK_BYTES];
      CHECK(store_lookup_active(d.store, HANDLE1, sizeof HANDLE1, seen, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
            "revoke-all: the lost device is revoked -- its next handshake gets the decoy"); }

    (void)close(fd);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

int main(void)
{
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
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
    test_base32();
    test_recovery();
    test_recovery_policy();
    test_recovery_revoke_all();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf("%s: test_authd_localapi (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
