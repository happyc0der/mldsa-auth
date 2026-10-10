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

/* The store's bytes as they are on disk: the database AND its WAL. In WAL mode
 * a just-written row is in the -wal file, so reading the database alone would
 * be a vacuous pass -- the recovery scan below failed exactly that way when it
 * was written, which is why every scan here carries a present canary. */
static char g_blob[8u * 1024u * 1024u];

static size_t read_store_files(const char *db, char *blob, size_t cap)
{
    size_t got = 0;
    const char *sfx[] = { "", "-wal" };
    for (size_t k = 0; k < 2u; k++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s%s", g_dir, db, sfx[k]);
        FILE *f = fopen(path, "rb");
        if (f == NULL) { continue; }
        got += fread(blob + got, 1, cap - got - 1u, f);
        fclose(f);
    }
    blob[got] = '\0';
    return got;
}

/* Req 4 for a 32-byte secret (a login code, a token, a ticket): the store
 * keeps only its SHA-256. Absent: every 16-byte window of the raw bytes and
 * every 32-character window of the lowercase hex, so half a secret parked in
 * some other column is found too. */
static int secret_absent(const char *blob, size_t n, const uint8_t secret[32])
{
    for (size_t i = 0; i + 16u <= 32u; i++) {
        if (memmem(blob, n, secret + i, 16u) != NULL) { return 0; }
    }
    char hex[65];
    hx(hex, sizeof hex, secret, 32u);
    for (size_t i = 0; i + 32u <= 64u; i++) {
        if (memmem(blob, n, hex + i, 32u) != NULL) { return 0; }
    }
    return 1;
}

/* The present canary for secret_absent: the SHA-256 the store should hold. */
static int secret_hash_present(const char *blob, size_t n, const uint8_t secret[32])
{
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, secret, 32u);
    return memmem(blob, n, h, sizeof h) != NULL;
}

/* Live connections, counted by owner. SERVING only: a closed slot is FREE. */
static size_t serving_for(const h_daemon_t *d, const uint8_t *user, size_t user_len)
{
    size_t n = 0;
    for (size_t i = 0; i < d->nslots; i++) {
        const authd_conn_t *c = &d->conns[i];
        if (c->stage == CONN_STAGE_SERVING && c->user_id_len == user_len &&
            memcmp(c->user_id, user, user_len) == 0) {
            n++;
        }
    }
    return n;
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

    /* Req 4 (CLAIMS D4): the store holds the login code and the live token
     * only as SHA-256 -- which the canary checks first, so an empty read
     * cannot pass for a clean one. */
    { uint8_t token[32];
      size_t tl = 0;
      CHECK(sodium_hex2bin(token, sizeof token, token_hex, strlen(token_hex), NULL, &tl, NULL) == 0 &&
            tl == 32u, "exch: the token decodes");
      const size_t n = read_store_files("exch.sqlite3", g_blob, sizeof g_blob);
      CHECK(secret_hash_present(g_blob, n, code) && secret_hash_present(g_blob, n, token),
            "exch: the store holds the SHA-256 of the login code and of the token (the present canary)");
      CHECK(secret_absent(g_blob, n, code), "exch: the plaintext login code is NOT in the store (Req 4)");
      CHECK(secret_absent(g_blob, n, token), "exch: the plaintext token is NOT in the store (Req 4)");
      sodium_memzero(token, sizeof token); }

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

/* A login code expires 60 s after it is issued (Req 5), and it is the STORE
 * that refuses it at EXCHANGE -- before V4-15a the only check was the TTL
 * LOGIN_CODE advertises on the wire (CLAIMS D5). The harness clock is
 * app.now_unix, fixed while the code is issued, so both sides of the boundary
 * can be hit exactly: expires_at = issue + 60, refused when now >= expires_at. */
static void test_exchange_expiry(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "expiry.sqlite3", 1) == 0, "expiry: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);
    const int64_t t0 = d.app.now_unix;

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0, "expiry: login");
    CHECK(h_get_login_code(&d, &c, code) == 0, "expiry: login code received");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "expiry: connect to site.sock");

    char hexcode[80], req[512], resp[16384];
    hx(hexcode, sizeof hexcode, code, sizeof code);
    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hexcode);

    d.app.now_unix = t0 + (int64_t)AUTHD_LOGIN_CODE_TTL_S;
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=expired"),
          "expiry: at exactly 60 s the login code is refused at EXCHANGE as expired (Req 5)");
    d.app.now_unix = t0 + (int64_t)AUTHD_LOGIN_CODE_TTL_S - 1;
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK token="),
          "expiry: one second earlier the same code exchanges -- the expired attempt did not spend it");

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

/* Req 9 for DISABLE-USER: the user's live session is closed, not just the row
 * updated -- and ONLY that user's, which the second user's session shows.
 * Until V4-15a only REVOKE-DEVICE had a live-session check (CLAIMS D9). */
static void test_disable_closes_sessions(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp, kp2;
    CHECK(h_start(&d, g_dir, "disable.sqlite3", 1) == 0, "disable: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);
    const uint8_t U3[] = { 'u','3' }, H5[] = { 'd','3','c','c' };
    CHECK(mldsa_keypair_generate(&kp2) == 0, "disable: a second user's key");
    CHECK(store_add_user(d.store, U3, sizeof U3, STORE_ROLE_USER) == STORE_OK &&
          store_enroll_device(d.store, H5, sizeof H5, U3, sizeof U3, kp2.public_key,
                              "site", "test", NULL, 0) == STORE_OK,
          "disable: fixture -- a second user with a device");

    h_client_t c1, c2;
    uint8_t code[32];
    CHECK(h_login(&d, &c1, HANDLE1, sizeof HANDLE1, &kp) == 0 && h_get_login_code(&d, &c1, code) == 0,
          "disable: u1 logs in");
    CHECK(h_login(&d, &c2, H5, sizeof H5, &kp2) == 0 && h_get_login_code(&d, &c2, code) == 0,
          "disable: u3 logs in");
    CHECK(serving_for(&d, U1, sizeof U1) == 1u && serving_for(&d, U3, sizeof U3) == 1u,
          "disable: both users have a live SERVING session before the disable (canary)");

    int adm = h_dial_unix(d.admin_path);
    CHECK(adm >= 0, "disable: connect to admin.sock");
    char uh[160], req[512], resp[16384];
    hx(uh, sizeof uh, U1, sizeof U1);
    snprintf(req, sizeof req, "DISABLE-USER user=%s", uh);
    CHECK(h_local_cmd(&d, adm, req, resp, sizeof resp) == 0 && starts(resp, "OK"),
          "disable: DISABLE-USER succeeds");
    CHECK(serving_for(&d, U1, sizeof U1) == 0u,
          "disable: the disabled user's live session was CLOSED, not just the row updated (Req 9)");
    CHECK(serving_for(&d, U3, sizeof U3) == 1u,
          "disable: another user's live session is untouched");

    (void)close(adm);
    h_client_close(&c1);
    h_client_close(&c2);
    mldsa_keypair_free(&kp);
    mldsa_keypair_free(&kp2);
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

/* ------------------------- the state binding, with a state (V4-14a, F79) */

/* Every other EXCHANGE check logs in over the RAW listener, whose state is the
 * empty string by definition (spec 7.1) -- so a daemon that bound SHA-256("")
 * instead of SHA-256(state) passed them all. v48b's C4 mutates exactly that,
 * and scored KILLED(compile) for months, so nobody saw that no test could kill
 * it. Here the login is over the WebSocket with a real state: the empty state
 * must be refused, and only the page's own state yields a token. */
static void test_state_binding_ws(void)
{
    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start(&d, g_dir, "stbind.sqlite3", 1) == 0, "state: daemon starts");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login_on(&d, &c, HANDLE1, sizeof HANDLE1, &kp, "stbind") == 0, "state: login over the WebSocket");
    CHECK(h_get_login_code(&d, &c, code) == 0, "state: login code received");
    int fd = h_dial_unix(d.site_path);
    char hexcode[80], req[512], resp[16384];
    hx(hexcode, sizeof hexcode, code, sizeof code);

    snprintf(req, sizeof req, "EXCHANGE code=%s state=", hexcode);
    CHECK(fd >= 0 && h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=state-mismatch"),
          "state: a WebSocket login's code is refused with the EMPTY state");
    snprintf(req, sizeof req, "EXCHANGE code=%s state=737462696e64", hexcode);      /* "stbind" */
    CHECK(fd >= 0 && h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK token="),
          "state: ...and exchanges with the state the page put in the WebSocket URL");

    if (fd >= 0) { (void)close(fd); }
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* ---------------------------- logging: the privacy switches (V4-13d, F14) */

/* The daemon's own wiring, as authd_main does it: the store computes the
 * pseudonym, so the key never reaches the logger. */
static int store_pseudonym_cb(void *ctx, const uint8_t *id, size_t id_len,
                              uint8_t out[AUTHD_LOG_PSEUDONYM_BYTES])
{
    return store_log_pseudonym((const store_t *)ctx, id, id_len, out) == STORE_OK ? 0 : -1;
}

/* A whole login through the deployed path -- PROXY v2 from 203.0.113.7, the
 * WebSocket listener, EXCHANGE on the site socket -- with log_identities =
 * hashed and log_client_ip = prefix. Every line that would have carried the
 * handle carries the store's pseudonym instead, and every address its /24. */
static void test_log_privacy(void)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (f == NULL) { printf("SKIP: open_memstream unavailable\n"); return; }

    h_daemon_t d;
    mldsa_keypair_t kp;
    CHECK(h_start_opts(&d, g_dir, "logpriv.sqlite3", 1, 1, 0) == 0, "privacy: daemon starts behind PROXY v2");
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);

    uint8_t p[STORE_PSEUDONYM_BYTES];
    char want[64], hexp[2u * STORE_PSEUDONYM_BYTES + 1u];
    CHECK(store_log_pseudonym(d.store, HANDLE1, sizeof HANDLE1, p) == STORE_OK, "privacy: the store's pseudonym");
    h_hex(hexp, sizeof hexp, p, sizeof p);
    snprintf(want, sizeof want, "idh=%s", hexp);

    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_HASHED, AUTHD_LOG_IP_PREFIX,
                                store_pseudonym_cb, d.store) == 0, "privacy: hashed + prefix applied");
    authd_log_init(f, AUTHD_LOG_INFO);

    h_client_t c;
    uint8_t code[32];
    CHECK(h_login_on(&d, &c, HANDLE1, sizeof HANDLE1, &kp, "stpriv") == 0, "privacy: login over PROXY v2");
    CHECK(h_get_login_code(&d, &c, code) == 0, "privacy: code received");
    int fd = h_dial_unix(d.site_path);
    char hexcode[80], req[512], resp[16384];
    hx(hexcode, sizeof hexcode, code, sizeof code);
    snprintf(req, sizeof req, "EXCHANGE code=%s state=737470726976", hexcode);   /* "stpriv" */
    CHECK(fd >= 0 && h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK token="),
          "privacy: exchange succeeds");
    fflush(f);

    /* canaries: the events are there, so absence below means something */
    CHECK(strstr(buf, "event=client-hello") != NULL && strstr(buf, "event=login-code-issued") != NULL &&
          strstr(buf, "event=exchange") != NULL && strstr(buf, "event=client-address") != NULL,
          "privacy: client-hello, login-code-issued, exchange and client-address are logged (canary)");
    { size_t n = 0;
      for (const char *q = buf; (q = strstr(q, want)) != NULL; q++) { n++; }
      CHECK(n >= 3u, "privacy: the handle's lines carry the STORE's pseudonym (client-hello, login-code-issued, exchange)"); }
    CHECK(strstr(buf, " id=") == NULL, "privacy: no line carries id=");
    CHECK(strstr(buf, "src=203.0.113.0/24 ") != NULL, "privacy: the client address is logged as its /24");
    CHECK(strstr(buf, "203.0.113.7") == NULL, "privacy: the client's full address appears nowhere");

    (void)authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_FULL, NULL, NULL);
    authd_log_init(stderr, AUTHD_LOG_ERROR);
    if (fd >= 0) { (void)close(fd); }
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
    { const size_t got = read_store_files("recovery.sqlite3", g_blob, sizeof g_blob);
      CHECK(memmem(g_blob, got, "$argon2id$", 10) != NULL,
            "recovery: the store holds an Argon2id hash (the present canary)");
      CHECK(memmem(g_blob, got, gen1, BASE32_CODE_CHARS) == NULL,
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

    /* ...and the ticket it bought: stored only as SHA-256 (Req 4, CLAIMS D4). */
    { uint8_t ticket[32];
      size_t tl = 0;
      CHECK(sodium_hex2bin(ticket, sizeof ticket, ticket_hex, strlen(ticket_hex), NULL, &tl, NULL) == 0 &&
            tl == 32u, "recovery: the ticket decodes");
      const size_t n = read_store_files("recovery.sqlite3", g_blob, sizeof g_blob);
      CHECK(secret_hash_present(g_blob, n, ticket),
            "recovery: the store holds the ticket's SHA-256 (the present canary)");
      CHECK(secret_absent(g_blob, n, ticket), "recovery: the plaintext ticket is NOT in the store (Req 4)");
      sodium_memzero(ticket, sizeof ticket); }

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

    /* Req 9 reaches live sessions here too (CLAIMS D9): a session is open
     * through both recoveries, and only revoke=all may close it. */
    h_client_t c;
    { uint8_t lc[32];
      CHECK(h_login(&d, &c, HANDLE1, sizeof HANDLE1, &kp) == 0 && h_get_login_code(&d, &c, lc) == 0,
            "revoke-all: the old device has a live session"); }
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", uh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "revoke-all: codes issued for the revoke=none recovery");
    { char c0[BASE32_CODE_CHARS + 1u];
      first_code(resp, c0);
      snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s revoke=none", uh, c0);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
            "revoke-all: a revoke=none recovery succeeds");
      CHECK(serving_for(&d, U1, sizeof U1) == 1u,
            "revoke-all: revoke=none leaves the user's live session open"); }

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
    CHECK(serving_for(&d, U1, sizeof U1) == 0u,
          "revoke-all: the lost device's live session was CLOSED, not just revoked in the store (Req 9)");

    (void)close(fd);
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
}

/* ------------------------------------------- Req 7: rejected AND logged */

/* Runs one request with the journal captured at INFO and returns what was
 * logged (the caller frees it), so each path's lines are checked against that
 * request alone rather than found anywhere in a shared log. */
static char *logged_cmd(h_daemon_t *d, int fd, const char *req, char *resp, size_t cap)
{
    char path[512];
    snprintf(path, sizeof path, "%s/req7.log", g_dir);
    FILE *lf = fopen(path, "w+");
    if (lf == NULL) { resp[0] = '\0'; return NULL; }
    authd_log_init(lf, AUTHD_LOG_INFO);
    if (h_local_cmd(d, fd, req, resp, cap) != 0) { resp[0] = '\0'; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);
    fflush(lf);
    long n = ftell(lf);
    if (n < 0) { n = 0; }
    rewind(lf);
    char *buf = (char *)calloc((size_t)n + 1u, 1u);
    if (buf != NULL && fread(buf, 1, (size_t)n, lf) != (size_t)n) { buf[0] = '\0'; }
    fclose(lf);
    return buf;
}

/* The three lines §15 requires for every Req 7 rejection: the event with the
 * handle, then the fingerprint of the key the handle holds and of the key that
 * was presented -- each compared with a SHA-256 computed here. */
static int req7_logged(const char *log, const char *id, const uint8_t *old_pk, const uint8_t *new_pk)
{
    if (log == NULL || strstr(log, "event=enroll-key-mismatch slot=") == NULL) { return 0; }
    char want[256], hex[crypto_hash_sha256_BYTES * 2u + 1u];
    uint8_t fp[crypto_hash_sha256_BYTES];
    snprintf(want, sizeof want, "id=%s", id);
    if (strstr(log, want) == NULL) { return 0; }
    crypto_hash_sha256(fp, old_pk, STORE_PK_BYTES);
    hx(hex, sizeof hex, fp, sizeof fp);
    snprintf(want, sizeof want, "event=enroll-key-mismatch-old fp=%s", hex);
    if (strstr(log, want) == NULL) { return 0; }
    crypto_hash_sha256(fp, new_pk, STORE_PK_BYTES);
    hx(hex, sizeof hex, fp, sizeof fp);
    snprintf(want, sizeof want, "event=enroll-key-mismatch-new fp=%s", hex);
    return strstr(log, want) != NULL;
}

static int head_is(const h_daemon_t *d, const uint8_t want[STORE_AUDIT_MAC_BYTES])
{
    uint8_t now[STORE_AUDIT_MAC_BYTES];
    return store_audit_head_mac(d->store, now) == STORE_OK && memcmp(now, want, sizeof now) == 0;
}

/* Req 7 (spec §5): re-registering an existing handle with a different key is
 * rejected AND logged -- the logging half is this daemon's own obligation, and
 * §15 lists every Req 7 rejection, with both fingerprints, as always logged.
 * Erratum 45: the journal is that log; a refused enrollment writes nothing to
 * the store, the audit chain included (F47).
 *
 * Four paths refuse a known handle's different key. Until V4-15a only the
 * first logged anything (F97): the other three answered `pk-in-use` in
 * silence, because the daemon's pre-check (a three-join over ACTIVE key,
 * device and user) cannot see them and the store's CONFLICT did not say why. */
static void test_req7_logged(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "req7.sqlite3", 1) == 0, "req7: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "req7: connect to site.sock");

    mldsa_keypair_t kp, other;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(mldsa_keypair_generate(&other) == 0, "req7: the key presented against known handles");

    char uh[160], hh[160], pkh[4000], req[8192], resp[16384];
    uint8_t head[STORE_AUDIT_MAC_BYTES];
    hx(uh, sizeof uh, U1, sizeof U1);
    hx(hh, sizeof hh, HANDLE1, sizeof HANDLE1);
    hx(pkh, sizeof pkh, other.public_key, sizeof other.public_key);

    /* (a) via=site against an active device: the daemon's own pre-check. */
    CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "req7: audit head read");
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, hh, pkh);
    { char *log = logged_cmd(&d, fd, req, resp, sizeof resp);
      CHECK(starts(resp, "ERR code=exists-different-key"),
            "req7(site): a known handle with a different key is refused");
      CHECK(req7_logged(log, "d1aa", kp.public_key, other.public_key),
            "req7(site): the refusal is logged with both key fingerprints");
      CHECK(head_is(&d, head), "req7(site): the refusal wrote nothing to the audit chain (erratum 45)");
      free(log); }

    /* (b) via=site naming a handle whose OWNER is disabled. The request names
     *     another user -- naming the disabled owner is refused earlier, as
     *     user-disabled -- so the three-join misses the handle and the store
     *     refuses it. */
    { const uint8_t U2[] = { 'u','2' }, H2[] = { 'd','2','b','b' }, NEWU[] = { 'n','u' };
      mldsa_keypair_t kp2;
      char h2h[160], nuh[160];
      CHECK(mldsa_keypair_generate(&kp2) == 0, "req7: the disabled owner's key");
      CHECK(store_add_user(d.store, U2, sizeof U2, STORE_ROLE_USER) == STORE_OK &&
            store_enroll_device(d.store, H2, sizeof H2, U2, sizeof U2, kp2.public_key,
                                "site", "test", NULL, 0) == STORE_OK &&
            store_disable_user(d.store, U2, sizeof U2, "test", (const uint8_t *)"x", 1u) == STORE_OK,
            "req7: fixture -- u2's device is enrolled, then u2 is disabled");
      hx(h2h, sizeof h2h, H2, sizeof H2);
      hx(nuh, sizeof nuh, NEWU, sizeof NEWU);
      CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "req7: audit head read");
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", nuh, h2h, pkh);
      char *log = logged_cmd(&d, fd, req, resp, sizeof resp);
      CHECK(starts(resp, "ERR code=exists-different-key"),
            "req7(disabled owner): the handle's different key is refused as exists-different-key");
      CHECK(req7_logged(log, "d2bb", kp2.public_key, other.public_key),
            "req7(disabled owner): the refusal is logged with both key fingerprints");
      CHECK(head_is(&d, head), "req7(disabled owner): the refusal wrote nothing to the audit chain");
      { store_role_t r; char st[16];
        CHECK(store_get_user(d.store, NEWU, sizeof NEWU, &r, st, sizeof st) == STORE_ERR_NOT_FOUND,
              "req7(disabled owner): the refused request created no user (F47)"); }
      free(log);
      mldsa_keypair_free(&kp2); }

    /* (c) via=site naming a REVOKED device's handle. Handles are never reused,
     *     so no key but the one it had can ever be registered under it. */
    { const uint8_t H3[] = { 'd','1','r','v' };
      mldsa_keypair_t kp3;
      char h3h[160];
      CHECK(mldsa_keypair_generate(&kp3) == 0, "req7: the revoked device's key");
      CHECK(store_enroll_device(d.store, H3, sizeof H3, U1, sizeof U1, kp3.public_key,
                                "site", "test", NULL, 0) == STORE_OK &&
            store_revoke_device(d.store, H3, sizeof H3, "test", (const uint8_t *)"x", 1u) == STORE_OK,
            "req7: fixture -- d1rv is enrolled, then revoked");
      hx(h3h, sizeof h3h, H3, sizeof H3);
      CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "req7: audit head read");
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, h3h, pkh);
      char *log = logged_cmd(&d, fd, req, resp, sizeof resp);
      CHECK(starts(resp, "ERR code=exists-different-key"),
            "req7(revoked handle): a new key under a revoked handle is refused as exists-different-key");
      CHECK(req7_logged(log, "d1rv", kp3.public_key, other.public_key),
            "req7(revoked handle): the refusal is logged with both key fingerprints");
      CHECK(head_is(&d, head), "req7(revoked handle): the refusal wrote nothing to the audit chain");
      free(log);
      mldsa_keypair_free(&kp3); }

    /* (d) via=recovery: a ticket authorises a NEW device, never a new key for
     *     a known handle -- and the refusal must not spend it. */
    { snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", uh);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
            "req7: recovery codes issued");
      char code[BASE32_CODE_CHARS + 1u];
      first_code(resp, code);
      snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", uh, code);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
            "req7: a ticket is issued");
      char ticket_hex[80] = {0};
      { const char *t = strstr(resp, "ticket=");
        if (t != NULL) { sscanf(t + 7, "%79[0-9a-f]", ticket_hex); } }
      CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "req7: audit head read");
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s",
               uh, hh, pkh, ticket_hex);
      char *log = logged_cmd(&d, fd, req, resp, sizeof resp);
      CHECK(starts(resp, "ERR code=exists-different-key"),
            "req7(recovery): a known handle with a different key is refused as exists-different-key");
      CHECK(req7_logged(log, "d1aa", kp.public_key, other.public_key),
            "req7(recovery): the refusal is logged with both key fingerprints");
      CHECK(head_is(&d, head), "req7(recovery): the refusal wrote nothing to the audit chain");
      free(log);
      const uint8_t H4[] = { 'd','1','n','w' };
      char h4h[160];
      hx(h4h, sizeof h4h, H4, sizeof H4);
      snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s",
               uh, h4h, pkh, ticket_hex);
      CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK fp="),
            "req7(recovery): the refusal did not spend the ticket -- it still enrolls a new device"); }

    (void)close(fd);
    mldsa_keypair_free(&kp);
    mldsa_keypair_free(&other);
    h_stop(&d);
}

/* V4-20, audit finding F48: a byte-identical re-enrollment is idempotent only
 * for the user the handle belongs to. The pre-check compared the key and never
 * the owner, so `ENROLL user=u2 handle=<u1's> pk=<u1's>` answered
 * `OK fp= idempotent=1` -- a site could conclude it had enrolled a device for
 * u2 -- and via=recovery answered a plain `OK fp=` without spending the
 * ticket. Each is the key-reuse refusal now: `pk-in-use`. */
static void test_enroll_other_users_handle(void)
{
    h_daemon_t d;
    CHECK(h_start(&d, g_dir, "owner.sqlite3", 1) == 0, "owner: daemon starts");
    int fd = h_dial_unix(d.site_path);
    CHECK(fd >= 0, "owner: connect to site.sock");

    mldsa_keypair_t kp, fresh;
    enroll_direct(&d, HANDLE1, sizeof HANDLE1, &kp);
    CHECK(mldsa_keypair_generate(&fresh) == 0, "owner: a fresh key for u2's own device");
    const uint8_t U2[] = { 'u','2' }, NEWU[] = { 'n','u' }, H2[] = { 'd','2','o','w' };
    CHECK(store_add_user(d.store, U2, sizeof U2, STORE_ROLE_USER) == STORE_OK, "owner: u2 exists");

    char uh[160], u2h[160], nuh[160], hh[160], h2h[160], pkh[4000], freshh[4000];
    char req[9000], resp[16384];
    uint8_t head[STORE_AUDIT_MAC_BYTES];
    hx(uh, sizeof uh, U1, sizeof U1);
    hx(u2h, sizeof u2h, U2, sizeof U2);
    hx(nuh, sizeof nuh, NEWU, sizeof NEWU);
    hx(hh, sizeof hh, HANDLE1, sizeof HANDLE1);
    hx(h2h, sizeof h2h, H2, sizeof H2);
    hx(pkh, sizeof pkh, kp.public_key, sizeof kp.public_key);
    hx(freshh, sizeof freshh, fresh.public_key, sizeof fresh.public_key);

    /* the canary: the owner's own re-enrollment is still idempotent */
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", uh, hh, pkh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && strstr(resp, "idempotent=1") != NULL,
          "owner(canary): u1 re-enrolling its own handle and key is idempotent");

    CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "owner: audit head read");
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", u2h, hh, pkh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=pk-in-use"),
          "owner(site): another user naming the handle and its key is refused as pk-in-use");
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=site", nuh, hh, pkh);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=pk-in-use"),
          "owner(site, new user): a request naming a fresh user is refused as pk-in-use");
    { store_role_t r; char st[16];
      CHECK(store_get_user(d.store, NEWU, sizeof NEWU, &r, st, sizeof st) == STORE_ERR_NOT_FOUND,
            "owner(site, new user): the refused request created no user (F47)"); }
    CHECK(head_is(&d, head), "owner(site): the refusals wrote nothing to the audit chain");

    /* via=recovery, with a ticket of u2's own */
    snprintf(req, sizeof req, "RECOVERY-ISSUE user=%s count=1", u2h);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK codes="),
          "owner: recovery codes issued to u2");
    char code[BASE32_CODE_CHARS + 1u];
    first_code(resp, code);
    snprintf(req, sizeof req, "RECOVERY-USE user=%s code=%s", u2h, code);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK ticket="),
          "owner: u2 is issued a ticket");
    char ticket_hex[80] = {0};
    { const char *t = strstr(resp, "ticket=");
      if (t != NULL) { sscanf(t + 7, "%79[0-9a-f]", ticket_hex); } }
    CHECK(store_audit_head_mac(d.store, head) == STORE_OK, "owner: audit head read");
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s",
             u2h, hh, pkh, ticket_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "ERR code=pk-in-use"),
          "owner(recovery): u2's ticket naming u1's handle and key is refused as pk-in-use");
    CHECK(head_is(&d, head), "owner(recovery): the refusal wrote nothing to the audit chain");
    { uint8_t got[STORE_PK_BYTES], uid[STORE_ID_MAX];
      size_t uid_len = 0;
      CHECK(store_lookup_active(d.store, HANDLE1, sizeof HANDLE1, got, uid, sizeof uid, &uid_len, NULL)
                == STORE_OK && uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0,
            "owner: the handle still belongs to u1"); }
    snprintf(req, sizeof req, "ENROLL user=%s handle=%s pk=%s via=recovery ticket=%s",
             u2h, h2h, freshh, ticket_hex);
    CHECK(h_local_cmd(&d, fd, req, resp, sizeof resp) == 0 && starts(resp, "OK fp="),
          "owner(recovery): the refusal did not spend the ticket -- it still enrolls u2's new device");

    (void)close(fd);
    mldsa_keypair_free(&kp);
    mldsa_keypair_free(&fresh);
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
    test_exchange_expiry();
    test_revocation_closes_sessions();
    test_disable_closes_sessions();
    test_enroll();
    test_sweep();
    test_log_hygiene();
    test_log_privacy();
    test_state_binding_ws();
    test_base32();
    test_recovery();
    test_recovery_policy();
    test_recovery_revoke_all();
    test_req7_logged();
    test_enroll_other_users_handle();

    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
      if (system(cmd) != 0) { /* best-effort cleanup */ } }
    printf("%s: test_authd_localapi (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
