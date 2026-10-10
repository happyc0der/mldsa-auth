/*
 * V4-7: the store. Every check is named so a mutation's kill is identifiable
 * from the output alone.
 *
 * The centrepiece is ATOMICITY: `store_rotate_key` is the one multi-row
 * operation, and the test drives it through the compiled-in fault hook so a
 * simulated crash lands exactly between superseding the old key and inserting
 * the new one. The store is then REOPENED and required to be either fully
 * rotated or not rotated at all -- never half. That is the property Req 14 /
 * §9.3 claims, proven rather than asserted.
 *
 * This target compiles store.c itself with MLDSA_STORE_FAULT_HOOK (it does not
 * link mldsa_authd, which carries the same object WITHOUT the hook), so the
 * shipped library never contains the fault-injection code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sodium.h>
#include <sqlite3.h>

#include "store.h"
#include "mldsa_wrap.h"
#include "kex.h"          /* kex_hkdf_sha256, to recompute key_log independently */

void store_fault_arm(int n_steps);   /* test-only, from store.c under the hook */

static int g_fail = 0;
static int g_checks = 0;

static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) {
        printf("FAIL: %s\n", what);
        g_fail = 1;
    }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

/* Runs one SQL statement straight against the store file. Used only to play
 * the attacker who has write access to the database -- the store's own API
 * deliberately offers no way to rewrite history. Returns 0 on success. */
static int raw_sql(const char *db, const char *sql)
{
    sqlite3 *h = NULL;
    if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        if (h) { sqlite3_close(h); }
        return -1;
    }
    char *err = NULL;
    int rc = sqlite3_exec(h, sql, NULL, NULL, &err);
    if (err) { sqlite3_free(err); }
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static char g_dir[512];

/* The return IS checked -- see the note in test_authd_keyfile.c (audit finding
 * F19): gcc at -O2 -D_FORTIFY_SOURCE=2 promotes this to
 * -Werror=format-truncation, and a truncated fixture path is a test bug. */
static void path(char *out, size_t cap, const char *leaf)
{
    const int n = snprintf(out, cap, "%s/%s", g_dir, leaf);
    if (n < 0 || (size_t)n >= cap) { fprintf(stderr, "fixture path truncated\n"); abort(); }
}

/* A fresh store on a fresh file; the KEK is fixed so the audit key is
 * reproducible across reopens within a test. */
static const uint8_t KEK[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18, 0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};

static const uint8_t U1[] = { 'u','1' };
static const uint8_t U2[] = { 'u','2' };
static const uint8_t UX[] = { 'n','o' };            /* never added */
static const uint8_t H3[] = { 'd','1','c','c' };
static const uint8_t TH1[STORE_HASH_BYTES] = { 0xa1, 0xa2, 0xa3 };
static const uint8_t TH2[STORE_HASH_BYTES] = { 0xb1, 0xb2, 0xb3 };
static const uint8_t TH3[STORE_HASH_BYTES] = { 0xc1, 0xc2, 0xc3 };

/* Counting helpers for the recovery-code iterator. `first` keeps the newest
 * code_id; `skip` lets the caller reach past it. */
typedef struct { size_t n; int64_t first; } count_ctx_t;
static int count_code(void *vctx, int64_t code_id, const char *pwhash_str)
{
    (void)pwhash_str;
    count_ctx_t *c = (count_ctx_t *)vctx;
    if (c->n == 0u) { c->first = code_id; }
    c->n++;
    return 0;
}
static int first_code_id(void *vctx, int64_t code_id, const char *pwhash_str)
{
    (void)pwhash_str;
    ((count_ctx_t *)vctx)->first = code_id;
    ((count_ctx_t *)vctx)->n++;
    return 1;                                        /* stop at the first */
}
/* The newest still-unused code_id, or 0. */
static int64_t any_unused(const store_t *s, const uint8_t *user, size_t user_len)
{
    count_ctx_t c = { 0u, 0 };
    if (store_list_unused_recovery_codes(s, user, user_len, first_code_id, &c) != STORE_OK) { return 0; }
    return c.first;
}
static const uint8_t H1[] = { 'd','1','a','a' };
static const uint8_t H2[] = { 'd','1','b','b' };

/* Collects the audit rows' timestamps by event, for the F45 checks. */
typedef struct {
    size_t n, wall_rows, revoke_rows;
    int64_t wall_lo, wall_hi, revoke_lo, revoke_hi;
    int64_t rotate_at, issue_at, invalid_at, locked_at, use_at;
} audit_clock_t;
static int audit_clock_row(void *vctx, int64_t seq, int64_t at, const char *event,
                           const uint8_t *user_id, size_t user_id_len,
                           const uint8_t *handle, size_t handle_len, const char *detail)
{
    (void)seq; (void)user_id; (void)user_id_len; (void)handle; (void)handle_len;
    audit_clock_t *c = (audit_clock_t *)vctx;
    c->n++;
    if (strcmp(event, "user-add") == 0 || strcmp(event, "device-enroll") == 0) {
        if (c->wall_rows == 0u || at < c->wall_lo) { c->wall_lo = at; }
        if (c->wall_rows == 0u || at > c->wall_hi) { c->wall_hi = at; }
        c->wall_rows++;
    } else if (strcmp(event, "device-revoke") == 0) {
        if (c->revoke_rows == 0u || at < c->revoke_lo) { c->revoke_lo = at; }
        if (c->revoke_rows == 0u || at > c->revoke_hi) { c->revoke_hi = at; }
        c->revoke_rows++;
    } else if (strcmp(event, "key-rotate") == 0)      { c->rotate_at = at; }
    else if (strcmp(event, "recovery-issue") == 0)    { c->issue_at = at; }
    else if (strcmp(event, "recovery-locked") == 0)   { c->locked_at = at; }
    else if (strcmp(event, "recovery-use") == 0) {
        if (strcmp(detail, "invalid") == 0) { c->invalid_at = at; } else { c->use_at = at; }
    }
    return 0;
}

/* Distinct, well-formed public keys (content is opaque to the store). */
static void make_pk(uint8_t pk[STORE_PK_BYTES], uint8_t seed)
{
    for (size_t i = 0; i < STORE_PK_BYTES; i++) {
        pk[i] = (uint8_t)(seed + (i * 31u));
    }
}

static store_t *fresh_store(const char *leaf, char *path_out, size_t cap)
{
    path(path_out, cap, leaf);
    (void)unlink(path_out);
    store_t *s = NULL;
    if (store_open(path_out, KEK, &s) != STORE_OK) {
        return NULL;
    }
    return s;
}

int main(void)
{
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }
    snprintf(g_dir, sizeof g_dir, "store-test-%ld", (long)getpid());
    if (mkdir(g_dir, 0700) != 0) {
        printf("FAIL: mkdir scratch\n");
        return 1;
    }

    char dbp[512];
    uint8_t pkA[STORE_PK_BYTES], pkB[STORE_PK_BYTES], pkC[STORE_PK_BYTES], pkD[STORE_PK_BYTES];
    make_pk(pkA, 1); make_pk(pkB, 2); make_pk(pkC, 3); make_pk(pkD, 4);

    /* ---- open, meta, audit on a virgin store ---------------------------- */
    {
        store_t *s = fresh_store("a.sqlite3", dbp, sizeof dbp);
        CHECK(s != NULL, "store_open creates a new store");
        if (s == NULL) { return 1; }

        uint8_t sid[STORE_STORE_ID_BYTES], sid2[STORE_STORE_ID_BYTES];
        CHECK(store_get_store_id(s, sid) == STORE_OK, "store_id is available");
        { int nz = 0; for (size_t i = 0; i < sizeof sid; i++) { if (sid[i]) nz = 1; }
          CHECK(nz, "store_id is not all-zero"); }

        uint8_t decoy[STORE_PK_BYTES];
        CHECK(store_get_decoy_pk(s, decoy) == STORE_OK, "decoy_pk is available");
        { int nz = 0; for (size_t i = 0; i < 64u; i++) { if (decoy[i]) nz = 1; }
          CHECK(nz, "decoy_pk is a real generated key, not zeros"); }

        uint8_t head[STORE_AUDIT_MAC_BYTES];
        CHECK(store_audit_head_mac(s, head) == STORE_OK, "head mac readable on an empty log");
        { int z = 1; for (size_t i = 0; i < sizeof head; i++) { if (head[i]) z = 0; }
          CHECK(z, "the empty audit log has an all-zero head mac"); }
        CHECK(store_audit_verify(s) == STORE_OK, "an empty audit chain verifies");

        store_close(s);

        /* reopen: store_id and decoy_pk persist */
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "reopen succeeds");
        CHECK(s2 != NULL && store_get_store_id(s2, sid2) == STORE_OK &&
              memcmp(sid, sid2, sizeof sid) == 0, "store_id persists across reopen");
        store_close(s2);
    }

    /* ---- users, enrollment, invariants ---------------------------------- */
    {
        store_t *s = fresh_store("b.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open b\n"); return 1; }

        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0)
                  == STORE_ERR_CONFLICT,
              "enrolling a device for an unknown user is refused (foreign key)");

        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "add_user");
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_ERR_CONFLICT,
              "the same user_id cannot be added twice");

        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "enroll a device with its first active key");

        /* invariant 3: the 3-join lookup */
        uint8_t got[STORE_PK_BYTES], uid[STORE_ID_MAX];
        size_t uid_len = 0;
        store_role_t role = STORE_ROLE_OPERATOR;
        CHECK(store_lookup_active(s, H1, sizeof H1, got, uid, sizeof uid, &uid_len, &role) == STORE_OK &&
              memcmp(got, pkA, STORE_PK_BYTES) == 0 &&
              uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0 && role == STORE_ROLE_USER,
              "lookup_active returns the active key, its user and role");
        CHECK(store_lookup_active(s, H2, sizeof H2, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
              "lookup_active on an unknown handle is NOT_FOUND");

        /* Req 7: same handle, different key -> rejected AND audited */
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkB, "site", "admin", NULL, 0)
                  == STORE_ERR_CONFLICT,
              "a known handle presenting a different key is rejected (Req 7)");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
              memcmp(got, pkA, STORE_PK_BYTES) == 0,
              "the rejected re-enrollment did not replace the active key");
        /* idempotent with the identical key */
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "re-enrolling the identical key is idempotent");

        /* invariant 2: a public key is unique across devices, forever */
        CHECK(store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, pkA, "site", "admin", NULL, 0)
                  == STORE_ERR_CONFLICT,
              "a public key already in use cannot be enrolled on another handle");

        /* user status gates the lookup */
        CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK, "disable_user");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
              "a disabled user's device does not resolve (3-join)");
        CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK, "enable_user");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK,
              "re-enabling the user restores the lookup");

        /* device status gates the lookup */
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "revoke_device");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
              "a revoked device does not resolve");
        /* invariant 2 again: the revoked key can never come back anywhere */
        CHECK(store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, pkA, "site", "admin", NULL, 0)
                  == STORE_ERR_CONFLICT,
              "a REVOKED public key can never be re-enrolled on any handle");

        CHECK(store_audit_verify(s) == STORE_OK, "the audit chain verifies after the lifecycle");
        store_close(s);
    }

    /* ---- rotation, and its atomicity under an injected fault ------------ */
    {
        store_t *s = fresh_store("c.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open c\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "rot: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "rot: enroll");

        const uint8_t hsid[16] = {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9};
        uint8_t got[STORE_PK_BYTES];
        int64_t rot_at = 0;

        /* happy path */
        CHECK(store_rotate_key(s, H1, sizeof H1, pkB, NULL, hsid, sizeof hsid, 0, 1000, &rot_at, NULL) == STORE_OK,
              "rotate succeeds");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
              memcmp(got, pkB, STORE_PK_BYTES) == 0,
              "after rotation the NEW key is the active one");
        CHECK(rot_at == 1000, "rotate stamps the caller's clock, not its own wall time");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkA, NULL, hsid, sizeof hsid, 0, 1000, NULL, NULL) == STORE_ERR_CONFLICT,
              "rotating back to a superseded key is refused (pk unique forever)");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkB, NULL, hsid, sizeof hsid, 0, 1000, NULL, NULL) == STORE_ERR_STATE,
              "rotating to the key already active is STATE, distinct from a duplicate");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkC, NULL, hsid, 15u, 0, 1000, NULL, NULL) == STORE_ERR_ARG,
              "a handshake_id that is not 16 bytes is refused before any bind");
        {
            int64_t vf = 0;
            CHECK(store_active_key_age(s, H1, sizeof H1, &vf) == STORE_OK && vf == 1000,
                  "the active key's valid_from is readable for the rotation_due hint");
        }

        /* ---- the atomicity proof ----
         * Arm the fault so it fires at the point between "old key superseded"
         * and "new key inserted". Without one transaction the store would be
         * left with NO active key for this handle. */
        store_fault_arm(0);
        store_status_t rr = store_rotate_key(s, H1, sizeof H1, pkC, NULL, hsid, sizeof hsid, 0, 1000, NULL, NULL);
        CHECK(rr != STORE_OK, "a fault injected mid-rotation makes the rotation fail");
        store_fault_arm(-1);

        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
              memcmp(got, pkB, STORE_PK_BYTES) == 0,
              "after the failed rotation the handle STILL has exactly its old active key (in-process)");
        store_close(s);

        /* and the same after a reopen -- the rollback was durable, not cached */
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "reopen after the injected fault");
        if (s2 != NULL) {
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
                  memcmp(got, pkB, STORE_PK_BYTES) == 0,
                  "a half-rotation is impossible: after reopen the old key is still active");
            /* the abandoned new key must not be anywhere */
            CHECK(store_rotate_key(s2, H1, sizeof H1, pkC, NULL, hsid, sizeof hsid, 0, 1000, NULL, NULL) == STORE_OK,
                  "the rolled-back key was never inserted, so it is still enrollable");
            CHECK(store_audit_verify(s2) == STORE_OK, "audit chain verifies after a rolled-back rotation");
            store_close(s2);
        }
    }

    /* Rotation must be refused for a device or a user that is no longer active,
     * and refused INSIDE the transaction rather than by whoever calls it: the
     * daemon and authd_admin are different processes writing the same file, so
     * a caller-side pre-check is a race, and Req 9 says revocation is
     * immediate. All three not-active outcomes answer NOT_FOUND so nothing
     * downstream can tell them apart. */
    {
        char dbp[512];
        store_t *s = fresh_store("d.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open d\n"); return 1; }
        static const uint8_t H2[] = { 'd','1','b','b' };
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "rev-rot: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "rev-rot: enroll one");
        CHECK(store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, pkB, "site", "admin", NULL, 0) == STORE_OK,
              "rev-rot: enroll two");
        const uint8_t hsid[16] = {7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7};

        /* Present canary: this handle CAN rotate right now, so the refusals
         * below are caused by the status change and not by the fixture. */
        CHECK(store_rotate_key(s, H1, sizeof H1, pkC, NULL, hsid, sizeof hsid, 0, 2000, NULL, NULL) == STORE_OK,
              "rev-rot: an active device rotates (canary)");

        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK,
              "rev-rot: revoke the device");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkD, NULL, hsid, sizeof hsid, 0, 2200, NULL, NULL)
                  == STORE_ERR_NOT_FOUND,
              "a revoked device cannot rotate its key");

        CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK,
              "rev-rot: disable the user");
        CHECK(store_rotate_key(s, H2, sizeof H2, pkD, NULL, hsid, sizeof hsid, 0, 2400, NULL, NULL)
                  == STORE_ERR_NOT_FOUND,
              "a disabled user's device cannot rotate its key");
        store_close(s);
    }

    /* ---- tokens and login codes ----------------------------------------- */
    {
        store_t *s = fresh_store("d.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open d\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "tok: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "tok: enroll");

        uint8_t th[STORE_HASH_BYTES];
        memset(th, 0x5a, sizeof th);
        CHECK(store_add_token(s, th, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 200, 200) == STORE_OK,
              "add_token");
        store_token_verdict_t v = STORE_TOKEN_UNKNOWN;
        store_token_info_t ti;
        CHECK(store_verify_token(s, th, 150, 0u, &v, &ti) == STORE_OK && v == STORE_TOKEN_OK &&
              ti.user_id_len == sizeof U1 && memcmp(ti.user_id, U1, sizeof U1) == 0 &&
              ti.handle_len == sizeof H1 && memcmp(ti.handle, H1, sizeof H1) == 0,
              "verify_token inside its lifetime returns the bound user and handle");
        CHECK(store_verify_token(s, th, 250, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_EXPIRED,
              "verify_token past its absolute lifetime is EXPIRED");

        /* V4-9a: the idle window slides, but never past the absolute expiry. */
        CHECK(store_verify_token(s, th, 150, 30u, &v, &ti) == STORE_OK && v == STORE_TOKEN_OK &&
              ti.idle_expires_at == 180, "verify_token slides the idle window forward");
        /* now=175 is inside the idle window (180) but 175+30 would overshoot the
         * absolute expiry (200), so the slide must be clamped to 200. */
        CHECK(store_verify_token(s, th, 175, 30u, &v, &ti) == STORE_OK && v == STORE_TOKEN_OK &&
              ti.idle_expires_at == 200,
              "the slide is CAPPED by expires_at: refreshing cannot outlive the token");
        { /* an idle window that has already passed is reported as such */
          uint8_t th3[STORE_HASH_BYTES]; memset(th3, 0x33, sizeof th3);
          CHECK(store_add_token(s, th3, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 900, 120) == STORE_OK,
                "add a token with a short idle window");
          CHECK(store_verify_token(s, th3, 150, 30u, &v, NULL) == STORE_OK && v == STORE_TOKEN_IDLE_EXPIRED,
                "an idle-expired token is distinguished from an expired one");
          CHECK(store_delete_token(s, th3, NULL) == STORE_OK, "cleanup"); }

        size_t ndel = 0;
        CHECK(store_delete_tokens_for_handle(s, H1, sizeof H1, &ndel) == STORE_OK && ndel == 1u,
              "delete tokens for handle reports the count");
        CHECK(store_verify_token(s, th, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_UNKNOWN,
              "a deleted token no longer verifies");

        /* revocation deletes tokens */
        CHECK(store_add_token(s, th, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 200, 200) == STORE_OK,
              "re-add token");
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "revoke device");
        CHECK(store_verify_token(s, th, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_UNKNOWN,
              "revoking a device deletes its tokens");

        /* A token that OUTLIVES its device -- only reachable by adding one
         * after the revoke -- must report device-revoked, not a generic miss:
         * that distinction is what the site shows the person. */
        { uint8_t th4[STORE_HASH_BYTES]; memset(th4, 0x44, sizeof th4);
          CHECK(store_add_token(s, th4, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 900, 900) == STORE_OK,
                "token on a revoked device");
          CHECK(store_verify_token(s, th4, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_DEVICE_REVOKED,
                "a token whose device was revoked reports DEVICE_REVOKED");
          CHECK(store_delete_token(s, th4, NULL) == STORE_OK, "cleanup"); }

        /* disabling a user drops that user's tokens too */
        { uint8_t th2[STORE_HASH_BYTES]; memset(th2, 0x7e, sizeof th2);
          uint8_t H3[] = {'d','1','c','c'}; uint8_t pk3[STORE_PK_BYTES]; make_pk(pk3, 9);
          CHECK(store_enroll_device(s, H3, sizeof H3, U1, sizeof U1, pk3, "site", "admin", NULL, 0) == STORE_OK,
                "tok: enroll a second device");
          CHECK(store_add_token(s, th2, U1, sizeof U1, H3, sizeof H3, NULL, 0, 100, 200, 200) == STORE_OK,
                "tok: token on the second device");
          CHECK(store_verify_token(s, th2, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_OK,
                "tok: it verifies before disable");
          CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK, "tok: disable the user");
          CHECK(store_verify_token(s, th2, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_UNKNOWN,
                "disabling a user deletes that user's tokens");
          CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK, "tok: re-enable"); }

        /* login code: single use, state-bound */
        uint8_t ch[STORE_HASH_BYTES], stateh[STORE_HASH_BYTES], wrong[STORE_HASH_BYTES];
        memset(ch, 0x11, sizeof ch);
        memset(stateh, 0x22, sizeof stateh);
        memset(wrong, 0x33, sizeof wrong);
        CHECK(store_add_login_code(s, ch, U1, sizeof U1, H1, sizeof H1, NULL, 0, stateh, 100, 200) == STORE_OK,
              "add_login_code");
        CHECK(store_consume_login_code(s, ch, wrong, 150, NULL, 0, NULL, NULL, 0, NULL) == STORE_ERR_CONFLICT,
              "a login code presented with the WRONG state is refused (login-CSRF binding)");
        { uint8_t uid[STORE_ID_MAX]; size_t uid_len = 0;
          CHECK(store_consume_login_code(s, ch, stateh, 150, uid, sizeof uid, &uid_len, NULL, 0, NULL) == STORE_OK &&
                uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0,
                "a login code with the right state is consumed, and returns its user"); }
        CHECK(store_consume_login_code(s, ch, stateh, 150, NULL, 0, NULL, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
              "a login code is single-use");
        store_close(s);
    }

    /* ---- audit chain: tamper and truncation are detected ---------------- */
    {
        store_t *s = fresh_store("e.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open e\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "audit: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "audit: enroll");
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "audit: revoke");
        CHECK(store_audit_verify(s) == STORE_OK, "a well-formed audit chain verifies");

        uint8_t head_before[STORE_AUDIT_MAC_BYTES];
        CHECK(store_audit_head_mac(s, head_before) == STORE_OK, "head mac readable");
        { int nz = 0; for (size_t i = 0; i < sizeof head_before; i++) { if (head_before[i]) nz = 1; }
          CHECK(nz, "a non-empty chain has a non-zero head mac"); }
        store_close(s);

        /* A store is just a file: an attacker with write access edits a row.
         * Rewriting `detail` changes the MAC input, so verification must fail. */
        {
            CHECK(raw_sql(dbp, "UPDATE audit SET detail='tampered' WHERE seq=1;") == 0,
                  "the attacker can edit an audit row (the control: the edit really happens)");
            store_t *s2 = NULL;
            CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "reopen the tampered store");
            if (s2 != NULL) {
                CHECK(store_audit_verify(s2) == STORE_ERR_CORRUPT,
                      "an edited audit row is detected (MAC mismatch)");
                store_close(s2);
            }
        }
    }
    {
        /* truncation: deleting the newest row must be detectable. The head MAC
         * is the published value (§9.2.4: written to the journal), so a
         * truncated log verifies internally but no longer matches the head a
         * second trust domain recorded -- that comparison is what this asserts. */
        store_t *s = fresh_store("f.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open f\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "trunc: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "trunc: enroll");
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "trunc: revoke");
        uint8_t published[STORE_AUDIT_MAC_BYTES];
        CHECK(store_audit_head_mac(s, published) == STORE_OK, "trunc: record the published head");
        store_close(s);

        CHECK(raw_sql(dbp, "DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit);") == 0,
              "trunc: the newest audit row can be deleted (the control)");
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "trunc: reopen the truncated store");
        if (s2 != NULL) {
            uint8_t now_head[STORE_AUDIT_MAC_BYTES];
            CHECK(store_audit_head_mac(s2, now_head) == STORE_OK, "trunc: read head after truncation");
            CHECK(memcmp(published, now_head, sizeof published) != 0,
                  "truncating the audit log changes the head mac (detectable against the journal)");
            store_close(s2);
        }
    }

    /* ---- a wrong KEK cannot verify the chain ---------------------------- */
    {
        store_t *s = fresh_store("g.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open g\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "kek: add_user");
        CHECK(store_audit_verify(s) == STORE_OK, "kek: verifies with the right KEK");
        store_close(s);

        uint8_t bad_kek[32];
        memcpy(bad_kek, KEK, sizeof bad_kek);
        bad_kek[0] ^= 0x01u;
        store_t *s2 = NULL;
        CHECK(store_open(dbp, bad_kek, &s2) == STORE_OK, "kek: store opens with a wrong KEK (it is not a password)");
        if (s2 != NULL) {
            CHECK(store_audit_verify(s2) == STORE_ERR_CORRUPT,
                  "the audit chain does NOT verify under a different KEK");
            store_close(s2);
        }
    }

    /* ---- revoke=all is part of the recovery's ONE transaction (V4-14c, F93) ----
     * RECOVERY-USE with revoke=all used to spend the code in one transaction
     * and revoke each device in its own, so a failure between them left the
     * code spent and only some devices revoked. Now all of it commits together:
     * a fault injected BETWEEN the two revocations must undo everything. */
    {
        store_t *s = fresh_store("ra.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open ra\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkC, "site", "admin", NULL, 0) == STORE_OK &&
              store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, pkD, "site", "admin", NULL, 0) == STORE_OK,
              "revoke-all: a user with two active devices");
        const char *g[] = { "hash-x", "hash-y" };
        CHECK(store_recovery_replace(s, U1, sizeof U1, g, 2, 100, NULL) == STORE_OK, "revoke-all: two codes");
        int64_t id = 0;
        { count_ctx_t c = {0, 0};
          (void)store_list_unused_recovery_codes(s, U1, sizeof U1, first_code_id, &c);
          id = c.first; }

        /* point 1 is consume's own (after the code is marked used); point 2
         * comes after the FIRST revocation -- arm(1) fires there */
        size_t revoked = 99;
        store_fault_arm(1);
        CHECK(store_recovery_consume_ex(s, id, U1, sizeof U1, TH2, 300, 900, 1, &revoked) != STORE_OK,
              "revoke-all: a fault between the two revocations fails the whole recovery");
        store_fault_arm(-1);
        CHECK(revoked == 0u, "revoke-all: ...and reports nothing revoked");
        store_close(s);

        store_t *s2 = NULL;
        uint8_t got[STORE_PK_BYTES];
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "revoke-all: reopen after the fault");
        if (s2 != NULL) {
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
                  store_lookup_active(s2, H2, sizeof H2, got, NULL, 0, NULL, NULL) == STORE_OK,
                  "revoke-all: after the fault BOTH devices are still active -- not one of two");
            { count_ctx_t c = {0, 0};
              CHECK(store_list_unused_recovery_codes(s2, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 2u,
                    "revoke-all: after the fault the code is still unspent"); }
            CHECK(store_audit_verify(s2) == STORE_OK, "revoke-all: the audit chain verifies after the rollback");

            /* the happy path: both revoked, in one commit */
            CHECK(store_recovery_consume_ex(s2, id, U1, sizeof U1, TH2, 300, 900, 1, &revoked) == STORE_OK &&
                  revoked == 2u, "revoke-all: the recovery revokes both devices and says so");
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND &&
                  store_lookup_active(s2, H2, sizeof H2, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
                  "revoke-all: neither device resolves any more");
            CHECK(store_audit_verify(s2) == STORE_OK, "revoke-all: the audit chain verifies");
            store_close(s2);
        }
    }

    /* ---- an audit row is stamped with the clock its transaction used (V4-20, F45) ----
     * audit_append read the wall clock for itself, so a primitive driven by
     * the caller's clock wrote its own columns at that time and its audit row
     * at another: a rotation's valid_from said 1000 while the row recording
     * it said today. Each clock-driven primitive below runs at a time no wall
     * clock will ever read, and its row must say exactly that time. The rows
     * written by primitives that take no clock are the canary: they DO carry
     * the wall time, which shows the reader sees `at` at all. */
    {
        store_t *s = fresh_store("clock.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open clock\n"); return 1; }
        const int64_t wall = (int64_t)time(NULL);
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK &&
              store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, pkB, "site", "admin", NULL, 0) == STORE_OK,
              "clock: a user with two devices");
        int64_t rot_at = 0;
        CHECK(store_rotate_key(s, H1, sizeof H1, pkC, pkA, NULL, 0, 0, 1000, &rot_at, NULL) == STORE_OK &&
              rot_at == 1000, "clock: rotate at 1000");
        const char *g[] = { "hash-c1", "hash-c2" };
        CHECK(store_recovery_replace(s, U1, sizeof U1, g, 2, 1100, NULL) == STORE_OK, "clock: issue at 1100");
        CHECK(store_recovery_note_failure(s, U1, sizeof U1, 1200, 5, 3600, NULL, NULL) == STORE_OK,
              "clock: one wrong code at 1200");
        int locked = 0;
        CHECK(store_recovery_note_failure(s, U1, sizeof U1, 1250, 2, 3600, &locked, NULL) == STORE_OK &&
              locked == 1, "clock: the second wrong code at 1250 locks");
        size_t revoked = 0;
        CHECK(store_recovery_consume_ex(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH1, 1300, 1900,
                                        1, &revoked) == STORE_OK && revoked == 2u,
              "clock: recovery with revoke=all at 1300");

        audit_clock_t ac;
        memset(&ac, 0, sizeof ac);
        CHECK(store_audit_tail(s, 64, audit_clock_row, &ac) == STORE_OK && ac.n == 10u,
              "clock: the ten rows read back");
        CHECK(ac.wall_rows == 3u && ac.wall_lo >= wall - 60 && ac.wall_hi <= (int64_t)time(NULL) + 60,
              "clock(canary): user-add and both enrollments carry the wall time");
        CHECK(ac.rotate_at == 1000, "clock: the key-rotate row is stamped with the rotation's clock");
        CHECK(ac.issue_at == 1100, "clock: the recovery-issue row is stamped with the caller's clock");
        CHECK(ac.invalid_at == 1200, "clock: a failed recovery's row is stamped with the caller's clock");
        CHECK(ac.locked_at == 1250, "clock: the recovery-locked row is stamped with the caller's clock");
        CHECK(ac.use_at == 1300, "clock: the recovery-use row is stamped with the caller's clock");
        CHECK(ac.revoke_rows == 2u && ac.revoke_lo == 1300 && ac.revoke_hi == 1300,
              "clock: revoke=all's two device-revoke rows are stamped with the recovery's clock");
        CHECK(store_audit_verify(s) == STORE_OK, "clock: the audit chain verifies");
        store_close(s);
    }

    /* ---- only the handle's own user re-enrolls it (V4-20, F48) ----
     * A byte-identical re-enrollment is idempotent -- for the user the handle
     * belongs to. The idempotent branch never asked whose handle it was, so
     * u2 naming u1's handle and key got OK, and a recovery ticket of u2's
     * "enrolled" u1's device without spending itself. Nothing was written
     * either way; what was wrong is the answer, which asserted that u2 holds
     * a device it does not. It is the key-reuse refusal now: CONFLICT. */
    {
        store_t *s = fresh_store("owner.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open owner\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_add_user(s, U2, sizeof U2, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "owner: u1 holds d1aa, u2 exists");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "owner(canary): u1 re-enrolling its own handle with the same key is idempotent");
        uint8_t head[STORE_AUDIT_MAC_BYTES], head2[STORE_AUDIT_MAC_BYTES];
        CHECK(store_audit_head_mac(s, head) == STORE_OK, "owner: audit head read");
        CHECK(store_enroll_device(s, H1, sizeof H1, U2, sizeof U2, pkA, "site", "admin", NULL, 0)
                  == STORE_ERR_CONFLICT,
              "owner: another user naming the handle and its key is refused, not idempotent");

        /* the same through a recovery ticket of u2's */
        const char *g[] = { "hash-o" };
        CHECK(store_recovery_replace(s, U2, sizeof U2, g, 1, 100, NULL) == STORE_OK &&
              store_recovery_consume(s, any_unused(s, U2, sizeof U2), U2, sizeof U2, TH1, 300, 900) == STORE_OK,
              "owner: u2 holds a recovery ticket");
        CHECK(store_audit_head_mac(s, head) == STORE_OK, "owner: audit head read");
        CHECK(store_enroll_via_ticket(s, TH1, U2, sizeof U2, H1, sizeof H1, pkA, NULL, 0, 400)
                  == STORE_ERR_CONFLICT,
              "owner: u2's ticket naming u1's handle and key is refused, not idempotent");
        CHECK(store_audit_head_mac(s, head2) == STORE_OK && memcmp(head, head2, sizeof head) == 0,
              "owner: the refusals wrote nothing to the audit chain");
        uint8_t got[STORE_PK_BYTES], uid[STORE_ID_MAX];
        size_t uid_len = 0;
        CHECK(store_lookup_active(s, H1, sizeof H1, got, uid, sizeof uid, &uid_len, NULL) == STORE_OK &&
              uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0,
              "owner: d1aa still belongs to u1");
        CHECK(store_enroll_via_ticket(s, TH1, U2, sizeof U2, H2, sizeof H2, pkB, NULL, 0, 400) == STORE_OK,
              "owner: the refusal did not spend u2's ticket -- it still enrolls a new device");
        CHECK(store_audit_verify(s) == STORE_OK, "owner: the audit chain verifies");
        store_close(s);
    }

    /* ---- the device-status filter holds on its own (V4-15a, CLAIMS D9) ----
     * Revocation marks the device AND its key revoked, so either clause of
     * store_lookup_active's filter would stop a revoked device by itself, and
     * no test could tell if the device clause went missing. Here the key row
     * is left active under a revoked device -- a state no API path can make,
     * only someone with the file -- and the lookup must still refuse it. */
    {
        store_t *s = fresh_store("filter.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open filter\n"); return 1; }
        uint8_t got[STORE_PK_BYTES];
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK &&
              store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK,
              "filter: an active device resolves (the canary)");
        store_close(s);
        CHECK(raw_sql(dbp, "UPDATE devices SET status='revoked' WHERE handle=X'64316161';") == 0,
              "filter: the device is marked revoked behind the store's back, its key row left active");
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "filter: reopen");
        if (s2 != NULL) {
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
                  "filter: a revoked device does not resolve even while its key row is active");
            store_close(s2);
        }
    }

    /* ---- revoke, disable and enroll, each crashed mid-way (V4-15a, D14) ----
     * Each runs in one transaction, and until V4-15a none had ever been
     * crashed part-way. A fault at the point after its first write must leave
     * NOTHING applied, and a reopen shows the rollback is durable rather than
     * cached: the device still resolves, a token issued beforehand still
     * verifies, the user is still active, no user or device appeared and the
     * ticket still redeems. */
    {
        store_t *s = fresh_store("fx.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open fx\n"); return 1; }
        const uint8_t FTH[STORE_HASH_BYTES] = { 0xf1, 0xf2, 0xf3 };      /* a token hash */
        const uint8_t UF[] = { 'u','f' }, HF[] = { 'd','f','f','f' }, HG[] = { 'd','g','g','g' };
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkC, "site", "admin", NULL, 0) == STORE_OK &&
              store_add_token(s, FTH, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 5000, 5000) == STORE_OK,
              "fault: a user with a device and a live token");
        const char *g[] = { "hash-f" };
        CHECK(store_recovery_replace(s, U1, sizeof U1, g, 1, 100, NULL) == STORE_OK &&
              store_recovery_consume(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH3, 300, 900) == STORE_OK,
              "fault: u1 holds an unspent enrollment ticket");
        uint8_t head[STORE_AUDIT_MAC_BYTES], head2[STORE_AUDIT_MAC_BYTES];
        CHECK(store_audit_head_mac(s, head) == STORE_OK, "fault: the audit head before the faults");

        /* point 0 for each call below is the new one after its first write,
         * except enroll-device's: store_enroll_device_ex passes the user
         * point first, so the device-row point is point 1 there. */
        store_fault_arm(0);
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", (const uint8_t *)"x", 1u) != STORE_OK,
              "fault(revoke): a fault after the four writes fails the revocation");
        store_fault_arm(0);
        CHECK(store_disable_user(s, U1, sizeof U1, "admin", (const uint8_t *)"x", 1u) != STORE_OK,
              "fault(disable): a fault after the status write fails the disable");
        store_fault_arm(0);
        CHECK(store_enroll_device_ex(s, HF, sizeof HF, UF, sizeof UF, STORE_ROLE_USER, pkD,
                                     "site", "admin", NULL, 0, NULL, NULL) != STORE_OK,
              "fault(enroll-user): a fault after the user is created fails the enrollment");
        store_fault_arm(1);
        CHECK(store_enroll_device_ex(s, HF, sizeof HF, U1, sizeof U1, STORE_ROLE_USER, pkD,
                                     "site", "admin", NULL, 0, NULL, NULL) != STORE_OK,
              "fault(enroll-device): a fault after the device row fails the enrollment");
        store_fault_arm(0);
        CHECK(store_enroll_via_ticket(s, TH3, U1, sizeof U1, HG, sizeof HG, pkB, NULL, 0, 400) != STORE_OK,
              "fault(ticket): a fault after the ticket is spent fails the enrollment");
        store_fault_arm(-1);
        store_close(s);

        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "fault: reopen after the five faults");
        if (s2 != NULL) {
            uint8_t got[STORE_PK_BYTES];
            store_token_verdict_t v = STORE_TOKEN_UNKNOWN;
            store_role_t role;
            char st[16];
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK,
                  "fault(revoke): after the fault the device still resolves -- the revocation is all or nothing");
            CHECK(store_verify_token(s2, FTH, 150, 0, &v, NULL) == STORE_OK && v == STORE_TOKEN_OK,
                  "fault(revoke, disable): the token issued before the faults still verifies");
            CHECK(store_get_user(s2, U1, sizeof U1, &role, st, sizeof st) == STORE_OK && strcmp(st, "active") == 0,
                  "fault(disable): after the fault the user is still active -- the disable is all or nothing");
            CHECK(store_get_user(s2, UF, sizeof UF, &role, st, sizeof st) == STORE_ERR_NOT_FOUND,
                  "fault(enroll-user): after the fault no user was created (F47's half-state)");
            CHECK(store_audit_head_mac(s2, head2) == STORE_OK && memcmp(head, head2, sizeof head) == 0,
                  "fault: the audit chain did not move");
            CHECK(store_enroll_device_ex(s2, HF, sizeof HF, U1, sizeof U1, STORE_ROLE_USER, pkD,
                                         "site", "admin", NULL, 0, NULL, NULL) == STORE_OK,
                  "fault(enroll-device): the handle enrolls cleanly afterwards -- no device row was left behind");
            CHECK(store_enroll_via_ticket(s2, TH3, U1, sizeof U1, HG, sizeof HG, pkB, NULL, 0, 400) == STORE_OK,
                  "fault(ticket): the ticket still redeems -- the fault did not spend it");
            CHECK(store_audit_verify(s2) == STORE_OK, "fault: the audit chain verifies");
            store_close(s2);
        }
    }

    /* ---- the log pseudonym (V4-13d, spec §15 log_identities = hashed) ---- */
    {
        store_t *s = fresh_store("lp.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open lp\n"); return 1; }
        uint8_t a1[STORE_PSEUDONYM_BYTES], a2[STORE_PSEUDONYM_BYTES], b1[STORE_PSEUDONYM_BYTES];
        CHECK(store_log_pseudonym(s, U1, sizeof U1, a1) == STORE_OK &&
              store_log_pseudonym(s, U1, sizeof U1, a2) == STORE_OK &&
              memcmp(a1, a2, sizeof a1) == 0, "pseudonym: deterministic for one id");
        CHECK(store_log_pseudonym(s, U2, sizeof U2, b1) == STORE_OK &&
              memcmp(a1, b1, sizeof a1) != 0, "pseudonym: two ids, two pseudonyms");

        /* The derivation, recomputed from its definition rather than from the
         * store: key_log = HKDF-SHA256(ikm=KEK, salt=store_id,
         * info="mldsa-authd/v1/log-pseudonym"), pseudonym = the first 8 bytes
         * of keyed BLAKE2b-128(id). authd_admin pseudonym and the daemon share
         * the code, so only an independent recomputation can pin the value an
         * operator's saved grep depends on -- and tell key_log from key_audit. */
        {
            uint8_t sid[STORE_STORE_ID_BYTES], k[32], h[crypto_generichash_BYTES_MIN];
            static const char label[] = "mldsa-authd/v1/log-pseudonym";
            int ok = store_get_store_id(s, sid) == STORE_OK &&
                     kex_hkdf_sha256(k, sizeof k, KEK, sizeof KEK, sid, sizeof sid,
                                     (const uint8_t *)label, sizeof label - 1u) == 0 &&
                     crypto_generichash(h, sizeof h, U1, sizeof U1, k, sizeof k) == 0;
            CHECK(ok && memcmp(h, a1, STORE_PSEUDONYM_BYTES) == 0,
                  "pseudonym: equals BLAKE2b under HKDF(KEK, store_id, log-pseudonym), recomputed");
            static const char alabel[] = "mldsa-authd/v1/audit-mac";
            ok = kex_hkdf_sha256(k, sizeof k, KEK, sizeof KEK, sid, sizeof sid,
                                 (const uint8_t *)alabel, sizeof alabel - 1u) == 0 &&
                 crypto_generichash(h, sizeof h, U1, sizeof U1, k, sizeof k) == 0;
            CHECK(ok && memcmp(h, a1, STORE_PSEUDONYM_BYTES) != 0,
                  "pseudonym: not keyed by the audit key (its own label)");
            sodium_memzero(k, sizeof k);
        }
        /* the empty id is an id; a NULL with a length is not */
        CHECK(store_log_pseudonym(s, NULL, 0u, b1) == STORE_OK, "pseudonym: the empty id has one");
        memset(b1, 0xaa, sizeof b1);
        CHECK(store_log_pseudonym(s, NULL, 3u, b1) == STORE_ERR_ARG &&
              b1[0] == 0 && b1[STORE_PSEUDONYM_BYTES - 1u] == 0,
              "pseudonym: NULL with a length is refused and the output zeroed");
        store_close(s);

        /* stable across a restart: the same store and KEK give the same value */
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "pseudonym: reopen");
        if (s2 != NULL) {
            CHECK(store_log_pseudonym(s2, U1, sizeof U1, a2) == STORE_OK &&
                  memcmp(a1, a2, sizeof a1) == 0, "pseudonym: stable across a restart");
            store_close(s2);
        }
        /* and keyed: a different KEK, or a different store, gives another */
        uint8_t other[32];
        memcpy(other, KEK, sizeof other);
        other[31] ^= 0x80u;
        CHECK(store_open(dbp, other, &s2) == STORE_OK, "pseudonym: open under another KEK");
        if (s2 != NULL) {
            CHECK(store_log_pseudonym(s2, U1, sizeof U1, a2) == STORE_OK &&
                  memcmp(a1, a2, sizeof a1) != 0, "pseudonym: another KEK, another pseudonym");
            store_close(s2);
        }
        char dbp2[600];
        store_t *s3 = fresh_store("lp2.sqlite3", dbp2, sizeof dbp2);
        CHECK(s3 != NULL && store_log_pseudonym(s3, U1, sizeof U1, a2) == STORE_OK &&
              memcmp(a1, a2, sizeof a1) != 0, "pseudonym: another store (store_id), another pseudonym");
        store_close(s3);
    }

    /* ---- backup / restore ------------------------------------------------ */
    {
        store_t *s = fresh_store("h.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open h\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "bk: add_user");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
              "bk: enroll");

        char bak[512];
        path(bak, sizeof bak, "backup.sqlite3");
        (void)unlink(bak);
        CHECK(store_backup(s, bak) == STORE_OK, "backup writes a snapshot");
        CHECK(store_backup(s, bak) == STORE_ERR_IO, "backup refuses to overwrite an existing file");

        /* mutate the live store AFTER the snapshot */
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "bk: revoke after backup");
        uint8_t got[STORE_PK_BYTES];
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
              "bk: the live store reflects the revocation");
        store_close(s);

        /* restore = open the snapshot: it must show the PRE-revocation state
         * and its audit chain must still verify under the same KEK. */
        store_t *r = NULL;
        CHECK(store_open(bak, KEK, &r) == STORE_OK, "the backup opens as a store");
        if (r != NULL) {
            CHECK(store_lookup_active(r, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
                  memcmp(got, pkA, STORE_PK_BYTES) == 0,
                  "the restored snapshot has the pre-revocation state");
            CHECK(store_audit_verify(r) == STORE_OK, "the restored snapshot's audit chain verifies");
            store_close(r);
        }
    }

    /* ---- argument validation --------------------------------------------- */
    {
        store_t *s = fresh_store("i.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open i\n"); return 1; }
        uint8_t pk[STORE_PK_BYTES]; make_pk(pk, 7);
        uint8_t got[STORE_PK_BYTES];
        CHECK(store_add_user(s, NULL, 0, STORE_ROLE_USER) == STORE_ERR_ARG, "add_user rejects NULL id");
        CHECK(store_add_user(s, U1, 0, STORE_ROLE_USER) == STORE_ERR_ARG, "add_user rejects a zero-length id");
        CHECK(store_add_user(s, U1, STORE_ID_MAX + 1u, STORE_ROLE_USER) == STORE_ERR_ARG,
              "add_user rejects an over-long id");
        CHECK(store_lookup_active(s, NULL, 0, got, NULL, 0, NULL, NULL) == STORE_ERR_ARG,
              "lookup rejects a NULL handle");
        CHECK(store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, NULL, "site", "a", NULL, 0) == STORE_ERR_ARG,
              "enroll rejects a NULL pk");
        CHECK(store_open(NULL, KEK, NULL) == STORE_ERR_ARG, "store_open rejects NULL arguments");
        store_close(s);
        store_close(NULL);   /* idempotent */
    }


    /* ---- recovery codes, tickets, and their atomicity (V4-9d, §10.3) ---- */
    {
        store_t *s = fresh_store("r.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open r\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "rec: add_user u1");
        CHECK(store_add_user(s, U2, sizeof U2, STORE_ROLE_USER) == STORE_OK, "rec: add_user u2");

        /* The hashes are opaque to the store, so the test uses distinguishable
         * literals rather than real Argon2id output: what is under test here is
         * the SQL, not the KDF. */
        const char *g1[] = { "hash-a", "hash-b", "hash-c" };
        const char *g2[] = { "hash-d", "hash-e" };
        size_t superseded = 0;

        CHECK(store_recovery_replace(s, U1, sizeof U1, g1, 3, 100, &superseded) == STORE_OK &&
              superseded == 0u, "rec: the first generation supersedes nothing");
        { count_ctx_t c = {0, 0};
          CHECK(store_list_unused_recovery_codes(s, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 3u,
                "rec: three unused codes are listed"); }

        CHECK(store_recovery_replace(s, U1, sizeof U1, g2, 2, 200, &superseded) == STORE_OK &&
              superseded == 3u, "rec: re-issuing supersedes the whole previous generation");
        { count_ctx_t c = {0, 0};
          CHECK(store_list_unused_recovery_codes(s, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 2u,
                "rec: only the current generation is listed -- this is what bounds the verify loop"); }
        CHECK(store_recovery_replace(s, UX, sizeof UX, g1, 1, 100, NULL) == STORE_ERR_NOT_FOUND,
              "rec: issuing for a user that does not exist is refused, not a silent no-op");

        /* One user's code is not another's, even knowing its code_id. */
        int64_t id_u1 = 0;
        { count_ctx_t c = {0, 0};
          (void)store_list_unused_recovery_codes(s, U1, sizeof U1, first_code_id, &c);
          id_u1 = c.first; }
        CHECK(id_u1 != 0, "rec: a code_id was obtained");
        CHECK(store_recovery_consume(s, id_u1, U2, sizeof U2, TH1, 300, 900) == STORE_ERR_NOT_FOUND,
              "rec: user B cannot spend user A's code, even by code_id");
        { count_ctx_t c = {0, 0};
          CHECK(store_list_unused_recovery_codes(s, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 2u,
                "rec: the refused cross-user consume changed nothing"); }

        /* ---- the atomicity proof: a fault between "code spent" and "ticket
         * issued" must leave the code UNSPENT, not spent-with-no-ticket. ---- */
        store_fault_arm(0);
        CHECK(store_recovery_consume(s, id_u1, U1, sizeof U1, TH1, 300, 900) != STORE_OK,
              "rec: a fault injected mid-consume makes the consume fail");
        store_fault_arm(-1);
        { count_ctx_t c = {0, 0};
          CHECK(store_list_unused_recovery_codes(s, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 2u,
                "rec: after the fault the code is STILL unused (in-process)"); }
        store_close(s);

        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "rec: reopen after the injected fault");
        if (s2 != NULL) {
            { count_ctx_t c = {0, 0};
              CHECK(store_list_unused_recovery_codes(s2, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 2u,
                    "rec: a half-consume is impossible: after reopen the code is still spendable"); }
            /* ...and no ticket was left behind by the rolled-back half. */
            CHECK(store_enroll_via_ticket(s2, TH1, U1, sizeof U1, H2, sizeof H2, pkB, NULL, 0, 400)
                      == STORE_ERR_NOT_FOUND,
                  "rec: the rolled-back ticket was never inserted");
            CHECK(store_audit_verify(s2) == STORE_OK, "rec: audit chain verifies after a rolled-back consume");

            /* the happy path, and the ticket it issues */
            CHECK(store_recovery_consume(s2, id_u1, U1, sizeof U1, TH1, 300, 900) == STORE_OK,
                  "rec: consume succeeds");
            { count_ctx_t c = {0, 0};
              CHECK(store_list_unused_recovery_codes(s2, U1, sizeof U1, count_code, &c) == STORE_OK && c.n == 1u,
                    "rec: the spent code is no longer listed"); }
            CHECK(store_recovery_consume(s2, id_u1, U1, sizeof U1, TH2, 300, 900) == STORE_ERR_NOT_FOUND,
                  "rec: a code cannot be spent twice");

            CHECK(store_enroll_via_ticket(s2, TH1, U2, sizeof U2, H2, sizeof H2, pkB, NULL, 0, 400)
                      == STORE_ERR_NOT_FOUND,
                  "rec: a ticket cannot be redeemed by a different user");
            CHECK(store_enroll_via_ticket(s2, TH1, U1, sizeof U1, H2, sizeof H2, pkB, NULL, 0, 901)
                      == STORE_ERR_NOT_FOUND,
                  "rec: a ticket past its expiry is refused (one second after)");
            CHECK(store_enroll_via_ticket(s2, TH1, U1, sizeof U1, H2, sizeof H2, pkB, NULL, 0, 899)
                      == STORE_OK,
                  "rec: a ticket one second before expiry still works (the lower bound)");
            { uint8_t got2[STORE_PK_BYTES];
              CHECK(store_lookup_active(s2, H2, sizeof H2, got2, NULL, 0, NULL, NULL) == STORE_OK &&
                    memcmp(got2, pkB, STORE_PK_BYTES) == 0,
                    "rec: the recovered device is active with its new key"); }
            CHECK(store_enroll_via_ticket(s2, TH1, U1, sizeof U1, H3, sizeof H3, pkC, NULL, 0, 899)
                      == STORE_ERR_NOT_FOUND,
                  "rec: a ticket is single-use");

            /* A pk already in use must not cost the user their ticket. */
            CHECK(store_recovery_consume(s2, any_unused(s2, U1, sizeof U1), U1, sizeof U1, TH2, 300, 900) == STORE_OK,
                  "rec: a second code is spent for the pk-in-use case");
            CHECK(store_enroll_via_ticket(s2, TH2, U1, sizeof U1, H3, sizeof H3, pkB, NULL, 0, 400)
                      == STORE_ERR_CONFLICT,
                  "rec: enrolling an already-used public key is refused");
            CHECK(store_enroll_via_ticket(s2, TH2, U1, sizeof U1, H3, sizeof H3, pkC, NULL, 0, 400)
                      == STORE_OK,
                  "rec: ...and the ticket was NOT spent by that refusal -- it still works");

            /* ---- lockout ---- */
            int locked = 0; int64_t until = 0; int fails = 0;
            CHECK(store_recovery_lock_state(s2, U1, sizeof U1, 1000, &locked, &until, &fails) == STORE_OK &&
                  !locked && fails == 0,
                  "lock: a user who has just recovered is not locked and has no failures");
            for (int i = 1; i < 5; i++) {
                CHECK(store_recovery_note_failure(s2, U1, sizeof U1, 1000, 5, 3600, &locked, &until) == STORE_OK &&
                      !locked, "lock: the first four failures do not lock");
            }
            CHECK(store_recovery_note_failure(s2, U1, sizeof U1, 1000, 5, 3600, &locked, &until) == STORE_OK &&
                  locked && until == 4600,
                  "lock: the fifth failure locks for an hour from the caller's clock");
            CHECK(store_recovery_lock_state(s2, U1, sizeof U1, 4599, &locked, NULL, NULL) == STORE_OK && locked,
                  "lock: still locked one second before the hour is up");
            CHECK(store_recovery_lock_state(s2, U1, sizeof U1, 4600, &locked, NULL, &fails) == STORE_OK &&
                  !locked && fails == 0,
                  "lock: the lock lifts on the hour, with a fresh allowance");
            /* A success must CLEAR the accumulated failures, or a user who
             * fumbles four times and then recovers stays one mistake away
             * from an hour's lockout for ever. */
            { const char *g3[] = { "hash-f", "hash-g" };
              CHECK(store_recovery_replace(s2, U1, sizeof U1, g3, 2, 5000, NULL) == STORE_OK,
                    "lock: a fresh generation for the clear-on-success check");
              for (int i = 0; i < 4; i++) {
                  CHECK(store_recovery_note_failure(s2, U1, sizeof U1, 5000, 5, 3600, &locked, NULL) == STORE_OK &&
                        !locked, "lock: four failures accumulate without locking");
              }
              CHECK(store_recovery_lock_state(s2, U1, sizeof U1, 5000, &locked, NULL, &fails) == STORE_OK &&
                    fails == 4, "lock: the four failures were counted (present canary)");
              CHECK(store_recovery_consume(s2, any_unused(s2, U1, sizeof U1), U1, sizeof U1,
                                           TH3, 5000, 5600) == STORE_OK,
                    "lock: a successful recovery after four failures");
              CHECK(store_recovery_lock_state(s2, U1, sizeof U1, 5000, &locked, NULL, &fails) == STORE_OK &&
                    !locked && fails == 0,
                    "lock: a SUCCESS clears the accumulated failure count"); }

            CHECK(store_recovery_note_failure(s2, UX, sizeof UX, 1000, 5, 3600, NULL, NULL) == STORE_ERR_NOT_FOUND,
                  "lock: noting a failure for a user that does not exist is refused");
            CHECK(store_recovery_lock_state(s2, UX, sizeof UX, 1000, &locked, NULL, NULL) == STORE_ERR_NOT_FOUND,
                  "lock: an unknown user has no lock state");
            CHECK(store_audit_verify(s2) == STORE_OK, "rec: audit chain verifies at the end");
            store_close(s2);
        }
    }

    {
        char cmd[640];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
        /* see the note in test_authd_conn.c: (void) does not silence gcc here */
        if (system(cmd) != 0) { /* best-effort cleanup */ }
    }

    printf("%s: test_authd_store (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
