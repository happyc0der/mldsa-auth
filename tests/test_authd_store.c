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
#include <unistd.h>
#include <sys/stat.h>

#include <sodium.h>
#include <sqlite3.h>

#include "store.h"
#include "mldsa_wrap.h"

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
static const uint8_t H1[] = { 'd','1','a','a' };
static const uint8_t H2[] = { 'd','1','b','b' };

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
    uint8_t pkA[STORE_PK_BYTES], pkB[STORE_PK_BYTES], pkC[STORE_PK_BYTES];
    make_pk(pkA, 1); make_pk(pkB, 2); make_pk(pkC, 3);

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

        /* happy path */
        CHECK(store_rotate_key(s, H1, sizeof H1, pkB, hsid, sizeof hsid, 0) == STORE_OK, "rotate succeeds");
        CHECK(store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK &&
              memcmp(got, pkB, STORE_PK_BYTES) == 0,
              "after rotation the NEW key is the active one");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkA, hsid, sizeof hsid, 0) == STORE_ERR_CONFLICT,
              "rotating back to a superseded key is refused (pk unique forever)");

        /* ---- the atomicity proof ----
         * Arm the fault so it fires at the point between "old key superseded"
         * and "new key inserted". Without one transaction the store would be
         * left with NO active key for this handle. */
        store_fault_arm(0);
        store_status_t rr = store_rotate_key(s, H1, sizeof H1, pkC, hsid, sizeof hsid, 0);
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
            CHECK(store_rotate_key(s2, H1, sizeof H1, pkC, hsid, sizeof hsid, 0) == STORE_OK,
                  "the rolled-back key was never inserted, so it is still enrollable");
            CHECK(store_audit_verify(s2) == STORE_OK, "audit chain verifies after a rolled-back rotation");
            store_close(s2);
        }
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
        uint8_t uid[STORE_ID_MAX]; size_t uid_len = 0;
        CHECK(store_verify_token(s, th, 150, uid, sizeof uid, &uid_len) == STORE_OK &&
              uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0,
              "verify_token inside its lifetime returns the bound user");
        CHECK(store_verify_token(s, th, 250, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
              "verify_token after expiry is NOT_FOUND");
        CHECK(store_delete_tokens_for_handle(s, H1, sizeof H1) == STORE_OK, "delete tokens for handle");
        CHECK(store_verify_token(s, th, 150, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
              "a deleted token no longer verifies");

        /* revocation deletes tokens */
        CHECK(store_add_token(s, th, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 200, 200) == STORE_OK,
              "re-add token");
        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK, "revoke device");
        CHECK(store_verify_token(s, th, 150, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
              "revoking a device deletes its tokens");

        /* disabling a user drops that user's tokens too */
        { uint8_t th2[STORE_HASH_BYTES]; memset(th2, 0x7e, sizeof th2);
          uint8_t H3[] = {'d','1','c','c'}; uint8_t pk3[STORE_PK_BYTES]; make_pk(pk3, 9);
          CHECK(store_enroll_device(s, H3, sizeof H3, U1, sizeof U1, pk3, "site", "admin", NULL, 0) == STORE_OK,
                "tok: enroll a second device");
          CHECK(store_add_token(s, th2, U1, sizeof U1, H3, sizeof H3, NULL, 0, 100, 200, 200) == STORE_OK,
                "tok: token on the second device");
          CHECK(store_verify_token(s, th2, 150, NULL, 0, NULL) == STORE_OK, "tok: it verifies before disable");
          CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK, "tok: disable the user");
          CHECK(store_verify_token(s, th2, 150, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
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
        CHECK(store_consume_login_code(s, ch, stateh, 150, uid, sizeof uid, &uid_len, NULL, 0, NULL) == STORE_OK,
              "a login code with the right state is consumed");
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

    {
        char cmd[640];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
        /* see the note in test_authd_conn.c: (void) does not silence gcc here */
        if (system(cmd) != 0) { /* best-effort cleanup */ }
    }

    printf("%s: test_authd_store (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
