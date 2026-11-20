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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sodium.h>
#include <sqlite3.h>

#include "store.h"
#include "schema.sql.h"     /* STORE_SCHEMA_SQL: its text is pinned below (F662) */
#include "mldsa_wrap.h"
#include "kex.h"          /* kex_hkdf_sha256, to recompute key_log independently */

void store_fault_arm(int n_steps);   /* test-only, from store.c under the hook */
void store_fault_arm_write(int n_writes);   /* test-only: fail the n-th writing step (V4-22c) */
int store_fault_arm_write_left(void);       /* -1 once that fault has fired */
void store_fault_arm_commit(int n_commits); /* test-only: fail the n-th COMMIT, transaction left open (V4-23) */
int store_fault_arm_commit_left(void);      /* -1 once that fault has fired */
typedef void (*store_backup_observer_t)(const char *dest_path);
void store_fault_arm_backup_observer(store_backup_observer_t fn); /* test-only (V4-59) */

/* V4-59: what the backup's file looked like the moment VACUUM INTO finished. */
static int g_bk_seen = 0;
static mode_t g_bk_mode = 0;
static void bk_observe(const char *dest)
{
    struct stat st;
    g_bk_seen = (lstat(dest, &st) == 0) ? 1 : -1;
    g_bk_mode = st.st_mode & 07777;
}

/* V4-315 (F541): how often the store called back during a backup. */
static int g_bk_ticks = 0;
static void bk_tick(void *ctx) { (*(int *)ctx)++; }

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
/* SHA-256 of a file's bytes. 0 on success. */
static int file_sha256(const char *p, uint8_t out[crypto_hash_sha256_BYTES])
{
    FILE *f = fopen(p, "rb");
    if (f == NULL) { return -1; }
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) { crypto_hash_sha256_update(&st, buf, n); }
    const int bad = ferror(f);
    (void)fclose(f);
    crypto_hash_sha256_final(&st, out);
    return bad ? -1 : 0;
}

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

/* One integer and one text column of one row, read by another connection.
 * Returns 0 and fills both; -1 if there is no row or the read fails. */
static int raw_row(const char *db, const char *sql, long long *num, char *text, size_t cap)
{
    sqlite3 *h = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *t = sqlite3_column_text(st, 1);
        *num = sqlite3_column_int64(st, 0);
        (void)snprintf(text, cap, "%s", t != NULL ? (const char *)t : "");
        rc = 0;
    }
    sqlite3_finalize(st);
    if (h) { sqlite3_close(h); }
    return rc;
}

/* Another process takes the store's write lock, says so on the pipe, holds it
 * for `ms` and lets go. Returns its pid, or -1.
 *
 * With `go` given, the `ms` are counted from the moment the caller writes a
 * byte to *go, not from the moment the lock was taken: a check that needs the
 * lock HELD must not depend on how soon this process is scheduled. On a fixed
 * 1.2 s timer, a test process that stalled for a second found the lock gone
 * and the daemon's write succeeding (V4-117; seen once on a macOS runner). */
static pid_t hold_write_lock(const char *db, int ms, int *go)
{
    int fds[2];
    int gate[2] = { -1, -1 };
    if (pipe(fds) != 0) { return -1; }
    if (go != NULL && pipe(gate) != 0) { (void)close(fds[0]); (void)close(fds[1]); return -1; }
    const pid_t pid = fork();
    if (pid == 0) {
        sqlite3 *h = NULL;
        (void)close(fds[0]);
        if (go != NULL) { (void)close(gate[1]); }
        if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK ||
            sqlite3_exec(h, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
            _exit(3);
        }
        if (write(fds[1], "L", 1) != 1) { _exit(4); }
        if (go != NULL) {
            char c = 0;
            ssize_t n;
            do { n = read(gate[0], &c, 1); } while (n < 0 && errno == EINTR);
            if (n != 1) { _exit(5); }       /* the caller went away: do not hold on */
        }
        { struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
          (void)nanosleep(&ts, NULL); }
        (void)sqlite3_exec(h, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(h);
        _exit(0);
    }
    (void)close(fds[1]);
    if (go != NULL) { (void)close(gate[0]); }
    if (pid > 0) {
        char c = 0;
        if (read(fds[0], &c, 1) != 1 || c != 'L') {
            (void)close(fds[0]);
            if (go != NULL) { (void)close(gate[1]); }
            (void)waitpid(pid, NULL, 0);
            return -1;
        }
    } else if (go != NULL) {
        (void)close(gate[1]);
    }
    (void)close(fds[0]);
    if (go != NULL) { *go = pid > 0 ? gate[1] : -1; }
    return pid;
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

/* ---- a fault on every write (V4-22c, CLAIMS D14) -------------------------
 *
 * The committed database as ANOTHER connection sees it -- which is what any
 * other process, or the daemon after a crash, would find -- reduced to one
 * SHA-256: every table in sqlite_master by name, every row by rowid, and
 * each column's type and value. Two digests are equal only if no row of any
 * table was added, removed or changed. */
static int db_digest(const char *db, uint8_t out[crypto_hash_sha256_BYTES])
{
    sqlite3 *h = NULL;
    if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (h != NULL) { sqlite3_close(h); }
        return -1;
    }
    crypto_hash_sha256_state hs;
    crypto_hash_sha256_init(&hs);
    int ok = 1;
    sqlite3_stmt *t = NULL;
    if (sqlite3_prepare_v2(h, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;", -1, &t, NULL)
            != SQLITE_OK) {
        ok = 0;
    }
    while (ok && sqlite3_step(t) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(t, 0);
        char q[256];
        sqlite3_stmt *r = NULL;
        snprintf(q, sizeof q, "SELECT * FROM \"%s\" ORDER BY rowid;", name);
        crypto_hash_sha256_update(&hs, (const unsigned char *)name, strlen(name) + 1u);
        if (sqlite3_prepare_v2(h, q, -1, &r, NULL) != SQLITE_OK) { ok = 0; break; }
        int rc;
        while ((rc = sqlite3_step(r)) == SQLITE_ROW) {
            const int nc = sqlite3_column_count(r);
            for (int c = 0; c < nc; c++) {
                const unsigned char ty = (unsigned char)sqlite3_column_type(r, c);
                crypto_hash_sha256_update(&hs, &ty, 1u);
                if (ty == SQLITE_INTEGER) {
                    const sqlite3_int64 v = sqlite3_column_int64(r, c);
                    crypto_hash_sha256_update(&hs, (const unsigned char *)&v, sizeof v);
                } else if (ty == SQLITE_FLOAT) {
                    const double v = sqlite3_column_double(r, c);
                    crypto_hash_sha256_update(&hs, (const unsigned char *)&v, sizeof v);
                } else if (ty == SQLITE_TEXT || ty == SQLITE_BLOB) {
                    const void *v = ty == SQLITE_TEXT ? (const void *)sqlite3_column_text(r, c)
                                                      : sqlite3_column_blob(r, c);
                    const uint32_t n = (uint32_t)sqlite3_column_bytes(r, c);
                    crypto_hash_sha256_update(&hs, (const unsigned char *)&n, sizeof n);
                    if (n > 0u) { crypto_hash_sha256_update(&hs, (const unsigned char *)v, n); }
                }
            }
            crypto_hash_sha256_update(&hs, (const unsigned char *)"\n", 1u);
        }
        if (rc != SQLITE_DONE) { ok = 0; }
        sqlite3_finalize(r);
    }
    sqlite3_finalize(t);
    sqlite3_close(h);
    crypto_hash_sha256_final(&hs, out);
    return ok ? 0 : -1;
}

/* One mutating primitive: `setup` gives it real work on a fresh store,
 * `call` performs it once and returns its status, `want` is what it should
 * return, and `changes` says whether a successful call changes the database
 * (the canary that the digest sees the call at all). */
typedef struct {
    const char *name;
    const char *check;          /* the named check, literal so the claim map can cite it */
    int (*setup)(store_t *s);
    store_status_t (*call)(store_t *s);
    store_status_t want;
    int changes;
    const char *commit_check;   /* the case's own transaction ends in a COMMIT: its named check; NULL if not */
} sweep_case_t;

static uint8_t g_swpk[4][STORE_PK_BYTES];
static const uint8_t SW_HSID[STORE_HSID_BYTES] = { 0x5e };
static const uint8_t SW_CODE[STORE_HASH_BYTES] = { 0xc0, 0xde };
static const uint8_t SW_STATE[STORE_HASH_BYTES] = { 0x57 };

static int sw_user(store_t *s) { return store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK ? 0 : -1; }
static int sw_device(store_t *s)
{
    return sw_user(s) == 0 &&
           store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, g_swpk[0], "site", "admin", NULL, 0) == STORE_OK
           ? 0 : -1;
}
static int sw_token(store_t *s)
{
    return sw_device(s) == 0 &&
           store_add_token(s, TH1, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 10000, 10000) == STORE_OK ? 0 : -1;
}
static int sw_none(store_t *s) { (void)s; return 0; }
static int sw_disabled(store_t *s)
{
    return sw_device(s) == 0 && store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK ? 0 : -1;
}
static int sw_codes(store_t *s)
{
    static const char *const two[] = { "hash-a", "hash-b" };
    return sw_device(s) == 0 && store_recovery_replace(s, U1, sizeof U1, two, 2, 100, NULL) == STORE_OK ? 0 : -1;
}
static int sw_two_devices(store_t *s)
{
    return sw_codes(s) == 0 &&
           store_enroll_device(s, H2, sizeof H2, U1, sizeof U1, g_swpk[1], "site", "admin", NULL, 0) == STORE_OK &&
           store_add_token(s, TH3, U1, sizeof U1, H2, sizeof H2, NULL, 0, 100, 10000, 10000) == STORE_OK ? 0 : -1;
}
static int sw_four_failures(store_t *s)
{
    int ok = sw_user(s) == 0;
    for (int i = 0; ok && i < 4; i++) {
        ok = store_recovery_note_failure(s, U1, sizeof U1, 1200, 5, 3600, NULL, NULL) == STORE_OK;
    }
    return ok ? 0 : -1;
}
static int sw_ticket(store_t *s)
{
    return sw_codes(s) == 0 &&
           store_recovery_consume(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH2, 300, 900) == STORE_OK ? 0 : -1;
}
static int sw_login_code(store_t *s)
{
    return sw_device(s) == 0 &&
           store_add_login_code(s, SW_CODE, U1, sizeof U1, H1, sizeof H1, NULL, 0, SW_STATE, 100, 200) == STORE_OK
           ? 0 : -1;
}
static int sw_expired(store_t *s)
{
    return sw_ticket(s) == 0 &&
           store_add_token(s, TH1, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 10000, 10000) == STORE_OK &&
           store_add_login_code(s, SW_CODE, U1, sizeof U1, H1, sizeof H1, NULL, 0, SW_STATE, 100, 200) == STORE_OK
           ? 0 : -1;
}

static store_status_t sc_add_user(store_t *s) { return store_add_user(s, U1, sizeof U1, STORE_ROLE_USER); }
static store_status_t sc_enroll_new(store_t *s)
{
    return store_enroll_device_ex(s, H1, sizeof H1, U1, sizeof U1, STORE_ROLE_USER, g_swpk[0], "site", "admin",
                                  NULL, 0, NULL, NULL);
}
static store_status_t sc_enroll(store_t *s)
{
    return store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, g_swpk[0], "site", "admin", NULL, 0);
}
static store_status_t sc_enroll_req7(store_t *s)
{
    return store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, g_swpk[1], "site", "admin", NULL, 0);
}
static store_status_t sc_disable(store_t *s) { return store_disable_user(s, U1, sizeof U1, "admin", NULL, 0); }
static store_status_t sc_enable(store_t *s) { return store_enable_user(s, U1, sizeof U1, "admin"); }
static store_status_t sc_rotate(store_t *s)
{
    return store_rotate_key(s, H1, sizeof H1, g_swpk[2], g_swpk[0], SW_HSID, sizeof SW_HSID, 1, 1000, NULL, NULL);
}
static store_status_t sc_revoke(store_t *s) { return store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0); }
static store_status_t sc_touch(store_t *s) { return store_touch_last_seen(s, H1, sizeof H1); }
static store_status_t sc_verify(store_t *s)
{
    store_token_verdict_t v = STORE_TOKEN_UNKNOWN;
    const store_status_t r = store_verify_token(s, TH1, 150, 0u, &v, NULL);
    return (r == STORE_OK && v != STORE_TOKEN_OK) ? STORE_ERR_NOT_FOUND : r;
}
static store_status_t sc_delete_token(store_t *s) { return store_delete_token(s, TH1, NULL); }
static store_status_t sc_delete_handle(store_t *s) { return store_delete_tokens_for_handle(s, U1, sizeof U1, H1, sizeof H1, NULL); }
static store_status_t sc_delete_user(store_t *s) { return store_delete_tokens_for_user(s, U1, sizeof U1, NULL); }
static store_status_t sc_add_token(store_t *s)
{
    return store_add_token(s, TH1, U1, sizeof U1, H1, sizeof H1, NULL, 0, 100, 10000, 10000);
}
static store_status_t sc_add_code(store_t *s)
{
    return store_add_login_code(s, SW_CODE, U1, sizeof U1, H1, sizeof H1, NULL, 0, SW_STATE, 100, 200);
}
static store_status_t sc_consume_code(store_t *s)
{
    return store_consume_login_code(s, SW_CODE, SW_STATE, 150, NULL, 0, NULL, NULL, 0, NULL);
}
static store_status_t sc_replace(store_t *s)
{
    static const char *const two[] = { "hash-c", "hash-d" };
    return store_recovery_replace(s, U1, sizeof U1, two, 2, 200, NULL);
}
static store_status_t sc_consume(store_t *s)
{
    return store_recovery_consume(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH2, 300, 900);
}
static store_status_t sc_consume_all(store_t *s)
{
    return store_recovery_consume_ex(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH2, 300, 900, 1, NULL);
}
static store_status_t sc_failure(store_t *s)
{
    return store_recovery_note_failure(s, U1, sizeof U1, 1200, 5, 3600, NULL, NULL);
}
static store_status_t sc_ticket(store_t *s)
{
    return store_enroll_via_ticket(s, TH2, U1, sizeof U1, H3, sizeof H3, g_swpk[3], NULL, 0, 400);
}
static store_status_t sc_sweep(store_t *s)
{
    store_sweep_counts_t n;
    return store_sweep(s, 100000, &n);
}

/* Faults write 0, 1, 2, ... of one call, in turn, on ONE store handle. While
 * the fault fires, the call must fail and the committed database must be
 * exactly as before it; the first N at which it does not fire is the call's
 * write count, and that call must return what it should. The handle is not
 * reopened between attempts on purpose: a call that left its transaction
 * open after a fault makes the NEXT attempt fail with the fault unfired. */
static int sweep_one(const sweep_case_t *c)
{
    char dbp[600];
    char leaf[64];
    snprintf(leaf, sizeof leaf, "sweep-%s.sqlite3", c->name);
    store_t *s = fresh_store(leaf, dbp, sizeof dbp);
    if (s == NULL || c->setup(s) != 0) {
        printf("  sweep(%s): setup failed\n", c->name);
        if (s != NULL) { store_close(s); }
        return 0;
    }
    uint8_t before[crypto_hash_sha256_BYTES], after[crypto_hash_sha256_BYTES];
    int ok = 1, n = 0;
    for (; n < 64; n++) {
        if (db_digest(dbp, before) != 0) { ok = 0; break; }
        store_fault_arm_write(n);
        const store_status_t r = c->call(s);
        const int fired = store_fault_arm_write_left() == -1;
        store_fault_arm_write(-1);
        if (db_digest(dbp, after) != 0) { ok = 0; break; }
        if (fired) {
            if (r == STORE_OK) {
                printf("  sweep(%s): write %d failed and the call still returned OK\n", c->name, n);
                ok = 0; break;
            }
            if (memcmp(before, after, sizeof before) != 0) {
                printf("  sweep(%s): after the fault at write %d the committed database had changed\n", c->name, n);
                ok = 0; break;
            }
            continue;
        }
        if (r != c->want) {
            printf("  sweep(%s): with the fault unfired the call returned %s, expected %s\n",
                   c->name, store_status_name(r), store_status_name(c->want));
            ok = 0; break;
        }
        if (c->changes && memcmp(before, after, sizeof before) == 0) {
            printf("  sweep(%s): the call changed nothing the digest could see (canary)\n", c->name);
            ok = 0;
        }
        break;
    }
    if (n == 0 || n >= 64) { ok = 0; }
    printf("  sweep(%s): %d write(s), each faulted in turn\n", c->name, n);
    store_close(s);
    return ok;
}

/* A failed COMMIT (V4-23, audit F112). The commit hook fails the call's
 * COMMIT with its transaction still open, which is what SQLite leaves after
 * COMMIT returns SQLITE_BUSY. The call must fail and the committed database
 * be as it was. Then a second store must open the same file -- store_open
 * takes the write lock, which an open transaction would still hold -- and
 * the same handle must complete the call, which it cannot from inside the
 * failed transaction. A case with a transaction of its own must reach the
 * hook: a COMMIT made around tx_commit would not. */
static int commit_one(const sweep_case_t *c)
{
    char dbp[600];
    char leaf[64];
    snprintf(leaf, sizeof leaf, "commit-%s.sqlite3", c->name);
    store_t *s = fresh_store(leaf, dbp, sizeof dbp);
    if (s == NULL || c->setup(s) != 0) {
        printf("  commit(%s): setup failed\n", c->name);
        if (s != NULL) { store_close(s); }
        return 0;
    }
    uint8_t before[crypto_hash_sha256_BYTES], after[crypto_hash_sha256_BYTES];
    int ok = db_digest(dbp, before) == 0;
    store_fault_arm_commit(0);
    store_status_t r = c->call(s);
    const int fired = store_fault_arm_commit_left() == -1;
    store_fault_arm_commit(-1);
    if (!fired) {
        printf("  commit(%s): the call reached no COMMIT through tx_commit\n", c->name);
        store_close(s);
        return 0;
    }
    if (r == STORE_OK) {
        printf("  commit(%s): the COMMIT failed and the call still returned OK\n", c->name);
        ok = 0;
    }
    if (db_digest(dbp, after) != 0 || memcmp(before, after, sizeof before) != 0) {
        printf("  commit(%s): after the failed COMMIT the committed database had changed\n", c->name);
        ok = 0;
    }
    store_t *s2 = NULL;
    if (store_open(dbp, KEK, &s2) != STORE_OK) {
        printf("  commit(%s): a second store could not open the file: the write lock is still held\n", c->name);
        ok = 0;
    } else {
        store_close(s2);
    }
    r = c->call(s);
    if (r != c->want) {
        printf("  commit(%s): the same handle then returned %s, expected %s\n",
               c->name, store_status_name(r), store_status_name(c->want));
        ok = 0;
    } else if (c->changes && (db_digest(dbp, after) != 0 || memcmp(before, after, sizeof before) == 0)) {
        printf("  commit(%s): the call made again changed nothing the digest could see (canary)\n", c->name);
        ok = 0;
    }
    printf("  commit(%s): its COMMIT failed with the transaction open, then the same handle made the call again\n",
           c->name);
    store_close(s);
    return ok;
}

/* V4-284 (F472): an observer that, once VACUUM INTO has written the copy,
 * moves the file aside and leaves a symlink to another file at its name. */
static char g_swap_dest[600], g_swap_target[600];
static int g_swapped = 0;
static void swap_for_symlink(const char *dest_path)
{
    char moved[640];
    snprintf(moved, sizeof moved, "%s.moved", dest_path);
    g_swapped = (rename(dest_path, moved) == 0 && symlink(g_swap_target, dest_path) == 0);
}
static int mode_of_path(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 ? (int)(st.st_mode & 07777) : -1;
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
    /* mkdtemp, not a pid-keyed name (audit F114): a run that crashes leaves its
     * directory behind, and a later run that drew the same pid stopped at once. */
    snprintf(g_dir, sizeof g_dir, "store-test-XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        printf("FAIL: mkdtemp scratch\n");
        return 1;
    }

    char dbp[512];
    uint8_t pkA[STORE_PK_BYTES], pkB[STORE_PK_BYTES], pkC[STORE_PK_BYTES], pkD[STORE_PK_BYTES], pkE[STORE_PK_BYTES];
    make_pk(pkA, 1); make_pk(pkB, 2); make_pk(pkC, 3); make_pk(pkD, 4); make_pk(pkE, 5);

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

        /* V4-200, F277: the DEVICE's status, by itself. store_revoke_device
         * also revokes the key row, and a rotation with no active key is
         * NOT_FOUND whatever the device row says -- so the check below this
         * block passed with the device-status clause removed (v49c W7 was
         * killed only by the disabled-USER check). Here the device row alone
         * says revoked and its key row is left active: the clause is the
         * only thing that can refuse. */
        CHECK(raw_sql(dbp, "UPDATE devices SET status='revoked' WHERE handle=x'64316262';") == 0,
              "rev-rot: one device's row is marked revoked, its key row left active");
        CHECK(store_rotate_key(s, H2, sizeof H2, pkD, NULL, hsid, sizeof hsid, 0, 2100, NULL, NULL)
                  == STORE_ERR_NOT_FOUND,
              "a device whose own row says revoked cannot rotate, even with an active key row (F277)");
        CHECK(raw_sql(dbp, "UPDATE devices SET status='active' WHERE handle=x'64316262';") == 0 &&
              store_rotate_key(s, H2, sizeof H2, pkD, NULL, hsid, sizeof hsid, 0, 2150, NULL, NULL) == STORE_OK,
              "rev-rot: with the row active again the same rotation is accepted (the canary)");

        CHECK(store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK,
              "rev-rot: revoke the device");
        CHECK(store_rotate_key(s, H1, sizeof H1, pkE, NULL, hsid, sizeof hsid, 0, 2200, NULL, NULL)
                  == STORE_ERR_NOT_FOUND,
              "a revoked device cannot rotate its key");

        CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK,
              "rev-rot: disable the user");
        CHECK(store_rotate_key(s, H2, sizeof H2, pkE, NULL, hsid, sizeof hsid, 0, 2400, NULL, NULL)
                  == STORE_ERR_NOT_FOUND,
              "a disabled user's device cannot rotate its key");

        /* V4-215, F292: the same rule for a NEW device. store_rotate_key and
         * the ticket enrollment re-read the user inside their transaction;
         * store_enroll_device_ex did not, and relied on its one caller having
         * looked a moment before. Asked directly, it enrolled an active
         * device for a disabled user -- live the moment the user is enabled
         * -- and added a device under a role the user does not have. */
        static const uint8_t H3[] = { 'd','1','c','c' };
        int created = 1, idem = 1;
        long long devs = -1;
        char unused[8];
        CHECK(store_enroll_device_ex(s, H3, sizeof H3, U1, sizeof U1, STORE_ROLE_USER, pkE, "site", "admin",
                                     NULL, 0, &created, &idem) == STORE_ERR_STATE && created == 0 && idem == 0,
              "enroll-ex: a device for a DISABLED user is refused inside the transaction (F292)");
        CHECK(raw_row(dbp, "SELECT COUNT(*), '' FROM devices WHERE handle=x'64316363';", &devs, unused, sizeof unused) == 0 &&
              devs == 0, "enroll-ex: and no device row is left (F292)");
        CHECK(store_audit_verify(s) == STORE_OK, "enroll-ex: the audit chain still verifies");
        store_close(s);
    }
    {
        char dbp[512];
        store_t *s = fresh_store("d2.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open d2\n"); return 1; }
        static const uint8_t H4[] = { 'd','1','d','d' }, H5[] = { 'd','1','e','e' };
        int created = 0, idem = 0;
        CHECK(store_enroll_device_ex(s, H4, sizeof H4, U1, sizeof U1, STORE_ROLE_USER, pkA, "site", "admin",
                                     NULL, 0, &created, &idem) == STORE_OK && created == 1,
              "enroll-ex: a new user and its first device (the canary)");
        CHECK(store_enroll_device_ex(s, H5, sizeof H5, U1, sizeof U1, STORE_ROLE_OPERATOR, pkB, "site", "admin",
                                     NULL, 0, &created, &idem) == STORE_ERR_STATE,
              "enroll-ex: a device under a role the existing user does not have is refused (F292)");
        CHECK(store_enroll_device_ex(s, H5, sizeof H5, U1, sizeof U1, STORE_ROLE_USER, pkB, "site", "admin",
                                     NULL, 0, &created, &idem) == STORE_OK && created == 0 && idem == 0,
              "enroll-ex: under the user's own role, an active user's second device is enrolled (the canary)");
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

        size_t ndel = 9;
        /* F123: another user named with this handle deletes nothing. */
        CHECK(store_delete_tokens_for_handle(s, U2, sizeof U2, H1, sizeof H1, &ndel) == STORE_OK && ndel == 0u,
              "delete tokens for handle: a user the handle does not belong to deletes nothing (F123)");
        CHECK(store_verify_token(s, th, 150, 0u, &v, NULL) == STORE_OK && v == STORE_TOKEN_OK,
              "delete tokens for handle: ...and the handle's token still verifies (F123)");
        CHECK(store_delete_tokens_for_handle(s, U1, sizeof U1, H1, sizeof H1, &ndel) == STORE_OK && ndel == 1u,
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
        /* H3, the active device: H1 was revoked above, and since V4-79 a code
         * whose device is not active is refused (the checks after this). */
        CHECK(store_add_login_code(s, ch, U1, sizeof U1, H3, sizeof H3, NULL, 0, stateh, 100, 200) == STORE_OK,
              "add_login_code");
        CHECK(store_consume_login_code(s, ch, wrong, 150, NULL, 0, NULL, NULL, 0, NULL) == STORE_ERR_CONFLICT,
              "a login code presented with the WRONG state is refused (login-CSRF binding)");
        { uint8_t uid[STORE_ID_MAX]; size_t uid_len = 0;
          CHECK(store_consume_login_code(s, ch, stateh, 150, uid, sizeof uid, &uid_len, NULL, 0, NULL) == STORE_OK &&
                uid_len == sizeof U1 && memcmp(uid, U1, sizeof U1) == 0,
                "a login code with the right state is consumed, and returns its user"); }
        CHECK(store_consume_login_code(s, ch, stateh, 150, NULL, 0, NULL, NULL, 0, NULL) == STORE_ERR_NOT_FOUND,
              "a login code is single-use");

        /* V4-79, F157: a code issued before its device was revoked, or before
         * its user was disabled, is refused and spent, so it cannot outlive
         * the revocation or come back with a re-enable. */
        { uint8_t c2[STORE_HASH_BYTES], c3[STORE_HASH_BYTES];
          memset(c2, 0x44, sizeof c2);
          memset(c3, 0x55, sizeof c3);
          store_code_verdict_t v = STORE_CODE_OK;
          CHECK(store_add_login_code(s, c2, U1, sizeof U1, H1, sizeof H1, NULL, 0, stateh, 100, 200) == STORE_OK &&
                store_consume_login_code_ex(s, c2, stateh, 150, &v, NULL, 0, NULL, NULL, 0, NULL) == STORE_OK &&
                v == STORE_CODE_DEVICE_REVOKED,
                "a code whose device was revoked after it was issued is refused DEVICE_REVOKED (F157)");
          CHECK(store_consume_login_code_ex(s, c2, stateh, 150, &v, NULL, 0, NULL, NULL, 0, NULL) == STORE_OK &&
                v == STORE_CODE_USED, "...and it is spent");
          /* Since V4-80 a disable spends the codes already issued, so the
           * exchange-time check is pinned with a code that exists only after
           * the disable (as a row written by anything else would). */
          CHECK(store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK &&
                store_add_login_code(s, c3, U1, sizeof U1, H3, sizeof H3, NULL, 0, stateh, 100, 200) == STORE_OK &&
                store_consume_login_code_ex(s, c3, stateh, 150, &v, NULL, 0, NULL, NULL, 0, NULL) == STORE_OK &&
                v == STORE_CODE_USER_DISABLED,
                "a code whose user is disabled when it is presented is refused USER_DISABLED (F157)");
          CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK &&
                store_consume_login_code_ex(s, c3, stateh, 150, &v, NULL, 0, NULL, NULL, 0, NULL) == STORE_OK &&
                v == STORE_CODE_USED, "...and a re-enable does not revive it"); }
        store_close(s);
    }

    /* ---- V4-109: a second disable or enable changes nothing (F194) ------ */
    {
        store_t *s = fresh_store("dd.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open dd\n"); return 1; }
        uint8_t m1[STORE_AUDIT_MAC_BYTES], m2[STORE_AUDIT_MAC_BYTES];
        long long at = 0;
        char why[64];
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_disable_user(s, U1, sizeof U1, "admin", (const uint8_t *)"stolen-device", 13u) == STORE_OK,
              "twice: a user is disabled with a reason");
        /* the first disable is dated in the past, so a rewrite of its time shows */
        CHECK(raw_sql(dbp, "UPDATE users SET disabled_at=1000;") == 0 &&
              store_audit_head_mac(s, m1) == STORE_OK, "twice: the first disable's time and the head are recorded");
        CHECK(store_disable_user(s, U1, sizeof U1, "local-api", (const uint8_t *)"routine-cleanup", 15u) == STORE_OK,
              "twice: a second disable of a disabled user answers OK");
        CHECK(raw_row(dbp, "SELECT disabled_at, CAST(disabled_reason AS TEXT) FROM users;", &at, why, sizeof why) == 0 &&
              at == 1000 && strcmp(why, "stolen-device") == 0,
              "twice: the first disable's time and reason stand (F194)");
        CHECK(store_audit_head_mac(s, m2) == STORE_OK && memcmp(m1, m2, sizeof m1) == 0,
              "twice: the second disable writes no audit entry (F194)");
        CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK &&
              store_audit_head_mac(s, m1) == STORE_OK && memcmp(m1, m2, sizeof m1) != 0,
              "twice: an enable of a disabled user is audited");
        CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK &&
              store_audit_head_mac(s, m2) == STORE_OK && memcmp(m1, m2, sizeof m1) == 0,
              "twice: a second enable of an enabled user answers OK and writes no audit entry (F194)");
        CHECK(store_disable_user(s, UX, sizeof UX, "admin", NULL, 0) == STORE_ERR_NOT_FOUND &&
              store_enable_user(s, UX, sizeof UX, "admin") == STORE_ERR_NOT_FOUND,
              "twice: a user that does not exist is still NOT_FOUND, for both");
        CHECK(store_audit_verify(s) == STORE_OK, "twice: the chain verifies");
        store_close(s);
    }

    /* ---- V4-109: store_open_existing creates nothing, and waits (F192, F193) */
    {
        char miss[600], empty[600];
        struct stat sb;
        store_t *s = fresh_store("oe.sqlite3", dbp, sizeof dbp);
        store_t *t = NULL;
        uint8_t p1[STORE_PSEUDONYM_BYTES], p2[STORE_PSEUDONYM_BYTES];
        if (s == NULL) { printf("FAIL: open oe\n"); return 1; }
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_log_pseudonym(s, U1, sizeof U1, p1) == STORE_OK, "existing: a store with one audit entry");

        path(miss, sizeof miss, "oe-typo.sqlite3");
        (void)unlink(miss);
        CHECK(store_open_existing(miss, KEK, &t) == STORE_ERR_IO && t == NULL,
              "existing: a path that names no file is an I/O failure (F193)");
        CHECK(stat(miss, &sb) != 0, "existing: and no file is created there (F193)");

        path(empty, sizeof empty, "oe-empty.sqlite3");
        { FILE *f = fopen(empty, "wb"); if (f != NULL) { (void)fclose(f); } }
        CHECK(store_open_existing(empty, KEK, &t) == STORE_ERR_DAMAGED && t == NULL &&
              strncmp(store_shape_note(), "it lacks ", 9) == 0,
              "existing: an empty file is not a store (F193)");
        CHECK(stat(empty, &sb) == 0 && sb.st_size == 0, "existing: and it is left empty (F193)");

        /* a database with the schema and no store id: something made the
         * tables, and neither init nor the daemon ever opened it */
        { char noid[600];
          long long ids = -1;
          char unused[8];
          store_t *n = fresh_store("oe-noid.sqlite3", noid, sizeof noid);
          CHECK(n != NULL, "existing: a second store, to take the store id out of");
          store_close(n);
          CHECK(raw_sql(noid, "DELETE FROM meta WHERE key='store_id';") == 0 &&
                store_open_existing(noid, KEK, &t) == STORE_ERR_DAMAGED && t == NULL,
                "existing: a database with no store id is not a store (F193)");
          CHECK(raw_row(noid, "SELECT COUNT(*), '' FROM meta WHERE key='store_id';", &ids, unused, sizeof unused) == 0 &&
                ids == 0, "existing: and it is not given one (F193)"); }

        CHECK(store_open_existing(dbp, KEK, &t) == STORE_OK && t != NULL &&
              store_log_pseudonym(t, U1, sizeof U1, p2) == STORE_OK && memcmp(p1, p2, sizeof p1) == 0 &&
              store_audit_verify(t) == STORE_OK,
              "existing: a real store opens, with the same pseudonym, and its chain verifies");
        store_close(t);
        t = NULL;

        /* V4-213, F290: a reader CHANGES nothing. `authd_admin audit-verify`
         * opened its store read-write and did what a creating open does:
         * switched the file to WAL, ran the schema, generated what was
         * missing. Pointed at a backup it rewrote the backup. */
        { char bk[600], sql[900], side[700];
          path(bk, sizeof bk, "oe-backup.sqlite3");
          (void)unlink(bk);
          snprintf(sql, sizeof sql, "VACUUM INTO '%s';", bk);
          CHECK(raw_sql(dbp, sql) == 0, "reader: a backup of the store, as VACUUM INTO makes one");
          uint8_t h0[crypto_hash_sha256_BYTES], h1[crypto_hash_sha256_BYTES];
          CHECK(file_sha256(bk, h0) == 0, "reader: the backup's digest before");
          CHECK(store_open_existing(bk, KEK, &t) == STORE_OK && t != NULL && store_audit_verify(t) == STORE_OK &&
                store_log_pseudonym(t, U1, sizeof U1, p2) == STORE_OK && memcmp(p1, p2, sizeof p1) == 0,
                "reader: the backup opens, its chain verifies and its pseudonym is the store's (the canary)");
          store_close(t);
          t = NULL;
          CHECK(file_sha256(bk, h1) == 0 && memcmp(h0, h1, sizeof h0) == 0,
                "reader: opening and verifying a backup leaves it byte for byte as it was (F290)");
          snprintf(side, sizeof side, "%s-wal", bk);
          const int wal = stat(side, &sb) == 0;
          snprintf(side, sizeof side, "%s-shm", bk);
          CHECK(!wal && stat(side, &sb) != 0, "reader: and no -wal or -shm file appears beside it (F290)");

          /* a database that is not a store but has a table called meta */
          char other[600];
          long long tables = -1;
          char unused[8];
          path(other, sizeof other, "oe-other.sqlite3");
          (void)unlink(other);
          { sqlite3 *h = NULL;
            const int made = sqlite3_open_v2(other, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK &&
                             sqlite3_exec(h, "CREATE TABLE meta(key TEXT, value BLOB); CREATE TABLE theirs(x);",
                                          NULL, NULL, NULL) == SQLITE_OK;
            (void)sqlite3_close(h);
            CHECK(made, "reader: somebody else's database, with a table called meta"); }
          CHECK(file_sha256(other, h0) == 0 && store_open_existing(other, KEK, &t) == STORE_ERR_DAMAGED && t == NULL,
                "reader: it is refused as not a store");
          CHECK(file_sha256(other, h1) == 0 && memcmp(h0, h1, sizeof h0) == 0 &&
                raw_row(other, "SELECT COUNT(*), '' FROM sqlite_master WHERE type='table';", &tables, unused, sizeof unused) == 0 &&
                tables == 2,
                "reader: and it is left as it was: its bytes, and its two tables (F290)");

          /* a store with a meta value missing is refused, not completed */
          static const char *const gone[] = { "schema_version", "decoy_pk" };
          for (size_t k = 0; k < 2u; k++) {
              char part[600];
              long long rows = -1;
              snprintf(side, sizeof side, "oe-part%zu.sqlite3", k);
              path(part, sizeof part, side);
              (void)unlink(part);
              snprintf(sql, sizeof sql, "VACUUM INTO '%s';", part);
              int ok = raw_sql(dbp, sql) == 0;
              snprintf(sql, sizeof sql, "DELETE FROM meta WHERE key='%s';", gone[k]);
              ok = ok && raw_sql(part, sql) == 0;
              ok = ok && store_open_existing(part, KEK, &t) == STORE_ERR_DAMAGED && t == NULL;
              snprintf(sql, sizeof sql, "SELECT COUNT(*), '' FROM meta WHERE key='%s';", gone[k]);
              ok = ok && raw_row(part, sql, &rows, unused, sizeof unused) == 0 && rows == 0;
              CHECK(ok, k == 0 ? "reader: a store with no schema_version is refused, and is not given one (F290)"
                               : "reader: a store with no decoy key is refused, and is not given one (F290)");
          }

          /* V4-213, F291: the schema version is an unsigned number from 1. */
          static const struct { const char *sql; const char *what; } vers[] = {
              { "UPDATE meta SET value=x'8000000000000000' WHERE key='schema_version';",
                "version: a schema_version with its top bit set is refused, not read as negative and old (F291)" },
              { "UPDATE meta SET value=x'ffffffffffffffff' WHERE key='schema_version';",
                "version: all ones is refused (F291)" },
              { "UPDATE meta SET value=x'0000000000000000' WHERE key='schema_version';",
                "version: zero is not a version (F291)" },
          };
          for (size_t k = 0; k < sizeof vers / sizeof vers[0]; k++) {
              char vp[600];
              snprintf(side, sizeof side, "oe-ver%zu.sqlite3", k);
              path(vp, sizeof vp, side);
              (void)unlink(vp);
              snprintf(sql, sizeof sql, "VACUUM INTO '%s';", vp);
              store_t *w = NULL;
              const int ok = raw_sql(dbp, sql) == 0 && raw_sql(vp, vers[k].sql) == 0 &&
                             store_open_existing(vp, KEK, &t) == STORE_ERR_SCHEMA && t == NULL &&
                             store_open(vp, KEK, &w) == STORE_ERR_SCHEMA && w == NULL;
              CHECK(ok, vers[k].what);
              if (w != NULL) { store_close(w); }
              /* V4-244, F347: and the open that refused it changed nothing.
               * The copy is in SQLite's rollback-journal mode (byte 18 of the
               * header is 1); the daemon's open set WAL (2) and ran its whole
               * schema over the file BEFORE it read the version. */
              if (k == 0) {
                  unsigned char hdr[20] = { 0 };
                  FILE *hf = fopen(vp, "rb");
                  const size_t hn = (hf != NULL) ? fread(hdr, 1, sizeof hdr, hf) : 0u;
                  if (hf != NULL) { (void)fclose(hf); }
                  CHECK(hn == sizeof hdr && hdr[18] == 1u && hdr[19] == 1u,
                        "version: a store of a version this build does not know is refused before anything in it is changed (F347)");
              }
          } }

        /* Another process holds the write lock until told to let go. The
         * daemon's handle gives up after a quarter of a second, however long
         * that takes to be scheduled; then the holder is given 1.2 s more,
         * and the offline open waits it out. */
        { int go = -1;
          const pid_t holder = hold_write_lock(dbp, 1200, &go);
          int st = 0;
          store_status_t busy;
          struct timespec t0, t1;
          long waited_ms;
          CHECK(holder > 0, "busy: another process holds the store's write lock");
          (void)clock_gettime(CLOCK_MONOTONIC, &t0);
          busy = store_disable_user(s, U1, sizeof U1, "admin", NULL, 0);
          (void)clock_gettime(CLOCK_MONOTONIC, &t1);
          waited_ms = (long)(t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
          /* The lock is held throughout, so only the time tells a quarter of a
           * second from an offline tool's five: under 3 s is "briefly". */
          if (busy != STORE_ERR_DB || waited_ms >= 3000) {
              printf("  busy: the daemon's handle returned %d after %ld ms\n", (int)busy, waited_ms);
          }
          CHECK(busy == STORE_ERR_DB && waited_ms < 3000,
                "busy: the daemon's handle waits only briefly, then reports database-error");
          /* V4-326 (F598): and it does WAIT, a quarter of a second. The lock
           * is held throughout here, so a handle with no wait at all returns
           * at once, whatever the scheduler does. The 60 ms leg below was
           * what killed that mutant (v89 OE6), and only when this process
           * was not stalled past the 60 ms: the kind of kill F596 was. */
          CHECK(busy == STORE_ERR_DB && waited_ms >= 200,
                "busy: the daemon's handle waits about a quarter of a second before it gives up, not no time at all (F598)");
          CHECK(go >= 0 && write(go, "G", 1) == 1, "busy: the holder is told to let go in 1.2 s");
          if (go >= 0) { (void)close(go); }
          CHECK(store_open_existing(dbp, KEK, &t) == STORE_OK && t != NULL,
                "busy: store_open_existing waits for the lock instead of failing (F192)");
          store_close(t);
          t = NULL;
          CHECK(holder > 0 && waitpid(holder, &st, 0) == holder && WIFEXITED(st) && WEXITSTATUS(st) == 0,
                "busy: the lock holder ran to its end"); }
        { const pid_t holder = hold_write_lock(dbp, 60, NULL);
          int st = 0;
          CHECK(holder > 0 && store_disable_user(s, U1, sizeof U1, "admin", NULL, 0) == STORE_OK,
                "busy: the daemon's handle waits out a lock held for 60 ms (F192)");
          CHECK(holder > 0 && waitpid(holder, &st, 0) == holder && WIFEXITED(st) && WEXITSTATUS(st) == 0,
                "busy: that holder ran to its end too"); }
        store_close(s);
    }

    /* ---- V4-111: a store says whether this open made it, and is made 0600
     * (F199, F200) */
    {
        char np[600], wal[640];
        struct stat sb;
        store_t *s = NULL, *t = NULL;
        path(np, sizeof np, "made.sqlite3");
        (void)unlink(np);
        const mode_t um = umask(022);
        const store_status_t st = store_open(np, KEK, &s);
        (void)umask(um);
        CHECK(st == STORE_OK && s != NULL && store_was_created(s) == 1,
              "created: the open that makes a store says so (F199)");
        CHECK(stat(np, &sb) == 0 && (sb.st_mode & 07777) == 0600,
              "created: a store made under a umask of 022 is 0600 (F200)");
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK,
              "created: a write, so the write-ahead log exists");
        (void)snprintf(wal, sizeof wal, "%s-wal", np);
        CHECK(stat(wal, &sb) == 0 && (sb.st_mode & 07777) == 0600,
              "created: and so is its write-ahead log (F200)");
        CHECK(store_open(np, KEK, &t) == STORE_OK && t != NULL && store_was_created(t) == 0,
              "created: a second open of the same store does not say so (F199)");
        store_close(t);
        t = NULL;
        CHECK(store_open_existing(np, KEK, &t) == STORE_OK && t != NULL && store_was_created(t) == 0 &&
              store_was_created(NULL) == 0,
              "created: nor does store_open_existing, nor a NULL handle");
        store_close(t);
        t = NULL;
        store_close(s);
        /* A store that is already there keeps the mode its owner gave it. */
        CHECK(chmod(np, 0640) == 0 && store_open(np, KEK, &t) == STORE_OK && t != NULL &&
              stat(np, &sb) == 0 && (sb.st_mode & 07777) == 0640,
              "created: an existing store's mode is left as it was");
        store_close(t);
    }

    /* F246 (V4-172): SQLite's in-memory name is not a file to create. Since
     * F200 store_open has pre-created the store's file 0600 before SQLite
     * opens it, and it did so for ":memory:" too: every in-memory store (the
     * fuzz targets open one each) left an empty file called ":memory:" in the
     * working directory. Found as an untracked file after a fuzz run. */
    {
        (void)unlink(":memory:");
        store_t *m = NULL;
        CHECK(store_open(":memory:", KEK, &m) == STORE_OK && m != NULL, "memory: an in-memory store opens");
        CHECK(access(":memory:", F_OK) != 0,
              "memory: opening an in-memory store creates no file named \":memory:\" in the working directory (F246)");
        if (m != NULL) {
            CHECK(store_add_user(m, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK, "memory: and it works as a store");
            store_close(m);
        }
        (void)unlink(":memory:");
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
        /* V4-81: revoking an already-revoked device answers OK and writes
         * nothing -- the first revocation's record, and the chain, stand. */
        { uint8_t m1[STORE_AUDIT_MAC_BYTES], m2[STORE_AUDIT_MAC_BYTES];
          CHECK(store_audit_head_mac(s, m1) == STORE_OK &&
                store_revoke_device(s, H1, sizeof H1, "local-api", (const uint8_t *)"again", 5) == STORE_OK &&
                store_audit_head_mac(s, m2) == STORE_OK && memcmp(m1, m2, sizeof m1) == 0,
                "audit: a second revoke of a revoked device is OK and writes nothing (V4-81)"); }

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
        /* V4-338 (F643): a row whose bytes are not stored as they were
         * written. Each edit below leaves what the verifier used to READ
         * unchanged -- SQLite converts text that begins with a number to that
         * number, and a C string ends at its first NUL -- so the chain
         * verified, with the same head, over rows that say something else to
         * every other reader of the file. Review 84 ran three of these
         * against the tool: `verify=ok entries=3`. One fresh store for each,
         * so that each is what fails. */
        static const struct { const char *sql; const char *what; int last_row; } EDIT[] = {
            { "UPDATE audit SET detail = detail || char(0) || ' by=someone-else' WHERE seq=1;",
              "audit shape: a detail with a NUL and a tail after it is not the row that was written (F643)", 0 },
            { "UPDATE audit SET at = CAST(at AS TEXT) || ' (really 1999-01-01)' WHERE seq=2;",
              "audit shape: a time stored as text that begins with the number is not the row that was written (F643)", 0 },
            { "UPDATE audit SET event = CAST(event AS BLOB) || x'00' || x'4142' WHERE seq=3;",
              "audit shape: an event stored as bytes with a NUL and a tail is not the row that was written (F643)", 1 },
            { "UPDATE audit SET event = CAST(event AS BLOB) WHERE seq=2;",
              "audit shape: an event stored as bytes, the same bytes, is not the row that was written (F643)", 0 },
            /* V4-339 (F656): the handle and the previous MAC, which the two
             * rows below this one left to the user id and the MAC. */
            { "UPDATE audit SET handle = CAST(handle AS TEXT) WHERE seq=2;",
              "audit shape: a handle stored as text is not the row that was written (F656)", 0 },
            { "UPDATE audit SET prev_mac = CAST(prev_mac AS TEXT) WHERE seq=2;",
              "audit shape: a previous MAC stored as text is not the row that was written (F656)", 0 },
            { "UPDATE audit SET user_id = CAST(user_id AS TEXT) WHERE seq=1;",
              "audit shape: a user id stored as text is not the row that was written (F643)", 0 },
            { "UPDATE audit SET mac = CAST(mac AS TEXT) WHERE seq=3;",
              "audit shape: a MAC stored as text is not the row that was written (F643)", 2 },
            { "UPDATE audit SET seq = seq WHERE seq=1; UPDATE audit SET at = at + 0.0 WHERE seq=3 AND 0;",
              NULL, 0 },                                  /* the control: an edit that changes nothing */
        };
        for (size_t e = 0; e < sizeof EDIT / sizeof EDIT[0]; e++) {
            char name[40];
            snprintf(name, sizeof name, "shape%zu.sqlite3", e);
            store_t *s = fresh_store(name, dbp, sizeof dbp);
            if (s == NULL) { printf("FAIL: open shape\n"); return 1; }
            const int made = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
                             store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK &&
                             store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK &&
                             store_audit_verify(s) == STORE_OK;
            store_close(s);
            const int edited = made && raw_sql(dbp, EDIT[e].sql) == 0;
            store_t *t = NULL;
            const int opened = edited && store_open(dbp, KEK, &t) == STORE_OK && t != NULL;
            if (EDIT[e].what == NULL) {
                audit_clock_t ac;
                memset(&ac, 0, sizeof ac);
                CHECK(opened && store_audit_verify(t) == STORE_OK && store_audit_tail_check(t) == STORE_OK &&
                      store_audit_tail(t, 64, audit_clock_row, &ac) == STORE_OK && ac.n == 3u,
                      "audit shape: three rows stored as they were written verify, pass the tail check and are all shown (the control)");
            } else {
                int64_t verified = -1;
                uint8_t head[STORE_AUDIT_MAC_BYTES];
                CHECK(opened && store_audit_verify_report(t, &verified, head) == STORE_ERR_CORRUPT, EDIT[e].what);
                if (EDIT[e].last_row) {
                    audit_clock_t ac;
                    memset(&ac, 0, sizeof ac);
                    CHECK(opened && store_audit_tail_check(t) == STORE_ERR_CORRUPT,
                          "audit shape: and the check the daemon makes of the last row at every start refuses it (F643)");
                    /* The reader that SHOWS rows does not select the MACs:
                     * a row whose MAC alone is misstored is the two checks
                     * above's to refuse. */
                    if (EDIT[e].last_row == 1) {
                        CHECK(opened && store_audit_tail(t, 64, audit_clock_row, &ac) == STORE_ERR_CORRUPT && ac.n == 2u,
                              "audit shape: and the rows are shown up to it, not through it (F643)");
                    }
                }
            }
            if (t != NULL) { store_close(t); }
        }
    }
    {
        /* V4-339 (F655): the writer has never stored a NULL detail. An empty
         * one and a NULL make the same MAC, so only how the row is stored
         * tells them apart, and a reader's `WHERE detail IS NULL` answers
         * differently. The row here is a revocation with nothing said of who
         * made it: its detail is empty. (The first form of this check edited
         * a row whose detail was not empty; the MAC refused it, and a
         * verifier that allowed NULL passed.) */
        store_t *s = fresh_store("nulldetail.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open nulldetail\n"); return 1; }
        const int made = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
                         store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK &&
                         store_revoke_device(s, H1, sizeof H1, "", NULL, 0) == STORE_OK &&
                         store_audit_verify(s) == STORE_OK;
        store_close(s);
        long long len = -1;
        char ev[64] = "";
        CHECK(made && raw_row(dbp, "SELECT length(detail), event FROM audit WHERE seq=3;", &len, ev, sizeof ev) == 0 &&
              len == 0 && strcmp(ev, "device-revoke") == 0,
              "audit shape: the third row is a revocation with an empty detail (the control)");
        store_t *t = NULL;
        CHECK(raw_sql(dbp, "UPDATE audit SET detail = NULL WHERE seq=3;") == 0 &&
              store_open(dbp, KEK, &t) == STORE_OK && t != NULL && store_audit_verify(t) == STORE_ERR_CORRUPT,
              "audit shape: a detail stored as NULL is not the row that was written (F655)");
        if (t != NULL) { store_close(t); }
    }
    {
        /* V4-339 (F653, F654): the store's SHAPE. Each of these is one write
         * to the file by someone without the server key; review 85 ran the
         * first three against the library and each did what it was planted
         * to do while every check passed. A store that is not shaped as this
         * build makes one is refused, by the daemon's open and by a tool's. */
        static const struct { const char *sql; const char *what; } PLANT[] = {
            { "CREATE TRIGGER audit_idx BEFORE INSERT ON audit WHEN NEW.event='device-revoke' "
              "BEGIN SELECT RAISE(IGNORE); END;",
              "shape: a store with a trigger that drops audit rows is refused at open (F653)" },
            { "CREATE TRIGGER dev_back AFTER UPDATE OF status ON devices "
              "BEGIN UPDATE devices SET status='active' WHERE handle=NEW.handle; END;",
              "shape: a store with a trigger that undoes revocations is refused at open (F653)" },
            { "ALTER TABLE audit RENAME TO audit_all; CREATE VIEW audit AS SELECT * FROM audit_all WHERE seq <= 2;",
              "shape: a store whose audit table is a view over another is refused at open (F653)" },
            { "ALTER TABLE audit ADD COLUMN note TEXT DEFAULT 'VOID: entered in error';",
              "shape: a store whose audit table has a column more is refused at open (F653)" },
            { "CREATE TABLE audit2(seq INT PRIMARY KEY, at INT, event TEXT, user_id BLOB, handle BLOB, detail TEXT, "
              "prev_mac BLOB, mac BLOB); INSERT INTO audit2 SELECT * FROM audit; DROP TABLE audit; "
              "ALTER TABLE audit2 RENAME TO audit;",
              "shape: a store whose audit sequence has an index of its own is refused at open (F654)" },
            { "CREATE TABLE audit2(seq INTEGER PRIMARY KEY, at INT, event TEXT, user_id BLOB, handle BLOB, detail BLOB, "
              "prev_mac BLOB, mac BLOB); INSERT INTO audit2 SELECT * FROM audit; DROP TABLE audit; "
              "ALTER TABLE audit2 RENAME TO audit;",
              "shape: a store whose audit table declares a column otherwise is refused at open (F653)" },
            /* V4-341 (F661, F663): the DEFINITIONS, not only the names and
             * the column lists. Review 86 opened each of these with V4-339. */
            { "DROP INDEX one_active_key; CREATE INDEX one_active_key ON device_keys(valid_to);",
              "shape: a store whose one-active-key index is no longer unique is refused at open (F661)" },
            { "DROP INDEX one_active_key; "
              "CREATE UNIQUE INDEX one_active_key ON device_keys(handle) WHERE status='nonsense';",
              "shape: a store whose one-active-key index has another WHERE is refused at open (F661)" },
            { "CREATE TABLE audit2(seq INTEGER PRIMARY KEY, at INT, event TEXT CHECK(event <> 'device-revoke'), "
              "user_id BLOB, handle BLOB, detail TEXT, prev_mac BLOB, mac BLOB); "
              "INSERT INTO audit2 SELECT * FROM audit; DROP TABLE audit; ALTER TABLE audit2 RENAME TO audit;",
              "shape: a store whose audit table has a CHECK this build does not write is refused at open (F661)" },
            { "PRAGMA foreign_keys=OFF; "
              "CREATE TABLE audit2(seq INTEGER PRIMARY KEY, at INT, event TEXT, user_id BLOB, "
              "handle BLOB REFERENCES tokens(token_hash) ON DELETE CASCADE, detail TEXT, prev_mac BLOB, mac BLOB); "
              "INSERT INTO audit2 SELECT * FROM audit; DROP TABLE audit; ALTER TABLE audit2 RENAME TO audit;",
              "shape: a store whose audit table has a foreign key that deletes its rows is refused at open (F663)" },
            { "CREATE INDEX zz_at ON audit(at);",
              "shape: a store with an index this build does not make is refused at open (F653)" },
            { "CREATE TABLE zz_extra(x);",
              "shape: a store with a table this build does not make is refused at open (F653)" },
        };
        for (size_t e = 0; e < sizeof PLANT / sizeof PLANT[0]; e++) {
            char name[40];
            snprintf(name, sizeof name, "plant%zu.sqlite3", e);
            store_t *s = fresh_store(name, dbp, sizeof dbp);
            if (s == NULL) { printf("FAIL: open plant\n"); return 1; }
            const int made = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
                             store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK;
            store_close(s);
            store_t *w = NULL, *t = NULL;
            const int clean = made && store_open(dbp, KEK, &w) == STORE_OK && w != NULL;
            if (w != NULL) { store_close(w); w = NULL; }
            const int planted = clean && raw_sql(dbp, PLANT[e].sql) == 0;
            const store_status_t rw = store_open(dbp, KEK, &w);
            const store_status_t rd = store_open_existing(dbp, KEK, &t);
            CHECK(planted && rw == STORE_ERR_DAMAGED && w == NULL, PLANT[e].what);
            CHECK(planted && rd == STORE_ERR_DAMAGED && t == NULL,
                  "shape: and a tool that only reads refuses it too (F653)");
            if (w != NULL) { store_close(w); }
            if (t != NULL) { store_close(t); }
        }
        /* V4-341 (F660): what SQLite itself leaves in a file is not a
         * difference. V4-339 refused a store on which someone had run
         * ANALYZE, as `store-corrupt`, at the next start and at every
         * audit-verify. */
        { static const struct { const char *sql; const char *what; } KEPT[] = {
              { "ANALYZE;", "shape: a store on which ANALYZE was run still opens, for the daemon and for a tool (F660)" },
              { "PRAGMA optimize;", "shape: so does one after PRAGMA optimize (F660)" },
              { "CREATE TABLE zz_seq(a INTEGER PRIMARY KEY AUTOINCREMENT); DROP TABLE zz_seq;",
                "shape: and one in which a dropped AUTOINCREMENT table left sqlite_sequence (F660)" },
              { "VACUUM;", "shape: and one that was vacuumed (the control)" },
          };
          for (size_t e = 0; e < sizeof KEPT / sizeof KEPT[0]; e++) {
              char name[40];
              snprintf(name, sizeof name, "kept%zu.sqlite3", e);
              store_t *s = fresh_store(name, dbp, sizeof dbp);
              if (s == NULL) { printf("FAIL: open kept\n"); return 1; }
              const int made = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
                               store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK;
              store_close(s);
              const int done = made && raw_sql(dbp, KEPT[e].sql) == 0;
              store_t *w = NULL, *t = NULL;
              const store_status_t rw = store_open(dbp, KEK, &w);
              const int note_empty = (store_shape_note()[0] == '\0');
              const store_status_t rd = store_open_existing(dbp, KEK, &t);
              CHECK(done && rw == STORE_OK && rd == STORE_OK && note_empty &&
                    w != NULL && store_audit_verify(w) == STORE_OK, KEPT[e].what);
              if (w != NULL) { store_close(w); }
              if (t != NULL) { store_close(t); }
          }
          long long n = 0;
          char txt[32] = "";
          path(dbp, sizeof dbp, "kept0.sqlite3");
          CHECK(raw_row(dbp, "SELECT count(*), '' FROM sqlite_master WHERE name = 'sqlite_stat1';", &n, txt, sizeof txt) == 0 && n == 1,
                "shape: the ANALYZE really left its table in the first of those (the control)"); }
        /* F660: a refusal says where it stopped. */
        { store_t *s = fresh_store("note.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open note\n"); return 1; }
          store_close(s);
          store_t *w = NULL;
          CHECK(raw_sql(dbp, "CREATE TABLE zz_extra(x);") == 0 && store_open(dbp, KEK, &w) == STORE_ERR_DAMAGED &&
                strstr(store_shape_note(), "zz_extra") != NULL,
                "shape: a refusal names the first object this build did not make (F660)");
          if (w != NULL) { store_close(w); } }
        /* F662: since the definitions are compared as text, the TEXT of the
         * schema is part of every store ever made. One space more in it and
         * every store the released builds made is refused at the next
         * start, with every other test passing, because each of them makes
         * its store and its reference from the same string. This is the
         * text as it has been since V4-9a (2026-09-17) and in every tagged
         * build that has a daemon. A change here is a migration, with a new
         * STORE_SCHEMA_VERSION: it is not made by updating this digest. */
        { unsigned char dg[crypto_hash_sha256_BYTES];
          char hex[2 * sizeof dg + 1];
          crypto_hash_sha256(dg, (const unsigned char *)STORE_SCHEMA_SQL, strlen(STORE_SCHEMA_SQL));
          (void)sodium_bin2hex(hex, sizeof hex, dg, sizeof dg);
          const int same = strcmp(hex, "5275e95ceb40c43149bd7565fa55db3cf6f227b28171263baa5cd1e2e19f0b8d") == 0;
          if (!same) { printf("  the schema's text now hashes to %s\n", hex); }
          CHECK(same, "shape: the schema's text is, byte for byte, the one every released store was made with (F662)"); }
        /* V4-342, review 87. */
        /* F670: the note says has or lacks, and names the object itself. */
        { static const struct { const char *sql, *want, *what; } NOTE[] = {
              { "DROP INDEX one_active_key;", "it lacks index one_active_key",
                "shape: a dropped index is named as lacking, not the next object the file has (F670)" },
              { "DROP TABLE enroll_tickets;", "it lacks index sqlite_autoindex_enroll_tickets_1",
                "shape: a dropped table is named by the first of its objects that is missing (F670)" },
              { "CREATE TABLE zz_extra(x);", "it has table zz_extra, which this build does not make",
                "shape: an added table is named as added (F670)" },
              { "DROP INDEX one_active_key; CREATE INDEX one_active_key ON device_keys(handle);",
                "it has index one_active_key, defined otherwise",
                "shape: a redefined index is named as defined otherwise (F670)" },
          };
          for (size_t i = 0; i < sizeof NOTE / sizeof NOTE[0]; i++) {
              store_t *s = fresh_store("note2.sqlite3", dbp, sizeof dbp);
              if (s == NULL) { printf("FAIL: open note2 %zu\n", i); return 1; }
              store_close(s);
              store_t *w = NULL;
              const int ok = raw_sql(dbp, NOTE[i].sql) == 0 && store_open(dbp, KEK, &w) == STORE_ERR_DAMAGED &&
                             strncmp(store_shape_note(), NOTE[i].want, strlen(NOTE[i].want)) == 0;
              if (!ok) { printf("  the note was: %s\n", store_shape_note()); }
              CHECK(ok, NOTE[i].what);
              if (w != NULL) { store_close(w); }
          }
          /* F677: and an open that fails for another reason has no note. */
          store_t *w = NULL;
          path(dbp, sizeof dbp, "no-such-file.sqlite3");
          (void)unlink(dbp);
          CHECK(store_open_existing(dbp, KEK, &w) != STORE_OK && store_shape_note()[0] == '\0',
                "shape: an open that failed for another reason carries no note from the one before (F677)");
          if (w != NULL) { store_close(w); } }
        /* F667: a table is SQLite's own by its name AND its definition. */
        { static const struct { const char *sql, *what; } HID[] = {
              { "CREATE TABLE zz(a REFERENCES tokens(user_id)); PRAGMA writable_schema=ON; "
                "UPDATE sqlite_master SET name='sqlite_zz', tbl_name='sqlite_zz', "
                "sql='CREATE TABLE sqlite_zz(a REFERENCES tokens(user_id))' WHERE name='zz'; PRAGMA writable_schema=OFF;",
                "shape: a table renamed to begin sqlite_ is refused at open (F667)" },
              { "CREATE TABLE zz(x); PRAGMA writable_schema=ON; "
                "UPDATE sqlite_master SET name='sqlite_stat1', tbl_name='sqlite_stat1', "
                "sql='CREATE TABLE sqlite_stat1(x)' WHERE name='zz'; PRAGMA writable_schema=OFF;",
                "shape: so is a table named sqlite_stat1 that is not defined as SQLite defines it (F667)" },
          };
          for (size_t i = 0; i < sizeof HID / sizeof HID[0]; i++) {
              store_t *s = fresh_store("hid.sqlite3", dbp, sizeof dbp);
              if (s == NULL) { printf("FAIL: open hid %zu\n", i); return 1; }
              store_close(s);
              store_t *w = NULL, *t = NULL;
              long long n = 0;
              char txt[32] = "";
              const int planted = raw_sql(dbp, HID[i].sql) == 0 &&
                                  raw_row(dbp, "SELECT count(*), '' FROM sqlite_master WHERE name LIKE 'sqlite\\_%' ESCAPE '\\' AND type = 'table';",
                                          &n, txt, sizeof txt) == 0 && n == 1;
              CHECK(planted && store_open(dbp, KEK, &w) == STORE_ERR_DAMAGED &&
                    store_open_existing(dbp, KEK, &t) == STORE_ERR_DAMAGED, HID[i].what);
              if (w != NULL) { store_close(w); }
              if (t != NULL) { store_close(t); }
          } }
        /* F668: the open completes nothing in a store that holds anything. */
        { static const struct { const char *key, *what; } GONE[] = {
              { "store_id", "created: a populated store whose store_id row is gone is refused, not given a new id and called created (F668)" },
              { "decoy_pk", "created: nor is one whose decoy key is gone given another (F668)" },
              { "schema_version", "created: nor one whose schema version is gone (F668)" },
          };
          for (size_t i = 0; i < sizeof GONE / sizeof GONE[0]; i++) {
              store_t *s = fresh_store("gone.sqlite3", dbp, sizeof dbp);
              if (s == NULL) { printf("FAIL: open gone %zu\n", i); return 1; }
              const int filled = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK;
              store_close(s);
              char sql[128];
              (void)snprintf(sql, sizeof sql, "DELETE FROM meta WHERE key = '%s';", GONE[i].key);
              store_t *w = NULL;
              const int cut = raw_sql(dbp, sql) == 0;
              const store_status_t ro = store_open(dbp, KEK, &w);
              long long n = -1;
              char txt[32] = "";
              (void)snprintf(sql, sizeof sql, "SELECT count(*), '' FROM meta WHERE key = '%s';", GONE[i].key);
              CHECK(filled && cut && ro == STORE_ERR_DAMAGED && w == NULL &&
                    raw_row(dbp, sql, &n, txt, sizeof txt) == 0 && n == 0, GONE[i].what);
              if (w != NULL) { store_close(w); }
          }
          /* The other side: a schema with no row in it -- a creation that
           * was cut short after its first transaction -- is completed, and
           * that IS a creation. */
          store_t *s = fresh_store("blank.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open blank\n"); return 1; }
          store_close(s);
          store_t *w = NULL;
          CHECK(raw_sql(dbp, "DELETE FROM audit; DELETE FROM meta;") == 0 && store_open(dbp, KEK, &w) == STORE_OK &&
                w != NULL && store_was_created(w) == 1,
                "created: a schema that holds no row is completed, and the open says it created the store (F668)");
          if (w != NULL) { store_close(w); } }
        /* F669: a newer build's store is a newer build's store to a tool too. */
        { store_t *s = fresh_store("newer.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open newer\n"); return 1; }
          store_close(s);
          store_t *w = NULL, *t = NULL;
          const int made = raw_sql(dbp, "UPDATE meta SET value = x'0000000000000063' WHERE key = 'schema_version'; "
                                        "CREATE TABLE passkeys(id BLOB PRIMARY KEY);") == 0;
          const store_status_t rw = store_open(dbp, KEK, &w), rt = store_open_existing(dbp, KEK, &t);
          CHECK(made && rw == STORE_ERR_SCHEMA && rt == STORE_ERR_SCHEMA,
                "shape: a store of a newer schema with a table this build lacks is 'newer' to a tool as to the daemon, not corrupt (F669)");
          if (w != NULL) { store_close(w); }
          if (t != NULL) { store_close(t); } }
        /* F672: a meta table that cannot be read as ours is the shape's. */
        { store_t *s = fresh_store("meta-col.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open meta-col\n"); return 1; }
          store_close(s);
          store_t *w = NULL;
          CHECK(raw_sql(dbp, "ALTER TABLE meta RENAME COLUMN value TO v;") == 0 &&
                store_open(dbp, KEK, &w) == STORE_ERR_DAMAGED && strstr(store_shape_note(), "table meta") != NULL,
                "shape: a meta table with a column renamed is store-corrupt from the daemon, and named (F672)");
          if (w != NULL) { store_close(w); } }
        /* F671: a refused file is not checkpointed on the way out. A
         * database that is not a store, in WAL mode, whose writer died with
         * its rows still in the WAL. */
        { char other[512], wal[530];
          path(other, sizeof other, "wal-other.sqlite3");
          (void)snprintf(wal, sizeof wal, "%s-wal", other);
          (void)unlink(other); (void)unlink(wal);
          const pid_t kid = fork();
          if (kid == 0) {
              sqlite3 *h = NULL;
              const int ok = sqlite3_open_v2(other, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK &&
                             sqlite3_exec(h, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; "
                                             "CREATE TABLE somebody_elses(x); INSERT INTO somebody_elses VALUES(zeroblob(9000));",
                                          NULL, NULL, NULL) == SQLITE_OK;
              _exit(ok ? 0 : 1);      /* no close: the WAL stays as a dead writer leaves it */
          }
          int st = -1;
          const int wrote = kid > 0 && waitpid(kid, &st, 0) == kid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
          struct stat m0, w0, m1, w1;
          const int before = stat(other, &m0) == 0 && stat(wal, &w0) == 0 && w0.st_size > 0;
          store_t *w = NULL;
          const store_status_t rw = store_open(other, KEK, &w);
          const int after = stat(other, &m1) == 0 && stat(wal, &w1) == 0;
          CHECK(wrote && before && rw == STORE_ERR_DAMAGED && w == NULL && after &&
                m1.st_size == m0.st_size && w1.st_size == w0.st_size,
                "shape: a refused database in WAL mode keeps its WAL and its size: it is not checkpointed on the way out (F671)");
          if (w != NULL) { store_close(w); } }
        /* V4-344, review 88. */
        /* F680: a store that has lost a meta value is refused before its
         * journal mode is touched, and the refusal says why. In rollback
         * mode, where the switch to WAL would show in the header. */
        { store_t *s = fresh_store("lost-id.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open lost-id\n"); return 1; }
          const int filled = store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK;
          store_close(s);
          char wal[560];
          (void)snprintf(wal, sizeof wal, "%s-wal", dbp);
          const int cut = raw_sql(dbp, "PRAGMA journal_mode=DELETE; DELETE FROM meta WHERE key = 'store_id';") == 0;
          unsigned char h0[32] = {0}, h1[32] = {0};
          FILE *f = fopen(dbp, "rb");
          const int read0 = f != NULL && fread(h0, 1, sizeof h0, f) == sizeof h0;
          if (f != NULL) { (void)fclose(f); }
          struct stat sb0, sb1, sbw;
          const int st0 = stat(dbp, &sb0) == 0;
          store_t *w = NULL;
          const store_status_t ro = store_open(dbp, KEK, &w);
          f = fopen(dbp, "rb");
          const int read1 = f != NULL && fread(h1, 1, sizeof h1, f) == sizeof h1;
          if (f != NULL) { (void)fclose(f); }
          CHECK(filled && cut && read0 && read1 && st0 && ro == STORE_ERR_DAMAGED && w == NULL &&
                stat(dbp, &sb1) == 0 && sb1.st_size == sb0.st_size && memcmp(h0, h1, sizeof h0) == 0 &&
                stat(wal, &sbw) != 0,
                "created: a store refused for a lost store_id keeps its header and gets no WAL: it is refused before the journal mode (F680)");
          CHECK(strncmp(store_shape_note(), "it holds rows and lacks", 23) == 0,
                "created: and the refusal says it holds rows and lacks a meta value (F680)");
          if (w != NULL) { store_close(w); } }
        /* F681: what a creation leaves, and nothing more. */
        { store_t *s = fresh_store("as-created.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open as-created\n"); return 1; }
          CHECK(store_is_as_created(s) == 1, "created: a store just made holds exactly what a creation leaves (F681)");
          CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK && store_is_as_created(s) == 0,
                "created: with one user in it, it no longer does (F681)");
          store_close(s);
          s = fresh_store("as-created.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: reopen as-created\n"); return 1; }
          CHECK(raw_sql(dbp, "INSERT INTO meta(key, value) VALUES('other', x'00');") == 0 && store_is_as_created(s) == 0,
                "created: nor with a fourth meta value written by another connection (F681)");
          store_close(s); }
        /* F682: a file that was there, empty and readable by all. */
        { char pre[512];
          path(pre, sizeof pre, "pre-empty.sqlite3");
          (void)unlink(pre);
          const int fd = open(pre, O_WRONLY | O_CREAT | O_EXCL, 0644);
          const int made = fd >= 0 && fchmod(fd, 0644) == 0;
          if (fd >= 0) { (void)close(fd); }
          store_t *w = NULL;
          CHECK(made && mode_of_path(pre) == 0644 && store_open(pre, KEK, &w) == STORE_OK && w != NULL &&
                store_was_created(w) == 1 && mode_of_path(pre) == 0600,
                "created: a store made in a file that was there, empty and 0644, is 0600 (F682)");
          if (w != NULL) { store_close(w); } }
        /* V4-345, review 89. */
        /* F694: the daemon's store is the file its path names. */
        { char link[512], target[512];
          path(link, sizeof link, "link.sqlite3");
          path(target, sizeof target, "link-target.sqlite3");
          (void)unlink(link); (void)unlink(target);
          struct stat sb;
          store_t *w = NULL;
          /* The link names its target beside itself: the fixture's paths are relative. */
          CHECK(symlink("link-target.sqlite3", link) == 0 && store_open(link, KEK, &w) == STORE_ERR_IO && w == NULL &&
                stat(target, &sb) != 0,
                "link: a store path that is a link to nothing is refused, and nothing is made where it points (F694)");
          if (w != NULL) { store_close(w); w = NULL; }
          store_t *s = fresh_store("link-target.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open link-target\n"); return 1; }
          store_close(s);
          CHECK(store_open(link, KEK, &w) == STORE_ERR_IO && w == NULL,
                "link: a store path that is a link to a store is refused by the daemon's open (F694)");
          if (w != NULL) { store_close(w); w = NULL; }
          CHECK(store_open_existing(link, KEK, &w) == STORE_OK && w != NULL,
                "link: and opened by a tool's, which may follow one (the control) (F694)");
          if (w != NULL) { store_close(w); }
          (void)unlink(link); }
        /* F695: a store the daemon cannot write is not opened. */
        { store_t *s = fresh_store("readonly.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open readonly\n"); return 1; }
          store_close(s);
          if (geteuid() == 0) {
              printf("SKIP: readonly: root writes a file of any mode, so a store that cannot be written is not staged (F695)\n");
          } else {
              /* Out of WAL first, so that the mode alone decides. */
              store_t *w = NULL;
              CHECK(raw_sql(dbp, "PRAGMA journal_mode=DELETE;") == 0 && chmod(dbp, 0400) == 0 &&
                    store_open(dbp, KEK, &w) == STORE_ERR_IO && w == NULL,
                    "readonly: a store whose mode refuses writing is not opened by the daemon (F695)");
              if (w != NULL) { store_close(w); w = NULL; }
              CHECK(store_open_existing(dbp, KEK, &w) == STORE_OK && w != NULL,
                    "readonly: and is read by a tool as before (the control) (F695)");
              if (w != NULL) { store_close(w); }
              (void)chmod(dbp, 0600);
          } }
        /* V4-341 (F664): the daemon's open LOOKS before it touches. A
         * database that is not a store was switched to WAL and given nine
         * tables before it was refused; a store with its index dropped was
         * given the index back and served. */
        { char other[512];
          path(other, sizeof other, "not-a-store.sqlite3");
          (void)unlink(other);
          sqlite3 *h = NULL;
          const int made = sqlite3_open_v2(other, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK &&
                           sqlite3_exec(h, "CREATE TABLE somebody_elses(x); INSERT INTO somebody_elses VALUES(1);",
                                        NULL, NULL, NULL) == SQLITE_OK;
          if (h != NULL) { (void)sqlite3_close(h); }
          store_t *w = NULL;
          const store_status_t rw = store_open(other, KEK, &w);
          long long n = -1;
          char mode[32] = "";
          const int read = raw_row(other, "SELECT (SELECT count(*) FROM sqlite_master), journal_mode FROM pragma_journal_mode;",
                                   &n, mode, sizeof mode) == 0;
          CHECK(made && rw == STORE_ERR_DAMAGED && w == NULL && read && n == 1 && strcmp(mode, "wal") != 0,
                "shape: a database that is not a store is refused and left as it was: one table, not in WAL (F664)");
          if (w != NULL) { store_close(w); }
          store_t *s = fresh_store("noindex.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open noindex\n"); return 1; }
          store_close(s);
          w = NULL;
          const int dropped = raw_sql(dbp, "DROP INDEX one_active_key;") == 0;
          const store_status_t ri = store_open(dbp, KEK, &w);
          n = -1;
          CHECK(dropped && ri == STORE_ERR_DAMAGED && w == NULL &&
                raw_row(dbp, "SELECT count(*), '' FROM sqlite_master WHERE name = 'one_active_key';", &n, mode, sizeof mode) == 0 &&
                n == 0,
                "shape: a store whose index was dropped is refused by the daemon too, and is not given it back (F664)");
          if (w != NULL) { store_close(w); } }
        /* Planted while the store is OPEN: the daemon does not look at the
         * shape again until its next start, and until then nothing the file
         * holds is run. The revocation's row is written. */
        { store_t *s = fresh_store("plant-live.sqlite3", dbp, sizeof dbp);
          if (s == NULL) { printf("FAIL: open plant-live\n"); return 1; }
          CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
                store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK,
                "shape, live: a user and a device");
          CHECK(raw_sql(dbp, PLANT[0].sql) == 0 && raw_sql(dbp, PLANT[1].sql) == 0,
                "shape, live: both triggers are planted in the open store (the control)");
          int64_t before = -1, after = -1;
          uint8_t head[STORE_AUDIT_MAC_BYTES];
          uint8_t pk[STORE_PK_BYTES];
          CHECK(store_audit_verify_report(s, &before, head) == STORE_OK &&
                store_revoke_device(s, H1, sizeof H1, "admin", NULL, 0) == STORE_OK &&
                store_audit_verify_report(s, &after, head) == STORE_OK && after == before + 1,
                "shape, live: a revocation made while a trigger to drop its audit row is planted is still recorded (F653)");
          CHECK(store_lookup_active(s, H1, sizeof H1, pk, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
                "shape, live: and with a trigger to undo it planted, the device is still revoked (F653)");
          store_close(s);
          store_t *again = NULL;
          CHECK(store_open(dbp, KEK, &again) == STORE_ERR_DAMAGED && again == NULL,
                "shape, live: and the next start refuses the store (F653)");
          if (again != NULL) { store_close(again); } }
    }
    {
        /* F229: the tail check the daemon makes at every start. One row, one
         * MAC: it answers "did this key write the end of this chain", which
         * is what a store beside the wrong server key gets wrong. */
        static const uint8_t OTHER_KEK[STORE_KEK_BYTES] = { 0x5a, 0x01, 0x02 };
        store_t *s = fresh_store("tail.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open tail\n"); return 1; }
        CHECK(store_audit_tail_check(s) == STORE_OK, "tail: an empty chain passes the tail check");
        CHECK(store_audit_tail_check(NULL) == STORE_ERR_ARG, "tail: no store is an argument error");
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_add_user(s, U2, sizeof U2, STORE_ROLE_USER) == STORE_OK, "tail: two entries written");
        CHECK(store_audit_tail_check(s) == STORE_OK, "tail: the key that wrote the chain passes the tail check");
        store_close(s);
        { store_t *o = NULL;
          CHECK(store_open(dbp, OTHER_KEK, &o) == STORE_OK && o != NULL,
                "tail: a store opens under another key (the control: opening does not check)");
          if (o != NULL) {
              CHECK(store_audit_tail_check(o) == STORE_ERR_CORRUPT,
                    "tail: a chain another key wrote fails the tail check (F229)");
              store_close(o);
          } }
        CHECK(raw_sql(dbp, "UPDATE audit SET detail='tampered' WHERE seq=1;") == 0, "tail: an earlier entry is edited");
        { store_t *o = NULL;
          CHECK(store_open(dbp, KEK, &o) == STORE_OK && o != NULL, "tail: reopen under the right key");
          if (o != NULL) {
              CHECK(store_audit_tail_check(o) == STORE_OK && store_audit_verify(o) == STORE_ERR_CORRUPT,
                    "tail: an edit that is not at the end passes the tail check and fails the full one (the limit)");
              store_close(o);
          } }
        /* F230: the walk reports how far it got and the MAC it ended on. Here
         * entry 1 is edited and entry 2 is not: nothing verifies. */
        { store_t *o = NULL;
          int64_t n = -1;
          uint8_t h[STORE_AUDIT_MAC_BYTES], zero[STORE_AUDIT_MAC_BYTES] = {0};
          CHECK(store_open(dbp, KEK, &o) == STORE_OK && o != NULL, "report: reopen");
          if (o != NULL) {
              CHECK(store_audit_verify_report(o, &n, h) == STORE_ERR_CORRUPT && n == 0 &&
                    memcmp(h, zero, sizeof h) == 0,
                    "report: an edited first entry fails with 0 verified and no head (F230)");
              CHECK(store_audit_verify_report(o, NULL, NULL) == STORE_ERR_CORRUPT,
                    "report: both outputs are optional");
              store_close(o);
          } }
        CHECK(raw_sql(dbp, "UPDATE audit SET detail='user' WHERE seq=1;") == 0, "report: the first entry is put back (add_user records the role)");
        { store_t *o = NULL;
          int64_t n = -1;
          uint8_t h[STORE_AUDIT_MAC_BYTES], stored[STORE_AUDIT_MAC_BYTES];
          CHECK(store_open(dbp, KEK, &o) == STORE_OK && o != NULL, "report: reopen whole");
          if (o != NULL) {
              CHECK(store_audit_verify_report(o, &n, h) == STORE_OK && n == 2 &&
                    store_audit_head_mac(o, stored) == STORE_OK && memcmp(h, stored, sizeof h) == 0,
                    "report: a whole chain reports every entry and the stored head (F230)");
              store_close(o);
          } }
        CHECK(raw_sql(dbp, "UPDATE audit SET detail='tampered' WHERE seq=2;") == 0, "tail: the last entry is edited");
        { store_t *o = NULL;
          int64_t n = -1;
          uint8_t h[STORE_AUDIT_MAC_BYTES], stored[STORE_AUDIT_MAC_BYTES];
          CHECK(store_open(dbp, KEK, &o) == STORE_OK && o != NULL, "report: reopen with the last entry edited");
          if (o != NULL) {
              CHECK(store_audit_verify_report(o, &n, h) == STORE_ERR_CORRUPT && n == 1 &&
                    store_audit_head_mac(o, stored) == STORE_OK && memcmp(h, stored, sizeof h) != 0,
                    "report: an edited last entry fails with 1 verified, and the head is entry 1's, not the stored one (F230)");
              store_close(o);
          } }
        { store_t *o = NULL;
          CHECK(store_open(dbp, KEK, &o) == STORE_OK && o != NULL, "tail: reopen again");
          if (o != NULL) {
              CHECK(store_audit_tail_check(o) == STORE_ERR_CORRUPT,
                    "tail: an edited last entry fails the tail check (F229)");
              store_close(o);
          } }
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

    /* ---- the key-status filter holds on its own (V4-22a, CLAIMS D9) ----
     * The mirror of the block above: the KEY row is revoked under an active
     * device and an active user. Rotation tests catch a filter that drops the
     * key clause outright (a superseded key would resolve), but not one that
     * only excludes superseded keys -- a revoked key under an active device
     * is again a state no API path makes, so only this block can see it. */
    {
        store_t *s = fresh_store("keyfilter.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open keyfilter\n"); return 1; }
        uint8_t got[STORE_PK_BYTES];
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_enroll_device(s, H1, sizeof H1, U1, sizeof U1, pkA, "site", "admin", NULL, 0) == STORE_OK &&
              store_lookup_active(s, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_OK,
              "keyfilter: an active key resolves (the canary)");
        store_close(s);
        CHECK(raw_sql(dbp, "UPDATE device_keys SET status='revoked' WHERE handle=X'64316161';") == 0,
              "keyfilter: the key is marked revoked behind the store's back, its device and user left active");
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK, "keyfilter: reopen");
        if (s2 != NULL) {
            CHECK(store_lookup_active(s2, H1, sizeof H1, got, NULL, 0, NULL, NULL) == STORE_ERR_NOT_FOUND,
                  "keyfilter: a revoked key does not resolve even while its device and user are active");
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
        /* V4-59 (F24's residue): the copy is never more open than 0600, not
         * even for the length of the copy. Under a umask of 022, VACUUM INTO
         * alone would create it 0644; the observer looks at the file between
         * the copy and the chmod after it. */
        const mode_t um = umask(022);
        store_fault_arm_backup_observer(bk_observe);
        g_bk_seen = 0;
        CHECK(store_backup(s, bak) == STORE_OK, "backup writes a snapshot");
        store_fault_arm_backup_observer(NULL);
        (void)umask(um);
        CHECK(g_bk_seen == 1, "backup: the observer saw the finished copy (the check below is not vacuous)");
        CHECK(g_bk_seen == 1 && g_bk_mode == 0600,
              "backup: the copy is 0600 the moment VACUUM INTO finishes, under a umask of 022 (F24)");
        { struct stat st;
          CHECK(stat(bak, &st) == 0 && (st.st_mode & 07777) == 0600, "backup: ...and 0600 when it returns"); }
        CHECK(store_backup(s, bak) == STORE_ERR_IO, "backup refuses to overwrite an existing file");
        /* V4-315, F541: the caller is called back while the copy runs, so a
         * daemon can go on telling systemd it is alive through a long one --
         * and at no other time, since the callback is the watchdog's. */
        { char tk[512];
          path(tk, sizeof tk, "backup-tick.sqlite3");
          (void)unlink(tk);
          /* Rows enough that copying one table is more than one tick's worth
           * of SQLite's steps: the count is per statement. */
          int filled = 1;
          for (unsigned i = 0; i < 600u; i++) {
              uint8_t ch[STORE_HASH_BYTES], hs[16], sh[STORE_HASH_BYTES];
              memset(ch, 0, sizeof ch); memset(hs, 0x5a, sizeof hs); memset(sh, 0x33, sizeof sh);
              ch[0] = (uint8_t)(i & 0xffu); ch[1] = (uint8_t)(i >> 8); ch[2] = 0xb7;
              if (store_add_login_code(s, ch, U1, sizeof U1, H1, sizeof H1, hs, sizeof hs, sh,
                                       1700000000, 1700000060) != STORE_OK) { filled = 0; }
          }
          CHECK(filled, "backup: 600 login codes are stored (the copy needs something to copy)");
          g_bk_ticks = 0;
          store_set_backup_tick(s, bk_tick, &g_bk_ticks);
          CHECK(store_backup(s, tk) == STORE_OK && g_bk_ticks > 0,
                "backup: the caller's tick is called while the copy runs (F541)");
          const int during = g_bk_ticks;
          /* A statement long enough to reach a tick's worth of steps, were
           * the callback still installed: all 600 codes swept in one DELETE. */
          store_sweep_counts_t swept;
          memset(&swept, 0, sizeof swept);
          CHECK(store_sweep(s, 1700000061, &swept) == STORE_OK && swept.login_codes == 600u &&
                g_bk_ticks == during,
                "backup: and by nothing else the store does (F541)");
          store_set_backup_tick(s, NULL, NULL);
          (void)unlink(tk);
          path(tk, sizeof tk, "backup-notick.sqlite3");
          (void)unlink(tk);
          CHECK(store_backup(s, tk) == STORE_OK && g_bk_ticks == during,
                "backup: with no tick set the copy calls nothing");
          (void)unlink(tk); }
        { struct stat st;
          store_t *chk = NULL;
          CHECK(stat(bak, &st) == 0 && st.st_size > 0 && store_open(bak, KEK, &chk) == STORE_OK,
                "backup: the refused second backup left the first one whole");
          if (chk != NULL) { store_close(chk); } }

        /* A backup that fails leaves no file: the copy it began is its own. */
        { char bad[512];
          path(bad, sizeof bad, "backup-failed.sqlite3");
          (void)unlink(bad);
          store_fault_arm_write(0);                /* VACUUM INTO is a writing statement */
          const store_status_t r = store_backup(s, bad);
          const int fired = store_fault_arm_write_left() == -1;
          store_fault_arm_write(-1);
          struct stat st;
          CHECK(fired && r != STORE_OK && lstat(bad, &st) != 0,
                "backup: a backup that fails leaves no file behind (F24)"); }

        /* A symlink at the path is refused, and its target is not created. */
        { char lnk[512], tgt[512];
          path(lnk, sizeof lnk, "backup-link.sqlite3");
          path(tgt, sizeof tgt, "backup-target.sqlite3");
          (void)unlink(lnk); (void)unlink(tgt);
          struct stat st;
          CHECK(symlink(tgt, lnk) == 0 && store_backup(s, lnk) == STORE_ERR_IO &&
                lstat(tgt, &st) != 0 && lstat(lnk, &st) == 0 && S_ISLNK(st.st_mode),
                "backup: a symlink at the path is refused, and nothing is created at its target");
          (void)unlink(lnk); }

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

    /* ---- a fault on every write of every mutation (V4-22c, CLAIMS D14) ---- */
    {
        for (int i = 0; i < 4; i++) { make_pk(g_swpk[i], (uint8_t)(0x90 + i)); }
        static const sweep_case_t cases[] = {
            { "add-user", "sweep(add-user): a fault at each of its writes leaves the database exactly as it was",
              sw_none, sc_add_user, STORE_OK, 1,
              "commit(add-user): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "enroll-new-user", "sweep(enroll-new-user): a fault at each of its writes leaves the database exactly as it was",
              sw_none, sc_enroll_new, STORE_OK, 1,
              "commit(enroll-new-user): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "enroll", "sweep(enroll): a fault at each of its writes leaves the database exactly as it was",
              sw_user, sc_enroll, STORE_OK, 1,
              "commit(enroll): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "enroll-req7", "sweep(enroll-req7): a fault at each of its writes leaves the database exactly as it was",
              sw_device, sc_enroll_req7, STORE_ERR_CONFLICT, 1,
              "commit(enroll-req7): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "disable", "sweep(disable): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_disable, STORE_OK, 1,
              "commit(disable): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "enable", "sweep(enable): a fault at each of its writes leaves the database exactly as it was",
              sw_disabled, sc_enable, STORE_OK, 1,
              "commit(enable): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "rotate", "sweep(rotate): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_rotate, STORE_OK, 1,
              "commit(rotate): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "revoke", "sweep(revoke): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_revoke, STORE_OK, 1,
              "commit(revoke): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            /* V4-84: the same three over a store that holds what V4-80 and
             * V4-82 make them spend -- recovery codes, a ticket, a token and a
             * login code (sw_expired) -- so every spend statement is itself
             * faulted against live rows. The fixtures above hold none, and
             * the round-5 review found their sweeps never reached them. */
            { "disable-outstanding", "sweep(disable-outstanding): a fault at each of its writes leaves the database exactly as it was",
              sw_expired, sc_disable, STORE_OK, 1, NULL },
            { "rotate-outstanding", "sweep(rotate-outstanding): a fault at each of its writes leaves the database exactly as it was",
              sw_expired, sc_rotate, STORE_OK, 1, NULL },
            { "revoke-outstanding", "sweep(revoke-outstanding): a fault at each of its writes leaves the database exactly as it was",
              sw_expired, sc_revoke, STORE_OK, 1, NULL },
            { "touch-last-seen", "sweep(touch-last-seen): a fault at each of its writes leaves the database exactly as it was",
              sw_device, sc_touch, STORE_OK, 1,
              NULL },
            { "verify-token", "sweep(verify-token): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_verify, STORE_OK, 1,
              NULL },
            { "delete-token", "sweep(delete-token): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_delete_token, STORE_OK, 1,
              NULL },
            { "delete-tokens-for-handle", "sweep(delete-tokens-for-handle): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_delete_handle, STORE_OK, 1,
              NULL },
            { "delete-tokens-for-user", "sweep(delete-tokens-for-user): a fault at each of its writes leaves the database exactly as it was",
              sw_token, sc_delete_user, STORE_OK, 1,
              NULL },
            { "add-token", "sweep(add-token): a fault at each of its writes leaves the database exactly as it was",
              sw_device, sc_add_token, STORE_OK, 1,
              "commit(add-token): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "add-login-code", "sweep(add-login-code): a fault at each of its writes leaves the database exactly as it was",
              sw_device, sc_add_code, STORE_OK, 1,
              "commit(add-login-code): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "consume-login-code", "sweep(consume-login-code): a fault at each of its writes leaves the database exactly as it was",
              sw_login_code, sc_consume_code, STORE_OK, 1,
              "commit(consume-login-code): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "recovery-replace", "sweep(recovery-replace): a fault at each of its writes leaves the database exactly as it was",
              sw_codes, sc_replace, STORE_OK, 1,
              "commit(recovery-replace): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "recovery-consume", "sweep(recovery-consume): a fault at each of its writes leaves the database exactly as it was",
              sw_codes, sc_consume, STORE_OK, 1,
              "commit(recovery-consume): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "recovery-consume-revoke-all", "sweep(recovery-consume-revoke-all): a fault at each of its writes leaves the database exactly as it was",
              sw_two_devices, sc_consume_all, STORE_OK, 1,
              "commit(recovery-consume-revoke-all): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "note-failure", "sweep(note-failure): a fault at each of its writes leaves the database exactly as it was",
              sw_user, sc_failure, STORE_OK, 1,
              "commit(note-failure): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "note-failure-lock", "sweep(note-failure-lock): a fault at each of its writes leaves the database exactly as it was",
              sw_four_failures, sc_failure, STORE_OK, 1,
              "commit(note-failure-lock): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "enroll-via-ticket", "sweep(enroll-via-ticket): a fault at each of its writes leaves the database exactly as it was",
              sw_ticket, sc_ticket, STORE_OK, 1,
              "commit(enroll-via-ticket): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
            { "sweep", "sweep(sweep): a fault at each of its writes leaves the database exactly as it was",
              sw_expired, sc_sweep, STORE_OK, 1,
              "commit(sweep): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            CHECK(sweep_one(&cases[i]), cases[i].check);
        }
        /* ---- and a failed COMMIT in each one with a transaction (V4-23, F112) */
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            if (cases[i].commit_check != NULL) {
                CHECK(commit_one(&cases[i]), cases[i].commit_check);
            }
        }
    }

    /* ---- V4-45 (audit F122 item 4): a damaged store is refused at open ----
     * store_open reads three values from `meta` and refuses a store whose
     * schema_version is malformed or from a later schema (STORE_ERR_SCHEMA),
     * or whose store_id or decoy_pk has the wrong length (STORE_ERR_DAMAGED since
     * V4-61; it was STORE_ERR_CORRUPT, named audit-chain-corrupt, F126).
     * V4-40's coverage run found none of those refusals had ever run. Each
     * case damages one value in a fresh store with raw SQL and needs the open
     * refused with its own status and no handle; the canary reopens the
     * undamaged store. A store_id one byte LONG overruns the read buffer
     * and is refused one layer down (STORE_ERR_DB), which is checked too. */
    {
        char dbp[512];
        store_t *s = fresh_store("damaged.sqlite3", dbp, sizeof dbp);
        CHECK(s != NULL, "damaged store: a fresh store opens");
        if (s != NULL) { store_close(s); }
        const char *names[] = { "schema_version", "store_id", "decoy_pk" };
        uint8_t keep[3][STORE_PK_BYTES];
        int keep_len[3] = { 0, 0, 0 };
        for (int k = 0; k < 3; k++) {
            sqlite3 *h = NULL; sqlite3_stmt *st = NULL;
            if (sqlite3_open_v2(dbp, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
                sqlite3_prepare_v2(h, "SELECT value FROM meta WHERE key=?1;", -1, &st, NULL) == SQLITE_OK &&
                sqlite3_bind_text(st, 1, names[k], -1, SQLITE_STATIC) == SQLITE_OK &&
                sqlite3_step(st) == SQLITE_ROW) {
                keep_len[k] = sqlite3_column_bytes(st, 0);
                if (keep_len[k] > 0 && (size_t)keep_len[k] <= sizeof keep[k]) {
                    memcpy(keep[k], sqlite3_column_blob(st, 0), (size_t)keep_len[k]);
                }
            }
            sqlite3_finalize(st); sqlite3_close(h);
        }
        CHECK(keep_len[0] == 8 && keep_len[1] == (int)STORE_STORE_ID_BYTES && keep_len[2] == (int)STORE_PK_BYTES,
              "damaged store: the three meta values have their expected lengths before any damage");
        const struct { const char *sql; store_status_t want; const char *what; } cases[] = {
            /* seven zero bytes: without the length check they would read as
             * version 0, which opens, so only that check can refuse them */
            { "UPDATE meta SET value=X'00000000000000' WHERE key='schema_version';", STORE_ERR_SCHEMA,
              "damaged store: a schema_version of 7 bytes is refused as SCHEMA, and no handle is returned" },
            { "UPDATE meta SET value=X'0000000000000002' WHERE key='schema_version';", STORE_ERR_SCHEMA,
              "damaged store: a store from a later schema is refused as SCHEMA, and no handle is returned" },
            { "UPDATE meta SET value=zeroblob(15) WHERE key='store_id';", STORE_ERR_DAMAGED,
              "damaged store: a store_id one byte short is refused as DAMAGED (store-corrupt), and no handle is returned" },
            { "UPDATE meta SET value=zeroblob(17) WHERE key='store_id';", STORE_ERR_DB,
              "damaged store: a store_id one byte long is refused (DB: it overruns the read buffer), and no handle is returned" },
            { "UPDATE meta SET value=zeroblob(1951) WHERE key='decoy_pk';", STORE_ERR_DAMAGED,
              "damaged store: a decoy_pk one byte short is refused as DAMAGED (store-corrupt), and no handle is returned" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            store_t *d = NULL;
            const int damaged = raw_sql(dbp, cases[i].sql) == 0;
            const store_status_t r = store_open(dbp, KEK, &d);
            CHECK(damaged && r == cases[i].want && d == NULL, cases[i].what);
            if (d != NULL) { store_close(d); }
            /* put every value back exactly, so each case damages one thing */
            for (int k = 0; k < 3; k++) {
                sqlite3 *h = NULL; sqlite3_stmt *st = NULL;
                if (sqlite3_open_v2(dbp, &h, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
                    sqlite3_prepare_v2(h, "UPDATE meta SET value=?2 WHERE key=?1;", -1, &st, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(st, 1, names[k], -1, SQLITE_STATIC);
                    sqlite3_bind_blob(st, 2, keep[k], keep_len[k], SQLITE_STATIC);
                    (void)sqlite3_step(st);
                }
                sqlite3_finalize(st); sqlite3_close(h);
            }
        }
        store_t *again = NULL;
        CHECK(store_open(dbp, KEK, &again) == STORE_OK && again != NULL,
              "damaged store: the same store, repaired, opens again -- the canary");
        /* F126: what an operator reads. A damaged value is not a broken audit chain. */
        CHECK(strcmp(store_status_name(STORE_ERR_DAMAGED), "store-corrupt") == 0 &&
              strcmp(store_status_name(STORE_ERR_CORRUPT), "audit-chain-corrupt") == 0,
              "damaged store: a damaged value is named store-corrupt, and only the audit chain is audit-chain-corrupt (F126)");
        if (again != NULL) { store_close(again); }
    }

    /* ---- V4-284 (F470): revoke=all revokes every active device, however many ----
     * It stopped after 1024 and committed, answering OK with the newest
     * devices still active. 1030 devices, then one recovery with revoke=all. */
    {
        store_t *s = fresh_store("many.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open many\n"); return 1; }
        int made = (store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK);
        for (unsigned i = 0; made && i < 1030u; i++) {
            uint8_t h[8], pk[STORE_PK_BYTES];
            (void)snprintf((char *)h, sizeof h, "h%05u", i);
            make_pk(pk, (uint8_t)i);
            pk[0] = (uint8_t)(i >> 8); pk[1] = (uint8_t)i; pk[2] = 0xa5;
            made = (store_enroll_device(s, h, 6u, U1, sizeof U1, pk, "site", "admin", NULL, 0) == STORE_OK);
        }
        CHECK(made, "revoke-all, many: a user with 1030 active devices");
        const char *g[] = { "hash-m1" };
        size_t revoked = 0;
        CHECK(store_recovery_replace(s, U1, sizeof U1, g, 1, 100, NULL) == STORE_OK &&
              store_recovery_consume_ex(s, any_unused(s, U1, sizeof U1), U1, sizeof U1, TH2, 300, 900, 1, &revoked)
                  == STORE_OK, "revoke-all, many: the recovery succeeds");
        store_close(s);
        long long active = -1, keys = -1;
        char t[8];
        CHECK(revoked == 1030u &&
              raw_row(dbp, "SELECT COUNT(*), '' FROM devices WHERE status='active';", &active, t, sizeof t) == 0 &&
              active == 0 &&
              raw_row(dbp, "SELECT COUNT(*), '' FROM device_keys WHERE status='active';", &keys, t, sizeof t) == 0 &&
              keys == 0,
              "revoke-all, many: all 1030 devices and their keys are revoked, not the first 1024 (F470)");
        store_t *s2 = NULL;
        CHECK(store_open(dbp, KEK, &s2) == STORE_OK && store_audit_verify(s2) == STORE_OK,
              "revoke-all, many: the audit chain verifies");
        if (s2 != NULL) { store_close(s2); }
    }

    /* ---- V4-284 (F471): an enable keeps the record of why the user was disabled ---- */
    {
        store_t *s = fresh_store("reason.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open reason\n"); return 1; }
        const char why[] = "stolen laptop";
        CHECK(store_add_user(s, U1, sizeof U1, STORE_ROLE_USER) == STORE_OK &&
              store_disable_user(s, U1, sizeof U1, "admin", (const uint8_t *)why, sizeof why - 1u) == STORE_OK,
              "disable reason: a user disabled with a reason");
        long long at0 = 0, at1 = 0;
        char r0[64] = "", r1[64] = "", st1[16] = "";
        const char *q = "SELECT disabled_at, CAST(disabled_reason AS TEXT) FROM users;";
        CHECK(raw_row(dbp, q, &at0, r0, sizeof r0) == 0 && at0 > 0 && strcmp(r0, why) == 0,
              "disable reason: the row holds the time and the reason (the canary)");
        CHECK(store_enable_user(s, U1, sizeof U1, "admin") == STORE_OK, "disable reason: the user is enabled again");
        store_close(s);
        long long dummy = 0;
        CHECK(raw_row(dbp, q, &at1, r1, sizeof r1) == 0 && at1 == at0 && strcmp(r1, why) == 0 &&
              raw_row(dbp, "SELECT 0, status FROM users;", &dummy, st1, sizeof st1) == 0 && strcmp(st1, "active") == 0,
              "disable reason: after the enable the user is active and the last disable's time and reason remain (F471)");
    }

    /* ---- V4-284 (F472): the backup's file is checked to be the one it made ----
     * VACUUM INTO and the chmod after it used the destination by name. Here
     * the name is swapped for a symlink to another file once the copy is
     * written (the observer runs there): the mode was set on the link's
     * target and the backup answered OK. Now it is refused, the target is
     * untouched, and the name -- no longer this call's -- is not removed. */
    {
        store_t *s = fresh_store("swap.sqlite3", dbp, sizeof dbp);
        if (s == NULL) { printf("FAIL: open swap\n"); return 1; }
        snprintf(g_swap_dest, sizeof g_swap_dest, "%s/swap-backup.sqlite3", g_dir);
        snprintf(g_swap_target, sizeof g_swap_target, "%s/swap-target", g_dir);
        char moved[640];
        snprintf(moved, sizeof moved, "%s.moved", g_swap_dest);
        FILE *f = fopen(g_swap_target, "w");
        if (f != NULL) { (void)fputs("someone else's\n", f); (void)fclose(f); }
        CHECK(chmod(g_swap_target, 0644) == 0, "backup swap: another file, mode 0644");
        store_fault_arm_backup_observer(swap_for_symlink);
        const store_status_t br = store_backup(s, g_swap_dest);
        store_fault_arm_backup_observer(NULL);
        struct stat ts, ls;
        CHECK(g_swapped == 1 && br == STORE_ERR_IO && stat(g_swap_target, &ts) == 0 && (ts.st_mode & 07777) == 0644 &&
              lstat(g_swap_dest, &ls) == 0 && S_ISLNK(ls.st_mode),
              "backup swap: a name swapped for a symlink after the copy fails the backup, and neither the link "
              "nor its target is touched (F472)");
        (void)unlink(g_swap_dest); (void)unlink(moved); (void)unlink(g_swap_target);
        char plain[600];
        snprintf(plain, sizeof plain, "%s/plain-backup.sqlite3", g_dir);
        CHECK(store_backup(s, plain) == STORE_OK && mode_of_path(plain) == 0600,
              "backup swap: the same backup, left alone, succeeds with mode 0600 (the control)");
        store_close(s);
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
