#include "store.h"
#include "schema.sql.h"

#include <sqlite3.h>
#include <sodium.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kex.h"
#include "secure_mem.h"
#include "mldsa_wrap.h"

/*
 * See store.h for the contract. Two things in here are load-bearing and are
 * spelled out rather than left to the reader:
 *
 * 1. EVERY mutation is wrapped in exactly one transaction (Req 14). The
 *    helpers tx_begin/tx_commit/tx_rollback are used by every operation that
 *    writes more than nothing, and `rotate` -- the only genuinely multi-row
 *    case -- supersedes the old key, inserts the new one, optionally drops
 *    tokens and appends the audit row inside a single BEGIN..COMMIT. A
 *    partially applied rotation is therefore impossible; the test-only fault
 *    hook below exists to prove that, not merely to assert it.
 *
 * 2. The audit MAC chain (§9.2.4) is
 *      mac_i = crypto_auth(key_audit, prev_mac || seq || at || event || 0x00 || fields)
 *    The spec leaves "fields" abstract; this implementation fixes it to an
 *    unambiguous, length-prefixed encoding (audit_mac_input below) so the MAC
 *    is injective over the row: no two distinct rows can produce the same MAC
 *    input by shifting a delimiter. The encoding is part of the on-disk format
 *    and must not change without a schema version bump.
 */

/* Test-only fault injection (the fuzz-only-RNG precedent): compiled in ONLY
 * when MLDSA_STORE_FAULT_HOOK is defined, which the test target does and no
 * normal build does. A test arms a countdown; when it reaches zero the next
 * fault point fails, simulating a crash mid-operation. */
#ifdef MLDSA_STORE_FAULT_HOOK
static int g_store_fault_countdown = -1; /* <0 disabled */
void store_fault_arm(int n_steps);       /* declared for the test; see store_test_hook.h */
void store_fault_arm(int n_steps) { g_store_fault_countdown = n_steps; }
static int store_fault_fire(void)
{
    if (g_store_fault_countdown < 0) {
        return 0;
    }
    if (g_store_fault_countdown == 0) {
        g_store_fault_countdown = -1;
        return 1;
    }
    g_store_fault_countdown--;
    return 0;
}
#define STORE_FAULT_POINT() (store_fault_fire())
#else
#define STORE_FAULT_POINT() (0)
#endif

struct store {
    sqlite3 *db;
    uint8_t *key_audit;                       /* secure_mem, STORE_AUDIT_MAC_BYTES */
    uint8_t store_id[STORE_STORE_ID_BYTES];
    uint8_t decoy_pk[STORE_PK_BYTES];
};

#define AUDIT_LABEL "mldsa-authd/v1/audit-mac"

const char *store_status_name(store_status_t st)
{
    switch (st) {
    case STORE_OK:            return "ok";
    case STORE_ERR_ARG:       return "bad-argument";
    case STORE_ERR_IO:        return "io";
    case STORE_ERR_DB:        return "database-error";
    case STORE_ERR_NOT_FOUND: return "not-found";
    case STORE_ERR_CONFLICT:  return "conflict";
    case STORE_ERR_STATE:     return "illegal-state";
    case STORE_ERR_SCHEMA:    return "unsupported-schema-version";
    case STORE_ERR_CRYPTO:    return "crypto-failure";
    case STORE_ERR_CORRUPT:   return "audit-chain-corrupt";
    default:                  return "unknown";
    }
}

/* --- small helpers ------------------------------------------------------ */

static int id_ok(const uint8_t *id, size_t len)
{
    return id != NULL && len >= 1u && len <= STORE_ID_MAX;
}

static int64_t now_unix(void)
{
    return (int64_t)time(NULL);
}

static store_status_t exec_simple(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return STORE_ERR_DB;
    }
    return STORE_OK;
}

static store_status_t tx_begin(store_t *s)  { return exec_simple(s->db, "BEGIN IMMEDIATE;"); }
static store_status_t tx_commit(store_t *s) { return exec_simple(s->db, "COMMIT;"); }
static void           tx_rollback(store_t *s) { (void)exec_simple(s->db, "ROLLBACK;"); }

static const char *role_text(store_role_t r) { return r == STORE_ROLE_OPERATOR ? "operator" : "user"; }

static store_status_t role_from_text(const unsigned char *t, store_role_t *out)
{
    if (t == NULL) {
        return STORE_ERR_DB;
    }
    if (strcmp((const char *)t, "operator") == 0) { *out = STORE_ROLE_OPERATOR; return STORE_OK; }
    if (strcmp((const char *)t, "user") == 0)     { *out = STORE_ROLE_USER;     return STORE_OK; }
    return STORE_ERR_DB;
}

/* Copies a blob column into a caller buffer with an explicit capacity. */
static store_status_t copy_blob_col(sqlite3_stmt *st, int col, uint8_t *out, size_t cap, size_t *out_len)
{
    const void *p = sqlite3_column_blob(st, col);
    int n = sqlite3_column_bytes(st, col);
    if (n < 0 || (size_t)n > cap) {
        return STORE_ERR_DB;
    }
    if (out != NULL && n > 0 && p != NULL) {
        memcpy(out, p, (size_t)n);
    }
    if (out_len != NULL) {
        *out_len = (size_t)n;
    }
    return STORE_OK;
}

static void be64(uint8_t out[8], int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(u & 0xffu); u >>= 8; }
}

/* --- audit chain -------------------------------------------------------- */

/* Builds the MAC input: prev_mac(32) || seq(8 BE) || at(8 BE) || event || 0x00
 * || u8 user_id_len || user_id || u8 handle_len || handle
 * || u16 detail_len (BE) || detail. Every variable field is length-prefixed,
 * so the encoding is injective (see the file header). Returns the length, or
 * 0 if the row does not fit the caller's buffer. */
static size_t audit_mac_input(uint8_t *buf, size_t cap,
                              const uint8_t prev_mac[STORE_AUDIT_MAC_BYTES],
                              int64_t seq, int64_t at, const char *event,
                              const uint8_t *user_id, size_t user_id_len,
                              const uint8_t *handle, size_t handle_len,
                              const char *detail)
{
    size_t ev_len = (event != NULL) ? strlen(event) : 0u;
    size_t de_len = (detail != NULL) ? strlen(detail) : 0u;
    if (user_id_len > 255u || handle_len > 255u || de_len > 0xffffu) {
        return 0u;
    }
    size_t need = STORE_AUDIT_MAC_BYTES + 8u + 8u + ev_len + 1u
                + 1u + user_id_len + 1u + handle_len + 2u + de_len;
    if (need > cap) {
        return 0u;
    }
    size_t o = 0;
    memcpy(buf + o, prev_mac, STORE_AUDIT_MAC_BYTES); o += STORE_AUDIT_MAC_BYTES;
    be64(buf + o, seq); o += 8u;
    be64(buf + o, at);  o += 8u;
    if (ev_len > 0u) { memcpy(buf + o, event, ev_len); o += ev_len; }
    buf[o++] = 0x00u;
    buf[o++] = (uint8_t)user_id_len;
    if (user_id_len > 0u) { memcpy(buf + o, user_id, user_id_len); o += user_id_len; }
    buf[o++] = (uint8_t)handle_len;
    if (handle_len > 0u) { memcpy(buf + o, handle, handle_len); o += handle_len; }
    buf[o++] = (uint8_t)((de_len >> 8) & 0xffu);
    buf[o++] = (uint8_t)(de_len & 0xffu);
    if (de_len > 0u) { memcpy(buf + o, detail, de_len); o += de_len; }
    return o;
}

/* Reads the current head (seq, mac). seq 0 and an all-zero mac when empty. */
static store_status_t audit_head(const store_t *s, int64_t *seq_out, uint8_t mac_out[STORE_AUDIT_MAC_BYTES])
{
    sqlite3_stmt *st = NULL;
    store_status_t r = STORE_OK;
    memset(mac_out, 0, STORE_AUDIT_MAC_BYTES);
    *seq_out = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1;", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *seq_out = sqlite3_column_int64(st, 0);
        size_t n = 0;
        r = copy_blob_col(st, 1, mac_out, STORE_AUDIT_MAC_BYTES, &n);
        if (r == STORE_OK && n != STORE_AUDIT_MAC_BYTES) {
            r = STORE_ERR_CORRUPT;
        }
    } else if (rc != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

/* Appends one audit row. MUST be called inside the caller's transaction. */
static store_status_t audit_append(store_t *s, const char *event,
                                   const uint8_t *user_id, size_t user_id_len,
                                   const uint8_t *handle, size_t handle_len,
                                   const char *detail)
{
    int64_t prev_seq = 0;
    uint8_t prev_mac[STORE_AUDIT_MAC_BYTES];
    store_status_t r = audit_head(s, &prev_seq, prev_mac);
    if (r != STORE_OK) {
        return r;
    }
    int64_t seq = prev_seq + 1;
    int64_t at = now_unix();

    uint8_t inbuf[1024];
    size_t in_len = audit_mac_input(inbuf, sizeof inbuf, prev_mac, seq, at, event,
                                    user_id, user_id_len, handle, handle_len, detail);
    if (in_len == 0u) {
        return STORE_ERR_ARG;
    }
    uint8_t mac[STORE_AUDIT_MAC_BYTES];
    if (crypto_auth(mac, inbuf, in_len, s->key_audit) != 0) {
        sodium_memzero(inbuf, sizeof inbuf);
        return STORE_ERR_CRYPTO;
    }
    sodium_memzero(inbuf, sizeof inbuf);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO audit(seq, at, event, user_id, handle, detail, prev_mac, mac)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8);", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    r = STORE_OK;
    if (sqlite3_bind_int64(st, 1, seq) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, at) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, event ? event : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 4, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 5, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 6, detail ? detail : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 7, prev_mac, (int)STORE_AUDIT_MAC_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 8, mac, (int)STORE_AUDIT_MAC_BYTES, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else if (sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

store_status_t store_audit_head_mac(const store_t *s, uint8_t out[STORE_AUDIT_MAC_BYTES])
{
    if (s == NULL || out == NULL) {
        return STORE_ERR_ARG;
    }
    int64_t seq = 0;
    return audit_head(s, &seq, out);
}

store_status_t store_audit_verify(const store_t *s)
{
    if (s == NULL) {
        return STORE_ERR_ARG;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT seq, at, event, user_id, handle, detail, prev_mac, mac FROM audit ORDER BY seq ASC;",
            -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    uint8_t running[STORE_AUDIT_MAC_BYTES];
    memset(running, 0, sizeof running);
    int64_t expect_seq = 1;
    store_status_t r = STORE_OK;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int64_t seq = sqlite3_column_int64(st, 0);
        int64_t at = sqlite3_column_int64(st, 1);
        const unsigned char *event = sqlite3_column_text(st, 2);
        const unsigned char *detail = sqlite3_column_text(st, 5);
        uint8_t uid[STORE_ID_MAX], hnd[STORE_ID_MAX];
        size_t uid_len = 0, hnd_len = 0;
        uint8_t stored_prev[STORE_AUDIT_MAC_BYTES], stored_mac[STORE_AUDIT_MAC_BYTES];
        size_t n_prev = 0, n_mac = 0;

        if (seq != expect_seq) { r = STORE_ERR_CORRUPT; break; }          /* gap or reorder */
        if (copy_blob_col(st, 3, uid, sizeof uid, &uid_len) != STORE_OK ||
            copy_blob_col(st, 4, hnd, sizeof hnd, &hnd_len) != STORE_OK ||
            copy_blob_col(st, 6, stored_prev, sizeof stored_prev, &n_prev) != STORE_OK ||
            copy_blob_col(st, 7, stored_mac, sizeof stored_mac, &n_mac) != STORE_OK) {
            r = STORE_ERR_CORRUPT; break;
        }
        if (n_prev != STORE_AUDIT_MAC_BYTES || n_mac != STORE_AUDIT_MAC_BYTES) { r = STORE_ERR_CORRUPT; break; }
        /* the chain link: this row's prev_mac must be the previous row's mac */
        if (sodium_memcmp(stored_prev, running, STORE_AUDIT_MAC_BYTES) != 0) { r = STORE_ERR_CORRUPT; break; }

        uint8_t inbuf[1024];
        size_t in_len = audit_mac_input(inbuf, sizeof inbuf, stored_prev, seq, at,
                                        (const char *)event, uid, uid_len, hnd, hnd_len,
                                        (const char *)detail);
        if (in_len == 0u) { r = STORE_ERR_CORRUPT; break; }
        uint8_t want[STORE_AUDIT_MAC_BYTES];
        int mac_rc = crypto_auth(want, inbuf, in_len, s->key_audit);
        sodium_memzero(inbuf, sizeof inbuf);
        if (mac_rc != 0) { r = STORE_ERR_CRYPTO; break; }
        if (sodium_memcmp(want, stored_mac, STORE_AUDIT_MAC_BYTES) != 0) { r = STORE_ERR_CORRUPT; break; }

        memcpy(running, stored_mac, STORE_AUDIT_MAC_BYTES);
        expect_seq++;
    }
    if (r == STORE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

/* --- open / close ------------------------------------------------------- */

static store_status_t meta_get(sqlite3 *db, const char *key, uint8_t *out, size_t cap, size_t *out_len, int *found)
{
    sqlite3_stmt *st = NULL;
    *found = 0;
    if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key=?1;", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            *found = 1;
            r = copy_blob_col(st, 0, out, cap, out_len);
        } else if (rc != SQLITE_DONE) {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    return r;
}

static store_status_t meta_put(sqlite3 *db, const char *key, const uint8_t *val, size_t len)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2);", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, val, (int)len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

store_status_t store_open(const char *path, const uint8_t kek[STORE_KEK_BYTES], store_t **out)
{
    if (path == NULL || kek == NULL || out == NULL) {
        return STORE_ERR_ARG;
    }
    *out = NULL;
    if (sodium_init() < 0) {
        return STORE_ERR_CRYPTO;
    }

    store_t *s = calloc(1, sizeof *s);
    if (s == NULL) {
        return STORE_ERR_CRYPTO;
    }
    store_status_t r = STORE_OK;

    if (sqlite3_open_v2(path, &s->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        r = STORE_ERR_IO;
        goto fail;
    }
    /* Spec §9: WAL, durable commits, foreign keys enforced. */
    if (exec_simple(s->db, "PRAGMA journal_mode=WAL;") != STORE_OK ||
        exec_simple(s->db, "PRAGMA synchronous=FULL;") != STORE_OK ||
        exec_simple(s->db, "PRAGMA foreign_keys=ON;") != STORE_OK) {
        r = STORE_ERR_DB;
        goto fail;
    }
    if (exec_simple(s->db, STORE_SCHEMA_SQL) != STORE_OK) {
        r = STORE_ERR_DB;
        goto fail;
    }

    if ((r = tx_begin(s)) != STORE_OK) {
        goto fail;
    }

    /* schema_version */
    uint8_t vbuf[8];
    size_t vlen = 0;
    int found = 0;
    if ((r = meta_get(s->db, "schema_version", vbuf, sizeof vbuf, &vlen, &found)) != STORE_OK) {
        goto fail_tx;
    }
    if (found) {
        if (vlen != 8u) { r = STORE_ERR_SCHEMA; goto fail_tx; }
        int64_t v = 0;
        for (size_t i = 0; i < 8u; i++) { v = (v << 8) | vbuf[i]; }
        if (v > STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; }
    } else {
        uint8_t nv[8];
        be64(nv, (int64_t)STORE_SCHEMA_VERSION);
        if ((r = meta_put(s->db, "schema_version", nv, sizeof nv)) != STORE_OK) { goto fail_tx; }
    }

    /* store_id */
    size_t n = 0;
    if ((r = meta_get(s->db, "store_id", s->store_id, sizeof s->store_id, &n, &found)) != STORE_OK) {
        goto fail_tx;
    }
    if (!found) {
        randombytes_buf(s->store_id, sizeof s->store_id);
        if ((r = meta_put(s->db, "store_id", s->store_id, sizeof s->store_id)) != STORE_OK) { goto fail_tx; }
    } else if (n != sizeof s->store_id) {
        r = STORE_ERR_CORRUPT;
        goto fail_tx;
    }

    /* decoy_pk: a REAL ML-DSA public key whose secret is discarded, so an
     * unknown identity gets a ServerHello indistinguishable from a real one
     * (spec decision 4 / §5). Generated once, at first open. */
    if ((r = meta_get(s->db, "decoy_pk", s->decoy_pk, sizeof s->decoy_pk, &n, &found)) != STORE_OK) {
        goto fail_tx;
    }
    if (!found) {
        mldsa_keypair_t kp;
        memset(&kp, 0, sizeof kp);
        if (mldsa_keypair_generate(&kp) != 0) { r = STORE_ERR_CRYPTO; goto fail_tx; }
        memcpy(s->decoy_pk, kp.public_key, sizeof s->decoy_pk);
        mldsa_keypair_free(&kp);   /* the secret key is wiped and dropped here */
        if ((r = meta_put(s->db, "decoy_pk", s->decoy_pk, sizeof s->decoy_pk)) != STORE_OK) { goto fail_tx; }
    } else if (n != sizeof s->decoy_pk) {
        r = STORE_ERR_CORRUPT;
        goto fail_tx;
    }

    if ((r = tx_commit(s)) != STORE_OK) {
        goto fail_tx;
    }

    /* key_audit = HKDF-SHA256(ikm=KEK, salt=store_id, info=label) (§9.2.4).
     * Held in secure memory; never leaves this module. */
    s->key_audit = secure_mem_alloc(STORE_AUDIT_MAC_BYTES);
    if (s->key_audit == NULL) {
        r = STORE_ERR_CRYPTO;
        goto fail;
    }
    if (kex_hkdf_sha256(s->key_audit, STORE_AUDIT_MAC_BYTES,
                        kek, STORE_KEK_BYTES,
                        s->store_id, sizeof s->store_id,
                        (const uint8_t *)AUDIT_LABEL, sizeof(AUDIT_LABEL) - 1u) != 0) {
        r = STORE_ERR_CRYPTO;
        goto fail;
    }

    *out = s;
    return STORE_OK;

fail_tx:
    tx_rollback(s);
fail:
    store_close(s);
    return r;
}

void store_close(store_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->key_audit != NULL) {
        secure_mem_free(s->key_audit, STORE_AUDIT_MAC_BYTES);
        s->key_audit = NULL;
    }
    if (s->db != NULL) {
        sqlite3_close(s->db);
        s->db = NULL;
    }
    sodium_memzero(s->store_id, sizeof s->store_id);
    free(s);
}

store_status_t store_get_store_id(const store_t *s, uint8_t out[STORE_STORE_ID_BYTES])
{
    if (s == NULL || out == NULL) { return STORE_ERR_ARG; }
    memcpy(out, s->store_id, STORE_STORE_ID_BYTES);
    return STORE_OK;
}

store_status_t store_get_decoy_pk(const store_t *s, uint8_t out[STORE_PK_BYTES])
{
    if (s == NULL || out == NULL) { return STORE_ERR_ARG; }
    memcpy(out, s->decoy_pk, STORE_PK_BYTES);
    return STORE_OK;
}

/* --- users -------------------------------------------------------------- */

store_status_t store_add_user(store_t *s, const uint8_t *user_id, size_t user_id_len, store_role_t role)
{
    if (s == NULL || !id_ok(user_id, user_id_len)) { return STORE_ERR_ARG; }
    if (role != STORE_ROLE_OPERATOR && role != STORE_ROLE_USER) { return STORE_ERR_ARG; }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO users(user_id, role, status, created_at) VALUES(?1,?2,'active',?3);",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, role_text(role), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 3, now_unix()) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r == STORE_OK) { r = audit_append(s, "user-add", user_id, user_id_len, NULL, 0, role_text(role)); }
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

static store_status_t set_user_status(store_t *s, const uint8_t *user_id, size_t user_id_len,
                                      const char *status, const char *by,
                                      const uint8_t *reason, size_t reason_len,
                                      int drop_tokens, const char *event)
{
    if (s == NULL || !id_ok(user_id, user_id_len)) { return STORE_ERR_ARG; }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "UPDATE users SET status=?2, disabled_at=?3, disabled_reason=?4 WHERE user_id=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    int is_disable = (strcmp(status, "disabled") == 0);
    if (sqlite3_bind_blob(st, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, status, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        (is_disable ? sqlite3_bind_int64(st, 3, now_unix()) : sqlite3_bind_null(st, 3)) != SQLITE_OK ||
        (is_disable && reason != NULL
            ? sqlite3_bind_blob(st, 4, reason, (int)reason_len, SQLITE_TRANSIENT)
            : sqlite3_bind_null(st, 4)) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else if (sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    } else if (sqlite3_changes(s->db) == 0) {
        r = STORE_ERR_NOT_FOUND;
    }
    sqlite3_finalize(st);

    if (r == STORE_OK && drop_tokens) {
        sqlite3_stmt *dt = NULL;
        if (sqlite3_prepare_v2(s->db, "DELETE FROM tokens WHERE user_id=?1;", -1, &dt, NULL) != SQLITE_OK) {
            r = STORE_ERR_DB;
        } else {
            if (sqlite3_bind_blob(dt, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_step(dt) != SQLITE_DONE) {
                r = STORE_ERR_DB;
            }
            sqlite3_finalize(dt);
        }
    }
    if (r == STORE_OK) { r = audit_append(s, event, user_id, user_id_len, NULL, 0, by); }
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_disable_user(store_t *s, const uint8_t *user_id, size_t user_id_len,
                                  const char *by, const uint8_t *reason, size_t reason_len)
{
    return set_user_status(s, user_id, user_id_len, "disabled", by, reason, reason_len, 1, "user-disable");
}

store_status_t store_enable_user(store_t *s, const uint8_t *user_id, size_t user_id_len, const char *by)
{
    return set_user_status(s, user_id, user_id_len, "active", by, NULL, 0, 0, "user-enable");
}

/* --- devices / keys ------------------------------------------------------ */

static void pk_fingerprint(const uint8_t pk[STORE_PK_BYTES], uint8_t out[crypto_hash_sha256_BYTES])
{
    crypto_hash_sha256(out, pk, STORE_PK_BYTES);
}

/* 1 if this pk exists anywhere in device_keys, in any state (invariant 2). */
static store_status_t pk_exists(store_t *s, const uint8_t pk[STORE_PK_BYTES], int *exists)
{
    sqlite3_stmt *st = NULL;
    *exists = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT 1 FROM device_keys WHERE pk=?1 LIMIT 1;", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, pk, (int)STORE_PK_BYTES, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) { *exists = 1; }
        else if (rc != SQLITE_DONE) { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    return r;
}

/* Fetches the handle's active key pk, if any. */
static store_status_t active_key_of(store_t *s, const uint8_t *handle, size_t handle_len,
                                    uint8_t pk_out[STORE_PK_BYTES], int64_t *key_id_out, int *found)
{
    sqlite3_stmt *st = NULL;
    *found = 0;
    if (sqlite3_prepare_v2(s->db,
            "SELECT key_id, pk FROM device_keys WHERE handle=?1 AND status='active' LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            *found = 1;
            if (key_id_out != NULL) { *key_id_out = sqlite3_column_int64(st, 0); }
            size_t n = 0;
            r = copy_blob_col(st, 1, pk_out, STORE_PK_BYTES, &n);
            if (r == STORE_OK && n != STORE_PK_BYTES) { r = STORE_ERR_CORRUPT; }
        } else if (rc != SQLITE_DONE) {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    return r;
}

store_status_t store_enroll_device(store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   const uint8_t *user_id, size_t user_id_len,
                                   const uint8_t pk[STORE_PK_BYTES],
                                   const char *via, const char *by,
                                   const uint8_t *label, size_t label_len)
{
    if (s == NULL || !id_ok(handle, handle_len) || !id_ok(user_id, user_id_len) || pk == NULL) {
        return STORE_ERR_ARG;
    }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    /* Req 7: a known handle presenting a DIFFERENT key is rejected and audited.
     * With the identical key the call is idempotent. */
    uint8_t cur[STORE_PK_BYTES];
    int have_active = 0;
    r = active_key_of(s, handle, handle_len, cur, NULL, &have_active);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    if (have_active) {
        if (sodium_memcmp(cur, pk, STORE_PK_BYTES) == 0) {
            tx_rollback(s);         /* nothing changed; no audit row */
            return STORE_OK;
        }
        r = audit_append(s, "enroll-key-mismatch", user_id, user_id_len, handle, handle_len,
                         "known handle presented a different key (Req 7)");
        if (r == STORE_OK) { (void)tx_commit(s); } else { tx_rollback(s); }
        return STORE_ERR_CONFLICT;
    }

    /* Invariant 2: the public key must be unused across all devices and states. */
    int dup = 0;
    r = pk_exists(s, pk, &dup);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    if (dup) { tx_rollback(s); return STORE_ERR_CONFLICT; }

    int64_t now = now_unix();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO devices(handle,user_id,label,status,enrolled_at,enrolled_via,enrolled_by)"
            " VALUES(?1,?2,?3,'active',?4,?5,?6);", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        (label != NULL ? sqlite3_bind_blob(st, 3, label, (int)label_len, SQLITE_TRANSIENT)
                       : sqlite3_bind_null(st, 3)) != SQLITE_OK ||
        sqlite3_bind_int64(st, 4, now) != SQLITE_OK ||
        sqlite3_bind_text(st, 5, via ? via : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 6, by ? by : "", -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }   /* unknown user_id (FK) or dup handle */
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    uint8_t fp[crypto_hash_sha256_BYTES];
    pk_fingerprint(pk, fp);
    st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO device_keys(handle,pk,pk_fp,status,valid_from) VALUES(?1,?2,?3,'active',?4);",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, pk, (int)STORE_PK_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 3, fp, (int)sizeof fp, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 4, now) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r == STORE_OK) { r = audit_append(s, "device-enroll", user_id, user_id_len, handle, handle_len, via); }
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_rotate_key(store_t *s,
                                const uint8_t *handle, size_t handle_len,
                                const uint8_t new_pk[STORE_PK_BYTES],
                                const uint8_t *hsid, size_t hsid_len,
                                int drop_tokens)
{
    if (s == NULL || !id_ok(handle, handle_len) || new_pk == NULL) {
        return STORE_ERR_ARG;
    }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    uint8_t cur[STORE_PK_BYTES];
    int64_t cur_id = 0;
    int have = 0;
    r = active_key_of(s, handle, handle_len, cur, &cur_id, &have);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    if (!have) { tx_rollback(s); return STORE_ERR_NOT_FOUND; }

    int dup = 0;
    r = pk_exists(s, new_pk, &dup);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    if (dup) { tx_rollback(s); return STORE_ERR_CONFLICT; }

    int64_t now = now_unix();

    /* Supersede FIRST: the partial unique index permits only one active key per
     * handle, so the new row cannot be inserted while the old one is active. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "UPDATE device_keys SET status='superseded', valid_to=?2, superseded_by_hsid=?3 WHERE key_id=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_int64(st, 1, cur_id) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK ||
        (hsid != NULL ? sqlite3_bind_blob(st, 3, hsid, (int)hsid_len, SQLITE_TRANSIENT)
                      : sqlite3_bind_null(st, 3)) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    /* The window a non-transactional implementation would leave half-open.
     * Armed only in the test build; proves the rollback, does not create it. */
    if (STORE_FAULT_POINT()) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }

    uint8_t fp[crypto_hash_sha256_BYTES];
    pk_fingerprint(new_pk, fp);
    st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO device_keys(handle,pk,pk_fp,status,valid_from) VALUES(?1,?2,?3,'active',?4);",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, new_pk, (int)STORE_PK_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 3, fp, (int)sizeof fp, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 4, now) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    if (drop_tokens) {
        sqlite3_stmt *dt = NULL;
        if (sqlite3_prepare_v2(s->db, "DELETE FROM tokens WHERE handle=?1;", -1, &dt, NULL) != SQLITE_OK) {
            tx_rollback(s);
            return STORE_ERR_DB;
        }
        if (sqlite3_bind_blob(dt, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_step(dt) != SQLITE_DONE) {
            r = STORE_ERR_DB;
        }
        sqlite3_finalize(dt);
        if (r != STORE_OK) { tx_rollback(s); return r; }
    }

    r = audit_append(s, "key-rotate", NULL, 0, handle, handle_len, drop_tokens ? "tokens-dropped" : "tokens-kept");
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_revoke_device(store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   const char *by, const uint8_t *reason, size_t reason_len)
{
    if (s == NULL || !id_ok(handle, handle_len)) { return STORE_ERR_ARG; }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "UPDATE devices SET status='revoked', revoked_at=?2, revoked_by=?3, revoked_reason=?4"
            " WHERE handle=?1;", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now_unix()) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, by ? by : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        (reason != NULL ? sqlite3_bind_blob(st, 4, reason, (int)reason_len, SQLITE_TRANSIENT)
                        : sqlite3_bind_null(st, 4)) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    } else if (sqlite3_changes(s->db) == 0) {
        r = STORE_ERR_NOT_FOUND;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    /* the active key goes with it */
    st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "UPDATE device_keys SET status='revoked', valid_to=?2 WHERE handle=?1 AND status='active';",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now_unix()) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    st = NULL;
    if (sqlite3_prepare_v2(s->db, "DELETE FROM tokens WHERE handle=?1;", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r == STORE_OK) { r = audit_append(s, "device-revoke", NULL, 0, handle, handle_len, by); }
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_lookup_active(const store_t *s,
                                   const uint8_t *handle, size_t handle_len,
                                   uint8_t pk_out[STORE_PK_BYTES],
                                   uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out,
                                   store_role_t *role_out)
{
    if (s == NULL || !id_ok(handle, handle_len) || pk_out == NULL) {
        return STORE_ERR_ARG;
    }
    sqlite3_stmt *st = NULL;
    /* Invariant 3: active key AND active device AND active user -- one query. */
    if (sqlite3_prepare_v2(s->db,
            "SELECT dk.pk, u.user_id, u.role"
            " FROM device_keys dk"
            " JOIN devices d ON d.handle = dk.handle"
            " JOIN users   u ON u.user_id = d.user_id"
            " WHERE dk.handle = ?1 AND dk.status='active'"
            "   AND d.status='active' AND u.status='active' LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            size_t n = 0;
            r = copy_blob_col(st, 0, pk_out, STORE_PK_BYTES, &n);
            if (r == STORE_OK && n != STORE_PK_BYTES) { r = STORE_ERR_CORRUPT; }
            if (r == STORE_OK && user_id_out != NULL) {
                r = copy_blob_col(st, 1, user_id_out, user_id_cap, user_id_len_out);
            }
            if (r == STORE_OK && role_out != NULL) {
                r = role_from_text(sqlite3_column_text(st, 2), role_out);
            }
        } else if (rc == SQLITE_DONE) {
            r = STORE_ERR_NOT_FOUND;
        } else {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    return r;
}

store_status_t store_touch_last_seen(store_t *s, const uint8_t *handle, size_t handle_len)
{
    if (s == NULL || !id_ok(handle, handle_len)) { return STORE_ERR_ARG; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "UPDATE devices SET last_seen=?2 WHERE handle=?1;", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now_unix()) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

/* --- tokens -------------------------------------------------------------- */

store_status_t store_add_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES],
                               const uint8_t *user_id, size_t user_id_len,
                               const uint8_t *handle, size_t handle_len,
                               const uint8_t *hsid, size_t hsid_len,
                               int64_t issued_at, int64_t expires_at, int64_t idle_expires_at)
{
    if (s == NULL || token_hash == NULL || !id_ok(user_id, user_id_len) || !id_ok(handle, handle_len)) {
        return STORE_ERR_ARG;
    }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO tokens(token_hash,user_id,handle,handshake_id,issued_at,expires_at,idle_expires_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7);", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, token_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 3, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        (hsid != NULL ? sqlite3_bind_blob(st, 4, hsid, (int)hsid_len, SQLITE_TRANSIENT)
                      : sqlite3_bind_null(st, 4)) != SQLITE_OK ||
        sqlite3_bind_int64(st, 5, issued_at) != SQLITE_OK ||
        sqlite3_bind_int64(st, 6, expires_at) != SQLITE_OK ||
        sqlite3_bind_int64(st, 7, idle_expires_at) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_verify_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES], int64_t now,
                                  uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out)
{
    if (s == NULL || token_hash == NULL) { return STORE_ERR_ARG; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT user_id FROM tokens WHERE token_hash=?1 AND expires_at>?2 AND idle_expires_at>?2 LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, token_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (user_id_out != NULL) { r = copy_blob_col(st, 0, user_id_out, user_id_cap, user_id_len_out); }
        } else if (rc == SQLITE_DONE) {
            r = STORE_ERR_NOT_FOUND;
        } else {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *up = NULL;
    if (sqlite3_prepare_v2(s->db, "UPDATE tokens SET last_verified_at=?2 WHERE token_hash=?1;", -1, &up, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(up, 1, token_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(up, 2, now) != SQLITE_OK ||
        sqlite3_step(up) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(up);
    return r;
}

static store_status_t delete_where_blob(store_t *s, const char *sql, const uint8_t *key, size_t key_len)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_blob(st, 1, key, (int)key_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    return r;
}

store_status_t store_delete_token(store_t *s, const uint8_t token_hash[STORE_HASH_BYTES])
{
    if (s == NULL || token_hash == NULL) { return STORE_ERR_ARG; }
    return delete_where_blob(s, "DELETE FROM tokens WHERE token_hash=?1;", token_hash, STORE_HASH_BYTES);
}

store_status_t store_delete_tokens_for_handle(store_t *s, const uint8_t *handle, size_t handle_len)
{
    if (s == NULL || !id_ok(handle, handle_len)) { return STORE_ERR_ARG; }
    return delete_where_blob(s, "DELETE FROM tokens WHERE handle=?1;", handle, handle_len);
}

store_status_t store_delete_tokens_for_user(store_t *s, const uint8_t *user_id, size_t user_id_len)
{
    if (s == NULL || !id_ok(user_id, user_id_len)) { return STORE_ERR_ARG; }
    return delete_where_blob(s, "DELETE FROM tokens WHERE user_id=?1;", user_id, user_id_len);
}

/* --- login codes ---------------------------------------------------------- */

store_status_t store_add_login_code(store_t *s, const uint8_t code_hash[STORE_HASH_BYTES],
                                    const uint8_t *user_id, size_t user_id_len,
                                    const uint8_t *handle, size_t handle_len,
                                    const uint8_t *hsid, size_t hsid_len,
                                    const uint8_t state_hash[STORE_HASH_BYTES],
                                    int64_t issued_at, int64_t expires_at)
{
    if (s == NULL || code_hash == NULL || state_hash == NULL ||
        !id_ok(user_id, user_id_len) || !id_ok(handle, handle_len)) {
        return STORE_ERR_ARG;
    }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO login_codes(code_hash,user_id,handle,handshake_id,state_hash,issued_at,expires_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7);", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, code_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 3, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        (hsid != NULL ? sqlite3_bind_blob(st, 4, hsid, (int)hsid_len, SQLITE_TRANSIENT)
                      : sqlite3_bind_null(st, 4)) != SQLITE_OK ||
        sqlite3_bind_blob(st, 5, state_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 6, issued_at) != SQLITE_OK ||
        sqlite3_bind_int64(st, 7, expires_at) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_consume_login_code(store_t *s, const uint8_t code_hash[STORE_HASH_BYTES],
                                        const uint8_t state_hash[STORE_HASH_BYTES], int64_t now,
                                        uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out,
                                        uint8_t *handle_out, size_t handle_cap, size_t *handle_len_out)
{
    if (s == NULL || code_hash == NULL || state_hash == NULL) { return STORE_ERR_ARG; }

    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT user_id, handle, state_hash FROM login_codes"
            " WHERE code_hash=?1 AND used_at IS NULL AND expires_at>?2 LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    uint8_t stored_state[STORE_HASH_BYTES];
    size_t n_state = 0;
    if (sqlite3_bind_blob(st, 1, code_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (user_id_out != NULL) { r = copy_blob_col(st, 0, user_id_out, user_id_cap, user_id_len_out); }
            if (r == STORE_OK && handle_out != NULL) { r = copy_blob_col(st, 1, handle_out, handle_cap, handle_len_out); }
            if (r == STORE_OK) { r = copy_blob_col(st, 2, stored_state, sizeof stored_state, &n_state); }
        } else if (rc == SQLITE_DONE) {
            r = STORE_ERR_NOT_FOUND;
        } else {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    /* login-CSRF binding: the code is only good for the `state` it was issued
     * against (§5). Constant-time compare, like every other secret compare. */
    if (n_state != STORE_HASH_BYTES || sodium_memcmp(stored_state, state_hash, STORE_HASH_BYTES) != 0) {
        tx_rollback(s);
        return STORE_ERR_CONFLICT;
    }

    st = NULL;
    if (sqlite3_prepare_v2(s->db, "UPDATE login_codes SET used_at=?2 WHERE code_hash=?1;", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, code_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

/* --- recovery codes / tickets --------------------------------------------- */

store_status_t store_add_recovery_code(store_t *s, const uint8_t *user_id, size_t user_id_len,
                                       const char *pwhash_str, int64_t issued_at)
{
    if (s == NULL || !id_ok(user_id, user_id_len) || pwhash_str == NULL) { return STORE_ERR_ARG; }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO recovery_codes(user_id,pwhash_str,issued_at) VALUES(?1,?2,?3);",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, pwhash_str, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 3, issued_at) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_mark_recovery_used(store_t *s, int64_t code_id, const char *used_from, int64_t used_at)
{
    if (s == NULL) { return STORE_ERR_ARG; }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    /* never deletes: a used code stays, marked (§10.3) */
    if (sqlite3_prepare_v2(s->db,
            "UPDATE recovery_codes SET used_at=?2, used_from=?3 WHERE code_id=?1 AND used_at IS NULL;",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_int64(st, 1, code_id) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, used_at) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, used_from ? used_from : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    } else if (sqlite3_changes(s->db) == 0) {
        r = STORE_ERR_NOT_FOUND;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_add_ticket(store_t *s, const uint8_t ticket_hash[STORE_HASH_BYTES],
                                const uint8_t *user_id, size_t user_id_len,
                                int64_t issued_at, int64_t expires_at)
{
    if (s == NULL || ticket_hash == NULL || !id_ok(user_id, user_id_len)) { return STORE_ERR_ARG; }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO enroll_tickets(ticket_hash,user_id,issued_at,expires_at) VALUES(?1,?2,?3,?4);",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, ticket_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 3, issued_at) != SQLITE_OK ||
        sqlite3_bind_int64(st, 4, expires_at) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_CONSTRAINT) { r = STORE_ERR_CONFLICT; }
        else if (rc != SQLITE_DONE)  { r = STORE_ERR_DB; }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

store_status_t store_consume_ticket(store_t *s, const uint8_t ticket_hash[STORE_HASH_BYTES], int64_t now,
                                    uint8_t *user_id_out, size_t user_id_cap, size_t *user_id_len_out)
{
    if (s == NULL || ticket_hash == NULL) { return STORE_ERR_ARG; }
    store_status_t r = tx_begin(s);
    if (r != STORE_OK) { return r; }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "SELECT user_id FROM enroll_tickets WHERE ticket_hash=?1 AND used_at IS NULL AND expires_at>?2 LIMIT 1;",
            -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, ticket_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (user_id_out != NULL) { r = copy_blob_col(st, 0, user_id_out, user_id_cap, user_id_len_out); }
        } else if (rc == SQLITE_DONE) {
            r = STORE_ERR_NOT_FOUND;
        } else {
            r = STORE_ERR_DB;
        }
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    st = NULL;
    if (sqlite3_prepare_v2(s->db, "UPDATE enroll_tickets SET used_at=?2 WHERE ticket_hash=?1;", -1, &st, NULL) != SQLITE_OK) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }
    if (sqlite3_bind_blob(st, 1, ticket_hash, (int)STORE_HASH_BYTES, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, now) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }
    return tx_commit(s);
}

/* --- backup ---------------------------------------------------------------- */

store_status_t store_backup(store_t *s, const char *dest_path)
{
    if (s == NULL || dest_path == NULL) { return STORE_ERR_ARG; }
    /* VACUUM INTO writes a consistent, compacted snapshot and refuses to
     * overwrite an existing file, which is exactly the no-clobber rule the
     * key files follow. The destination is bound as a parameter so a path
     * containing a quote cannot alter the statement (SQLITE_DQS=0 as well). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "VACUUM INTO ?1;", -1, &st, NULL) != SQLITE_OK) {
        return STORE_ERR_DB;
    }
    store_status_t r = STORE_OK;
    if (sqlite3_bind_text(st, 1, dest_path, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    } else if (sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_IO;   /* destination exists, or is not writable */
    }
    sqlite3_finalize(st);
    return r;
}
