#include "recovery.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The stored form of a code (V4-76, F143): "$mrc1$<ops>$<mem>$<salt>$<hash>",
 * the salt and the raw Argon2id13 hash in lowercase hex. Every code of one
 * generation shares its salt, so a typed code is hashed ONCE and compared with
 * every unused code, instead of once per code -- which is what made the time
 * of a refusal say how many codes a user had. The cost: one guess against a
 * stolen store tests all of a generation's codes at once, at most 16, and 80
 * bits less 4 is still the defence (spec 10.3). */
#define MRC1_PREFIX "$mrc1$"
#define MRC1_HASH_BYTES 32u

static void hexs(char *out, const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2u * i] = hx[p[i] >> 4];
        out[2u * i + 1u] = hx[p[i] & 0x0fu];
    }
    out[2u * n] = '\0';
}

static int unhex(const char *s, size_t n_chars, uint8_t *out)
{
    for (size_t i = 0; i < n_chars / 2u; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            const char c = s[2u * i + (size_t)k];
            int d;
            if (c >= '0' && c <= '9') { d = c - '0'; }
            else if (c >= 'a' && c <= 'f') { d = c - 'a' + 10; }
            else { return -1; }
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* Parses an $mrc1$ string. 0 on success; -1 for anything else, a legacy
 * crypto_pwhash_str among it. */
static int mrc1_parse(const char *str, unsigned long long *ops, size_t *mem,
                      uint8_t salt[crypto_pwhash_SALTBYTES], uint8_t hash[MRC1_HASH_BYTES])
{
    const size_t pl = sizeof MRC1_PREFIX - 1u;
    if (strncmp(str, MRC1_PREFIX, pl) != 0) { return -1; }
    const char *p = str + pl;
    char *end = NULL;
    const unsigned long long o = strtoull(p, &end, 10);
    if (end == p || *end != '$') { return -1; }
    p = end + 1;
    const unsigned long long m = strtoull(p, &end, 10);
    if (end == p || *end != '$') { return -1; }
    p = end + 1;
    if (strlen(p) != 2u * crypto_pwhash_SALTBYTES + 1u + 2u * MRC1_HASH_BYTES ||
        p[2u * crypto_pwhash_SALTBYTES] != '$' ||
        unhex(p, 2u * crypto_pwhash_SALTBYTES, salt) != 0 ||
        unhex(p + 2u * crypto_pwhash_SALTBYTES + 1u, 2u * MRC1_HASH_BYTES, hash) != 0) {
        return -1;
    }
    *ops = o;
    *mem = (size_t)m;
    return 0;
}

static int mrc1_hash(uint8_t out[MRC1_HASH_BYTES], const char *canonical,
                     const uint8_t salt[crypto_pwhash_SALTBYTES], unsigned long long ops, size_t mem)
{
    return crypto_pwhash(out, MRC1_HASH_BYTES, canonical, (unsigned long long)BASE32_CODE_CHARS,
                         salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13);
}

void recovery_new_salt(uint8_t salt[crypto_pwhash_SALTBYTES])
{
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
}

int recovery_make_code(char code_out[BASE32_CODE_CHARS + 1u],
                       char hash_out[crypto_pwhash_STRBYTES],
                       const uint8_t salt[crypto_pwhash_SALTBYTES],
                       unsigned long long ops, size_t mem)
{
    if (code_out == NULL || hash_out == NULL || salt == NULL) {
        return -1;
    }
    memset(code_out, 0, BASE32_CODE_CHARS + 1u);
    memset(hash_out, 0, crypto_pwhash_STRBYTES);

    uint8_t raw[BASE32_CODE_BYTES];
    randombytes_buf(raw, sizeof raw);
    const int enc = base32_encode(raw, sizeof raw, code_out, BASE32_CODE_CHARS + 1u);
    sodium_memzero(raw, sizeof raw);
    if (enc != 0) {
        return -1;
    }
    /* The canonical STRING is the password, not the bytes: it is what the user
     * holds and what normalisation produces (base32.h). */
    uint8_t h[MRC1_HASH_BYTES];
    if (mrc1_hash(h, code_out, salt, ops, mem) != 0) {
        sodium_memzero(code_out, BASE32_CODE_CHARS + 1u);
        sodium_memzero(h, sizeof h);
        return -1;
    }
    char salt_hex[2u * crypto_pwhash_SALTBYTES + 1u], hash_hex[2u * MRC1_HASH_BYTES + 1u];
    hexs(salt_hex, salt, crypto_pwhash_SALTBYTES);
    hexs(hash_hex, h, sizeof h);
    sodium_memzero(h, sizeof h);
    const int w = snprintf(hash_out, crypto_pwhash_STRBYTES, MRC1_PREFIX "%llu$%zu$%s$%s",
                           ops, mem, salt_hex, hash_hex);
    if (w < 0 || (size_t)w >= crypto_pwhash_STRBYTES) {
        sodium_memzero(code_out, BASE32_CODE_CHARS + 1u);
        sodium_memzero(hash_out, crypto_pwhash_STRBYTES);
        return -1;
    }
    return 0;
}

/* One Argon2id computation at `ops`/`mem` whose result nobody reads. */
void recovery_spend_one(unsigned long long ops, size_t mem)
{
    static const uint8_t salt[crypto_pwhash_SALTBYTES] = {0};
    uint8_t h[MRC1_HASH_BYTES];
    if (crypto_pwhash(h, sizeof h, "0000000000000000", (unsigned long long)BASE32_CODE_CHARS,
                      salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        /* Nothing to report: the computation, not its result, is the point.
         * (A (void) cast does not silence gcc's warn_unused_result.) */
    }
    sodium_memzero(h, sizeof h);
}

void recovery_make_ticket(uint8_t ticket_out[RECOVERY_TICKET_BYTES],
                          uint8_t hash_out[STORE_HASH_BYTES])
{
    randombytes_buf(ticket_out, RECOVERY_TICKET_BYTES);
    crypto_hash_sha256(hash_out, ticket_out, RECOVERY_TICKET_BYTES);
}

/* Every unused code of the user, collected so the verification can be done
 * once for the generation instead of once per code. */
#define FIND_CAP 64u
typedef struct {
    size_t  n;
    int     overflow;
    int64_t id[FIND_CAP];
    char    str[FIND_CAP][crypto_pwhash_STRBYTES];
} collect_ctx_t;

static int collect_one(void *vctx, int64_t code_id, const char *pwhash_str)
{
    collect_ctx_t *c = (collect_ctx_t *)vctx;
    if (c->n == FIND_CAP) {
        c->overflow = 1;
        return 1;
    }
    c->id[c->n] = code_id;
    snprintf(c->str[c->n], sizeof c->str[c->n], "%s", pwhash_str);
    c->n++;
    return 0;
}

int recovery_find_match(const store_t *s, const uint8_t *user_id, size_t user_id_len,
                        const char *typed, size_t typed_len,
                        unsigned long long ops, size_t mem,
                        int64_t *code_id_out, size_t *tried_out)
{
    if (tried_out != NULL) { *tried_out = 0u; }
    if (s == NULL || user_id == NULL || typed == NULL || code_id_out == NULL) {
        return -1;
    }
    static collect_ctx_t col;          /* ~8 KiB of hashes, not of secrets; one thread */
    memset(&col, 0, sizeof col);
    const store_status_t r = store_list_unused_recovery_codes(s, user_id, user_id_len,
                                                              collect_one, &col);
    if (r != STORE_OK || col.overflow) {
        return -1;
    }

    size_t tried = 0;
    int64_t match = 0;
    int found = 0;
    char canonical[BASE32_CODE_CHARS + 1u];
    if (base32_normalize(typed, typed_len, canonical) == 0) {
        /* Hash once per distinct (salt, parameters): one generation is one
         * group, which is all a user has once re-issuing has superseded the
         * last. Then compare with EVERY code, without an early exit. */
        uint8_t done_salt[FIND_CAP][crypto_pwhash_SALTBYTES];
        unsigned long long done_ops[FIND_CAP];
        size_t done_mem[FIND_CAP];
        uint8_t done_h[FIND_CAP][MRC1_HASH_BYTES];
        size_t nd = 0;
        for (size_t i = 0; i < col.n; i++) {
            unsigned long long o = 0;
            size_t m = 0;
            uint8_t salt[crypto_pwhash_SALTBYTES], want[MRC1_HASH_BYTES];
            if (mrc1_parse(col.str[i], &o, &m, salt, want) == 0) {
                size_t g = nd;
                for (size_t k = 0; k < nd; k++) {
                    if (done_ops[k] == o && done_mem[k] == m &&
                        memcmp(done_salt[k], salt, sizeof salt) == 0) { g = k; break; }
                }
                if (g == nd) {
                    memcpy(done_salt[nd], salt, sizeof salt);
                    done_ops[nd] = o;
                    done_mem[nd] = m;
                    tried++;
                    if (mrc1_hash(done_h[nd], canonical, salt, o, m) != 0) {
                        sodium_memzero(canonical, sizeof canonical);
                        sodium_memzero(done_h, sizeof done_h);
                        return -1;
                    }
                    nd++;
                }
                if (sodium_memcmp(done_h[g], want, MRC1_HASH_BYTES) == 0 && !found) {
                    match = col.id[i];
                    found = 1;
                }
            } else {
                /* A code issued before V4-76: its own salt, so its own
                 * verification. Re-issuing replaces the generation. */
                tried++;
                if (crypto_pwhash_str_verify(col.str[i], canonical,
                                             (unsigned long long)BASE32_CODE_CHARS) == 0 && !found) {
                    match = col.id[i];
                    found = 1;
                }
            }
        }
        sodium_memzero(done_h, sizeof done_h);
    }
    sodium_memzero(canonical, sizeof canonical);
    /* No code to hash against, or a code that is not a code at all: the same
     * one computation. What remains is the store work around it, not the KDF:
     * a known user's refusal also lists its codes and writes the failure
     * count, so it is tens of microseconds slower than an unknown user's,
     * against ~45 ms of Argon2id (V4-78, F156). */
    if (tried == 0u) {
        recovery_spend_one(ops, mem);
        tried = 1u;
    }
    if (tried_out != NULL) { *tried_out = tried; }
    if (!found) {
        return 0;
    }
    *code_id_out = match;
    return 1;
}
