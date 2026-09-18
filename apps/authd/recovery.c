#include "recovery.h"

#include <string.h>

int recovery_make_code(char code_out[BASE32_CODE_CHARS + 1u],
                       char hash_out[crypto_pwhash_STRBYTES],
                       unsigned long long ops, size_t mem)
{
    if (code_out == NULL || hash_out == NULL) {
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
    if (crypto_pwhash_str(hash_out, code_out, (unsigned long long)BASE32_CODE_CHARS,
                          ops, mem) != 0) {
        sodium_memzero(code_out, BASE32_CODE_CHARS + 1u);
        sodium_memzero(hash_out, crypto_pwhash_STRBYTES);
        return -1;
    }
    return 0;
}

void recovery_make_ticket(uint8_t ticket_out[RECOVERY_TICKET_BYTES],
                          uint8_t hash_out[STORE_HASH_BYTES])
{
    randombytes_buf(ticket_out, RECOVERY_TICKET_BYTES);
    crypto_hash_sha256(hash_out, ticket_out, RECOVERY_TICKET_BYTES);
}

typedef struct {
    const char *canonical;
    int64_t     code_id;
    int         found;
    size_t      tried;
} match_ctx_t;

static int try_one(void *vctx, int64_t code_id, const char *pwhash_str)
{
    match_ctx_t *c = (match_ctx_t *)vctx;
    c->tried++;
    if (crypto_pwhash_str_verify(pwhash_str, c->canonical,
                                 (unsigned long long)BASE32_CODE_CHARS) == 0) {
        c->code_id = code_id;
        c->found = 1;
        return 1;                       /* stop: the iterator's early exit */
    }
    return 0;
}

int recovery_find_match(const store_t *s, const uint8_t *user_id, size_t user_id_len,
                        const char *typed, size_t typed_len,
                        int64_t *code_id_out, size_t *tried_out)
{
    if (tried_out != NULL) { *tried_out = 0u; }
    if (s == NULL || user_id == NULL || typed == NULL || code_id_out == NULL) {
        return -1;
    }
    char canonical[BASE32_CODE_CHARS + 1u];
    if (base32_normalize(typed, typed_len, canonical) != 0) {
        /* Not a well-formed code at all: no hashing, and the caller still
         * counts it as a failed attempt (it is a guess like any other). */
        return 0;
    }
    match_ctx_t ctx = { canonical, 0, 0, 0u };
    const store_status_t r = store_list_unused_recovery_codes(s, user_id, user_id_len,
                                                              try_one, &ctx);
    sodium_memzero(canonical, sizeof canonical);
    if (tried_out != NULL) { *tried_out = ctx.tried; }
    if (r != STORE_OK) {
        return -1;
    }
    if (!ctx.found) {
        return 0;
    }
    *code_id_out = ctx.code_id;
    return 1;
}
