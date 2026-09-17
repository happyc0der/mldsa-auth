#include "tokens.h"

#include <string.h>

#include <sodium.h>

uint32_t tokens_ttl_s(store_role_t role)
{
    return (role == STORE_ROLE_OPERATOR) ? TOKEN_TTL_OPERATOR_S : TOKEN_TTL_USER_S;
}

uint32_t tokens_idle_ttl_s(store_role_t role)
{
    return (role == STORE_ROLE_OPERATOR) ? TOKEN_IDLE_TTL_OPERATOR_S : TOKEN_IDLE_TTL_USER_S;
}

store_status_t tokens_issue(store_t *s, store_role_t role,
                            const uint8_t *user_id, size_t user_id_len,
                            const uint8_t *handle, size_t handle_len,
                            const uint8_t *hsid, size_t hsid_len,
                            int64_t now,
                            uint8_t token_out[TOKEN_BYTES],
                            int64_t *issued_out, int64_t *expires_out)
{
    if (s == NULL || token_out == NULL) {
        return STORE_ERR_ARG;
    }
    randombytes_buf(token_out, TOKEN_BYTES);

    uint8_t token_hash[STORE_HASH_BYTES];
    crypto_hash_sha256(token_hash, token_out, TOKEN_BYTES);

    const int64_t expires = now + (int64_t)tokens_ttl_s(role);
    const int64_t idle = now + (int64_t)tokens_idle_ttl_s(role);

    const store_status_t r = store_add_token(s, token_hash,
                                             user_id, user_id_len,
                                             handle, handle_len,
                                             hsid, hsid_len,
                                             now, expires, idle);
    sodium_memzero(token_hash, sizeof token_hash);
    if (r != STORE_OK) {
        /* Never hand back a token the store did not accept. */
        sodium_memzero(token_out, TOKEN_BYTES);
        return r;
    }
    if (issued_out != NULL) { *issued_out = now; }
    if (expires_out != NULL) { *expires_out = expires; }
    return STORE_OK;
}
