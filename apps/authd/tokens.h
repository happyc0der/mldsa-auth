#ifndef MLDSA_AUTHD_TOKENS_H
#define MLDSA_AUTHD_TOKENS_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"

/*
 * Session tokens (V4-9a), spec mldsa-authd §11.
 *
 * Opaque, 256 bits, stored only as SHA-256 (Req 4). Signed or structured
 * tokens are rejected by the spec for a reason worth restating: offline
 * verification would need an ML-DSA implementation in the site's language and
 * would lose instant revocation, and the credential is a bearer either way.
 *
 * The token never reaches browser JavaScript. The client receives the
 * single-use login code (§6.2) and hands that to the site; only the site, over
 * the local socket, can exchange it. An XSS that steals the code cannot
 * exchange it.
 *
 * LIFETIMES ARE CONSTANTS, not config. An operator who could set a 30-day
 * token would be configuring away the property the design rests on, and V4-11
 * can revisit it with a stated reason rather than by default.
 */

#define TOKEN_BYTES 32u   /* 256 bits from randombytes_buf */

/* Spec §11: absolute 12 h / idle 1 h for users; 8 h / 30 min for operators. */
#define TOKEN_TTL_USER_S          (12u * 3600u)
#define TOKEN_IDLE_TTL_USER_S     (1u * 3600u)
#define TOKEN_TTL_OPERATOR_S      (8u * 3600u)
#define TOKEN_IDLE_TTL_OPERATOR_S (30u * 60u)

/* How often the daemon sweeps expired tokens, codes and tickets. */
#define TOKEN_SWEEP_INTERVAL_MS 60000u

uint32_t tokens_ttl_s(store_role_t role);
uint32_t tokens_idle_ttl_s(store_role_t role);

/* Mints a token for an authenticated session: fills `token_out` with
 * TOKEN_BYTES of fresh randomness and inserts SHA-256(token) bound to
 * {user, handle, handshake_id, issued, expires, idle} with the role's
 * lifetimes. The plaintext token exists only in `token_out`, which the caller
 * must wipe after encoding it into its reply. */
store_status_t tokens_issue(store_t *s, store_role_t role,
                            const uint8_t *user_id, size_t user_id_len,
                            const uint8_t *handle, size_t handle_len,
                            const uint8_t *hsid, size_t hsid_len,
                            int64_t now,
                            uint8_t token_out[TOKEN_BYTES],
                            int64_t *issued_out, int64_t *expires_out);

#endif /* MLDSA_AUTHD_TOKENS_H */
