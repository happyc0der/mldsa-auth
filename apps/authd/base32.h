#ifndef MLDSA_AUTHD_BASE32_H
#define MLDSA_AUTHD_BASE32_H

#include <stddef.h>
#include <stdint.h>

/*
 * Crockford base32 for recovery codes (V4-9d), spec mldsa-authd §10.3.
 *
 * §10.3 fixes the shape -- "10 random bytes rendered as 16 base32 characters
 * (80 bits)" -- but names no alphabet. Crockford is chosen because this is the
 * one value in the whole system a human reads off paper and types back months
 * later, possibly in a hurry, possibly having lost their only device:
 *
 *   - the alphabet excludes I, L, O and U, so the shapes that are confused on
 *     paper are never emitted in the first place;
 *   - the decoder nevertheless ACCEPTS I and l as 1, O and o as 0, either
 *     case, and ignores '-', so a user who transcribes what they think they
 *     see, or who types the code in groups, still gets in.
 *
 * 80 bits is exactly 16 symbols, so there are no leftover bits and no padding:
 * a 16-symbol string decodes and re-encodes to itself. Normalisation is
 * therefore a per-character map, not a decode/encode round trip, and that is
 * why there is no base32_decode() here -- nothing in the daemon needs the
 * bytes back, and an unused decoder would be a surface with no oracle.
 *
 * NORMALISATION LIVES HERE, next to the code that hashes the result, and never
 * in the site's JavaScript. What is hashed is the canonical string, so two
 * sites cannot disagree about what a given code "is"; see recovery.h.
 *
 * The Crockford charset plus its tolerated confusables is a subset of
 * [0-9A-Za-z-], which contains no comma, space, LF or '=' -- which is what
 * lets §8 carry these codes as text in a comma-separated list without
 * introducing any escaping rule (see localapi.h).
 */

#define BASE32_CODE_BYTES 10u   /* 80 bits of entropy, spec §10.3 */
#define BASE32_CODE_CHARS 16u   /* 80 / 5, exactly -- no padding */

/* Encodes `n` bytes as Crockford base32 into `out`, NUL-terminated.
 * Requires cap >= (n * 8 + 4) / 5 + 1. Returns 0 on success, -1 on a NULL
 * argument, n == 0, or insufficient capacity (out is untouched on failure). */
int base32_encode(const uint8_t *in, size_t n, char *out, size_t cap);

/* Canonicalises a user-typed code: upper-cases, maps the confusables
 * (I/i/L/l -> 1, O/o -> 0) and drops '-'. Writes exactly BASE32_CODE_CHARS
 * characters plus a NUL. Returns 0 on success, -1 if any character is outside
 * the accepted set or the result is not exactly BASE32_CODE_CHARS symbols
 * (`out` is zeroed on failure, never left holding a partial code). */
int base32_normalize(const char *in, size_t in_len, char out[BASE32_CODE_CHARS + 1u]);

#endif /* MLDSA_AUTHD_BASE32_H */
