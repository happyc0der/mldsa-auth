#include "passphrase.h"

#include <string.h>

#include <sodium.h>

/* Character classes, one bit each; the pool of a passphrase is the sum of the
 * sizes of the classes it uses. */
#define C_LOWER  0x01u
#define C_UPPER  0x02u
#define C_DIGIT  0x04u
#define C_SYMBOL 0x08u   /* printable ASCII that is not a letter or digit, space included */
#define C_OTHER  0x10u   /* anything outside ASCII */

/* floor(1000 * log2(pool)) for every combination of the classes above, sizes
 * 26, 26, 10, 33, 100 -- precomputed rather than calling log2(), so the
 * policy needs no libm on any platform (a missing -lm was a V3 Linux defect)
 * and computes the same integer everywhere, wasm included. */
static const uint32_t POOL_MILLIBITS[32] = {
    0, 4700, 4700, 5700, 3321, 5169, 5169, 5954, 5044, 5882, 5882, 6409, 5426, 6108, 6108, 6569,
    6643, 6977, 6977, 7247, 6781, 7087, 7087, 7339, 7055, 7312, 7312, 7531, 7159, 7400, 7400, 7607,
};

/* A character that continues a run, a repeat or a keyboard walk adds almost
 * nothing an attacker's model would not predict. */
#define PREDICTED_MILLIBITS 1000u
/* A string that is one unit repeated costs the unit plus a little for the
 * count. */
#define REPEAT_COUNT_MILLIBITS 2000u

static const char *const KEYBOARD_ROWS[] = {
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()",
};

const char *pp_verdict_name(pp_verdict_t v)
{
    switch (v) {
    case PP_OK:          return "ok";
    case PP_NOT_UTF8:    return "not-utf8";
    case PP_TOO_LONG:    return "too-long";
    case PP_TOO_SHORT:   return "too-short";
    case PP_COMMON:      return "common";
    case PP_PREDICTABLE: return "predictable";
    }
    return "unknown";
}

/* Strict UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF.
 * Returns the number of code points, or -1. */
static long utf8_decode(const uint8_t *s, size_t len, uint32_t *cp, size_t cap)
{
    size_t i = 0, n = 0;
    while (i < len) {
        const uint8_t b = s[i];
        uint32_t c;
        size_t need;
        if (b < 0x80u)      { c = b;          need = 0; }
        else if (b >= 0xC2u && b <= 0xDFu) { c = b & 0x1Fu; need = 1; }
        else if (b >= 0xE0u && b <= 0xEFu) { c = b & 0x0Fu; need = 2; }
        else if (b >= 0xF0u && b <= 0xF4u) { c = b & 0x07u; need = 3; }
        else { return -1; }
        if (need > len - i - 1u) { return -1; }
        for (size_t k = 1; k <= need; k++) {
            if ((s[i + k] & 0xC0u) != 0x80u) { return -1; }
            c = (c << 6) | (s[i + k] & 0x3Fu);
        }
        if ((need == 2 && (c < 0x800u || (c >= 0xD800u && c <= 0xDFFFu))) ||
            (need == 3 && (c < 0x10000u || c > 0x10FFFFu))) {
            return -1;
        }
        if (n == cap) { return -1; }
        cp[n++] = c;
        i += need + 1u;
    }
    return (long)n;
}

static uint32_t class_of(uint32_t c)
{
    if (c >= 'a' && c <= 'z') { return C_LOWER; }
    if (c >= 'A' && c <= 'Z') { return C_UPPER; }
    if (c >= '0' && c <= '9') { return C_DIGIT; }
    if (c >= 0x20u && c <= 0x7Eu) { return C_SYMBOL; }
    return C_OTHER;
}

static uint32_t fold(uint32_t c) { return (c >= 'A' && c <= 'Z') ? c + 32u : c; }

static int is_common(const char *w)
{
    size_t lo = 0, hi = pp_common_count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2u;
        const int r = strcmp(w, pp_common[mid]);
        if (r == 0) { return 1; }
        if (r < 0) { hi = mid; } else { lo = mid + 1u; }
    }
    return 0;
}

/* The passphrase, and its core with leading and trailing digits and ASCII
 * symbols stripped ("Password1234!" -> "password"), against the list. Only
 * ASCII can match: the list is ASCII. */
static int common_match(const uint32_t *cp, size_t n)
{
    char w[PP_MAX_BYTES + 1u];
    size_t a = 0, b = n;
    int ascii = 1;
    for (size_t i = 0; i < n; i++) {
        if (cp[i] > 0x7Eu) { ascii = 0; break; }
        w[i] = (char)fold(cp[i]);
    }
    w[ascii ? n : 0] = '\0';
    int hit = ascii && is_common(w);
    if (ascii && !hit) {
        while (a < b && (class_of(cp[a]) & (C_DIGIT | C_SYMBOL)) != 0u) { a++; }
        while (b > a && (class_of(cp[b - 1u]) & (C_DIGIT | C_SYMBOL)) != 0u) { b--; }
        if (b - a >= 4u && !(a == 0 && b == n)) {
            w[b] = '\0';
            hit = is_common(w + a);
        }
    }
    sodium_memzero(w, sizeof w);   /* a folded copy of the passphrase */
    return hit;
}

/* 1 when a, b, c (folded) are consecutive along one keyboard row, in either
 * direction. */
static int keyboard_walk(uint32_t a, uint32_t b, uint32_t c)
{
    a = fold(a); b = fold(b); c = fold(c);
    for (size_t r = 0; r < sizeof KEYBOARD_ROWS / sizeof KEYBOARD_ROWS[0]; r++) {
        const char *row = KEYBOARD_ROWS[r];
        const char *pa = (a < 0x80u) ? strchr(row, (int)a) : NULL;
        const char *pb = (b < 0x80u) ? strchr(row, (int)b) : NULL;
        const char *pc = (c < 0x80u) ? strchr(row, (int)c) : NULL;
        if (a != 0u && b != 0u && c != 0u && pa != NULL && pb != NULL && pc != NULL &&
            ((pb == pa + 1 && pc == pb + 1) || (pb == pa - 1 && pc == pb - 1))) {
            return 1;
        }
    }
    return 0;
}

/* The estimate over cp[0..n), in milli-bits, accumulating reasons. */
static uint32_t estimate(const uint32_t *cp, size_t n, uint32_t *reasons)
{
    uint32_t classes = 0;
    for (size_t i = 0; i < n; i++) { classes |= class_of(cp[i]); }
    const uint32_t per = POOL_MILLIBITS[classes & 31u];
    uint32_t total = 0;
    for (size_t i = 0; i < n; i++) {
        if (i >= 1 && cp[i] == cp[i - 1]) {
            total += PREDICTED_MILLIBITS;
            *reasons |= PP_R_REPEATS;
        } else if (i >= 2 && (cp[i] - cp[i - 1]) == (cp[i - 1] - cp[i - 2]) &&
                   (cp[i] - cp[i - 1] == 1u || cp[i - 1] - cp[i] == 1u) &&
                   (class_of(cp[i]) & (C_LOWER | C_UPPER | C_DIGIT)) != 0u) {
            total += PREDICTED_MILLIBITS;
            *reasons |= PP_R_SEQUENCE;
        } else if (i >= 2 && keyboard_walk(cp[i - 2], cp[i - 1], cp[i])) {
            total += PREDICTED_MILLIBITS;
            *reasons |= PP_R_KEYBOARD;
        } else {
            total += per;
        }
    }
    return total;
}

pp_verdict_t pp_check(const uint8_t *pass, size_t len, pp_report_t *report)
{
    pp_report_t r;
    memset(&r, 0, sizeof r);
    pp_verdict_t v = PP_OK;
    uint32_t cp[PP_MAX_BYTES];

    if (len > PP_MAX_BYTES) {
        v = PP_TOO_LONG;
        goto out;
    }
    if (pass == NULL && len != 0u) {
        v = PP_NOT_UTF8;
        goto out;
    }
    const long n = (len == 0u) ? 0 : utf8_decode(pass, len, cp, PP_MAX_BYTES);
    if (n < 0) {
        v = PP_NOT_UTF8;
        goto out;
    }
    r.code_points = (uint32_t)n;
    if ((size_t)n < PP_MIN_CODE_POINTS) {
        v = PP_TOO_SHORT;
        goto out;
    }
    if (common_match(cp, (size_t)n)) {
        v = PP_COMMON;
        goto out;
    }

    uint32_t classes = 0;
    for (long i = 0; i < n; i++) { classes |= class_of(cp[i]); }
    if ((classes & (classes - 1u)) == 0u) {
        r.reasons |= PP_R_ONE_CLASS;
    }
    uint32_t millibits = estimate(cp, (size_t)n, &r.reasons);
    /* One unit repeated: the unit, plus a little for the count. The smallest
     * unit is found first, so "abababababab" is "ab" repeated. */
    for (long u = 1; u <= n / 2; u++) {
        if (n % u != 0) { continue; }
        long k = u;
        while (k < n && cp[k] == cp[k % u]) { k++; }
        if (k == n) {
            uint32_t unit_reasons = 0;
            const uint32_t unit = estimate(cp, (size_t)u, &unit_reasons) + REPEAT_COUNT_MILLIBITS;
            if (unit < millibits) {
                millibits = unit;
            }
            r.reasons |= PP_R_REPEATED_UNIT;
            break;
        }
    }
    r.est_bits = millibits / 1000u;
    if (r.est_bits < PP_MIN_BITS) {
        v = PP_PREDICTABLE;
    }
out:
    sodium_memzero(cp, sizeof cp);   /* the passphrase's code points do not outlive the call */
    if (report != NULL) {
        *report = r;
    }
    return v;
}
