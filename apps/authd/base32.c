#include "base32.h"

#include <string.h>

/* Crockford's alphabet: no I, L, O or U. Position i encodes the value i. */
static const char ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

_Static_assert(sizeof ALPHABET == 33u, "the alphabet must be exactly 32 symbols plus NUL");
_Static_assert(BASE32_CODE_BYTES * 8u == BASE32_CODE_CHARS * 5u,
               "80 bits must be exactly 16 symbols: no padding is defined");

/* Value of an input character, or -1 if it is not accepted. The confusables
 * are folded here rather than at the call site so the encoder's alphabet and
 * the decoder's tolerance can never drift apart. 'U' is NOT accepted:
 * Crockford excludes it from the alphabet and defines no substitution. */
static int sym_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'z') {
        c = (char)(c - ('a' - 'A'));
    }
    if (c == 'O') { return 0; }          /* the letter read as the digit */
    if (c == 'I' || c == 'L') { return 1; }
    for (int i = 10; i < 32; i++) {      /* 0-9 handled above */
        if (ALPHABET[i] == c) {
            return i;
        }
    }
    return -1;
}

int base32_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    if (in == NULL || out == NULL || n == 0u) {
        return -1;
    }
    const size_t symbols = (n * 8u + 4u) / 5u;
    if (cap < symbols + 1u) {
        return -1;
    }
    for (size_t i = 0; i < symbols; i++) {
        const size_t bit   = i * 5u;
        const size_t byte  = bit / 8u;
        const size_t shift = bit % 8u;
        /* A 16-bit window at `byte`, so a symbol straddling a byte boundary is
         * read in one shot. Past the end contributes zero bits, which is what
         * makes the final partial symbol well defined. */
        uint32_t w = (uint32_t)in[byte] << 8;
        if (byte + 1u < n) {
            w |= (uint32_t)in[byte + 1u];
        }
        out[i] = ALPHABET[(w >> (11u - shift)) & 0x1fu];
    }
    out[symbols] = '\0';
    return 0;
}

int base32_normalize(const char *in, size_t in_len, char out[BASE32_CODE_CHARS + 1u])
{
    if (out == NULL) {
        return -1;
    }
    memset(out, 0, BASE32_CODE_CHARS + 1u);
    if (in == NULL) {
        return -1;
    }
    size_t j = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '-') {
            continue;                    /* grouping is the user's business */
        }
        const int v = sym_value(in[i]);
        if (v < 0 || j >= BASE32_CODE_CHARS) {
            memset(out, 0, BASE32_CODE_CHARS + 1u);
            return -1;
        }
        out[j++] = ALPHABET[v];
    }
    if (j != BASE32_CODE_CHARS) {
        memset(out, 0, BASE32_CODE_CHARS + 1u);
        return -1;
    }
    return 0;
}
