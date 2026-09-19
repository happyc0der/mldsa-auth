#include "sha1.h"

#include <string.h>

/* RFC 3174. See sha1.h for why this is here and why nothing else may use it. */

static uint32_t rol(uint32_t v, unsigned s) { return (v << s) | (v >> (32u - s)); }

static void sha1_block(uint32_t h[5], const uint8_t b[SHA1_BLOCK_BYTES])
{
    uint32_t w[80];
    for (unsigned i = 0; i < 16u; i++) {
        w[i] = ((uint32_t)b[i * 4u] << 24) | ((uint32_t)b[i * 4u + 1u] << 16) |
               ((uint32_t)b[i * 4u + 2u] << 8) | (uint32_t)b[i * 4u + 3u];
    }
    for (unsigned i = 16u; i < 80u; i++) {
        w[i] = rol(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1u);
    }

    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (unsigned i = 0; i < 80u; i++) {
        uint32_t f, k;
        if (i < 20u)      { f = (bb & c) | (~bb & d);            k = 0x5a827999u; }
        else if (i < 40u) { f = bb ^ c ^ d;                      k = 0x6ed9eba1u; }
        else if (i < 60u) { f = (bb & c) | (bb & d) | (c & d);   k = 0x8f1bbcdcu; }
        else              { f = bb ^ c ^ d;                      k = 0xca62c1d6u; }
        const uint32_t t = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(bb, 30u); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;

    memset(w, 0, sizeof w);
}

void sha1(const uint8_t *in, size_t n, uint8_t out[SHA1_DIGEST_BYTES])
{
    uint32_t h[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u };

    size_t off = 0;
    while (n - off >= SHA1_BLOCK_BYTES) {
        sha1_block(h, in + off);
        off += SHA1_BLOCK_BYTES;
    }

    /* The tail: the remainder, 0x80, zeros, then the 64-bit big-endian bit
     * count. That needs one block, or two when the remainder leaves no room
     * for the length field. */
    uint8_t tail[2u * SHA1_BLOCK_BYTES];
    const size_t rem = n - off;
    memset(tail, 0, sizeof tail);
    memcpy(tail, in + off, rem);
    tail[rem] = 0x80u;
    const size_t total = (rem + 1u + 8u > SHA1_BLOCK_BYTES) ? (2u * SHA1_BLOCK_BYTES) : SHA1_BLOCK_BYTES;
    const uint64_t bits = (uint64_t)n * 8u;
    for (unsigned i = 0; i < 8u; i++) {
        tail[total - 1u - i] = (uint8_t)(bits >> (8u * i));
    }
    sha1_block(h, tail);
    if (total == 2u * SHA1_BLOCK_BYTES) {
        sha1_block(h, tail + SHA1_BLOCK_BYTES);
    }

    for (unsigned i = 0; i < 5u; i++) {
        out[i * 4u]      = (uint8_t)(h[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(h[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(h[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)h[i];
    }
    memset(h, 0, sizeof h);
    memset(tail, 0, sizeof tail);
}
