#ifndef MLDSA_AUTHD_SHA1_H
#define MLDSA_AUTHD_SHA1_H

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-1 (RFC 3174), vendored for ONE purpose: RFC 6455's opening handshake.
 *
 * WHY A PROJECT LIKE THIS CONTAINS A BROKEN HASH, stated here so it is never
 * read out of context:
 *
 *   RFC 6455 §1.3 fixes the WebSocket accept value as
 *       base64(SHA-1(Sec-WebSocket-Key || "258EAFA5-...-C5AB0DC85B11"))
 *   and that is not negotiable -- a browser computes it and compares. It is
 *   not a security primitive here and RFC 6455 does not treat it as one: its
 *   job is to prove the server actually read the client's header, so that a
 *   caching intermediary cannot be tricked into replaying a non-WebSocket
 *   response. No secret enters it, nothing is authenticated by it, and its
 *   collision resistance is irrelevant to every property this daemon claims.
 *
 *   There was no alternative to check: libsodium 1.0.22 ships SHA-256,
 *   SHA-512, SHA-3, BLAKE2b, HMAC and HKDF but NO SHA-1; the project links no
 *   OpenSSL; and Caddy has no "WebSocket in, raw stream out" mode, so the
 *   daemon must complete the handshake itself.
 *
 * SCOPE IS THE CONTROL. Nothing outside the WebSocket upgrade may use this.
 * Everything else in the daemon that hashes uses SHA-256 through libsodium,
 * and a `git grep sha1` should only ever find ws.c.
 */

#define SHA1_DIGEST_BYTES 20u
#define SHA1_BLOCK_BYTES  64u

/* One-shot SHA-1 over `n` bytes. Allocates nothing. */
void sha1(const uint8_t *in, size_t n, uint8_t out[SHA1_DIGEST_BYTES]);

#endif /* MLDSA_AUTHD_SHA1_H */
