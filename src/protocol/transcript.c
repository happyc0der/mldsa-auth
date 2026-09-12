#include "transcript.h"

#include "wire_int.h"

#include <sodium.h>
#include <string.h>

/* --- internal helpers --------------------------------------------------- */

static size_t client_hello_encoded_len(uint8_t id_len) {
    return 1u + 1u + id_len + WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN;
}

static size_t server_hello_unsigned_encoded_len(uint8_t id_len) {
    return 1u + 1u + id_len + WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN;
}

/* Writes ServerHello's unsigned prefix with NO validation -- callers
 * must have already checked id_len bounds and output capacity. Kept
 * separate from encode_server_hello_unsigned() so encode_server_hello()
 * can validate everything (including sig_len and total capacity) before
 * writing anything, then reuse this for the shared prefix bytes. */
static void write_server_hello_unsigned_unchecked(const server_hello_t *msg, uint8_t *out) {
    size_t off = 0;
    wire_int_write_u8(out + off, (uint8_t)MSG_TYPE_SERVER_HELLO);
    off += 1;
    wire_int_write_u8(out + off, msg->id_len);
    off += 1;
    memcpy(out + off, msg->id, msg->id_len);
    off += msg->id_len;
    memcpy(out + off, msg->ephemeral_pub, WIRE_X25519_PUB_LEN);
    off += WIRE_X25519_PUB_LEN;
    memcpy(out + off, msg->nonce, WIRE_NONCE_LEN);
    off += WIRE_NONCE_LEN;
    memcpy(out + off, msg->session_id_echo, WIRE_SESSION_ID_LEN);
    /* off + WIRE_SESSION_ID_LEN == server_hello_unsigned_encoded_len(id_len) */
}

static int hash_label_and_two_buffers(const char *label, size_t label_len,
                                       const uint8_t *a, size_t a_len,
                                       const uint8_t *b, size_t b_len,
                                       uint8_t out[32]) {
    static const uint8_t separator = 0x00;
    crypto_hash_sha256_state st;

    if (crypto_hash_sha256_init(&st) != 0) {
        return -1;
    }
    if (crypto_hash_sha256_update(&st, (const unsigned char *)label, label_len) != 0) {
        return -1;
    }
    if (crypto_hash_sha256_update(&st, &separator, 1) != 0) {
        return -1;
    }
    if (crypto_hash_sha256_update(&st, a, a_len) != 0) {
        return -1;
    }
    if (crypto_hash_sha256_update(&st, b, b_len) != 0) {
        return -1;
    }
    if (crypto_hash_sha256_final(&st, out) != 0) {
        return -1;
    }
    return 0;
}

size_t transcript_server_hello_unsigned_len(uint8_t id_len) {
    if (id_len < WIRE_ID_MIN_LEN || id_len > WIRE_ID_MAX_LEN) {
        return 0;
    }
    return server_hello_unsigned_encoded_len(id_len);
}

/* --- encoders ------------------------------------------------------------ */

int encode_client_hello(const client_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (msg == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (msg->id_len < WIRE_ID_MIN_LEN || msg->id_len > WIRE_ID_MAX_LEN) {
        return -1;
    }

    size_t needed = client_hello_encoded_len(msg->id_len);
    if (out_cap < needed) {
        return -1;
    }

    size_t off = 0;
    wire_int_write_u8(out + off, (uint8_t)MSG_TYPE_CLIENT_HELLO);
    off += 1;
    wire_int_write_u8(out + off, msg->id_len);
    off += 1;
    memcpy(out + off, msg->id, msg->id_len);
    off += msg->id_len;
    memcpy(out + off, msg->ephemeral_pub, WIRE_X25519_PUB_LEN);
    off += WIRE_X25519_PUB_LEN;
    memcpy(out + off, msg->session_id, WIRE_SESSION_ID_LEN);
    off += WIRE_SESSION_ID_LEN;
    memcpy(out + off, msg->nonce, WIRE_NONCE_LEN);
    off += WIRE_NONCE_LEN;

    *out_len = off;
    return 0;
}

int encode_server_hello_unsigned(const server_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (msg == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (msg->id_len < WIRE_ID_MIN_LEN || msg->id_len > WIRE_ID_MAX_LEN) {
        return -1;
    }

    size_t needed = server_hello_unsigned_encoded_len(msg->id_len);
    if (out_cap < needed) {
        return -1;
    }

    write_server_hello_unsigned_unchecked(msg, out);
    *out_len = needed;
    return 0;
}

int encode_server_hello(const server_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (msg == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (msg->id_len < WIRE_ID_MIN_LEN || msg->id_len > WIRE_ID_MAX_LEN) {
        return -1;
    }
    if (msg->sig_len < 1 || msg->sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        return -1;
    }

    size_t unsigned_len = server_hello_unsigned_encoded_len(msg->id_len);
    size_t needed = unsigned_len + 2u + msg->sig_len;
    if (out_cap < needed) {
        return -1;
    }

    write_server_hello_unsigned_unchecked(msg, out);
    wire_int_write_u16(out + unsigned_len, msg->sig_len);
    memcpy(out + unsigned_len + 2, msg->sig, msg->sig_len);

    *out_len = needed;
    return 0;
}

int encode_client_auth(const client_auth_t *msg, uint8_t *out, size_t out_cap, size_t *out_len) {
    if (msg == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (msg->sig_len < 1 || msg->sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        return -1;
    }

    size_t needed = 1u + WIRE_HANDSHAKE_ID_LEN + 2u + msg->sig_len;
    if (out_cap < needed) {
        return -1;
    }

    size_t off = 0;
    wire_int_write_u8(out + off, (uint8_t)MSG_TYPE_CLIENT_AUTH);
    off += 1;
    memcpy(out + off, msg->handshake_id, WIRE_HANDSHAKE_ID_LEN);
    off += WIRE_HANDSHAKE_ID_LEN;
    wire_int_write_u16(out + off, msg->sig_len);
    off += 2;
    memcpy(out + off, msg->sig, msg->sig_len);
    off += msg->sig_len;

    *out_len = off;
    return 0;
}

/* --- decoders ------------------------------------------------------------
 *
 * Each function follows the same shape: read/validate a field, advance
 * `off`, and `goto fail` immediately on any problem. `off` never exceeds
 * `len` at any point -- every read is preceded by a check that enough
 * bytes remain, so `len - off` is never computed after `off` could have
 * exceeded `len`.
 */

int decode_client_hello(const uint8_t *buf, size_t len, client_hello_t *out, size_t *consumed) {
    if (buf == NULL || out == NULL || consumed == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    uint8_t msg_type;
    uint8_t id_len;

    if (wire_int_read_u8(buf + off, len - off, &msg_type) != 0) {
        goto fail;
    }
    off += 1;
    if (msg_type != MSG_TYPE_CLIENT_HELLO) {
        goto fail;
    }

    if (wire_int_read_u8(buf + off, len - off, &id_len) != 0) {
        goto fail;
    }
    off += 1;
    if (id_len < WIRE_ID_MIN_LEN || id_len > WIRE_ID_MAX_LEN) {
        goto fail;
    }
    if (len - off < id_len) {
        goto fail;
    }
    memcpy(out->id, buf + off, id_len);
    out->id_len = id_len;
    off += id_len;

    if (len - off < WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN) {
        goto fail;
    }
    memcpy(out->ephemeral_pub, buf + off, WIRE_X25519_PUB_LEN);
    off += WIRE_X25519_PUB_LEN;
    memcpy(out->session_id, buf + off, WIRE_SESSION_ID_LEN);
    off += WIRE_SESSION_ID_LEN;
    memcpy(out->nonce, buf + off, WIRE_NONCE_LEN);
    off += WIRE_NONCE_LEN;

    if (off != len) {
        goto fail;
    }

    *consumed = off;
    return 0;

fail:
    memset(out, 0, sizeof(*out));
    return -1;
}

int decode_server_hello(const uint8_t *buf, size_t len, server_hello_t *out, size_t *consumed) {
    if (buf == NULL || out == NULL || consumed == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    uint8_t msg_type;
    uint8_t id_len;
    uint16_t sig_len;

    if (wire_int_read_u8(buf + off, len - off, &msg_type) != 0) {
        goto fail;
    }
    off += 1;
    if (msg_type != MSG_TYPE_SERVER_HELLO) {
        goto fail;
    }

    if (wire_int_read_u8(buf + off, len - off, &id_len) != 0) {
        goto fail;
    }
    off += 1;
    if (id_len < WIRE_ID_MIN_LEN || id_len > WIRE_ID_MAX_LEN) {
        goto fail;
    }
    if (len - off < id_len) {
        goto fail;
    }
    memcpy(out->id, buf + off, id_len);
    out->id_len = id_len;
    off += id_len;

    if (len - off < WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN) {
        goto fail;
    }
    memcpy(out->ephemeral_pub, buf + off, WIRE_X25519_PUB_LEN);
    off += WIRE_X25519_PUB_LEN;
    memcpy(out->nonce, buf + off, WIRE_NONCE_LEN);
    off += WIRE_NONCE_LEN;
    memcpy(out->session_id_echo, buf + off, WIRE_SESSION_ID_LEN);
    off += WIRE_SESSION_ID_LEN;

    if (wire_int_read_u16(buf + off, len - off, &sig_len) != 0) {
        goto fail;
    }
    off += 2;
    if (sig_len < 1 || sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        goto fail;
    }
    if (len - off < sig_len) {
        goto fail;
    }
    memcpy(out->sig, buf + off, sig_len);
    out->sig_len = sig_len;
    off += sig_len;

    if (off != len) {
        goto fail;
    }

    *consumed = off;
    return 0;

fail:
    memset(out, 0, sizeof(*out));
    return -1;
}

int decode_client_auth(const uint8_t *buf, size_t len, client_auth_t *out, size_t *consumed) {
    if (buf == NULL || out == NULL || consumed == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    uint8_t msg_type;
    uint16_t sig_len;

    if (wire_int_read_u8(buf + off, len - off, &msg_type) != 0) {
        goto fail;
    }
    off += 1;
    if (msg_type != MSG_TYPE_CLIENT_AUTH) {
        goto fail;
    }

    if (len - off < WIRE_HANDSHAKE_ID_LEN) {
        goto fail;
    }
    memcpy(out->handshake_id, buf + off, WIRE_HANDSHAKE_ID_LEN);
    off += WIRE_HANDSHAKE_ID_LEN;

    if (wire_int_read_u16(buf + off, len - off, &sig_len) != 0) {
        goto fail;
    }
    off += 2;
    if (sig_len < 1 || sig_len > MLDSA_SIGNATURE_MAX_BYTES) {
        goto fail;
    }
    if (len - off < sig_len) {
        goto fail;
    }
    memcpy(out->sig, buf + off, sig_len);
    out->sig_len = sig_len;
    off += sig_len;

    if (off != len) {
        goto fail;
    }

    *consumed = off;
    return 0;

fail:
    memset(out, 0, sizeof(*out));
    return -1;
}

/* --- transcript hashes ---------------------------------------------------- */

int transcript_hash_server_auth(const uint8_t *client_hello_bytes, size_t ch_len,
                                 const uint8_t *sh_unsigned_bytes, size_t sh_unsigned_len,
                                 uint8_t out[32]) {
    if (client_hello_bytes == NULL || sh_unsigned_bytes == NULL || out == NULL) {
        return -1;
    }
    return hash_label_and_two_buffers(TRANSCRIPT_LABEL_SERVER_AUTH, sizeof(TRANSCRIPT_LABEL_SERVER_AUTH) - 1,
                                       client_hello_bytes, ch_len,
                                       sh_unsigned_bytes, sh_unsigned_len,
                                       out);
}

int transcript_hash_client_auth(const uint8_t *client_hello_bytes, size_t ch_len,
                                 const uint8_t *server_hello_bytes, size_t sh_len,
                                 uint8_t out[32]) {
    if (client_hello_bytes == NULL || server_hello_bytes == NULL || out == NULL) {
        return -1;
    }
    return hash_label_and_two_buffers(TRANSCRIPT_LABEL_CLIENT_AUTH, sizeof(TRANSCRIPT_LABEL_CLIENT_AUTH) - 1,
                                       client_hello_bytes, ch_len,
                                       server_hello_bytes, sh_len,
                                       out);
}

int transcript_handshake_id(const uint8_t *client_hello_bytes, size_t ch_len,
                             const uint8_t *server_hello_bytes, size_t sh_len,
                             uint8_t out[16]) {
    if (client_hello_bytes == NULL || server_hello_bytes == NULL || out == NULL) {
        return -1;
    }
    uint8_t digest[32];
    if (hash_label_and_two_buffers(TRANSCRIPT_LABEL_HANDSHAKE_ID, sizeof(TRANSCRIPT_LABEL_HANDSHAKE_ID) - 1,
                                    client_hello_bytes, ch_len,
                                    server_hello_bytes, sh_len,
                                    digest) != 0) {
        return -1;
    }
    memcpy(out, digest, 16);
    sodium_memzero(digest, sizeof digest); /* not secret, but no reason to leave it lying around */
    return 0;
}
