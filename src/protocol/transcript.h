#ifndef MLDSA_AUTH_PROTOCOL_TRANSCRIPT_H
#define MLDSA_AUTH_PROTOCOL_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_wrap.h" /* MLDSA_SIGNATURE_MAX_BYTES -- single authoritative
                         * constant, not redefined here (Step 3 plan
                         * decision 6). */

/*
 * Deterministic wire-format serialization and transcript hashing for the
 * three handshake messages (Section 6.3): ClientHello, ServerHello,
 * ClientAuth.
 *
 * Field sizes not given by the spec (nonce, and by extension the
 * session-id-echo/handshake-id fields below) were chosen for consistency
 * with the spec's other 32-byte fields; see the Step 3 plan for the full
 * reasoning. All multi-byte integers are big-endian (Section 6.4's
 * existing convention). client_id is an opaque byte string (1-64 bytes)
 * -- no UTF-8 validation/normalization is performed here or anywhere in
 * v1.
 */

#define WIRE_ID_MIN_LEN 1u
#define WIRE_ID_MAX_LEN 64u
#define WIRE_X25519_PUB_LEN 32u
#define WIRE_SESSION_ID_LEN 16u
#define WIRE_NONCE_LEN 32u
#define WIRE_HANDSHAKE_ID_LEN 16u

#define MSG_TYPE_CLIENT_HELLO 0x01u
#define MSG_TYPE_SERVER_HELLO 0x02u
#define MSG_TYPE_CLIENT_AUTH 0x03u

/* Domain-separation labels for the transcript hashes below. Each is
 * hashed as a literal ASCII prefix followed by a single 0x00 separator
 * byte, then the message bytes -- the label is part of what's signed,
 * not documentation. TRANSCRIPT_LABEL_HANDSHAKE_ID is a separate label
 * from the other two, so handshake_id can never collide with either
 * signature's hash domain. */
#define TRANSCRIPT_LABEL_SERVER_AUTH "mldsa-auth/v1/server-auth"
#define TRANSCRIPT_LABEL_CLIENT_AUTH "mldsa-auth/v1/client-auth"
#define TRANSCRIPT_LABEL_HANDSHAKE_ID "mldsa-auth/v1/handshake-id"

/* Maximum possible encoded length of each message type, for caller-side
 * stack buffer sizing. */
#define CLIENT_HELLO_MAX_ENCODED_LEN \
    (1u + 1u + WIRE_ID_MAX_LEN + WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN)
#define SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN \
    (1u + 1u + WIRE_ID_MAX_LEN + WIRE_X25519_PUB_LEN + WIRE_NONCE_LEN + WIRE_SESSION_ID_LEN)
#define SERVER_HELLO_MAX_ENCODED_LEN \
    (SERVER_HELLO_UNSIGNED_MAX_ENCODED_LEN + 2u + MLDSA_SIGNATURE_MAX_BYTES)
#define CLIENT_AUTH_MAX_ENCODED_LEN \
    (1u + WIRE_HANDSHAKE_ID_LEN + 2u + MLDSA_SIGNATURE_MAX_BYTES)

typedef struct {
    uint8_t id[WIRE_ID_MAX_LEN];
    uint8_t id_len; /* WIRE_ID_MIN_LEN..WIRE_ID_MAX_LEN */
    uint8_t ephemeral_pub[WIRE_X25519_PUB_LEN];
    uint8_t session_id[WIRE_SESSION_ID_LEN];
    uint8_t nonce[WIRE_NONCE_LEN];
} client_hello_t;

typedef struct {
    uint8_t id[WIRE_ID_MAX_LEN];
    uint8_t id_len; /* WIRE_ID_MIN_LEN..WIRE_ID_MAX_LEN */
    uint8_t ephemeral_pub[WIRE_X25519_PUB_LEN];
    uint8_t nonce[WIRE_NONCE_LEN];
    uint8_t session_id_echo[WIRE_SESSION_ID_LEN]; /* must equal the peer
                                                    * ClientHello.session_id
                                                    * -- checked by Step 4,
                                                    * not here */
    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    uint16_t sig_len; /* 1..MLDSA_SIGNATURE_MAX_BYTES */
} server_hello_t;

typedef struct {
    /* Structurally validated wire field only -- Step 3 cannot establish
     * that this was actually derived from a real transcript (that needs
     * the transcript, which this struct doesn't carry). Step 4 must
     * populate it exclusively via transcript_handshake_id() over the
     * accepted ClientHello/ServerHello, and on receipt must recompute
     * and compare it the same way before trusting anything -- see the
     * Step 3 plan's "API boundary" note. */
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    uint16_t sig_len; /* 1..MLDSA_SIGNATURE_MAX_BYTES */
} client_auth_t;

/* --- Encoders ---------------------------------------------------------
 *
 * Every encode_* function validates its input struct AND that `out_cap`
 * is large enough for the full message BEFORE writing a single byte to
 * `out` (Step 3 plan decision 9) -- on failure, `out` is left completely
 * untouched, never partially written. Returns 0 on success (with
 * *out_len set to the exact number of bytes written), nonzero on
 * failure.
 */

int encode_client_hello(const client_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len);

/* Writes only ServerHello's unsigned prefix (SH_unsigned): everything
 * except sig_len/sig. This is what transcript_hash_server_auth() hashes
 * to produce the value sig_B is computed over -- BEFORE sig_b exists. */
int encode_server_hello_unsigned(const server_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len);

/* Writes the full ServerHello as transmitted: encode_server_hello_unsigned()'s
 * bytes followed by sig_len/sig. Literally
 * encode(ServerHello) = SH_unsigned || sig_len || sig -- not a separate
 * encoding. */
int encode_server_hello(const server_hello_t *msg, uint8_t *out, size_t out_cap, size_t *out_len);

int encode_client_auth(const client_auth_t *msg, uint8_t *out, size_t out_cap, size_t *out_len);

/* --- Decoders -----------------------------------------------------------
 *
 * Each decode_* function accepts ONLY its own exact message_type byte
 * (Step 3 plan decision 4) and requires *consumed == len on success --
 * strict mode, no trailing bytes tolerated (decision 8). Every length
 * field is validated against its declared bound AND the actual
 * remaining buffer size before any payload byte is read. On any
 * failure, *out is zeroed and the function returns nonzero; *consumed
 * is only set on success.
 */

int decode_client_hello(const uint8_t *buf, size_t len, client_hello_t *out, size_t *consumed);
int decode_server_hello(const uint8_t *buf, size_t len, server_hello_t *out, size_t *consumed);
int decode_client_auth(const uint8_t *buf, size_t len, client_auth_t *out, size_t *consumed);

/* --- Transcript hashes -------------------------------------------------
 *
 * All three below return 0 on success, nonzero on failure (NULL
 * pointers only -- SHA-256 itself cannot fail on valid input). Each
 * hashes: label || 0x00 || message bytes in argument order, via
 * incremental SHA-256 (crypto_hash_sha256_init/update/final) -- never
 * by concatenating into one buffer first.
 */

/* TH_server_auth = SHA-256(LABEL_SERVER_AUTH || 0x00 ||
 *                          encode(ClientHello) || SH_unsigned) */
int transcript_hash_server_auth(const uint8_t *client_hello_bytes, size_t ch_len,
                                 const uint8_t *sh_unsigned_bytes, size_t sh_unsigned_len,
                                 uint8_t out[32]);

/* TH_client_auth = SHA-256(LABEL_CLIENT_AUTH || 0x00 ||
 *                          encode(ClientHello) || encode(ServerHello)) */
int transcript_hash_client_auth(const uint8_t *client_hello_bytes, size_t ch_len,
                                 const uint8_t *server_hello_bytes, size_t sh_len,
                                 uint8_t out[32]);

/* handshake_id = SHA-256(LABEL_HANDSHAKE_ID || 0x00 ||
 *                        encode(ClientHello) || encode(ServerHello))[0:16]
 * The full 32-byte digest is always computed first; only the finished
 * digest is truncated -- never a separately-constructed 16-byte hash. */
int transcript_handshake_id(const uint8_t *client_hello_bytes, size_t ch_len,
                             const uint8_t *server_hello_bytes, size_t sh_len,
                             uint8_t out[16]);

#endif /* MLDSA_AUTH_PROTOCOL_TRANSCRIPT_H */
