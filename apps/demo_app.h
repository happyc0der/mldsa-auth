#ifndef MLDSA_AUTH_APPS_DEMO_APP_H
#define MLDSA_AUTH_APPS_DEMO_APP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "frame.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "session.h"

/*
 * Step 6 reference connection logic (spec §6.5), shared by auth_server,
 * auth_client and tests/test_net.c. One connection at a time; everything
 * here is single-threaded (spec §6.3.6, confinement).
 *
 * DEMO APPLICATION PROTOCOL (inside session records; reference-app level,
 * NOT part of the cryptographic protocol -- spec §6.4 is unchanged):
 *   plaintext = op (1 byte) || body
 *   DEMO_OP_MSG     client -> server; server replies DEMO_OP_ECHO, same body
 *   DEMO_OP_GOODBYE either direction; authenticated close, answered by GOODBYE
 * The responder's first record is EMPTY (the Step 5 confirmation record) and
 * carries no op; every later record must be non-empty. EOF without a
 * GOODBYE is reported as DEMO_ERR_PEER_CLOSED (possible truncation), never
 * as success.
 *
 * LOGGING: fixed event text, stage/status names, byte counts and peer ids
 * only. Keys, secrets, session keys, signatures, nonces, raw frames and
 * decrypted payloads are NEVER logged; there is no option to enable them.
 *
 * TCP IS NOT AUTHENTICATION: peer addresses are never consulted; identity
 * comes only from the ML-DSA handshake against pinned keys.
 */

#define DEMO_OP_MSG 0x01u
#define DEMO_OP_ECHO 0x02u
#define DEMO_OP_GOODBYE 0x03u
#define DEMO_MAX_MESSAGE_BYTES (SESSION_MAX_CONTENT_BYTES - 1u) /* one byte is the op */

#define DEMO_HANDSHAKE_TIMEOUT_MS_DEFAULT 10000u
#define DEMO_IDLE_TIMEOUT_MS_DEFAULT 30000u
#define DEMO_DEFAULT_PORT 47443u
#define DEMO_LOG_LINE_MAX 512u /* fits a fully \xHH-escaped 64-byte id */

typedef struct {
    void (*fn)(void *ctx, const char *line); /* NULL: write to stderr */
    void *ctx;
} demo_log_t;

typedef struct {
    const uint8_t *local_id;
    size_t local_id_len;
    const mldsa_keypair_t *local_kp; /* borrowed */
    const keystore_t *pins;          /* borrowed: server = pinned clients, client = pinned server */
    const uint8_t *peer_id;          /* client only: the identity it dials */
    size_t peer_id_len;
    uint64_t handshake_timeout_ms;   /* absolute, until established (client: until confirmed) */
    uint64_t idle_timeout_ms;        /* per session-phase frame */
    /* Sender-side record padding (spec-v2 6.4.1): one of
     * {1, 16, 64, 256, 1024, 4096}, affecting only what THIS peer sends.
     * Never negotiated; the far side needs no knowledge of it.
     *
     * DEMO-LAYER CONVENTION: 0 means "unset -- use the library default",
     * because every caller zero-initializes this struct. The library
     * itself does NOT accept 0 (session.h: a bucket outside the six is an
     * error, never a silent default); demo_app.c translates 0 into "pass
     * NULL limits" rather than passing a zero through. */
    uint32_t pad_bucket;
    demo_log_t log;
} demo_config_t;

/* 196 666 bytes; caller-owned, allocated once per process and reused. Zeroed
 * by the demo functions at the end of every connection (it can hold
 * plaintext). */
typedef struct {
    uint8_t rx[FRAME_BUF_BYTES];
    uint8_t tx[FRAME_BUF_BYTES];
    uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES];
} demo_buffers_t;

typedef enum {
    DEMO_STAGE_CONNECT = 0,
    DEMO_STAGE_CLIENT_HELLO,
    DEMO_STAGE_SERVER_HELLO,
    DEMO_STAGE_CLIENT_AUTH,
    DEMO_STAGE_CONFIRM,
    DEMO_STAGE_SESSION,
    DEMO_STAGE_GOODBYE
} demo_stage_t;

typedef enum {
    DEMO_OK = 0,
    DEMO_ERR_CONFIG,
    DEMO_ERR_IO,
    DEMO_ERR_TIMEOUT,
    DEMO_ERR_PEER_CLOSED,  /* EOF at a frame boundary without an authenticated GOODBYE */
    DEMO_ERR_TRUNCATED,    /* EOF mid-frame */
    DEMO_ERR_FRAME_SIZE,   /* frame length outside the per-state bounds */
    DEMO_ERR_HANDSHAKE,    /* see hs_status */
    DEMO_ERR_SESSION,      /* see sess_status */
    DEMO_ERR_NOT_CONFIRMED,
    DEMO_ERR_APP_PROTOCOL,
    DEMO_ERR_RESOURCE
} demo_status_t;

typedef struct {
    demo_status_t status;
    demo_stage_t stage;             /* where the connection ended */
    handshake_status_t hs_status;
    session_status_t sess_status;
    frame_status_t frame_status;
    uint32_t messages_echoed;
    size_t pending_active_after;    /* server: live ledger entries after cleanup */
    net_stats_t net;
} demo_result_t;

typedef struct {
    const uint8_t *data;
    size_t len; /* 1 .. DEMO_MAX_MESSAGE_BYTES */
} demo_message_t;

/* Handles one accepted connection end to end, then wipes all state and the
 * buffers and closes conn. Always fills *res; returns res->status. */
demo_status_t demo_server_handle_connection(const demo_config_t *cfg, handshake_pending_store_t *store,
                                            net_conn_t *conn, demo_buffers_t *buf, demo_result_t *res);

/* Runs the client side over a connected conn: handshake, waits for the
 * empty confirmation record, then sends each message, verifies its echo,
 * and exchanges GOODBYE. Wipes everything and closes conn. */
demo_status_t demo_client_run(const demo_config_t *cfg, net_conn_t *conn, const demo_message_t *msgs,
                              size_t n_msgs, demo_buffers_t *buf, demo_result_t *res);

/* The ONLY way application data is sent: seals op || body and frames it.
 * Refuses with DEMO_ERR_NOT_CONFIRMED -- writing nothing -- unless
 * session_is_peer_confirmed(s). body may alias buf->pt + 1. */
demo_status_t demo_send_app(session_t *s, net_conn_t *conn, demo_buffers_t *buf, uint8_t op,
                            const uint8_t *body, size_t body_len, uint64_t deadline_ms);

const char *demo_status_name(demo_status_t st);
const char *demo_stage_name(demo_stage_t st);

/* ---- CLI helpers shared by auth_server and auth_client ------------------ */

/* Decimal only, full consumption, min <= value <= max. 0 on success. */
int demo_parse_u64(const char *s, uint64_t min, uint64_t max, uint64_t *out);

/* True for one of the six pad buckets spec-v2 6.4.1 permits. The CLIs use
 * it to reject --pad-bucket values a range check would admit (32, say). */
bool demo_pad_bucket_valid(uint32_t bucket);

/* Demo identity: 1..64 bytes of [A-Za-z0-9._-], not starting with '.'
 * (they also name key files). 0 on success. */
int demo_parse_id(const char *s, const uint8_t **id, size_t *id_len);

/* Splits "ID=PATH" at the first '='; the ID must satisfy demo_parse_id. */
int demo_split_pin(const char *arg, const uint8_t **id, size_t *id_len, const char **path);

/* Publishes "PORT\n" at path atomically and without clobbering: written to
 * a 0600 temporary file created O_EXCL, closed, then link()ed to path
 * (fails if path exists) and the temporary unlinked. 0 on success. */
int demo_publish_port_file(const char *path, uint16_t port);

/* "<prog> keygen --id ID --dir DIR": argv[first..argc) are the options.
 * Returns a process exit status (0 ok, 1 failure, 2 usage). */
int demo_cli_keygen(int argc, char **argv, int first, const char *prog);

#endif /* MLDSA_AUTH_APPS_DEMO_APP_H */
