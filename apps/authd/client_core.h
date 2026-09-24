#ifndef MLDSA_AUTH_APPS_AUTHD_CLIENT_CORE_H
#define MLDSA_AUTH_APPS_AUTHD_CLIENT_CORE_H

/*
 * The client, as bytes in and bytes out (V4-13a).
 *
 * Everything a device does against mldsa-authd -- create an identity, open it,
 * log in, rotate -- with NO sockets, NO files, NO stdout and NO statics. The
 * native CLI (authd_client) drives it over a Unix or TCP socket; the browser
 * build (13b) drives the very same functions from JavaScript over a
 * WebSocket. One implementation, two transports: so the end-to-end tests that
 * run the CLI are regression tests for exactly the code a browser runs.
 *
 * MESSAGES. Every message in or out is ONE WHOLE FRAME: a 4-byte big-endian
 * length followed by that many payload bytes -- exactly one WebSocket message,
 * or exactly what frame_send/frame_recv move on a raw stream. On input the
 * length is CHECKED against the message size and against the bound for the
 * current state (cc_recv_bounds), and the payload is always msg+4 for
 * msg_len-4 bytes: the header's claim is never used to index anything.
 *
 * STATE. cc_t is caller-owned (about 135 KB: a keystore and a record-sized
 * scratch buffer), initialised by cc_init and destroyed by cc_wipe. Calls are
 * accepted only in the state that expects them. ANY failure is terminal: the
 * core moves to CC_STATE_FAILED, wipes every secret it holds, and refuses
 * every later call but cc_wipe.
 *
 * THE SECRET KEY'S LIFETIME is as short as the protocol allows, and tested:
 * the handshake needs it from ClientHello until ClientAuth is signed (one
 * round trip), and not after. A key the core opened itself (from an MLDSAEK1
 * envelope) is FREED when ClientAuth is built and on every failure; a key the
 * caller lent has its pointer dropped at the same point. CC_KEEP_FOR_ROTATE is
 * the one extension: rotation signs with the old key after the session
 * exists, so it is kept until cc_rotate_build and no longer.
 *
 * PHISHING RESISTANCE (spec 4) is the pin: cc_pin_server fixes the server's
 * id and key BEFORE anything is sent, and a ServerHello not signed by that
 * key is refused with no ClientAuth produced.
 *
 * ORDER, one deliberate difference from the pre-V4-13a CLI: the handshake is
 * finished and the session keyed BEFORE ClientAuth leaves, not after. Both
 * steps are local and cannot be influenced by the peer between the two
 * points, so this is observable only if one of them fails internally.
 */

#include <stddef.h>
#include <stdint.h>

#include "authmsg.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"

/* Argon2id parameters for a key sealed IN A BROWSER, spec 12: ops 3, 64 MiB
 * (111.5 ms in wasm at V4-2 S6). The CLI's operator values are 3 / 256 MiB;
 * a browser tab cannot count on a quarter of a gigabyte. */
#define CC_KDF_OPS_BROWSER 3u
#define CC_KDF_MEM_BROWSER (64u * 1024u * 1024u)

/* Spec 3.1: "d1" || 32 lowercase hex characters, plus a NUL. */
#define CC_HANDLE_LEN 34u
#define CC_HANDLE_BUF (CC_HANDLE_LEN + 1u)

/* Flags for cc_login_begin / cc_login_begin_sealed. */
#define CC_KEEP_FOR_ROTATE 0x01u

typedef enum {
    CC_OK = 0,
    CC_ERR_ARG,           /* misuse: NULL, a buffer too small; no state change */
    CC_ERR_STATE,         /* not the call this state expects; no state change */
    CC_ERR_FRAME,         /* length header disagrees with the message, or out of bounds */
    CC_ERR_HANDSHAKE,     /* the handshake refused (cc_diag_t names why) */
    CC_ERR_SESSION,       /* a record did not authenticate, or the session expired */
    CC_ERR_MESSAGE,       /* a record authenticated but is not the message expected */
    CC_ERR_REFUSED,       /* the daemon answered with an ERROR message */
    CC_ERR_ACK_MISMATCH,  /* ROTATE_ACK names a different handle or key */
    CC_ERR_KEYFILE,       /* an MLDSAEK1 envelope failed (cc_diag_t names why) */
    CC_ERR_KEYS,          /* an MLDSAPK1 image failed (cc_diag_t names why) */
    CC_ERR_CRYPTO         /* key generation, signing, allocation */
} cc_status_t;

typedef enum {
    CC_STATE_NEW = 0,          /* cc_init done; pin next */
    CC_STATE_PINNED,           /* cc_login_begin[_sealed] next */
    CC_STATE_WAIT_SERVER_HELLO,
    CC_STATE_WAIT_LOGIN_CODE,
    CC_STATE_LIVE,             /* logged in: cc_rotate_build or cc_bye */
    CC_STATE_WAIT_ROTATE_REPLY,
    CC_STATE_CLOSED,           /* BYE built; the session is gone */
    CC_STATE_FAILED            /* terminal; cc_wipe */
} cc_state_t;

/* Where and why the last call failed, in the vocabulary the CLI has always
 * printed -- so moving the CLI onto the core changes no stderr line.
 *
 *   kind HANDSHAKE   "<stage>: <detail>"   detail = a handshake status name
 *   kind MESSAGE     "<stage>: <detail>"   detail = an authmsg status name,
 *                    then "failed at <stage>"
 *   kind IO          "failed at <stage>"   (framing, session, transport)
 *   kind KEYS        detail = a keyfile or demo_keys status name
 *
 * Both strings are static; neither ever contains peer-supplied bytes. */
typedef enum { CC_DIAG_NONE = 0, CC_DIAG_HANDSHAKE, CC_DIAG_MESSAGE, CC_DIAG_IO, CC_DIAG_KEYS } cc_diag_kind_t;
typedef struct {
    cc_diag_kind_t kind;
    const char *stage;
    const char *detail;
} cc_diag_t;

/* Caller-owned; every field is private to client_core.c. */
typedef struct {
    cc_state_t state;
    cc_diag_t diag;
    handshake_clock_fn clock_fn;
    void *clock_ctx;

    keystore_t pins;                         /* exactly one: the server */
    uint8_t sid[64];
    size_t sid_len;
    uint8_t hid[64];
    size_t hid_len;

    const mldsa_keypair_t *kp;               /* the key signing ClientAuth; NULL once used */
    mldsa_keypair_t own_kp;                  /* set when the core opened the key itself */
    unsigned flags;

    handshake_ctx_t hs;
    session_t sess;
    uint8_t hsid[AUTHMSG_HANDSHAKE_ID_BYTES];
    uint8_t want_fp[AUTHMSG_FP_BYTES];       /* the new key a ROTATE_ACK must name */

    uint8_t body[AUTHMSG_ROTATE_MAX_CONTENT];
    uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES]; /* opened records; wiped after each */
} cc_t;

const char *cc_status_name(cc_status_t st);
/* The name the daemon's log uses for a handshake status (spec 13). */
const char *cc_handshake_status_name(handshake_status_t st);

/* ---- identity, no network ------------------------------------------------ */

/* A fresh device handle (spec 3.1) from 16 random bytes. out gets
 * CC_HANDLE_LEN characters and a NUL. */
void cc_new_handle(char out[CC_HANDLE_BUF]);

/* Generates a keypair for `hid` and returns it as a sealed MLDSAEK1 envelope
 * (ek_out, keyfile_sealed_len(demo_keys_sk2_image_len(hid_len)) bytes) and an
 * MLDSAPK1 image (pub_out, demo_keys_public_image_len(hid_len) bytes). The
 * plaintext MLDSASK2 image exists only in secure memory, briefly. pk_out may
 * be NULL. `diag` (may be NULL) names a failure. */
cc_status_t cc_seal_new_identity(const uint8_t *hid, size_t hid_len, const char *pass, size_t pass_len,
                                 uint32_t opslimit, uint64_t memlimit,
                                 uint8_t *ek_out, size_t ek_cap, size_t *ek_len,
                                 uint8_t *pub_out, size_t pub_cap, size_t *pub_len,
                                 uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES], cc_diag_t *diag);

/* Opens an MLDSAEK1 envelope for `hid` (keyfile_open_buf). kp_out's secret
 * key is secure memory; free it with mldsa_keypair_free. */
cc_status_t cc_open_sealed(const uint8_t *ek, size_t ek_len, const uint8_t *hid, size_t hid_len,
                           const char *pass, size_t pass_len, mldsa_keypair_t *kp_out, cc_diag_t *diag);

/* Parses the pinned server's MLDSAPK1 image; its embedded id must be `sid`. */
cc_status_t cc_parse_server_pub(const uint8_t *pub, size_t pub_len, const uint8_t *sid, size_t sid_len,
                                uint8_t pk_out[MLDSA_PUBLIC_KEY_BYTES], cc_diag_t *diag);

/* ---- login --------------------------------------------------------------- */

/* clock_fn NULL = the library's monotonic clock. The session layer times the
 * session with it (rekey and hard-expiry limits), so a caller that injects one
 * -- a test, or a browser that must not trust a throttled tab's timers --
 * governs the session with it. */
void cc_init(cc_t *cc, handshake_clock_fn clock_fn, void *clock_ctx);

/* NEW -> PINNED. The server's id and public key; nothing is sent before this. */
cc_status_t cc_pin_server(cc_t *cc, const uint8_t *sid, size_t sid_len,
                          const uint8_t pk[MLDSA_PUBLIC_KEY_BYTES]);

/* PINNED -> WAIT_SERVER_HELLO, writing the ClientHello frame to out.
 * `kp` is BORROWED: it must stay valid until ClientAuth is built (or until
 * cc_rotate_build, with CC_KEEP_FOR_ROTATE), and the core never frees it. */
cc_status_t cc_login_begin(cc_t *cc, const uint8_t *hid, size_t hid_len, const mldsa_keypair_t *kp,
                           unsigned flags, uint8_t *out, size_t out_cap, size_t *out_len);

/* As cc_login_begin, but the core opens the envelope itself and OWNS the key,
 * freeing it at ClientAuth (or at cc_rotate_build with CC_KEEP_FOR_ROTATE),
 * and on any failure. A wrong passphrase is CC_ERR_KEYFILE and leaves the
 * core PINNED, so the caller may ask again. */
cc_status_t cc_login_begin_sealed(cc_t *cc, const uint8_t *hid, size_t hid_len,
                                  const uint8_t *ek, size_t ek_len, const char *pass, size_t pass_len,
                                  unsigned flags, uint8_t *out, size_t out_cap, size_t *out_len);

/* WAIT_SERVER_HELLO -> WAIT_LOGIN_CODE. Verifies the ServerHello against the
 * pin, builds ClientAuth into out, releases the key, finishes the handshake
 * and keys the session. On refusal nothing is written to out. */
cc_status_t cc_login_on_server_hello(cc_t *cc, const uint8_t *msg, size_t msg_len,
                                     uint8_t *out, size_t out_cap, size_t *out_len);

/* WAIT_LOGIN_CODE -> LIVE. The daemon's first record MUST be LOGIN_CODE. */
cc_status_t cc_login_on_record(cc_t *cc, const uint8_t *msg, size_t msg_len, authmsg_login_code_t *code_out);

/* LIVE -> CLOSED, writing a BYE frame so the daemon frees the slot now rather
 * than at its idle deadline. */
cc_status_t cc_bye(cc_t *cc, uint8_t *out, size_t out_cap, size_t *out_len);

/* ---- rotation (spec 6.3, 10.2) ------------------------------------------ */

/* LIVE -> WAIT_ROTATE_REPLY. Requires CC_KEEP_FOR_ROTATE at login. Signs the
 * rotation with the old key and `new_kp`, seals ROTATE into out, and frees
 * (or drops) the old key. The caller MUST have made `new_kp` durable -- as
 * <handle>.ek.next, or its storage's equivalent -- BEFORE sending this. */
cc_status_t cc_rotate_build(cc_t *cc, const mldsa_keypair_t *new_kp, uint8_t rotate_flags,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/* WAIT_ROTATE_REPLY -> LIVE when the record authenticated (whatever it
 * said), FAILED when it did not. CC_OK only for a ROTATE_ACK naming THIS
 * handle and THIS new key -- the one outcome that licenses replacing the old
 * key. CC_ERR_REFUSED sets *err_code (may be NULL). No outcome but CC_OK
 * proves anything about what the daemon committed (spec 10.2). */
cc_status_t cc_rotate_on_reply(cc_t *cc, const uint8_t *msg, size_t msg_len, uint8_t *err_code);

/* ---- state -------------------------------------------------------------- */

cc_state_t cc_state(const cc_t *cc);
const cc_diag_t *cc_diag(const cc_t *cc);

/* The payload bounds the next inbound frame must satisfy in this state
 * (both 0 when none is expected). A transport that can bound its read uses
 * these; the core checks them again either way. */
void cc_recv_bounds(const cc_t *cc, size_t *min_payload, size_t *max_payload);

/* Wipes and frees everything; the struct is left FAILED. Idempotent. */
void cc_wipe(cc_t *cc);

/* ---- the .ek.next decision (spec 10.2) ----------------------------------- */

/* Which key file is live after an interrupted rotation.
 *
 * Exposed for tests: it is the subtlest decision in the client, and the only
 * way to exercise every branch without staging a crash mid-round-trip. The
 * rule is NOT the spec's original wording -- see client_core.c for why "if it
 * is unknown, the server never committed" cannot be implemented, and why only
 * .ek authenticating licenses discarding .ek.next. */
typedef enum {
    KEY_PLAN_USE_EK = 0,    /* .ek is current; if .ek.next exists it is stale */
    KEY_PLAN_PROMOTE_NEXT,  /* .ek.next is live: finish the interrupted rename */
    KEY_PLAN_REFUSE         /* neither authenticates: say so, change nothing */
} key_plan_t;

key_plan_t client_key_plan(int ek_ok, int next_present, int next_ok);

/* ---- randomness --------------------------------------------------------- */

/* Routes liboqs's randomness (ML-DSA keygen and hedged signing, ML-KEM) to
 * libsodium's randombytes_buf, so ONE generator serves both libraries.
 *
 * Why it exists: under Emscripten liboqs's own default may fopen
 * /dev/urandom and exit() when that fails, and a known-answer test that
 * substitutes libsodium's generator must reach liboqs too or its golden is
 * silently half-random. It mutates PROCESS-GLOBAL state, so it is called only
 * by the wasm module's init (13b) and by test_client_core_kat -- never by the
 * CLI, and never by a test that shares its process with the daemon. */
void cc_use_sodium_rng_for_oqs(void);

#endif /* MLDSA_AUTH_APPS_AUTHD_CLIENT_CORE_H */
