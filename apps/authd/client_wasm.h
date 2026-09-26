#ifndef MLDSA_AUTH_APPS_AUTHD_CLIENT_WASM_H
#define MLDSA_AUTH_APPS_AUTHD_CLIENT_WASM_H

/*
 * The client core's export surface for JavaScript (V4-13b).
 *
 * Flat functions over client_core.h, in the only shapes a wasm export can
 * carry cheaply: pointers into the module's memory, 32-bit lengths, ints and
 * doubles. JavaScript allocates every buffer (the module's malloc) and moves
 * bytes; it never sees a key, never chooses a KDF parameter and never does
 * cryptography. Everything else is client_core's, unchanged.
 *
 * Plain C, deliberately: it compiles natively too, so test_client_wasm drives
 * it on the ASan tree and campaign v54 mutates it with the same runner as
 * every other campaign. Under Emscripten each function is kept alive and
 * listed in the module's explicit export list; natively the macro is empty.
 *
 * Three decisions a browser caller cannot override:
 *   - the Argon2id parameters are the browser's (spec 12: ops 3, 64 MiB);
 *   - the clock is the caller's (ccw_set_now_ms), and a login cannot BEGIN
 *     until it has been set -- a shim that silently fell back to some default
 *     would make "the injected clock governs the session" untrue in exactly
 *     the environment the injection exists for;
 *   - ccw_init routes liboqs's randomness to libsodium's generator, which
 *     under Emscripten draws from the host's crypto.getRandomValues.
 */

#include <stddef.h>
#include <stdint.h>

#include "client_core.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define CCW_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define CCW_EXPORT
#endif

/* The handle JavaScript holds. Fields are private to client_wasm.c; the
 * struct is visible only so the native test can assert on key release. */
typedef struct {
    cc_t cc;
    uint64_t now_ms;
    int clock_set;
} ccw_t;

/* sodium_init + liboqs routed to libsodium. Idempotent; 0 on success. Every
 * other entry point but the size queries refuses until it has succeeded. */
CCW_EXPORT int ccw_init(void);

CCW_EXPORT ccw_t *ccw_new(void);                 /* NULL if not initialised or out of memory */
CCW_EXPORT void ccw_free(ccw_t *h);              /* wipes, then frees; NULL is a no-op */

/* Milliseconds from a monotonic source (performance.now() in a browser).
 * Refused (-1) unless finite, >= 0 and not before the last value set. */
CCW_EXPORT int ccw_set_now_ms(ccw_t *h, double ms);

/* Buffer sizes JavaScript must allocate. */
CCW_EXPORT uint32_t ccw_frame_buf_bytes(void);           /* one whole frame, header included */
CCW_EXPORT uint32_t ccw_sealed_len(uint32_t hid_len);     /* an MLDSAEK1 envelope for this handle */
CCW_EXPORT uint32_t ccw_public_len(uint32_t hid_len);     /* an MLDSAPK1 image for this handle */

/* ---- identity ------------------------------------------------------------ */

/* Writes CC_HANDLE_LEN characters and a NUL. */
CCW_EXPORT int ccw_new_handle(char *out);

/* A new identity for `hid`, sealed at the BROWSER's Argon2id parameters. */
CCW_EXPORT int ccw_seal_new_identity(const uint8_t *hid, uint32_t hid_len, const char *pass, uint32_t pass_len,
                                     uint8_t *ek_out, uint32_t ek_cap, uint32_t *ek_len,
                                     uint8_t *pub_out, uint32_t pub_cap, uint32_t *pub_len);

/* ---- login --------------------------------------------------------------- */

/* Parses the server's MLDSAPK1 (its id must be `sid`) and pins it. */
CCW_EXPORT int ccw_pin_server_pub(ccw_t *h, const uint8_t *pub, uint32_t pub_len,
                                  const uint8_t *sid, uint32_t sid_len);

/* Opens the envelope inside the core and writes the ClientHello frame. A
 * wrong passphrase is CC_ERR_KEYFILE and leaves the handle able to try again. */
CCW_EXPORT int ccw_login_begin(ccw_t *h, const uint8_t *hid, uint32_t hid_len,
                               const uint8_t *ek, uint32_t ek_len, const char *pass, uint32_t pass_len,
                               int keep_for_rotate, uint8_t *out, uint32_t out_cap, uint32_t *out_len);

CCW_EXPORT int ccw_on_server_hello(ccw_t *h, const uint8_t *msg, uint32_t msg_len,
                                   uint8_t *out, uint32_t out_cap, uint32_t *out_len);

/* The login code (32 bytes), its flags and its expiry in unix seconds. On any
 * failure code_out is zeroed. */
CCW_EXPORT int ccw_on_record(ccw_t *h, const uint8_t *msg, uint32_t msg_len,
                             uint8_t *code_out, uint32_t *flags_out, double *expires_out);

CCW_EXPORT int ccw_bye(ccw_t *h, uint8_t *out, uint32_t out_cap, uint32_t *out_len);

/* ---- rotation ------------------------------------------------------------- */

/* Opens the NEW identity's envelope (the caller must already have stored it
 * durably), builds ROTATE, and frees the new key again before returning. */
CCW_EXPORT int ccw_rotate_build(ccw_t *h, const uint8_t *new_ek, uint32_t new_ek_len,
                                const char *pass, uint32_t pass_len,
                                uint8_t *out, uint32_t out_cap, uint32_t *out_len);

CCW_EXPORT int ccw_rotate_on_reply(ccw_t *h, const uint8_t *msg, uint32_t msg_len, uint32_t *err_code);

/* ---- state ---------------------------------------------------------------- */

CCW_EXPORT int ccw_state(const ccw_t *h);
CCW_EXPORT uint32_t ccw_recv_max(const ccw_t *h);         /* max payload of the next inbound frame */
CCW_EXPORT const char *ccw_diag_stage(const ccw_t *h);    /* static strings, "" when none */
CCW_EXPORT const char *ccw_diag_detail(const ccw_t *h);
CCW_EXPORT const char *ccw_status_name(int st);
CCW_EXPORT int ccw_key_plan(int ek_ok, int next_present, int next_ok);

#endif /* MLDSA_AUTH_APPS_AUTHD_CLIENT_WASM_H */
