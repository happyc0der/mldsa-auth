#include "client_wasm.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "demo_keys.h"
#include "frame.h"
#include "keyfile.h"
#include "passphrase.h"

static int g_ready = 0;

/* The session's clock is the caller's. Until it has been set the handle
 * refuses to begin a login (ccw_login_begin), so this value is never read by
 * a session that matters; UINT64_MAX is the library's own fail-closed value. */
static uint64_t ccw_clock(void *ctx)
{
    const ccw_t *h = (const ccw_t *)ctx;
    return h->clock_set ? h->now_ms : UINT64_MAX;
}

int ccw_init(void)
{
    if (g_ready) {
        return 0;
    }
    if (sodium_init() < 0) {
        return -1;
    }
    cc_use_sodium_rng_for_oqs();
    g_ready = 1;
    return 0;
}

ccw_t *ccw_new(void)
{
    if (!g_ready) {
        return NULL;
    }
    ccw_t *h = (ccw_t *)malloc(sizeof *h);
    if (h == NULL) {
        return NULL;
    }
    memset(h, 0, sizeof *h);
    cc_init(&h->cc, ccw_clock, h);
    return h;
}

void ccw_free(ccw_t *h)
{
    if (h == NULL) {
        return;
    }
    cc_wipe(&h->cc);
    sodium_memzero(h, sizeof *h);
    free(h);
}

int ccw_set_now_ms(ccw_t *h, double ms)
{
    /* 2^53: the largest integer a double holds exactly -- ~285,000 years of
     * milliseconds, so no honest clock is refused. */
    if (h == NULL || !isfinite(ms) || ms < 0.0 || ms > 9007199254740992.0) {
        return -1;
    }
    const uint64_t v = (uint64_t)ms;
    if (h->clock_set && v < h->now_ms) {
        return -1;   /* monotonic: a clock that runs backwards is not a clock */
    }
    h->now_ms = v;
    h->clock_set = 1;
    return 0;
}

uint32_t ccw_frame_buf_bytes(void) { return (uint32_t)FRAME_BUF_BYTES; }

uint32_t ccw_sealed_len(uint32_t hid_len)
{
    return (uint32_t)keyfile_sealed_len(demo_keys_sk2_image_len(hid_len));
}

uint32_t ccw_public_len(uint32_t hid_len) { return (uint32_t)demo_keys_public_image_len(hid_len); }

int ccw_new_handle(char *out)
{
    if (!g_ready || out == NULL) {
        return CC_ERR_ARG;
    }
    cc_new_handle(out);
    return CC_OK;
}

int ccw_passphrase_check(const char *pass, uint32_t pass_len, uint32_t *code_points,
                         uint32_t *est_bits, uint32_t *reasons)
{
    pp_report_t r;
    const pp_verdict_t v = pp_check((const uint8_t *)pass, pass_len, &r);
    if (code_points != NULL) { *code_points = r.code_points; }
    if (est_bits != NULL) { *est_bits = r.est_bits; }
    if (reasons != NULL) { *reasons = r.reasons; }
    return (int)v;
}

int ccw_seal_new_identity(const uint8_t *hid, uint32_t hid_len, const char *pass, uint32_t pass_len,
                          uint8_t *ek_out, uint32_t ek_cap, uint32_t *ek_len,
                          uint8_t *pub_out, uint32_t pub_cap, uint32_t *pub_len)
{
    if (!g_ready || ek_len == NULL || pub_len == NULL) {
        return CC_ERR_ARG;
    }
    *ek_len = 0u;
    *pub_len = 0u;
    if (pp_check((const uint8_t *)pass, pass_len, NULL) != PP_OK) {
        return CC_ERR_PASSPHRASE;
    }
    size_t el = 0, pl = 0;
    const cc_status_t st = cc_seal_new_identity(hid, hid_len, pass, pass_len,
                                                CC_KDF_OPS_BROWSER, CC_KDF_MEM_BROWSER,
                                                ek_out, ek_cap, &el, pub_out, pub_cap, &pl, NULL, NULL);
    *ek_len = (uint32_t)el;
    *pub_len = (uint32_t)pl;
    return st;
}

int ccw_pin_server_pub(ccw_t *h, const uint8_t *pub, uint32_t pub_len, const uint8_t *sid, uint32_t sid_len)
{
    if (h == NULL) {
        return CC_ERR_ARG;
    }
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    cc_status_t st = cc_parse_server_pub(pub, pub_len, sid, sid_len, pk, &h->cc.diag);
    if (st == CC_OK) {
        st = cc_pin_server(&h->cc, sid, sid_len, pk);
    }
    sodium_memzero(pk, sizeof pk);
    return st;
}

int ccw_login_begin(ccw_t *h, const uint8_t *hid, uint32_t hid_len,
                    const uint8_t *ek, uint32_t ek_len, const char *pass, uint32_t pass_len,
                    int keep_for_rotate, uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    if (h == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    *out_len = 0u;
    if (!h->clock_set) {
        return CC_ERR_STATE;   /* the session's clock is the caller's: set it first */
    }
    size_t n = 0;
    const cc_status_t st = cc_login_begin_sealed(&h->cc, hid, hid_len, ek, ek_len, pass, pass_len,
                                                 keep_for_rotate ? CC_KEEP_FOR_ROTATE : 0u,
                                                 out, out_cap, &n);
    *out_len = (uint32_t)n;
    return st;
}

int ccw_on_server_hello(ccw_t *h, const uint8_t *msg, uint32_t msg_len,
                        uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    if (h == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    size_t n = 0;
    const cc_status_t st = cc_login_on_server_hello(&h->cc, msg, msg_len, out, out_cap, &n);
    *out_len = (uint32_t)n;
    return st;
}

int ccw_on_record(ccw_t *h, const uint8_t *msg, uint32_t msg_len,
                  uint8_t *code_out, uint32_t *flags_out, double *expires_out)
{
    if (h == NULL || code_out == NULL || flags_out == NULL || expires_out == NULL) {
        return CC_ERR_ARG;
    }
    authmsg_login_code_t lc;
    const cc_status_t st = cc_login_on_record(&h->cc, msg, msg_len, &lc);
    if (st == CC_OK) {
        memcpy(code_out, lc.code, AUTHMSG_CODE_BYTES);
        *flags_out = lc.flags;
        *expires_out = (double)lc.code_expires;
    } else {
        sodium_memzero(code_out, AUTHMSG_CODE_BYTES);
        *flags_out = 0u;
        *expires_out = 0.0;
    }
    sodium_memzero(&lc, sizeof lc);
    return st;
}

int ccw_bye(ccw_t *h, uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    if (h == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    size_t n = 0;
    const cc_status_t st = cc_bye(&h->cc, out, out_cap, &n);
    *out_len = (uint32_t)n;
    return st;
}

int ccw_rotate_build(ccw_t *h, const uint8_t *new_ek, uint32_t new_ek_len,
                     const char *pass, uint32_t pass_len,
                     uint8_t *out, uint32_t out_cap, uint32_t *out_len)
{
    if (h == NULL || out_len == NULL) {
        return CC_ERR_ARG;
    }
    *out_len = 0u;
    mldsa_keypair_t nkp;
    memset(&nkp, 0, sizeof nkp);
    cc_status_t st = cc_open_sealed(new_ek, new_ek_len, h->cc.hid, h->cc.hid_len, pass, pass_len, &nkp,
                                    &h->cc.diag);
    if (st == CC_OK) {
        size_t n = 0;
        st = cc_rotate_build(&h->cc, &nkp, 0u, out, out_cap, &n);
        *out_len = (uint32_t)n;
    }
    mldsa_keypair_free(&nkp);   /* the new key signed ROTATE; it is not needed again here */
    return st;
}

int ccw_rotate_on_reply(ccw_t *h, const uint8_t *msg, uint32_t msg_len, uint32_t *err_code)
{
    if (h == NULL || err_code == NULL) {
        return CC_ERR_ARG;
    }
    uint8_t code = 0;
    const cc_status_t st = cc_rotate_on_reply(&h->cc, msg, msg_len, &code);
    *err_code = code;
    return st;
}

int ccw_state(const ccw_t *h) { return (int)cc_state(h != NULL ? &h->cc : NULL); }

uint32_t ccw_recv_max(const ccw_t *h)
{
    size_t hi = 0;
    cc_recv_bounds(h != NULL ? &h->cc : NULL, NULL, &hi);
    return (uint32_t)hi;
}

const char *ccw_diag_stage(const ccw_t *h)
{
    const cc_diag_t *d = cc_diag(h != NULL ? &h->cc : NULL);
    return (d != NULL && d->stage != NULL) ? d->stage : "";
}

const char *ccw_diag_detail(const ccw_t *h)
{
    const cc_diag_t *d = cc_diag(h != NULL ? &h->cc : NULL);
    return (d != NULL && d->detail != NULL) ? d->detail : "";
}

const char *ccw_status_name(int st) { return cc_status_name((cc_status_t)st); }

int ccw_key_plan(int ek_ok, int next_present, int next_ok) { return (int)client_key_plan(ek_ok, next_present, next_ok); }
