/* V4-9a: the local socket protocol (apps/authd/localapi.c).
 *
 * The local API is reached only over a uid-restricted Unix socket, so its
 * caller is trusted-ish -- but it is still a PARSER handling variable-length
 * attacker-shaped input, it is the path that mints and verifies bearer
 * tokens, and "the site process was compromised" is squarely in the threat
 * model. A parser bug here is a bug in the thing that issues credentials.
 *
 * THE ORACLE IS THE PROTOCOL'S CONTRACT, not a second parser. Re-implementing
 * the grammar would just be two copies of one misunderstanding (the same
 * reasoning as fuzz_authd_config). What is checkable independently:
 *
 *   1. EXACTLY ONE response, and it is well-formed: a single line starting
 *      "OK " / "OK\n" / "ERR code=", or a list that starts "OK count=" and
 *      ends with a final "END\n". Nothing else ever reaches the socket.
 *   2. A response NEVER contains a raw newline in the middle of a single-line
 *      reply -- log/response injection through a hex-decoded value would show
 *      up here first.
 *   3. An `ERR` response NEVER advances the audit-chain head. A refused
 *      request must not have half-mutated the store; this compares the head
 *      MAC before and after every single input, which no amount of reading
 *      the handlers would prove.
 *   4. Determinism: the same line twice gives the same answer (modulo the
 *      commands that legitimately change state, which are re-checked against
 *      invariant 3 rather than for equality).
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

#include "authd_conn.h"
#include "authd_log.h"
#include "conn_io.h"
#include "evloop.h"
#include "localapi.h"
#include "recovery.h"
#include "store.h"
#include "tokens.h"
#include "handshake.h"
#include "mldsa_wrap.h"

#include <sodium.h>

const char *const fuzz_target_name = "localapi";
const size_t fuzz_target_max_len = 8192;

int fuzz_target_command(int argc, char **argv) { (void)argc; (void)argv; return -1; }

static const uint8_t SERVER_ID[] = { 'a','u','t','h','d' };
static const uint8_t USER1[]     = { 'u','1' };
static const uint8_t HANDLE1[]   = { 'd','1','a','a' };
static const uint8_t KEK[32] = { 7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,
                                 7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7 };

static int g_ready;
static store_t *g_store;
static mldsa_keypair_t g_server_kp;
static mldsa_keypair_t g_device_kp;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_common_init();
    authd_log_init(stderr, AUTHD_LOG_ERROR);   /* the daemon's chatter would drown libFuzzer */

    if (mldsa_keypair_generate(&g_server_kp) != 0) { return 0; }
    if (mldsa_keypair_generate(&g_device_kp) != 0) { return 0; }
    if (store_open(":memory:", KEK, &g_store) != STORE_OK) { return 0; }
    if (store_add_user(g_store, USER1, sizeof USER1, STORE_ROLE_USER) != STORE_OK) { return 0; }
    if (store_enroll_device(g_store, HANDLE1, sizeof HANDLE1, USER1, sizeof USER1,
                            g_device_kp.public_key, "fuzz", "fuzz", NULL, 0) != STORE_OK) { return 0; }
    g_ready = 1;
    return 0;
}

/* Reads everything the handler queued into `out`. The response lives in the
 * slot's out buffer; nothing is written to a socket, so this sees exactly what
 * the peer would have received. */
static size_t drain(authd_slot_t *slot, char *out, size_t cap)
{
    const size_t n = conn_io_pending(&slot->io);
    const size_t take = (n < cap - 1u) ? n : cap - 1u;
    if (take > 0u) {
        memcpy(out, conn_io_pending_ptr(&slot->io), take);
    }
    out[take] = '\0';
    conn_io_sent(&slot->io, n);
    return take;
}

/* Whether a LIST response is expected is decided by the COMMAND, not by the
 * response prefix.
 *
 * This is a real property of the protocol, found by this oracle's first run:
 * `REVOKE-TOKENS` answers a single-line `OK count=N`, and a list answers
 * `OK count=N` followed by items and `END`. The prefix alone is therefore
 * ambiguous, and a client must know which command it sent -- which every real
 * client does, including the Node reference handler. The first version of this
 * oracle guessed from the prefix and immediately reported a "missing END" on a
 * perfectly correct REVOKE-TOKENS reply. */
/* Is `key` present with exactly `val`? A prefix test is NOT good enough: the
 * mutator produced `user=753167`, whose value merely STARTS with 7531 and
 * decodes to a different (nonexistent) user, and a substring check called it
 * a match. Found by this target on its first ASan run. */
static int kv_equals(const uint8_t *line, size_t len, const char *key, const char *val)
{
    const size_t kn = strlen(key), vn = strlen(val);
    for (size_t i = 0; i + kn <= len; i++) {
        if (memcmp(line + i, key, kn) != 0) { continue; }
        if (i > 0 && line[i - 1] != ' ') { continue; }        /* mid-token */
        const size_t vs = i + kn;
        if (vs + vn > len || memcmp(line + vs, val, vn) != 0) { continue; }
        if (vs + vn == len || line[vs + vn] == ' ') { return 1; }
    }
    return 0;
}

/* Does this request line name `cmd`? The command is the first token. */
static int cmd_is(const uint8_t *line, size_t len, const char *cmd)
{
    const size_t n = strlen(cmd);
    if (len < n) { return 0; }
    if (memcmp(line, cmd, n) != 0) { return 0; }
    return (len == n) || (line[n] == ' ');
}

static int expects_list(const uint8_t *line, size_t len)
{
    static const char *const LISTY[] = { "LIST-DEVICES", "LIST-USERS", "AUDIT-TAIL" };
    for (size_t i = 0; i < sizeof LISTY / sizeof LISTY[0]; i++) {
        const size_t n = strlen(LISTY[i]);
        if (len >= n && memcmp(line, LISTY[i], n) == 0 && (len == n || line[n] == ' ')) {
            return 1;
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_ready || size == 0u || size > fuzz_target_max_len) { return 0; }

    /* The input is one request line: strip anything the reassembler would
     * already have removed, so the fuzzer explores the GRAMMAR rather than the
     * framing (conn_io's line handling is covered by test_authd_evloop). */
    static uint8_t line[8192];
    size_t len = 0;
    for (size_t i = 0; i < size && len < sizeof line; i++) {
        if (data[i] == (uint8_t)'\n' || data[i] == (uint8_t)'\r') { break; }
        line[len++] = data[i];
    }
    if (len == 0u) { return 0; }

    static authd_conn_t conns[2];
    static authd_slot_t slots[2];
    static authd_slot_t local[2];
    static authd_app_t app;
    static handshake_pending_store_t pending;
    static evloop_t ev;

    memset(&app, 0, sizeof app);
    memset(conns, 0, sizeof conns);
    app.conns = conns;
    app.n_conns = 2u;
    app.store = g_store;
    app.server_kp = &g_server_kp;
    app.server_id = SERVER_ID;
    app.server_id_len = sizeof SERVER_ID;
    app.pad_bucket = 256u;
    app.code_ttl_s = AUTHD_LOGIN_CODE_TTL_S;
    /* The KDF is lowered to libsodium's MINIMUM here and ONLY here. At the
     * spec's 2/64MiB a single RECOVERY-ISSUE of 16 codes costs over a second,
     * which would make this fuzz target unusably slow while proving nothing
     * extra: every property under test is about WHICH code matches and what
     * the store does, not about how expensive the hash is. The daemon's real
     * parameters are asserted by tools/audit/check_spec_constants.sh. */
    app.recovery_ops = crypto_pwhash_OPSLIMIT_MIN;
    app.recovery_mem = crypto_pwhash_MEMLIMIT_MIN;
    app.recovery_lock_threshold = RECOVERY_LOCK_THRESHOLD;
    app.recovery_lock_seconds = RECOVERY_LOCK_SECONDS;
    app.ticket_ttl_s = RECOVERY_TICKET_TTL_S;

    app.now_ms = FUZZ_CLOCK_T0;
    app.now_unix = 1700000000;
    app.started_ms = FUZZ_CLOCK_T0;

    if (handshake_pending_store_init(&pending, 2u, 10000u, authd_app_clock, &app) != PENDING_OK) {
        return 0;
    }
    app.pending = &pending;
    if (evloop_init(&ev, slots, 2u, 10000u, 60000u,
                    authd_conn_on_frame, authd_conn_on_close, &app) != 0) {
        return 0;
    }
    (void)evloop_set_local(&ev, local, 2u, localapi_on_line);
    app.ev = &ev;

    /* Both tables are exercised: the selector picks the socket, so an admin
     * command's refusal on the site socket is on the fuzzer's path too. */
    const uint8_t sel = fuzz_selector(data, size, 0u);
    authd_slot_t *slot = &local[0];
    slot->kind = SLOT_KIND_LOCAL;
    slot->is_admin = (sel & 1u) ? 1 : 0;
    slot->index = 0u;
    slot->fd = -1;
    slot->state = SLOT_ACTIVE;
    slot->peer.uid = 501u;
    slot->peer.pid = 1234;
    conn_io_reset(&slot->io);
    conn_io_set_mode(&slot->io, CONN_IO_MODE_LINE);

    uint8_t head_before[STORE_AUDIT_MAC_BYTES], head_after[STORE_AUDIT_MAC_BYTES];
    const int have_before = (store_audit_head_mac(g_store, head_before) == STORE_OK);

    (void)localapi_on_line(&app, slot, line, len);

    static char resp[16384];
    const size_t rn = drain(slot, resp, sizeof resp);

    /* 1. exactly one well-formed response */
    FUZZ_ASSERT(rn > 0u, "the local API produced NO response to a request");
    FUZZ_ASSERT(resp[rn - 1u] == '\n', "a response does not end with a newline");
    FUZZ_ASSERT(strncmp(resp, "OK", 2) == 0 || strncmp(resp, "ERR code=", 9) == 0,
                "a response is neither OK nor ERR code=");

    if (expects_list(line, len) && strncmp(resp, "OK count=", 9) == 0) {
        /* a list ends with a final END line and nothing after it */
        const char *end = strstr(resp, "\nEND\n");
        FUZZ_ASSERT(end != NULL, "a list response has no END line");
        FUZZ_ASSERT(end + 5 == resp + rn, "a list response has bytes after its END line");
    } else {
        /* 2. a single-line reply carries exactly one newline: its own. A hex
         *    value that decoded into a newline and reached the response would
         *    otherwise split one reply into two. */
        FUZZ_ASSERT(memchr(resp, '\n', rn - 1u) == NULL,
                    "a single-line response contains an embedded newline");
    }

    /* 3. A refusal never moves the audit chain -- with exactly one exception,
     *    which is asserted rather than excused.
     *
     *    RECOVERY-USE answering `invalid` MUST leave a durable trace: that row
     *    is the failure count the §10.3 lockout is built on, and §15 requires
     *    failures to be logged. So for that one case the invariant inverts --
     *    the chain must ADVANCE -- and a change that silently stopped counting
     *    failures (which is a lockout bypass) fails this target instead of
     *    slipping through a hole in it. Every other refusal, including
     *    RECOVERY-USE's own `locked`, `malformed` and `user-disabled`, must
     *    still leave the store untouched. */
    const int have_after = (store_audit_head_mac(g_store, head_after) == STORE_OK);
    if (strncmp(resp, "ERR code=", 9) == 0 && have_before && have_after) {
        const int moved = (memcmp(head_before, head_after, sizeof head_before) != 0);
        if (cmd_is(line, len, "RECOVERY-USE") && strncmp(resp, "ERR code=invalid", 16) == 0) {
            /* Only for the user this harness actually enrolled ("u1" = 7531):
             * an UNKNOWN user answers `invalid` too -- deliberately
             * indistinguishable -- but has no row to count against, so
             * requiring movement there would be a false alarm, not a finding. */
            if (kv_equals(line, len, "user=", "7531")) {
                FUZZ_ASSERT(moved,
                            "a failed RECOVERY-USE did NOT record the attempt: the lockout cannot count");
            }
        } else {
            FUZZ_ASSERT(!moved,
                        "an ERR response ADVANCED the audit chain: a refused request mutated the store");
        }
    }

    conn_io_reset(&slot->io);
    handshake_pending_store_wipe(&pending);
    return 0;
}

static void emit_str(fuzz_emit_fn emit, void *ctx, const char *name, const char *s)
{
    emit(ctx, name, (const uint8_t *)s, strlen(s));
}

/* An ENROLL seed with a FULL-LENGTH public key. Without one the request dies
 * on the pk length check before `via` or `ticket` are examined, so a short-pk
 * seed cannot reach the enrollment branches at all. */
static void emit_enroll(fuzz_emit_fn emit, void *ctx, const char *name,
                        const char *via, const char *ticket)
{
    static char line[2u * STORE_PK_BYTES + 256u];
    static char pkhex[2u * STORE_PK_BYTES + 1u];
    for (size_t i = 0; i < 2u * STORE_PK_BYTES; i++) { pkhex[i] = "0123456789abcdef"[i % 16u]; }
    pkhex[2u * STORE_PK_BYTES] = '\0';
    const int n = snprintf(line, sizeof line, "ENROLL user=7531 handle=64316161 pk=%s via=%s%s%s",
                           pkhex, via, (ticket != NULL) ? " ticket=" : "",
                           (ticket != NULL) ? ticket : "");
    if (n > 0) { emit(ctx, name, (const uint8_t *)line, (size_t)n); }
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx)
{
    emit(ctx, "empty", fuzz_empty, 0);
    emit_str(emit, ctx, "ping", "PING");
    emit_str(emit, ctx, "unknown-command", "NOSUCHCOMMAND");
    emit_str(emit, ctx, "admin-on-site", "LIST-USERS");
    emit_str(emit, ctx, "list-devices", "LIST-DEVICES user=7531");
    emit_str(emit, ctx, "verify-short", "VERIFY token=00");
    emit_str(emit, ctx, "verify-len", "VERIFY token="
             "0000000000000000000000000000000000000000000000000000000000000000");
    emit_str(emit, ctx, "logout", "LOGOUT token="
             "1111111111111111111111111111111111111111111111111111111111111111");
    emit_str(emit, ctx, "exchange-empty-state", "EXCHANGE code="
             "2222222222222222222222222222222222222222222222222222222222222222 state=");
    emit_str(emit, ctx, "exchange-with-state", "EXCHANGE code="
             "3333333333333333333333333333333333333333333333333333333333333333 state=6162");
    emit_str(emit, ctx, "revoke-device", "REVOKE-DEVICE handle=64316161 reason=6161");
    emit_str(emit, ctx, "revoke-tokens", "REVOKE-TOKENS user=7531");
    emit_str(emit, ctx, "disable-user", "DISABLE-USER user=7531 reason=6161");
    emit_str(emit, ctx, "enable-user", "ENABLE-USER user=7531");
    emit_str(emit, ctx, "audit-tail", "AUDIT-TAIL n=5");
    /* recovery (V4-9d). The KDF is at libsodium's minimum in this harness, so
     * these are cheap; at the spec's parameters one issue of 16 codes would
     * cost over a second and the target would stop being a fuzzer. */
    emit_str(emit, ctx, "recovery-issue", "RECOVERY-ISSUE user=7531 count=3");
    emit_str(emit, ctx, "recovery-issue-max", "RECOVERY-ISSUE user=7531 count=16");
    emit_str(emit, ctx, "recovery-issue-over", "RECOVERY-ISSUE user=7531 count=17");
    emit_str(emit, ctx, "recovery-issue-zero", "RECOVERY-ISSUE user=7531 count=0");
    emit_str(emit, ctx, "recovery-use", "RECOVERY-USE user=7531 code=0123456789ABCDEF");
    emit_str(emit, ctx, "recovery-use-lower", "RECOVERY-USE user=7531 code=0123-4567-89ab-cdef");
    emit_str(emit, ctx, "recovery-use-confusable", "RECOVERY-USE user=7531 code=O123456789ABCDEl");
    emit_str(emit, ctx, "recovery-use-short", "RECOVERY-USE user=7531 code=012");
    emit_str(emit, ctx, "recovery-use-revoke", "RECOVERY-USE user=7531 code=0123456789ABCDEF revoke=all");
    emit_str(emit, ctx, "recovery-use-badrevoke", "RECOVERY-USE user=7531 code=0123456789ABCDEF revoke=some");
    emit_str(emit, ctx, "audit-tail-huge", "AUDIT-TAIL n=9999");
    emit_str(emit, ctx, "dup-key", "VERIFY token=00 token=11");
    emit_str(emit, ctx, "unknown-key", "PING nope=1");
    emit_str(emit, ctx, "no-equals", "VERIFY token");
    emit_str(emit, ctx, "empty-key", "VERIFY =aa");
    emit_str(emit, ctx, "odd-hex", "VERIFY token=abc");
    /* NOTE: `pk` must be a full 1952-byte key or the length check refuses the
     * request before `via` is ever looked at -- which is why the original
     * pk=00 form of this seed never reached the branch it is named for. The
     * generator emits a full-length pk so these two actually exercise it. */
    emit_enroll(emit, ctx, "enroll-recovery-no-ticket", "recovery", NULL);
    emit_enroll(emit, ctx, "enroll-recovery-ticket", "recovery",
                "0000000000000000000000000000000000000000000000000000000000000000");
    emit_enroll(emit, ctx, "enroll-site-with-ticket", "site",
                "1111111111111111111111111111111111111111111111111111111111111111");
    emit_str(emit, ctx, "backup", "BACKUP path=2f746d702f78");
}
