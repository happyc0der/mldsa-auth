/* V4-8a: the daemon's configuration parser (apps/authd/authd_config.c).
 *
 * The config file is attacker-adjacent in the way that matters: it is a file
 * on disk that an operator edits, parsed by new code before the daemon drops
 * into its event loop, and every value in it becomes a bound the daemon then
 * trusts (buffer sizes, slot counts, timeouts, a pad bucket handed to
 * session_init). A parser that accepts an out-of-range value moves a security
 * decision from review time to run time.
 *
 * THE ORACLE IS NOT A RE-IMPLEMENTATION. For a line-based parser, writing a
 * second line-based parser and diffing them produces two copies of the same
 * misunderstanding -- the "independent model" would not be independent. So the
 * oracle here is the parser's own CONTRACT, checked against its output:
 *
 *   on OK   -- every documented bound in authd_config.h holds for the struct
 *              that came back: strings NUL-terminated inside their capacity
 *              and printable, server_id length in 1..64, max_slots and both
 *              timeouts inside their ranges, pad_bucket one of the six the
 *              record layer accepts, and at least one listener configured.
 *   on FAIL -- the struct is exactly the defaults (the documented "left in the
 *              defaults state" contract), so no half-applied config escapes.
 *   always  -- parsing is deterministic and reads nothing outside the input.
 *
 * That catches the defects that matter (a bound not enforced, a string left
 * unterminated, a partial config surviving an error) without pretending to an
 * independence the shape of the problem does not allow. Non-vacuity is proven
 * the usual way: breaking a bound check in authd_config.c makes this fire.
 */
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"
#include "authd_config.h"
#include "session.h"

const char *const fuzz_target_name = "authd_config";
const size_t fuzz_target_max_len = 4096;

int fuzz_target_command(int argc, char **argv) {
    (void)argc; (void)argv;
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    fuzz_common_init();
    return 0;
}

static int printable_cstr(const char *s, size_t cap) {
    size_t i = 0;
    for (; i < cap; i++) {
        if (s[i] == '\0') { break; }
        if ((unsigned char)s[i] < 0x20u || (unsigned char)s[i] > 0x7eu) { return 0; }
    }
    return i < cap;            /* a NUL was found inside the buffer */
}

static int bucket_ok(uint32_t b) {
    return b == 1u || b == 16u || b == 64u || b == 256u || b == 1024u || b == 4096u;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > fuzz_target_max_len) { return 0; }
    const uint8_t *in = fuzz_ptr(data, size);

    authd_config_t cfg;
    size_t line = 0;
    const authd_config_status_t st = authd_config_parse(in, size, &cfg, &line);

    /* determinism: the same bytes must give the same answer and the same struct */
    {
        authd_config_t cfg2;
        size_t line2 = 0;
        const authd_config_status_t st2 = authd_config_parse(in, size, &cfg2, &line2);
        FUZZ_ASSERT(st2 == st && line2 == line && memcmp(&cfg, &cfg2, sizeof cfg) == 0,
                    "authd_config_parse is not deterministic");
    }

    if (st == AUTHD_CFG_OK) {
        /* every documented bound, re-checked against the result */
        FUZZ_ASSERT(printable_cstr(cfg.store_path, sizeof cfg.store_path),
                    "store_path is not a printable NUL-terminated string");
        FUZZ_ASSERT(printable_cstr(cfg.key_path, sizeof cfg.key_path),
                    "key_path is not a printable NUL-terminated string");
        FUZZ_ASSERT(printable_cstr(cfg.listen_unix, sizeof cfg.listen_unix),
                    "listen_unix is not a printable NUL-terminated string");
        FUZZ_ASSERT(cfg.store_path[0] != '\0' && cfg.key_path[0] != '\0',
                    "a required path came back empty on OK");
        FUZZ_ASSERT(cfg.server_id_len >= 1u && cfg.server_id_len <= AUTHD_ID_MAX,
                    "server_id_len out of range on OK");
        for (size_t i = 0; i < cfg.server_id_len; i++) {
            FUZZ_ASSERT(cfg.server_id[i] >= 0x20u && cfg.server_id[i] <= 0x7eu,
                        "server_id contains a non-printable byte on OK");
        }
        FUZZ_ASSERT(cfg.max_slots >= AUTHD_SLOTS_MIN && cfg.max_slots <= AUTHD_SLOTS_MAX,
                    "max_slots out of range on OK");
        FUZZ_ASSERT(cfg.handshake_timeout_ms >= AUTHD_TIMEOUT_MS_MIN &&
                        cfg.handshake_timeout_ms <= AUTHD_TIMEOUT_MS_MAX,
                    "handshake_timeout_ms out of range on OK");
        FUZZ_ASSERT(cfg.idle_timeout_ms >= AUTHD_TIMEOUT_MS_MIN &&
                        cfg.idle_timeout_ms <= AUTHD_TIMEOUT_MS_MAX,
                    "idle_timeout_ms out of range on OK");
        FUZZ_ASSERT(bucket_ok(cfg.pad_bucket), "pad_bucket is not one of the six on OK");
        FUZZ_ASSERT(cfg.listen_port != 0u || cfg.listen_unix[0] != '\0',
                    "OK with no listener configured");
        /* V4-10b. The limiter's values are what stand between the decoy flow
         * and an unbounded signature cost (spec §7.3), so a parse that
         * accepted a zero would disable the defence rather than misconfigure
         * it -- and `proxy_protocol` or `proxy_uids` without the listener they
         * configure is a key that does nothing, which the parser refuses
         * rather than silently honours. */
        FUZZ_ASSERT(cfg.rate_per_min >= 1u && cfg.rate_per_min <= RATELIMIT_PER_MIN_MAX,
                    "rate_per_min out of range on OK");
        FUZZ_ASSERT(cfg.rate_burst >= 1u && cfg.rate_burst <= RATELIMIT_BURST_MAX,
                    "rate_burst out of range on OK");
        FUZZ_ASSERT(cfg.rate_global_per_sec >= 1u &&
                        cfg.rate_global_per_sec <= RATELIMIT_GLOBAL_MAX,
                    "rate_global_per_sec out of range on OK");
        FUZZ_ASSERT(cfg.max_conns_per_addr >= 1u &&
                        cfg.max_conns_per_addr <= RATELIMIT_MAX_CONNS_MAX,
                    "max_conns_per_addr out of range on OK");
        FUZZ_ASSERT(cfg.n_proxy_uids <= AUTHD_MAX_UIDS, "too many proxy_uids on OK");
        FUZZ_ASSERT((cfg.proxy_protocol_v2 == 0 && cfg.n_proxy_uids == 0u) ||
                        cfg.listen_unix[0] != '\0',
                    "OK with proxy settings but no proxy listener");
    } else {
        /* a failed parse must leave nothing half-applied */
        authd_config_t def;
        authd_config_defaults(&def);
        FUZZ_ASSERT(memcmp(&cfg, &def, sizeof cfg) == 0,
                    "a failed parse left a partially applied config");
    }
    return 0;
}

static void emit_str(fuzz_emit_fn emit, void *ctx, const char *name, const char *s) {
    emit(ctx, name, (const uint8_t *)s, strlen(s));
}

void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx) {
    emit(ctx, "empty", fuzz_empty, 0);
    emit_str(emit, ctx, "minimal-valid",
             "store_path = /var/lib/mldsa-authd/store.sqlite3\n"
             "key_path = /var/lib/mldsa-authd/server.ek\n"
             "key_passphrase_file = /run/credentials/mldsa-authd/pass\n"
             "server_id = authd-server\n"
             "listen_port = 8443\n");
    emit_str(emit, ctx, "full-valid",
             "# a comment\n"
             "store_path = /s\n"
             "key_path = /k\n"
             "key_passphrase_file = /p\n"
             "server_id = s1\n"
             "listen_unix = /run/mldsa-authd/ws.sock\n"
             "listen_port = 1\n"
             "max_slots = 4096\n"
             "handshake_timeout_ms = 100\n"
             "idle_timeout_ms = 600000\n"
             "pad_bucket = 4096\n");
    emit_str(emit, ctx, "proxy-v2-full",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n"
             "listen_unix = /run/p.sock\nproxy_protocol = v2\nproxy_uids = 33,1001\n"
             "rate_per_min = 5\nrate_burst = 10\nrate_global_per_sec = 50\n"
             "max_conns_per_addr = 8\n");
    emit_str(emit, ctx, "proxy-without-listener",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n"
             "listen_port = 1\nproxy_protocol = v2\n");
    emit_str(emit, ctx, "proxy-protocol-bogus",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n"
             "listen_unix = /run/p.sock\nproxy_protocol = yes\n");
    emit_str(emit, ctx, "rate-zero",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n"
             "listen_port = 1\nrate_per_min = 0\n");
    emit_str(emit, ctx, "proxy-uids-empty",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n"
             "listen_unix = /run/p.sock\nproxy_uids = \n");
    emit_str(emit, ctx, "missing-required", "listen_port = 1\n");
    emit_str(emit, ctx, "no-listener",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n");
    emit_str(emit, ctx, "unknown-key",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 1\nnope = 1\n");
    emit_str(emit, ctx, "duplicate-key",
             "store_path = /s\nstore_path = /t\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 1\n");
    emit_str(emit, ctx, "bucket-32",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 1\npad_bucket = 32\n");
    emit_str(emit, ctx, "slots-0",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 1\nmax_slots = 0\n");
    emit_str(emit, ctx, "slots-4097",
             "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 1\nmax_slots = 4097\n");
    emit_str(emit, ctx, "port-65536",
             "store_path = /s\nkey_path = /k\nserver_id = s\nlisten_port = 65536\n");
    emit_str(emit, ctx, "no-equals", "store_path\n");
    emit_str(emit, ctx, "empty-key", " = /s\n");
    emit_str(emit, ctx, "no-trailing-newline",
             "store_path = /s\nkey_path = /k\nserver_id = s\nlisten_port = 1");
    emit_str(emit, ctx, "overflow-number",
             "store_path = /s\nkey_path = /k\nserver_id = s\nlisten_port = 99999999999\n");
}
