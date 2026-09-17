#ifndef MLDSA_AUTHD_LOG_H
#define MLDSA_AUTHD_LOG_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Structured logging for the daemon (V4-8a), spec mldsa-authd §15.
 *
 * The never-list is a property of the API, not of the caller's discipline:
 * there is no function here that takes a byte buffer, so key material, shared
 * secrets, session keys, signatures, nonces, raw frames, decrypted payloads,
 * tokens, login codes, recovery codes and tickets CANNOT be logged by calling
 * this interface correctly. The only ways in are a small integer, a slot
 * index, a status name from one of the status_name() functions, and an
 * identifier that has already been vetted as printable.
 *
 * There is deliberately no "debug" level that relaxes this, and no compile
 * flag that adds one. Spec §15: "There is no option to enable any of them."
 *
 * Format is one line per event, `key=value` pairs, which journald and a human
 * both read: `<level> event=<name> slot=<n> ...`.
 */

typedef enum {
    AUTHD_LOG_ERROR = 0,
    AUTHD_LOG_WARN,
    AUTHD_LOG_INFO
} authd_log_level_t;

/* Sets the destination (default stderr) and the minimum level. Passing NULL
 * leaves the stream unchanged. Used by the tests to capture output. */
void authd_log_init(FILE *dest, authd_log_level_t min_level);

/* An event with no subject. */
void authd_log_event(authd_log_level_t lvl, const char *event);

/* An event about one connection slot. */
void authd_log_slot(authd_log_level_t lvl, const char *event, size_t slot);

/* An event about one slot carrying a short status/reason word. `detail` must
 * be a literal or a status_name() result -- never peer-supplied bytes. */
void authd_log_slot_detail(authd_log_level_t lvl, const char *event, size_t slot, const char *detail);

/* An event about one slot and one identifier. `id` is escaped: any byte
 * outside printable ASCII is rendered as '.', and the whole field is truncated
 * to 64 bytes, so a hostile identifier can neither inject a newline into the
 * log nor smuggle binary through it. Identities ARE logged (they are not
 * secret); spec §15 and the V4-1 audit finding F14 note that for end users an
 * identifier is PII, which is why it is the only peer-influenced field here. */
void authd_log_slot_id(authd_log_level_t lvl, const char *event, size_t slot,
                       const uint8_t *id, size_t id_len);

/* A local-API request (spec 8: "every request is logged with the peer's uid
 * and pid"). `cmd` is the command NAME only -- never the line, never a value:
 * the values carry tokens and login codes, which the never-list forbids.
 * `detail` is a literal ("site"/"admin"/"malformed"). */
void authd_log_local(authd_log_level_t lvl, const char *event, const char *cmd,
                     unsigned long uid, long pid, const char *detail);

/* A 32-byte PUBLIC-KEY FINGERPRINT, hex-encoded.
 *
 * This is the one function here that takes a byte buffer, and it is
 * deliberately shaped so it cannot become a leak: the length is fixed at 32 by
 * the prototype, so it can encode a SHA-256 fingerprint and nothing else --
 * not a key, not a token, not a record. It exists because spec 15 REQUIRES
 * fingerprints on every enrollment and every Req 7 rejection; without it the
 * daemon could not log what the spec says it must. */
void authd_log_fp(authd_log_level_t lvl, const char *event, const uint8_t fp[32]);

/* An event with one unsigned number (a count, a port, a millisecond figure). */
void authd_log_num(authd_log_level_t lvl, const char *event, const char *key, uint64_t value);

#endif /* MLDSA_AUTHD_LOG_H */
