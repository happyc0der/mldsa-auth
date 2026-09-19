#ifndef MLDSA_AUTHD_RATELIMIT_H
#define MLDSA_AUTHD_RATELIMIT_H

#include <stddef.h>
#include <stdint.h>

#include "proxy_v2.h"

/*
 * Transport rate limiting (V4-10b), debt-ledger item A4.
 *
 * WHY IT IS NEEDED, precisely. §7.3's uniform responder flow pins a decoy
 * public key for every identity that is not active and signs a real
 * ServerHello anyway, so that an unknown handle is indistinguishable from a
 * known one. The spec states the consequence in one sentence: "This costs one
 * signature per probe, which is the rate limiter's problem." Until this file
 * existed, nobody owned that problem -- one connection, one ML-DSA-65
 * signature, no ceiling.
 *
 * WHERE IT FIRES. As soon as the client's address is known, which is when the
 * PROXY v2 preamble completes -- strictly before the HTTP upgrade, and
 * therefore long before handshake_responder_create_server_hello(). A limiter
 * that acted on the ClientHello would already have paid for the thing it
 * exists to stop.
 *
 * ONE HANDSHAKE PER CONNECTION (V4-8b), so one token per connection is exactly
 * one token per probe. Admission is a single call that either takes a token AND
 * counts the connection, or does neither: a half-applied decision is not
 * representable.
 *
 * THE TABLE is fixed-capacity and allocates nothing, modelled on the library's
 * handshake_pending_store_t: bounded, swept on insert, and it REFUSES rather
 * than evicting a live entry -- eviction under pressure is how a limiter is
 * made to forget the address that is attacking it. Indexing is SipHash-2-4
 * (crypto_shorthash) under a key drawn once per process, so an attacker cannot
 * compute which addresses collide and steer them into one bucket.
 *
 * TIME IS AN ARGUMENT, never a syscall, for the reason the event loop makes it
 * one: a test can then prove a bucket is still empty one millisecond before its
 * refill and full one millisecond after.
 */

/* Entries. 1024 distinct addresses in flight is far beyond what a
 * single-threaded daemon with a 256-slot default pool can be serving, and the
 * table is deliberately larger than the pool so that a connection's bucket
 * survives the connection. */
#define RATELIMIT_ENTRIES 1024u

/* Bounds for the operator-set values. The spec fixes no numbers (§17 has no
 * row for them), so these are policy with a documented default, the
 * rotation_due_age_s precedent -- not invented protocol constants. */
#define RATELIMIT_PER_MIN_DEFAULT      5u
#define RATELIMIT_BURST_DEFAULT       10u
#define RATELIMIT_GLOBAL_PER_SEC_DEF  50u
#define RATELIMIT_MAX_CONNS_DEFAULT    8u
#define RATELIMIT_PER_MIN_MAX      10000u
#define RATELIMIT_BURST_MAX        10000u
#define RATELIMIT_GLOBAL_MAX       10000u
#define RATELIMIT_MAX_CONNS_MAX     4096u

typedef enum {
    RATELIMIT_ALLOW = 0,
    RATELIMIT_DENY_CONNS,    /* too many concurrent connections from this address */
    RATELIMIT_DENY_ADDR,     /* this address's token bucket is empty */
    RATELIMIT_DENY_GLOBAL,   /* the whole-daemon bucket is empty */
    RATELIMIT_DENY_TABLE,    /* no room to track another address */
    RATELIMIT_DENY_NO_ADDR   /* Req 12: no address, no service */
} ratelimit_verdict_t;

const char *ratelimit_verdict_name(ratelimit_verdict_t v);

typedef struct {
    uint8_t  key[16];
    size_t   key_len;        /* 0 = the entry is free */
    uint64_t tokens_milli;   /* 1000 milli-tokens = one admission */
    uint64_t last_ms;
    uint32_t conns;          /* connections currently open from this address */
} ratelimit_entry_t;

typedef struct {
    uint8_t  hash_key[16];   /* crypto_shorthash_KEYBYTES */
    uint32_t per_min;
    uint32_t burst;
    uint32_t global_per_sec;
    uint32_t max_conns;

    uint64_t global_tokens_milli;
    uint64_t global_last_ms;

    ratelimit_entry_t e[RATELIMIT_ENTRIES];

    /* observable, for the operator and for tests */
    uint64_t admitted;
    uint64_t denied_conns;
    uint64_t denied_addr;
    uint64_t denied_global;
    uint64_t denied_table;
} ratelimit_t;

/* Zeroes the table, draws a fresh SipHash key and starts every bucket FULL, so
 * a daemon that has just started does not refuse its first callers. Values
 * outside the documented bounds are clamped rather than rejected: the config
 * parser is the gate, and a limiter that failed to initialise would be worse
 * than one that is slightly stricter than asked. */
void ratelimit_init(ratelimit_t *r, uint32_t per_min, uint32_t burst,
                    uint32_t global_per_sec, uint32_t max_conns, uint64_t now_ms);

/* Admits one connection from `addr`, or says why not.
 *
 * On RATELIMIT_ALLOW a token has been taken from both buckets AND the
 * address's connection count has been incremented -- the caller owes exactly
 * one ratelimit_release(). On every DENY nothing has changed. */
ratelimit_verdict_t ratelimit_admit(ratelimit_t *r, const authd_addr_t *addr, uint64_t now_ms);

/* Gives back the connection counted by a previous ALLOW. Tokens are NOT
 * returned: they paid for a handshake that happened. */
void ratelimit_release(ratelimit_t *r, const authd_addr_t *addr);

/* Connections currently counted for `addr`. For tests and for the log. */
uint32_t ratelimit_conns(const ratelimit_t *r, const authd_addr_t *addr);

#endif /* MLDSA_AUTHD_RATELIMIT_H */
