#include "ratelimit.h"

#include <string.h>

#include <sodium.h>

const char *ratelimit_verdict_name(ratelimit_verdict_t v)
{
    switch (v) {
    case RATELIMIT_ALLOW:        return "allow";
    case RATELIMIT_DENY_CONNS:   return "too-many-connections";
    case RATELIMIT_DENY_ADDR:    return "rate-limited";
    case RATELIMIT_DENY_GLOBAL:  return "global-rate-limited";
    case RATELIMIT_DENY_TABLE:   return "limiter-table-full";
    case RATELIMIT_DENY_NO_ADDR: return "no-client-address";
    default:                     return "unknown";
    }
}

static uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi)
{
    if (v < lo) { return lo; }
    if (v > hi) { return hi; }
    return v;
}

uint64_t ratelimit_entries_wanted(uint32_t per_min, uint32_t global_per_sec, uint32_t max_slots)
{
    const uint64_t pm = (uint64_t)clamp_u32(per_min, 1u, RATELIMIT_PER_MIN_MAX);
    const uint64_t gl = (uint64_t)clamp_u32(global_per_sec, 1u, RATELIMIT_GLOBAL_MAX);
    const uint64_t held = (gl * 60u + pm - 1u) / pm;       /* rounded up */
    uint64_t want = held + (held + 3u) / 4u;               /* a quarter's headroom */
    /* F544 (V4-315): AND an entry for every slot, not the larger of the two.
     * An address with a connection open keeps its entry for as long as the
     * connection lasts, whatever its bucket holds, so the open connections
     * and the refilling buckets are in the table together. */
    want += (uint64_t)max_slots;
    if (want < (uint64_t)RATELIMIT_ENTRIES) {
        want = (uint64_t)RATELIMIT_ENTRIES;
    }
    return want;
}

size_t ratelimit_entries_for(uint32_t per_min, uint32_t global_per_sec, uint32_t max_slots)
{
    const uint64_t want = ratelimit_entries_wanted(per_min, global_per_sec, max_slots);
    return (want > (uint64_t)RATELIMIT_ENTRIES_MAX) ? (size_t)RATELIMIT_ENTRIES_MAX : (size_t)want;
}

void ratelimit_init(ratelimit_t *r, ratelimit_entry_t *table, size_t n_entries,
                    uint32_t per_min, uint32_t burst,
                    uint32_t global_per_sec, uint32_t max_conns, uint64_t now_ms)
{
    if (r == NULL) {
        return;
    }
    memset(r, 0, sizeof *r);
    if (table != NULL && n_entries > 0u) {
        memset(table, 0, n_entries * sizeof *table);
        r->e = table;
        r->n_entries = n_entries;
    }
    crypto_shorthash_keygen(r->hash_key);
    r->per_min        = clamp_u32(per_min, 1u, RATELIMIT_PER_MIN_MAX);
    r->burst          = clamp_u32(burst, 1u, RATELIMIT_BURST_MAX);
    r->global_per_sec = clamp_u32(global_per_sec, 1u, RATELIMIT_GLOBAL_MAX);
    r->max_conns      = clamp_u32(max_conns, 1u, RATELIMIT_MAX_CONNS_MAX);
    /* Full at start-up: the first caller after a restart is not the attacker
     * the limiter exists for, and refusing them would make every deploy look
     * like an outage. */
    r->global_tokens_milli = (uint64_t)r->global_per_sec * 1000u;
    r->global_last_ms = now_ms;
}

/* ------------------------------------------------------------- the buckets */

/* Adds whatever `elapsed` milliseconds have earned, capped.
 *
 * Integer arithmetic throughout, in THOUSANDTHS of a token, because a limiter
 * whose refill depends on floating point is a limiter whose boundary cannot be
 * asserted exactly.
 *
 * The rate is per_ms_num milli-tokens every per_ms_den milliseconds. Reduced
 * by their common divisor that is `step_tok` milli-tokens every `step_ms`
 * milliseconds, both whole, and the bucket is credited in whole steps only:
 * what is added and how far `*last_ms` moves are then exactly the same
 * amount of time, at every rate, and the part of a step that has not yet
 * elapsed stays behind `*last_ms` for the next call.
 *
 * F310: it used to add floor(elapsed * num / den) and advance the clock by
 * floor(add * den / num). At a rate that is not a whole number of
 * milli-tokens a millisecond (100 a minute is 5 every 3 ms) one elapsed
 * millisecond added 1 and advanced the clock by 0, so every further call in
 * that millisecond added 1 again: an address asking ten times a millisecond
 * was admitted 729 times in a minute at a limit of 100. The shipped 5 a
 * minute, and every rate that divides 60000, was exact. */
static uint64_t gcd_u64(uint64_t a, uint64_t b)
{
    while (b != 0u) {
        const uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static void refill(uint64_t *tokens_milli, uint64_t *last_ms, uint64_t now_ms,
                   uint64_t per_ms_num, uint64_t per_ms_den, uint64_t cap_milli)
{
    if (now_ms <= *last_ms || per_ms_num == 0u || per_ms_den == 0u) {
        return;                       /* a clock that did not advance owes nothing */
    }
    const uint64_t g = gcd_u64(per_ms_num, per_ms_den);
    const uint64_t step_tok = per_ms_num / g;
    const uint64_t step_ms = per_ms_den / g;
    const uint64_t steps = (now_ms - *last_ms) / step_ms;
    if (steps == 0u) {
        return;                       /* keep last_ms: the part of a step is not lost */
    }
    *tokens_milli += steps * step_tok;
    if (*tokens_milli > cap_milli) {
        *tokens_milli = cap_milli;
    }
    *last_ms += steps * step_ms;
}

/* per_min tokens a minute is (per_min * 1000) milli-tokens per 60000 ms, i.e.
 * per_min per 60 ms -- the form that keeps the division exact for the rates an
 * operator actually sets. */
static void refill_addr(const ratelimit_t *r, ratelimit_entry_t *e, uint64_t now_ms)
{
    refill(&e->tokens_milli, &e->last_ms, now_ms,
           (uint64_t)r->per_min, 60u, (uint64_t)r->burst * 1000u);
}

static void refill_global(ratelimit_t *r, uint64_t now_ms)
{
    /* global_per_sec tokens a second is global_per_sec milli-tokens per ms. */
    refill(&r->global_tokens_milli, &r->global_last_ms, now_ms,
           (uint64_t)r->global_per_sec, 1u, (uint64_t)r->global_per_sec * 1000u);
}

/* -------------------------------------------------------------- the table */

static size_t bucket_of(const ratelimit_t *r, const uint8_t *key, size_t key_len)
{
    uint8_t h[crypto_shorthash_BYTES];
    crypto_shorthash(h, key, key_len, r->hash_key);
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof h; i++) {
        v = (v << 8) | (uint64_t)h[i];
    }
    return (size_t)(v % (uint64_t)r->n_entries);   /* callers have checked n_entries != 0 */
}

static int same_key(const ratelimit_entry_t *e, const uint8_t *key, size_t key_len)
{
    return e->key_len == key_len && memcmp(e->key, key, key_len) == 0;
}

/* An entry carries no information once its bucket has refilled to the brim and
 * nothing is connected: it is then indistinguishable from an address that has
 * never been seen, so reclaiming it forgets nothing. This is the whole sweep --
 * there is no expiry timer, because "full and idle" IS the expiry condition. */
static int reclaimable(const ratelimit_t *r, const ratelimit_entry_t *e, uint64_t now_ms)
{
    if (e->key_len == 0u) {
        return 1;
    }
    if (e->conns != 0u) {
        return 0;
    }
    ratelimit_entry_t tmp = *e;
    refill_addr(r, &tmp, now_ms);
    return tmp.tokens_milli >= (uint64_t)r->burst * 1000u;
}

/* Finds `key`, or r->n_entries (which is also the answer with no table). Probing stops at the first genuinely free
 * entry, which is where an insert would have put it. An INDEX rather than a
 * pointer so the const and the mutating callers share one implementation
 * instead of one of them casting the qualifier away. */
static size_t find_idx(const ratelimit_t *r, const uint8_t *key, size_t key_len)
{
    if (r->n_entries == 0u) {
        return 0u;                    /* == r->n_entries: not found */
    }
    const size_t b = bucket_of(r, key, key_len);
    for (size_t n = 0; n < r->n_entries; n++) {
        const size_t i = (b + n) % r->n_entries;
        const ratelimit_entry_t *e = &r->e[i];
        if (e->key_len == 0u) {
            return r->n_entries;
        }
        if (same_key(e, key, key_len)) {
            return i;
        }
    }
    return r->n_entries;
}

/* Finds `key` or makes room for it. NULL means the table is full of entries
 * that are all still saying something -- at which point the connection is
 * REFUSED rather than some other address's history being thrown away. */
static ratelimit_entry_t *find_or_add(ratelimit_t *r, const uint8_t *key, size_t key_len,
                                      uint64_t now_ms)
{
    const size_t at = find_idx(r, key, key_len);
    if (at != r->n_entries) {
        return &r->e[at];
    }
    if (r->n_entries == 0u) {
        return NULL;
    }
    size_t b = bucket_of(r, key, key_len);
    for (size_t n = 0; n < r->n_entries; n++) {
        ratelimit_entry_t *c = &r->e[(b + n) % r->n_entries];
        if (reclaimable(r, c, now_ms)) {
            memset(c, 0, sizeof *c);
            memcpy(c->key, key, key_len);
            c->key_len = key_len;
            c->tokens_milli = (uint64_t)r->burst * 1000u;   /* a new address starts full */
            c->last_ms = now_ms;
            return c;
        }
    }
    return NULL;
}

/* --------------------------------------------------------------- the gate */

ratelimit_verdict_t ratelimit_admit(ratelimit_t *r, const authd_addr_t *addr, uint64_t now_ms)
{
    if (r == NULL) {
        return RATELIMIT_DENY_NO_ADDR;
    }
    uint8_t key[16];
    const size_t key_len = authd_addr_key(addr, key);
    if (key_len == 0u) {
        /* Req 12: a connection whose client address is missing or unverifiable
         * is not served. The limiter says so rather than silently keying on a
         * constant, which would pool every addressless connection into one
         * bucket and call that rate limiting. */
        return RATELIMIT_DENY_NO_ADDR;
    }

    ratelimit_entry_t *e = find_or_add(r, key, key_len, now_ms);
    if (e == NULL) {
        r->denied_table++;
        return RATELIMIT_DENY_TABLE;
    }

    /* 1. concurrency, first because it is about a resource already held and
     *    because a connection refused for it has not attempted a handshake and
     *    should not be charged a token for one. */
    if (e->conns >= r->max_conns) {
        r->denied_conns++;
        return RATELIMIT_DENY_CONNS;
    }
    /* 2. this address's bucket */
    refill_addr(r, e, now_ms);
    if (e->tokens_milli < 1000u) {
        r->denied_addr++;
        return RATELIMIT_DENY_ADDR;
    }
    /* 3. the whole-daemon bucket, which is what bounds the damage when the
     *    proxy is lying about addresses or when many addresses are genuine. */
    refill_global(r, now_ms);
    if (r->global_tokens_milli < 1000u) {
        r->denied_global++;
        return RATELIMIT_DENY_GLOBAL;
    }

    /* Nothing above this line changed anything, so every DENY is free of side
     * effects and this is the single commit point. */
    e->tokens_milli -= 1000u;
    r->global_tokens_milli -= 1000u;
    e->conns++;
    r->admitted++;
    return RATELIMIT_ALLOW;
}

void ratelimit_release(ratelimit_t *r, const authd_addr_t *addr)
{
    if (r == NULL) {
        return;
    }
    uint8_t key[16];
    const size_t key_len = authd_addr_key(addr, key);
    if (key_len == 0u) {
        return;
    }
    const size_t at = find_idx(r, key, key_len);
    if (at != r->n_entries && r->e[at].conns > 0u) {
        r->e[at].conns--;
    }
}

void ratelimit_refund(ratelimit_t *r, const authd_addr_t *addr, uint64_t now_ms)
{
    if (r == NULL) {
        return;
    }
    uint8_t key[16];
    const size_t key_len = authd_addr_key(addr, key);
    if (key_len == 0u) {
        return;
    }
    const size_t at = find_idx(r, key, key_len);
    if (at == r->n_entries) {
        return;
    }
    ratelimit_entry_t *e = &r->e[at];
    refill_addr(r, e, now_ms);
    const uint64_t cap = (uint64_t)r->burst * 1000u;
    e->tokens_milli = (e->tokens_milli + 1000u > cap) ? cap : e->tokens_milli + 1000u;
    r->refunded++;
}

uint64_t ratelimit_tokens_milli(const ratelimit_t *r, const authd_addr_t *addr)
{
    if (r == NULL) {
        return 0u;
    }
    uint8_t key[16];
    const size_t key_len = authd_addr_key(addr, key);
    if (key_len == 0u) {
        return 0u;
    }
    const size_t at = find_idx(r, key, key_len);
    return (at != r->n_entries) ? r->e[at].tokens_milli : 0u;
}

uint32_t ratelimit_conns(const ratelimit_t *r, const authd_addr_t *addr)
{
    if (r == NULL) {
        return 0u;
    }
    uint8_t key[16];
    const size_t key_len = authd_addr_key(addr, key);
    if (key_len == 0u) {
        return 0u;
    }
    const size_t at = find_idx(r, key, key_len);
    return (at != r->n_entries) ? r->e[at].conns : 0u;
}
