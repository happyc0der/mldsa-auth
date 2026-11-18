#ifndef MLDSA_AUTHD_MEMLOCK_H
#define MLDSA_AUTHD_MEMLOCK_H

#include <stddef.h>
#include <stdint.h>

#include "authd_log.h"

/*
 * Does this process have enough locked memory to keep its secrets off disk?
 * (V4-11, spec mldsa-authd §16; audit finding F6.)
 *
 * THE HAZARD, measured rather than supposed. V4-2's S1 spike ran 1,000
 * concurrent `sodium_malloc(32)` allocations under a deliberately tight
 * `RLIMIT_MEMLOCK`:
 *
 *   RLIMIT_MEMLOCK   allocations succeeding   VmLck    outcome
 *   8 MiB            1000 / 1000              4000 KiB every block locked
 *   64 KiB           1000 / 1000              64 KiB   ~16 locked, 984 NOT
 *
 * Under the tight limit **every allocation still succeeds**. libsodium calls
 * mlock(), ignores its failure, and returns memory that looks identical to
 * locked memory. Nothing errors and nothing is logged, so the daemon's secret
 * keys, session keys and login codes quietly become swappable -- and the
 * operator's only symptom is the absence of one.
 *
 * That is why §16 calls `LimitMEMLOCK` "a correctness setting, not a tuning
 * knob", and why this check exists in the DAEMON rather than only in the
 * service unit: a unit file protects the operators who use the unit. This
 * protects the ones who do not.
 *
 * IT WARNS, IT DOES NOT REFUSE. Linux's usual 8 MiB default is already below
 * the need at the default `max_slots = 256`, so refusing would convert a
 * widespread misconfiguration into an outage -- and would stop every
 * development run and the end-to-end test besides. The loud line in the
 * journal is what makes a host that is not using the unit visible; the unit
 * is what fixes it.
 */

typedef enum {
    MEMLOCK_OK = 0,        /* the limit covers the derived need */
    MEMLOCK_UNLIMITED,     /* RLIM_INFINITY: nothing to check */
    MEMLOCK_LOW,           /* below the derived need -- secrets may be swappable */
    MEMLOCK_UNKNOWN        /* getrlimit failed, or the platform has no such limit */
} memlock_status_t;

const char *memlock_status_name(memlock_status_t st);

/* The bytes this daemon needs locked, from S1's measurement: about ten secure
 * allocations per in-flight handshake, each costing one PAGE of locked memory
 * (guard pages are mapped but not locked). mlock() works in whole pages, so
 * the page is the host's, read at run time (F403): 4 KiB on x86_64, but 16 KiB
 * or 64 KiB on some arm64 kernels, where a 4 KiB figure would understate the
 * need four- or sixteen-fold and the shortfall would be logged as "ok".
 * Measured on a 16 KiB host (V4-306): each sodium_malloc of 64, 2400 or 4032
 * bytes locks one 16 KiB data page.
 *
 * MEMLOCK_PAGE_BYTES is only the answer when the host will not say
 * (sysconf fails), and x86_64's figure the documents quote. */
#define MEMLOCK_PAGE_BYTES        4096u
#define MEMLOCK_BLOCKS_PER_SLOT     10u
/* The host's page size in bytes: sysconf(_SC_PAGESIZE), else 4096. */
uint64_t memlock_page_bytes(void);
/* page x 10 x max_slots, for a given page -- the formula on its own, so a
 * test can pin it from literals at every page size without such a host. */
uint64_t memlock_required_bytes_for(uint64_t page_bytes, uint32_t max_slots);
/* The need on THIS host: memlock_required_bytes_for(memlock_page_bytes(), n). */
uint64_t memlock_required_bytes(uint32_t max_slots);

/* Reads RLIMIT_MEMLOCK and compares it with the need for `max_slots`.
 * `*limit_out` receives the soft limit in bytes (UINT64_MAX for unlimited)
 * and `*need_out` the derived requirement; both may be NULL. Takes the slot
 * count rather than reading the config so a test can drive it directly. */
memlock_status_t memlock_check(uint32_t max_slots, uint64_t *limit_out, uint64_t *need_out);

/* The level the startup line is logged at: WARN for LOW, INFO for everything
 * else. A one-line function rather than a ternary at the call site because
 * "the insufficient case is loud" is a REQUIREMENT, and a requirement buried
 * in an expression inside main() has no oracle -- the ambient RLIMIT_MEMLOCK
 * differs by platform, so an end-to-end test could not pin which level came
 * out. Here a test names both answers directly. */
authd_log_level_t memlock_log_level(memlock_status_t st);

#endif /* MLDSA_AUTHD_MEMLOCK_H */
