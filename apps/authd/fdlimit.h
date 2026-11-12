#ifndef MLDSA_AUTHD_FDLIMIT_H
#define MLDSA_AUTHD_FDLIMIT_H

#include <stdint.h>

#include "authd_log.h"

/*
 * Does this process have a file descriptor for every connection it has been
 * configured to hold? (V4-120, spec mldsa-authd §16; audit finding F205.)
 *
 * THE HAZARD, measured. With RLIMIT_NOFILE at 64 and the default
 * `max_slots = 256`, a daemon accepted 54 idle connections and then none: not
 * on the protocol listener, not on the site socket, not on the admin socket.
 * accept() failed with EMFILE, the loop returned, and nothing was logged. The
 * slot table says "refuse at capacity, loudly"; the descriptor table ran out
 * first and said nothing.
 *
 * systemd's default soft limit is 1024, so a unit without LimitNOFILE is
 * short from `max_slots` of about 950 up, and the configured ceiling is 4096.
 *
 * Every slot is one descriptor. The rest is counted generously: stdio, four
 * listeners, the store's database, journal and WAL files, the one descriptor
 * accept() needs before a full table can refuse the connection, and room for
 * what a library opens without saying.
 *
 * IT RAISES THE SOFT LIMIT ITSELF when the hard limit allows, which is what a
 * soft limit is for and what makes the usual case need no operator. When the
 * hard limit is short it WARNS and does not refuse, for memlock.h's reason:
 * the daemon serves correctly up to the limit, and refusing would turn a
 * misconfiguration that may never be reached into an outage on upgrade.
 */

typedef enum {
    FDLIMIT_OK = 0,     /* the soft limit already covers the need */
    FDLIMIT_RAISED,     /* it did not; the soft limit was raised to the need */
    FDLIMIT_LOW,        /* the hard limit is below the need (or the raise was refused) */
    FDLIMIT_UNKNOWN     /* getrlimit failed */
} fdlimit_status_t;

const char *fdlimit_status_name(fdlimit_status_t st);

#define FDLIMIT_OVERHEAD 32u
uint64_t fdlimit_required(uint32_t max_slots, uint32_t max_local_slots);

/* How many remote connections fit under `limit` descriptors once the local
 * slots and the overhead are set aside: `max_slots` when they all fit, never
 * less than 1. (V4-123, F207: a daemon that accepted until accept() failed
 * had no descriptor left for the admin socket, so the operator could not ask
 * it what was wrong. Held to this, the slot table refuses first.) */
uint32_t fdlimit_slot_cap(uint64_t limit, uint32_t max_slots, uint32_t max_local_slots);

/* Reads RLIMIT_NOFILE and, if the soft limit is below `need`, raises it to
 * exactly `need` when the hard limit allows. `*limit_out` receives the soft
 * limit in force afterwards (UINT64_MAX for unlimited); it may be NULL. */
fdlimit_status_t fdlimit_ensure(uint64_t need, uint64_t *limit_out);

/* WARN for LOW, INFO otherwise; a function for memlock_log_level's reason. */
authd_log_level_t fdlimit_log_level(fdlimit_status_t st);

#endif /* MLDSA_AUTHD_FDLIMIT_H */
