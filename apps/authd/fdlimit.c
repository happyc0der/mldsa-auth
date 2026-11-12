#include "fdlimit.h"

#include <stdint.h>

#include <sys/resource.h>
#include <sys/time.h>

const char *fdlimit_status_name(fdlimit_status_t st)
{
    switch (st) {
    case FDLIMIT_OK:      return "ok";
    case FDLIMIT_RAISED:  return "raised";
    case FDLIMIT_LOW:     return "below-requirement";
    case FDLIMIT_UNKNOWN: return "unknown";
    default:              return "unknown";
    }
}

authd_log_level_t fdlimit_log_level(fdlimit_status_t st)
{
    return (st == FDLIMIT_LOW) ? AUTHD_LOG_WARN : AUTHD_LOG_INFO;
}

uint64_t fdlimit_required(uint32_t max_slots, uint32_t max_local_slots)
{
    return (uint64_t)max_slots + (uint64_t)max_local_slots + (uint64_t)FDLIMIT_OVERHEAD;
}

uint32_t fdlimit_slot_cap(uint64_t limit, uint32_t max_slots, uint32_t max_local_slots)
{
    const uint64_t aside = (uint64_t)max_local_slots + (uint64_t)FDLIMIT_OVERHEAD;
    if (limit <= aside) {
        return 1u;
    }
    const uint64_t fit = limit - aside;
    return (fit >= (uint64_t)max_slots) ? max_slots : (uint32_t)fit;
}

fdlimit_status_t fdlimit_ensure(uint64_t need, uint64_t *limit_out)
{
    if (limit_out != NULL) {
        *limit_out = 0u;
    }
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return FDLIMIT_UNKNOWN;
    }
    if (rl.rlim_cur == RLIM_INFINITY) {
        if (limit_out != NULL) {
            *limit_out = UINT64_MAX;
        }
        return FDLIMIT_OK;
    }
    if (limit_out != NULL) {
        *limit_out = (uint64_t)rl.rlim_cur;
    }
    if ((uint64_t)rl.rlim_cur >= need) {
        return FDLIMIT_OK;
    }
    if (rl.rlim_max != RLIM_INFINITY && (uint64_t)rl.rlim_max < need) {
        return FDLIMIT_LOW;
    }
    /* Exactly the need, not the hard limit: macOS refuses a soft limit above
     * OPEN_MAX when the hard limit is unlimited, and the daemon has no use
     * for more than it derived. */
    rl.rlim_cur = (rlim_t)need;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return FDLIMIT_LOW;
    }
    if (limit_out != NULL) {
        *limit_out = need;
    }
    return FDLIMIT_RAISED;
}
