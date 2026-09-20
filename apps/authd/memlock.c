#include "memlock.h"

#include <stdint.h>

#include <sys/resource.h>
#include <sys/time.h>

const char *memlock_status_name(memlock_status_t st)
{
    switch (st) {
    case MEMLOCK_OK:        return "ok";
    case MEMLOCK_UNLIMITED: return "unlimited";
    case MEMLOCK_LOW:       return "below-requirement";
    case MEMLOCK_UNKNOWN:   return "unknown";
    default:                return "unknown";
    }
}

authd_log_level_t memlock_log_level(memlock_status_t st)
{
    /* Only LOW is a problem. UNKNOWN is not: a platform without the limit has
     * nothing to misconfigure, and warning about it would train operators to
     * ignore the line that matters. */
    return (st == MEMLOCK_LOW) ? AUTHD_LOG_WARN : AUTHD_LOG_INFO;
}

uint64_t memlock_required_bytes(uint32_t max_slots)
{
    /* 4 KiB x 10 x max_slots (V4-2 S1). Computed in 64 bits because the
     * product overflows 32 at the configured ceiling: 4096 * 10 * 4096 is
     * 167,772,160, which fits -- but a future ceiling need not, and a limit
     * that wrapped would read as "plenty". */
    return (uint64_t)MEMLOCK_PAGE_BYTES * (uint64_t)MEMLOCK_BLOCKS_PER_SLOT *
           (uint64_t)max_slots;
}

memlock_status_t memlock_check(uint32_t max_slots, uint64_t *limit_out, uint64_t *need_out)
{
    const uint64_t need = memlock_required_bytes(max_slots);
    if (need_out != NULL) {
        *need_out = need;
    }
    if (limit_out != NULL) {
        *limit_out = 0u;
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        return MEMLOCK_UNKNOWN;
    }
    if (rl.rlim_cur == RLIM_INFINITY) {
        if (limit_out != NULL) {
            *limit_out = UINT64_MAX;
        }
        return MEMLOCK_UNLIMITED;
    }
    const uint64_t limit = (uint64_t)rl.rlim_cur;
    if (limit_out != NULL) {
        *limit_out = limit;
    }
    return (limit >= need) ? MEMLOCK_OK : MEMLOCK_LOW;
}
