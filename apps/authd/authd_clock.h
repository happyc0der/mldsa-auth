/* The daemon's wall clock, read so that a failed read admits nothing it
 * would not (V4-300, F515).
 *
 * time() returning -1 was used as the time: -1 is before every expiry, so an
 * expired token verified, an expired code exchanged, an expired ticket was
 * redeemed, and the sweep deleted nothing. A failed read now keeps the last
 * good wall time, advanced by the monotonic clock since it was read; with no
 * good read yet there is no time to keep, and the caller refuses to start. */
#ifndef MLDSA_AUTHD_CLOCK_H
#define MLDSA_AUTHD_CLOCK_H

#include <stdint.h>

/* `got` is what time() returned, as int64_t. Returns the wall time to use,
 * or -1 when there has never been a good read. */
static inline int64_t authd_wall_next(int64_t got, int64_t *last_unix, uint64_t *last_ms, uint64_t now_ms)
{
    if (got != -1) {
        *last_unix = got;
        *last_ms = now_ms;
        return got;
    }
    if (*last_unix <= 0) {
        return -1;
    }
    return *last_unix + (int64_t)((now_ms - *last_ms) / 1000u);
}

#endif /* MLDSA_AUTHD_CLOCK_H */
