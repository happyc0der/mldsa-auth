/* See stdfds.h. */
#include "stdfds.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int stdfds_ensure_open(void)
{
    int mask = 0;
    for (int fd = 0; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
            continue;                        /* open */
        }
        /* open() returns the LOWEST free descriptor. 0..fd-1 are open (the
         * loop has just seen to that), so it is fd -- and if it is not,
         * something is wrong enough to stop. */
        const int got = open("/dev/null", (fd == 0) ? O_RDONLY : O_WRONLY);
        if (got != fd) {
            if (got >= 0) { (void)close(got); }
            return -1;
        }
        mask |= 1 << fd;
    }
    return mask;
}
