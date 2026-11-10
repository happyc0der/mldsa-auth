#include "sdnotify.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

int authd_sd_notify(const char *msg)
{
    const char *p = getenv("NOTIFY_SOCKET");
    if (p == NULL || p[0] == '\0') {
        return 0;
    }
    if (msg == NULL || (p[0] != '/' && p[0] != '@')) {
        return -1;
    }
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    const size_t n = strlen(p);
    if (n >= sizeof a.sun_path) {
        return -1;
    }
    memcpy(a.sun_path, p, n);
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
    if (p[0] == '@') {
        a.sun_path[0] = '\0';                  /* the abstract namespace */
    } else {
        alen = (socklen_t)(alen + 1u);         /* and its NUL */
    }
    const int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    const size_t ml = strlen(msg);
    const ssize_t w = sendto(fd, msg, ml, 0, (const struct sockaddr *)&a, alen);
    (void)close(fd);
    return (w == (ssize_t)ml) ? 1 : -1;
}
