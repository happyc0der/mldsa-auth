#include "sdnotify.h"

#include <fcntl.h>
#include <stdint.h>
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

/* A decimal number and nothing else: no sign, no space, no overflow. */
static int parse_u64_strict(const char *s, uint64_t *out)
{
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    uint64_t v = 0;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        const uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u) {
            return -1;
        }
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

unsigned authd_sd_watchdog_period_ms(void)
{
    const char *sock = getenv("NOTIFY_SOCKET");
    if (sock == NULL || sock[0] == '\0') {
        return 0u;
    }
    uint64_t usec = 0;
    if (parse_u64_strict(getenv("WATCHDOG_USEC"), &usec) != 0 || usec == 0u) {
        return 0u;
    }
    const char *pid = getenv("WATCHDOG_PID");
    if (pid != NULL) {
        uint64_t want = 0;
        if (parse_u64_strict(pid, &want) != 0 || want != (uint64_t)getpid()) {
            return 0u;
        }
    }
    uint64_t ms = usec / 4000u;
    if (ms < 1u) {
        ms = 1u;
    }
    if (ms > AUTHD_SD_WATCHDOG_MAX_MS) {
        ms = AUTHD_SD_WATCHDOG_MAX_MS;
    }
    return (unsigned)ms;
}
