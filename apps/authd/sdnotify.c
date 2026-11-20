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

/* F437: ONE socket, opened by the first notification that needs it (READY=1,
 * at start, when descriptors are plentiful) and kept. It was opened for each
 * datagram, so a system-wide shortage of file-table entries (ENFILE) lasting
 * the watchdog's 30 seconds stopped the pings of a loop that was still
 * turning, and systemd killed it -- where spec 16 says accepting resumes by
 * itself. Unconnected: each datagram names $NOTIFY_SOCKET afresh. One
 * descriptor, inside the reserve fdlimit keeps (F207). */
static int g_notify_fd = -1;

void authd_sd_notify_close(void)
{
    if (g_notify_fd >= 0) {
        (void)close(g_notify_fd);
        g_notify_fd = -1;
    }
}

int authd_sd_notify_usable(void)
{
    const char *p = getenv("NOTIFY_SOCKET");
    if (p == NULL || p[0] == '\0') {
        return 1;
    }
    return (p[0] == '/' || p[0] == '@') && strlen(p) < sizeof ((struct sockaddr_un *)0)->sun_path;
}

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
    if (g_notify_fd < 0) {
        g_notify_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (g_notify_fd < 0) {
            return -1;
        }
        (void)fcntl(g_notify_fd, F_SETFD, FD_CLOEXEC);
    }
    const size_t ml = strlen(msg);
    /* F685 (V4-344): never waits. The loop is one thread, and a notify
     * socket whose queue is full would have stopped it serving for as long
     * as systemd did not read. A ping that cannot be queued is a failed
     * ping: the caller says so or, for the watchdog, lets systemd act. */
    const ssize_t w = sendto(g_notify_fd, msg, ml, MSG_DONTWAIT, (const struct sockaddr *)&a, alen);
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

int authd_sd_watchdog_tick_at(authd_wd_tick_t *t, uint64_t now_ms)
{
    if (t == NULL || t->period_ms == 0u || now_ms - t->last_ms < (uint64_t)t->period_ms) {
        return 0;
    }
    (void)authd_sd_notify("WATCHDOG=1");
    t->last_ms = now_ms;
    return 1;
}

void authd_sd_watchdog_tick(void *ctx)
{
    authd_wd_tick_t *t = ctx;
    if (t != NULL && t->clock_ms != NULL) {
        (void)authd_sd_watchdog_tick_at(t, t->clock_ms());
    }
}

int authd_sd_watchdog_wait_ms(unsigned period_ms, uint64_t since_ms, int idle_ms)
{
    if (period_ms == 0u || idle_ms <= 0) {
        return idle_ms;
    }
    const uint64_t left = (since_ms < (uint64_t)period_ms) ? (uint64_t)period_ms - since_ms : 0u;
    return (left < (uint64_t)idle_ms) ? (int)left : idle_ms;
}
