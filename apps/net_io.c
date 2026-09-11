#include "net_io.h"

#include "handshake.h" /* handshake_default_clock_ms: the library's fail-closed clock */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(MSG_NOSIGNAL)
#define NET_SEND_FLAGS MSG_NOSIGNAL
#else
#define NET_SEND_FLAGS 0
#endif

void net_conn_init(net_conn_t *c) {
    if (c != NULL) {
        memset(c, 0, sizeof(*c));
        c->fd = -1;
    }
}

uint64_t net_now_ms(void) {
    return handshake_default_clock_ms(NULL);
}

uint64_t net_deadline_in(uint64_t ms) {
    const uint64_t now = net_now_ms();
    if (now == UINT64_MAX) {
        return 0; /* unreadable clock: already expired */
    }
    if (ms >= (NET_NO_DEADLINE - 1u) - now) {
        return NET_NO_DEADLINE - 1u; /* saturate, but never "no deadline" */
    }
    return now + ms;
}

/* ---- socket configuration ------------------------------------------------ */

static int set_cloexec(int fd) {
    const int flags = fcntl(fd, F_GETFD);
    return (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) ? -1 : 0;
}

static int set_nonblock(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    return (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) ? -1 : 0;
}

/* Non-blocking, TCP_NODELAY, SIGPIPE suppressed (FD_CLOEXEC is set by the
 * caller immediately after the fd is created). */
static int configure_stream(int fd) {
    const int one = 1;
    if (set_nonblock(fd) != 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        return -1;
    }
#if defined(SO_NOSIGPIPE)
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        return -1;
    }
#endif
    return 0;
}

static void loopback_addr(struct sockaddr_in *sa, uint16_t port) {
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

/* ---- deadline-bounded waiting --------------------------------------------- */

/* poll() for `events`, bounded by the ABSOLUTE deadline (re-checked on every
 * iteration, so neither EINTR nor a trickling peer can extend it). */
static net_status_t wait_io(int fd, short events, uint64_t deadline_ms, net_stats_t *st) {
    for (;;) {
        int timeout = -1;
        if (deadline_ms != NET_NO_DEADLINE) {
            const uint64_t now = net_now_ms();
            if (now == UINT64_MAX || now >= deadline_ms) {
                return NET_TIMEOUT;
            }
            const uint64_t rem = deadline_ms - now;
            timeout = (rem > (uint64_t)INT_MAX) ? INT_MAX : (int)rem;
        }
        struct pollfd p;
        p.fd = fd;
        p.events = events;
        p.revents = 0;
        const int r = poll(&p, 1, timeout);
        if (r > 0) {
            return NET_OK; /* readiness, HUP or ERR: the next recv/send reports it */
        }
        if (r == 0) {
            continue; /* the loop head decides whether the deadline has passed */
        }
        if (errno == EINTR) {
            if (st != NULL) {
                st->eintr_retries++;
            }
            continue;
        }
        return NET_ERR_IO;
    }
}

/* ---- listen / accept / connect -------------------------------------------- */

net_status_t net_listen_loopback(uint16_t port, int backlog, int *listen_fd, uint16_t *bound_port) {
    if (listen_fd == NULL || bound_port == NULL || backlog < 1) {
        return NET_ERR_INVALID_ARG;
    }
    *listen_fd = -1;
    *bound_port = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NET_ERR_IO;
    }
    const int one = 1;
    struct sockaddr_in sa;
    loopback_addr(&sa, port);
    socklen_t sl = sizeof(sa);
    if (set_cloexec(fd) != 0 || set_nonblock(fd) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, backlog) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        net_close_fd(&fd);
        return NET_ERR_IO;
    }
    *listen_fd = fd;
    *bound_port = ntohs(sa.sin_port);
    return NET_OK;
}

net_status_t net_accept(int listen_fd, uint64_t deadline_ms, net_conn_t *out) {
    if (out == NULL || listen_fd < 0) {
        return NET_ERR_INVALID_ARG;
    }
    net_conn_init(out);
    for (;;) {
        const net_status_t w = wait_io(listen_fd, POLLIN, deadline_ms, &out->stats);
        if (w != NET_OK) {
            return w;
        }
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                out->stats.eintr_retries++;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                continue; /* the pending connection went away */
            }
            return NET_ERR_IO;
        }
        if (set_cloexec(fd) != 0 || configure_stream(fd) != 0) {
            net_close_fd(&fd);
            return NET_ERR_IO;
        }
        out->fd = fd;
        return NET_OK;
    }
}

net_status_t net_connect_loopback(uint16_t port, uint64_t deadline_ms, net_conn_t *out) {
    if (out == NULL || port == 0) {
        return NET_ERR_INVALID_ARG;
    }
    net_conn_init(out);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NET_ERR_IO;
    }
    if (set_cloexec(fd) != 0 || configure_stream(fd) != 0) {
        net_close_fd(&fd);
        return NET_ERR_IO;
    }
    struct sockaddr_in sa;
    loopback_addr(&sa, port);
    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errno == EINTR) {
            out->stats.eintr_retries++; /* the connect continues asynchronously */
        } else if (errno != EINPROGRESS) {
            net_close_fd(&fd);
            return NET_ERR_IO;
        }
        const net_status_t w = wait_io(fd, POLLOUT, deadline_ms, &out->stats);
        if (w != NET_OK) {
            net_close_fd(&fd);
            return w;
        }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            net_close_fd(&fd);
            return NET_ERR_IO;
        }
    }
    out->fd = fd;
    return NET_OK;
}

/* ---- exact reads and writes ---------------------------------------------- */

net_status_t net_read_exact(net_conn_t *c, uint8_t *buf, size_t n, uint64_t deadline_ms, size_t *got) {
    if (got != NULL) {
        *got = 0;
    }
    if (c == NULL || c->fd < 0 || got == NULL || (buf == NULL && n != 0)) {
        return NET_ERR_INVALID_ARG;
    }
    size_t off = 0;
    while (off < n) {
        const net_status_t w = wait_io(c->fd, POLLIN, deadline_ms, &c->stats);
        if (w != NET_OK) {
            *got = off;
            return w;
        }
        const ssize_t r = recv(c->fd, buf + off, n - off, 0);
        if (r > 0) {
            c->stats.recv_calls++;
            c->stats.bytes_rx += (uint64_t)r;
            off += (size_t)r;
            continue;
        }
        if (r == 0) {
            c->stats.recv_calls++;
            *got = off;
            return NET_EOF;
        }
        if (errno == EINTR) {
            c->stats.eintr_retries++;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        *got = off;
        return NET_ERR_IO;
    }
    *got = off;
    return NET_OK;
}

net_status_t net_write_all(net_conn_t *c, const uint8_t *buf, size_t n, uint64_t deadline_ms) {
    if (c == NULL || c->fd < 0 || (buf == NULL && n != 0)) {
        return NET_ERR_INVALID_ARG;
    }
    size_t off = 0;
    while (off < n) {
        const net_status_t w = wait_io(c->fd, POLLOUT, deadline_ms, &c->stats);
        if (w != NET_OK) {
            return w;
        }
        const ssize_t r = send(c->fd, buf + off, n - off, NET_SEND_FLAGS);
        if (r > 0) {
            c->stats.send_calls++;
            c->stats.bytes_tx += (uint64_t)r;
            off += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) {
            c->stats.eintr_retries++;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        return NET_ERR_IO; /* EPIPE, ECONNRESET, ... (SIGPIPE is suppressed) */
    }
    return NET_OK;
}

void net_close_fd(int *fd) {
    if (fd != NULL && *fd >= 0) {
        /* No retry on EINTR: the descriptor is released either way. */
        (void)close(*fd);
        *fd = -1;
    }
}

void net_close(net_conn_t *c) {
    if (c != NULL) {
        net_close_fd(&c->fd);
    }
}

const char *net_status_name(net_status_t st) {
    switch (st) {
    case NET_OK: return "ok";
    case NET_EOF: return "eof";
    case NET_TIMEOUT: return "timeout";
    case NET_ERR_IO: return "io-error";
    case NET_ERR_INVALID_ARG: return "invalid-arg";
    }
    return "unknown";
}
