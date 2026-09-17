#ifndef MLDSA_AUTH_APPS_NET_IO_H
#define MLDSA_AUTH_APPS_NET_IO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Loopback TCP socket primitives for the Step 6 reference apps (spec §6.5).
 *
 * Every connected socket is non-blocking, close-on-exec, TCP_NODELAY and
 * SIGPIPE-suppressed. Every blocking operation is poll() bounded by an
 * ABSOLUTE monotonic deadline: a peer that trickles bytes cannot extend it.
 * EINTR is retried everywhere (and counted); short reads and writes are
 * looped until the full count is done -- nothing assumes one recv() is one
 * protocol message.
 *
 * TCP provides NO authentication here: peer addresses are never used for
 * any trust decision. Identity comes only from the ML-DSA handshake.
 */

typedef struct {
    uint64_t recv_calls;    /* recv() calls that returned data or EOF */
    uint64_t send_calls;    /* send() calls that wrote data */
    uint64_t eintr_retries; /* poll/recv/send/accept/connect retried after EINTR */
    uint64_t bytes_rx;
    uint64_t bytes_tx;
} net_stats_t;

/* Owns fd; fd == -1 when closed. */
typedef struct {
    int fd;
    net_stats_t stats;
} net_conn_t;

typedef enum {
    NET_OK = 0,
    NET_EOF,     /* orderly TCP close by the peer (not an authenticated close) */
    NET_TIMEOUT, /* absolute deadline reached, or the clock could not be read */
    NET_ERR_IO,  /* includes ECONNRESET / EPIPE */
    NET_ERR_INVALID_ARG
} net_status_t;

#define NET_NO_DEADLINE UINT64_MAX

/* fd = -1, stats zeroed. */
void net_conn_init(net_conn_t *c);

/* Monotonic milliseconds (the library's fail-closed clock: UINT64_MAX if the
 * clock cannot be read, which every deadline check treats as expired). */
uint64_t net_now_ms(void);

/* Absolute deadline `ms` from now; saturating, never NET_NO_DEADLINE. An
 * unreadable clock yields 0 (already expired: fails closed). */
uint64_t net_deadline_in(uint64_t ms);

/* socket + FD_CLOEXEC + SO_REUSEADDR + bind(127.0.0.1:port) + listen. port 0
 * selects an ephemeral port, reported in *bound_port. Loopback only. */
net_status_t net_listen_loopback(uint16_t port, int backlog, int *listen_fd, uint16_t *bound_port);

/* Waits (poll, bounded by deadline_ms; NET_NO_DEADLINE = wait forever) and
 * accepts one connection into *out, configured as described above. */
net_status_t net_accept(int listen_fd, uint64_t deadline_ms, net_conn_t *out);

/* Non-blocking connect to 127.0.0.1:port, bounded by deadline_ms. */
net_status_t net_connect_loopback(uint16_t port, uint64_t deadline_ms, net_conn_t *out);

/* Non-blocking connect to an AF_UNIX stream socket at `path`, bounded by
 * deadline_ms (V4-9b: the CLIs reach a co-located daemon this way, and the
 * end-to-end test uses it so there is no ephemeral-port race at all).
 *
 * A path that does not fit sun_path -- 104 bytes on macOS, 108 on Linux, well
 * under AUTHD_PATH_MAX -- is NET_ERR_INVALID_ARG, never a silent truncation to
 * some other socket. */
net_status_t net_connect_unix(const char *path, uint64_t deadline_ms, net_conn_t *out);

/* Reads exactly n bytes. *got always reports how many bytes were read, also
 * on NET_EOF / NET_TIMEOUT / NET_ERR_IO (so callers can tell a clean EOF at
 * a boundary from a truncation). */
net_status_t net_read_exact(net_conn_t *c, uint8_t *buf, size_t n, uint64_t deadline_ms, size_t *got);

/* Writes exactly n bytes. */
net_status_t net_write_all(net_conn_t *c, const uint8_t *buf, size_t n, uint64_t deadline_ms);

/* Idempotent. */
void net_close(net_conn_t *c);
void net_close_fd(int *fd);

const char *net_status_name(net_status_t st);

#endif /* MLDSA_AUTH_APPS_NET_IO_H */
