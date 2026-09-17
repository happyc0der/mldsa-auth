#ifndef MLDSA_AUTHD_LISTENER_H
#define MLDSA_AUTHD_LISTENER_H

#include <stdint.h>
#include <sys/types.h>

/*
 * Non-blocking listeners for the daemon (V4-8a).
 *
 * Two kinds, because the deployment has two (spec §7.2, §16):
 *
 *   - a loopback TCP listener, which is what an operator reaches through an
 *     SSH tunnel in milestone A, and
 *   - a Unix-socket listener, which is the proxy-facing one. It is created
 *     0660 and the daemon checks the connecting peer's uid with SO_PEERCRED
 *     (Linux) / LOCAL_PEERCRED (macOS), so only the proxy's user can reach it.
 *     Filesystem permissions alone are not relied on.
 *
 * Every accepted fd is non-blocking and CLOEXEC. Accept never blocks: the loop
 * must never stall on one peer.
 */

typedef enum {
    LISTENER_OK = 0,
    LISTENER_ERR_ARG,
    LISTENER_ERR_SOCKET,
    LISTENER_ERR_BIND,
    LISTENER_ERR_LISTEN,
    LISTENER_ERR_PATH,       /* unix path too long, or refused */
    LISTENER_AGAIN,          /* accept: nothing pending right now */
    LISTENER_ERR_PEER        /* accept: peer credential check failed */
} listener_status_t;

const char *listener_status_name(listener_status_t st);

/* Binds 127.0.0.1:port (port 0 = pick one; *bound_port receives it). */
listener_status_t listener_open_loopback(uint16_t port, int backlog, int *fd, uint16_t *bound_port);

/* Binds a Unix stream socket at `path`, mode 0660. An existing socket file at
 * that path is removed first (a stale socket after a crash must not wedge the
 * service); anything else at that path is refused rather than unlinked. */
listener_status_t listener_open_unix(const char *path, int backlog, int *fd);

/* Accepts one connection without blocking. On LISTENER_OK *out_fd is a
 * non-blocking CLOEXEC fd. LISTENER_AGAIN means nothing was pending.
 *
 * When `require_uid` is not (uid_t)-1 the peer's uid must equal it, or the
 * connection is closed and LISTENER_ERR_PEER returned -- this is the proxy
 * authentication for the Unix listener. */
listener_status_t listener_accept(int listen_fd, uid_t require_uid, int *out_fd);

/* Closes and, for a Unix listener, unlinks its path. */
void listener_close(int *fd, const char *unix_path);

#endif /* MLDSA_AUTHD_LISTENER_H */
