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

/* Binds a Unix stream socket at `path` with `mode`. An existing socket file at
 * that path is removed first (a stale socket after a crash must not wedge the
 * service); anything else at that path is refused rather than unlinked.
 *
 * The mode is a PARAMETER because spec 8 gives the two local sockets different
 * ones: site.sock is 0660 (owner plus the site's group) while admin.sock is
 * 0600, root only. Until V4-9b every socket was chmod 0660 unconditionally,
 * which made the admin socket group-reachable -- the uid allowlist still
 * refused such a peer, but defence in depth is exactly what a second layer is
 * for, and the spec said 0600. Only these two are permitted; anything else is
 * LISTENER_ERR_PATH, so a future caller cannot invent 0666. */
#define LISTENER_MODE_PRIVATE 0600  /* admin.sock */
#define LISTENER_MODE_GROUP   0660  /* site.sock and the proxy-facing listener */
listener_status_t listener_open_unix(const char *path, int backlog, mode_t mode, int *fd);

/* The peer of a Unix-socket connection. Spec 8 requires every local-API
 * request to be logged with the peer's uid AND pid; both are portable --
 * Linux carries them in SO_PEERCRED's struct ucred, macOS has getpeereid()
 * plus LOCAL_PEERPID. A pid of 0 means "not available on this platform",
 * which is logged as such rather than as a real pid. */
typedef struct {
    uid_t uid;
    pid_t pid;
} listener_peer_t;

#define LISTENER_MAX_ALLOW 8u

/* Accepts one connection without blocking, enforcing a uid ALLOWLIST rather
 * than a single uid, and reporting the peer.
 *
 * `n_allow == 0` disables the check (the protocol listeners, which are
 * reached through the proxy and authenticated by the handshake, not by uid).
 * Otherwise the peer's uid must appear in `allow[0..n_allow)`, or the
 * connection is closed and LISTENER_ERR_PEER returned.
 *
 * An allowlist rather than one uid because the site and the daemon are not
 * always the same user in a real deployment, and "root only" for the admin
 * socket is a DEFAULT, not a constant -- a gate that only root can exercise
 * is a gate that never gets tested. */
listener_status_t listener_accept_ex(int listen_fd, const uid_t *allow, size_t n_allow,
                                     int *out_fd, listener_peer_t *peer_out);

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
