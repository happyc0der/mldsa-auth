/* glibc exposes `struct ucred` (SO_PEERCRED) only under _GNU_SOURCE, and this
 * MUST be defined before the first glibc header is pulled in -- hence before
 * every #include below. macOS uses getpeereid() and never needed it, which is
 * why a macOS-only build could not have caught this: CI's Linux jobs did, on
 * both clang ("incomplete type") and gcc ("storage size isn't known"). */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include "listener.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/types.h>
#elif defined(__APPLE__)
#include <sys/ucred.h>
#endif

const char *listener_status_name(listener_status_t st)
{
    switch (st) {
    case LISTENER_OK:          return "ok";
    case LISTENER_ERR_ARG:     return "bad-argument";
    case LISTENER_ERR_SOCKET:  return "socket";
    case LISTENER_ERR_BIND:    return "bind";
    case LISTENER_ERR_LISTEN:  return "listen";
    case LISTENER_ERR_PATH:    return "path";
    case LISTENER_AGAIN:       return "again";
    case LISTENER_ERR_PEER:    return "peer-credential";
    case LISTENER_ERR_IN_USE:  return "in-use";
    default:                   return "unknown";
    }
}

static int set_nonblock_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        return -1;
    }
    int fd_fl = fcntl(fd, F_GETFD, 0);
    if (fd_fl < 0 || fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}

listener_status_t listener_open_loopback(uint16_t port, int backlog, int *fd, uint16_t *bound_port)
{
    if (fd == NULL || backlog <= 0) {
        return LISTENER_ERR_ARG;
    }
    *fd = -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return LISTENER_ERR_SOCKET;
    }
    int one = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* loopback only, never 0.0.0.0 */
    if (bind(s, (const struct sockaddr *)&a, sizeof a) != 0) {
        (void)close(s);
        return LISTENER_ERR_BIND;
    }
    if (listen(s, backlog) != 0) {
        (void)close(s);
        return LISTENER_ERR_LISTEN;
    }
    if (set_nonblock_cloexec(s) != 0) {
        (void)close(s);
        return LISTENER_ERR_SOCKET;
    }
    if (bound_port != NULL) {
        struct sockaddr_in got;
        socklen_t gl = sizeof got;
        if (getsockname(s, (struct sockaddr *)&got, &gl) == 0) {
            *bound_port = ntohs(got.sin_port);
        } else {
            *bound_port = port;
        }
    }
    *fd = s;
    return LISTENER_OK;
}

/* Is anything listening on the socket at `a`? 1 yes or cannot tell, 0 no.
 *
 * A socket file whose listener is gone refuses a connection (ECONNREFUSED);
 * that, and the file having vanished meanwhile, are the only answers that
 * make it a leftover. Everything else -- connected, a full backlog (EAGAIN
 * on a non-blocking connect), no permission -- leaves it somebody's: a path
 * this cannot prove dead is not this process's to unlink (F204). The look is
 * one connection the listener sees opened and closed, with nothing sent. */
static int unix_socket_in_use(const struct sockaddr_un *a)
{
    const int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) {
        return 1;
    }
    int rc = -1;
    int err = 0;
    if (set_nonblock_cloexec(c) == 0) {
        do {
            rc = connect(c, (const struct sockaddr *)a, sizeof *a);
        } while (rc != 0 && errno == EINTR);
        err = (rc != 0) ? errno : 0;
    }
    (void)close(c);
    if (rc != 0 && (err == ECONNREFUSED || err == ENOENT)) {
        return 0;
    }
    return 1;
}

listener_status_t listener_open_unix(const char *path, int backlog, mode_t mode, int *fd)
{
    if (path == NULL || fd == NULL || backlog <= 0) {
        return LISTENER_ERR_ARG;
    }
    /* Only the two modes spec 8 defines. A caller that wants something else is
     * a bug, not a configuration: refuse instead of obeying. */
    if (mode != (mode_t)LISTENER_MODE_PRIVATE && mode != (mode_t)LISTENER_MODE_GROUP) {
        return LISTENER_ERR_ARG;
    }
    *fd = -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    const size_t n = strlen(path);
    if (n == 0u || n >= sizeof a.sun_path) {
        return LISTENER_ERR_PATH;
    }
    memcpy(a.sun_path, path, n);

    /* A stale socket from a crash must not wedge the service, but anything
     * that is NOT a socket at that path is refused rather than removed -- the
     * daemon does not delete an operator's file because it wanted the name.
     *
     * Nor a socket that is being listened on (F204): that is a running
     * daemon's, and unlinking it left that daemon up and unreachable while
     * this one served in its place. With a TCP listener configured the
     * second daemon failed at its bind before it got here; with
     * listen_port = 0, which the example configuration offers, nothing
     * stopped it. Two daemons started at the same instant over a leftover
     * can still both find it dead; this is not a lock. */
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            return LISTENER_ERR_PATH;
        }
        if (unix_socket_in_use(&a)) {
            return LISTENER_ERR_IN_USE;
        }
        if (unlink(path) != 0) {
            return LISTENER_ERR_PATH;
        }
    }

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        return LISTENER_ERR_SOCKET;
    }
    /* Create with a restrictive umask so there is no window in which the
     * socket is world-accessible between bind() and chmod(). */
    const mode_t old = umask(0177);
    const int brc = bind(s, (const struct sockaddr *)&a, sizeof a);
    (void)umask(old);
    if (brc != 0) {
        (void)close(s);
        return LISTENER_ERR_BIND;
    }
    /* Spec 8: admin.sock 0600, site.sock and the proxy listener 0660. */
    if (chmod(path, mode) != 0) {
        (void)close(s);
        (void)unlink(path);
        return LISTENER_ERR_PATH;
    }
    if (listen(s, backlog) != 0) {
        (void)close(s);
        (void)unlink(path);
        return LISTENER_ERR_LISTEN;
    }
    if (set_nonblock_cloexec(s) != 0) {
        (void)close(s);
        (void)unlink(path);
        return LISTENER_ERR_SOCKET;
    }
    *fd = s;
    return LISTENER_OK;
}

/* Reads the connecting peer's credentials. Returns 0 on success. pid is left
 * 0 where the platform does not offer it. */
static int peer_creds(int fd, listener_peer_t *p)
{
    p->uid = (uid_t)-1;
    p->pid = 0;
#if defined(__linux__)
    struct ucred c;
    socklen_t l = sizeof c;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &c, &l) != 0) {
        return -1;
    }
    p->uid = c.uid;
    p->pid = c.pid;
    return 0;
#elif defined(__APPLE__)
    uid_t u = 0;
    gid_t g = 0;
    if (getpeereid(fd, &u, &g) != 0) {
        return -1;
    }
    p->uid = u;
    /* LOCAL_PEERPID (sys/un.h) is best-effort: a failure leaves pid 0, which
     * the log renders as unavailable rather than inventing a number. */
    pid_t pp = 0;
    socklen_t pl = sizeof pp;
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pp, &pl) == 0) {
        p->pid = pp;
    }
    return 0;
#else
    (void)fd;
    return -1;
#endif
}

listener_status_t listener_accept_ex(int listen_fd, const uid_t *allow, size_t n_allow,
                                     int *out_fd, listener_peer_t *peer_out)
{
    if (out_fd == NULL || listen_fd < 0 || (n_allow > 0u && allow == NULL) ||
        n_allow > LISTENER_MAX_ALLOW) {
        return LISTENER_ERR_ARG;
    }
    *out_fd = -1;
    if (peer_out != NULL) {
        peer_out->uid = (uid_t)-1;
        peer_out->pid = 0;
    }
    int c;
    do {
        c = accept(listen_fd, NULL, NULL);
        /* ECONNABORTED: the peer left while queued. That connection is gone
         * and the next one is not; it is not a failure of the listener, which
         * is what LISTENER_ERR_SOCKET now means to the loop (F205). */
    } while (c < 0 && (errno == EINTR || errno == ECONNABORTED));

    if (c < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return LISTENER_AGAIN;
        }
        return LISTENER_ERR_SOCKET;
    }
    if (set_nonblock_cloexec(c) != 0) {
        (void)close(c);
        return LISTENER_ERR_SOCKET;
    }
    if (n_allow > 0u) {
        listener_peer_t p;
        if (peer_creds(c, &p) != 0) {
            (void)close(c);
            return LISTENER_ERR_PEER;   /* fail closed: no credentials, no service */
        }
        int ok = 0;
        for (size_t i = 0; i < n_allow; i++) {
            if (allow[i] == p.uid) { ok = 1; break; }
        }
        if (!ok) {
            (void)close(c);
            return LISTENER_ERR_PEER;
        }
        if (peer_out != NULL) { *peer_out = p; }
    } else if (peer_out != NULL) {
        /* No allowlist: still report what we can, for the log. */
        (void)peer_creds(c, peer_out);
    }
    *out_fd = c;
    return LISTENER_OK;
}

void listener_close(int *fd, const char *unix_path)
{
    /* F130: the path is unlinked only for a listener this process holds. The
     * daemon's start-up failure path calls this for EVERY listener, opened or
     * not, and unlinking unconditionally deleted a regular file that
     * listener_open_unix had just refused to bind over -- and, when a second
     * daemon with the same config failed at its TCP bind, the running daemon's
     * three live sockets, leaving it up and unreachable. A listener that
     * failed after bind() has already unlinked its own path. */
    if (fd == NULL || *fd < 0) {
        return;
    }
    (void)close(*fd);
    *fd = -1;
    if (unix_path != NULL && unix_path[0] != '\0') {
        (void)unlink(unix_path);
    }
}
