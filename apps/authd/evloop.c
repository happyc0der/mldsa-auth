#include "evloop.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_log.h"
#include "listener.h"

/* One read per readable slot per iteration. Bounded so a fast peer cannot
 * monopolise the loop: fairness across slots matters more than throughput on
 * any one of them. */
#define READ_CHUNK 4096u

int evloop_init(evloop_t *ev, authd_slot_t *slots, size_t n_slots,
                uint32_t handshake_timeout_ms, uint32_t idle_timeout_ms,
                evloop_on_frame_fn on_frame, evloop_on_close_fn on_close, void *user)
{
    /* The pool's own maximum is enforced HERE, at registration, which is what
     * makes the poll array's bound unreachable by contract rather than by
     * coincidence (F62). The daemon cannot exceed it -- authd_config.c parses
     * max_slots against AUTHD_SLOTS_MAX -- but a test or a future tool can. */
    if (ev == NULL || slots == NULL || n_slots == 0u || n_slots > AUTHD_SLOTS_MAX ||
        on_frame == NULL) {
        return -1;
    }
    memset(ev, 0, sizeof *ev);
    ev->slots = slots;
    ev->n_slots = n_slots;
    ev->handshake_timeout_ms = handshake_timeout_ms;
    ev->idle_timeout_ms = idle_timeout_ms;
    ev->on_frame = on_frame;
    ev->on_close = on_close;
    ev->user = user;
    for (size_t i = 0; i < n_slots; i++) {
        memset(&slots[i], 0, sizeof slots[i]);
        slots[i].fd = -1;
        slots[i].state = SLOT_FREE;
        slots[i].index = i;
        conn_io_reset(&slots[i].io);
    }
    for (size_t i = 0; i < AUTHD_MAX_LISTENERS; i++) {
        ev->listen_fd[i] = -1;
        ev->listen_kind[i] = SLOT_KIND_PROTO;
        ev->listen_is_admin[i] = 0;
        ev->listen_ws[i] = 0;
        ev->listen_proxy[i] = 0;
        ev->listen_n_allow[i] = 0u;
    }
    return 0;
}

int evloop_set_on_addr(evloop_t *ev, evloop_on_addr_fn on_addr)
{
    if (ev == NULL || on_addr == NULL) {
        return -1;
    }
    ev->on_addr = on_addr;
    return 0;
}

int evloop_set_local(evloop_t *ev, authd_slot_t *local_slots, size_t n_local_slots,
                     evloop_on_line_fn on_line)
{
    if (ev == NULL || local_slots == NULL || n_local_slots == 0u ||
        n_local_slots > AUTHD_LOCAL_SLOTS_MAX || on_line == NULL) {
        return -1;
    }
    ev->local_slots = local_slots;
    ev->n_local_slots = n_local_slots;
    ev->on_line = on_line;
    for (size_t i = 0; i < n_local_slots; i++) {
        memset(&local_slots[i], 0, sizeof local_slots[i]);
        local_slots[i].fd = -1;
        local_slots[i].state = SLOT_FREE;
        local_slots[i].kind = SLOT_KIND_LOCAL;
        local_slots[i].index = i;
        conn_io_reset(&local_slots[i].io);
        conn_io_set_mode(&local_slots[i].io, CONN_IO_MODE_LINE);
    }
    return 0;
}

size_t evloop_local_active(const evloop_t *ev)
{
    return (ev == NULL) ? 0u : ev->local_in_use;
}

int evloop_add_local_listener(evloop_t *ev, int fd, const uid_t *allow, size_t n_allow, int is_admin)
{
    if (ev == NULL || fd < 0 || ev->n_listeners >= AUTHD_MAX_LISTENERS ||
        ev->local_slots == NULL || ev->on_line == NULL ||
        n_allow > LISTENER_MAX_ALLOW || (n_allow > 0u && allow == NULL)) {
        return -1;
    }
    const size_t i = ev->n_listeners;
    ev->listen_fd[i] = fd;
    ev->listen_kind[i] = SLOT_KIND_LOCAL;
    ev->listen_is_admin[i] = is_admin ? 1 : 0;
    ev->listen_ws[i] = 0;
    ev->listen_n_allow[i] = n_allow;
    for (size_t j = 0; j < n_allow; j++) {
        ev->listen_allow[i][j] = allow[j];
    }
    ev->n_listeners++;
    return 0;
}

static int add_proto_listener(evloop_t *ev, int fd, const uid_t *allow, size_t n_allow,
                              int is_ws, int proxy_v2)
{
    if (ev == NULL || fd < 0 || ev->n_listeners >= AUTHD_MAX_LISTENERS ||
        n_allow > LISTENER_MAX_ALLOW || (n_allow > 0u && allow == NULL)) {
        return -1;
    }
    const size_t i = ev->n_listeners;
    ev->listen_fd[i] = fd;
    ev->listen_kind[i] = SLOT_KIND_PROTO;
    ev->listen_is_admin[i] = 0;
    ev->listen_ws[i] = is_ws ? 1 : 0;
    ev->listen_proxy[i] = (is_ws && proxy_v2) ? 1 : 0;
    ev->listen_n_allow[i] = n_allow;
    for (size_t j = 0; j < n_allow; j++) {
        ev->listen_allow[i][j] = allow[j];
    }
    ev->n_listeners++;
    return 0;
}

int evloop_add_listener(evloop_t *ev, int fd, uid_t require_uid)
{
    if (require_uid == (uid_t)-1) {
        return add_proto_listener(ev, fd, NULL, 0u, 0, 0);
    }
    const uid_t one[1] = { require_uid };
    return add_proto_listener(ev, fd, one, 1u, 0, 0);
}

int evloop_add_ws_listener(evloop_t *ev, int fd, const uid_t *allow, size_t n_allow,
                           int proxy_v2)
{
    return add_proto_listener(ev, fd, allow, n_allow, 1, proxy_v2);
}

size_t evloop_active(const evloop_t *ev)
{
    return (ev == NULL) ? 0u : ev->in_use;
}

void evloop_close_slot(evloop_t *ev, authd_slot_t *s)
{
    if (ev == NULL || s == NULL || s->state == SLOT_FREE) {
        return;
    }
    if (ev->on_close != NULL) {
        ev->on_close(ev->user, s);
    }
    if (s->fd >= 0) {
        (void)close(s->fd);
        s->fd = -1;
    }
    /* Wipe before the slot is handed to the next connection: the buffers held
     * handshake messages and decrypted records. */
    const int local = (s->kind == SLOT_KIND_LOCAL);
    conn_io_reset(&s->io);
    if (local) {
        conn_io_set_mode(&s->io, CONN_IO_MODE_LINE);   /* the mode is the pool's, not the connection's */
    }
    /* A PROTO slot's mode is the LISTENER's and is re-applied on the next
     * accept, so nothing is restored here -- conn_io_reset above has already
     * zeroed the WebSocket state, which is what must not survive a slot. */
    s->state = SLOT_FREE;
    s->deadline_ms = 0;
    s->opened_ms = 0;
    s->user = NULL;
    s->is_admin = 0;
    s->addr_settled = 0;
    s->addr_admitted = 0;
    s->peer.uid = (uid_t)-1;
    s->peer.pid = 0;
    if (local) {
        if (ev->local_in_use > 0u) { ev->local_in_use--; }
    } else if (ev->in_use > 0u) {
        ev->in_use--;
    }
}

void evloop_close_all(evloop_t *ev)
{
    if (ev == NULL) {
        return;
    }
    for (size_t i = 0; i < ev->n_slots; i++) {
        if (ev->slots[i].state != SLOT_FREE) {
            evloop_close_slot(ev, &ev->slots[i]);
        }
    }
    for (size_t i = 0; i < ev->n_local_slots; i++) {
        if (ev->local_slots[i].state != SLOT_FREE) {
            evloop_close_slot(ev, &ev->local_slots[i]);
        }
    }
}

void evloop_stop(evloop_t *ev)
{
    if (ev == NULL) {
        return;
    }
    ev->stopping = 1;
    /* Connections with nothing queued go now; the rest flush first. */
    for (size_t i = 0; i < ev->n_slots; i++) {
        if (ev->slots[i].state == SLOT_ACTIVE) {
            ev->slots[i].state = SLOT_DRAINING;
        }
    }
    for (size_t i = 0; i < ev->n_local_slots; i++) {
        if (ev->local_slots[i].state == SLOT_ACTIVE) {
            ev->local_slots[i].state = SLOT_DRAINING;
        }
    }
}

static authd_slot_t *take_slot(evloop_t *ev, slot_kind_t kind)
{
    authd_slot_t *pool = (kind == SLOT_KIND_LOCAL) ? ev->local_slots : ev->slots;
    const size_t n = (kind == SLOT_KIND_LOCAL) ? ev->n_local_slots : ev->n_slots;
    for (size_t i = 0; i < n; i++) {
        if (pool[i].state == SLOT_FREE) {
            return &pool[i];
        }
    }
    return NULL;
}

static void accept_ready(evloop_t *ev, size_t li, uint64_t now_ms)
{
    for (;;) {
        if (ev->stopping) {
            return;
        }
        const slot_kind_t kind = ev->listen_kind[li];
        int cfd = -1;
        listener_peer_t peer;
        const listener_status_t st = listener_accept_ex(ev->listen_fd[li],
                                                        ev->listen_n_allow[li] ? ev->listen_allow[li] : NULL,
                                                        ev->listen_n_allow[li], &cfd, &peer);
        if (st == LISTENER_AGAIN) {
            return;
        }
        if (st == LISTENER_ERR_PEER) {
            ev->closed_peer++;
            authd_log_event(AUTHD_LOG_WARN, "listener-peer-rejected");
            continue;
        }
        if (st != LISTENER_OK) {
            return;
        }
        authd_slot_t *s = take_slot(ev, kind);
        if (s == NULL) {
            /* Refusing is the correct behaviour at capacity: closing at once
             * is cheaper for us than for the peer, and nothing is allocated. */
            (void)close(cfd);
            if (kind == SLOT_KIND_LOCAL) {
                ev->local_refused_no_slot++;
                authd_log_event(AUTHD_LOG_WARN, "local-accept-refused-no-slot");
            } else {
                ev->refused_no_slot++;
                authd_log_event(AUTHD_LOG_WARN, "accept-refused-no-slot");
            }
            continue;
        }
        conn_io_reset(&s->io);
        conn_io_set_mode(&s->io, (kind == SLOT_KIND_LOCAL) ? CONN_IO_MODE_LINE
                                 : (ev->listen_ws[li] ? CONN_IO_MODE_WS : CONN_IO_MODE_FRAME));
        conn_io_set_proxy(&s->io, ev->listen_proxy[li]);
        s->fd = cfd;
        s->addr_settled = 0;
        s->addr_admitted = 0;
        s->kind = kind;
        s->state = SLOT_ACTIVE;
        s->opened_ms = now_ms;
        s->user = NULL;
        if (kind == SLOT_KIND_LOCAL) {
            s->peer = peer;
            s->is_admin = ev->listen_is_admin[li];
            /* The local API is not a handshake: it gets the idle deadline from
             * the first moment, so a site process that connects and says
             * nothing cannot hold a slot indefinitely. */
            s->deadline_ms = (ev->idle_timeout_ms > 0u) ? now_ms + (uint64_t)ev->idle_timeout_ms : 0u;
            ev->local_in_use++;
            ev->local_accepted++;
            authd_log_slot(AUTHD_LOG_INFO, "local-accepted", s->index);
        } else {
            s->deadline_ms = (ev->handshake_timeout_ms > 0u)
                                 ? now_ms + (uint64_t)ev->handshake_timeout_ms
                                 : 0u;
            ev->in_use++;
            ev->accepted++;
            authd_log_slot(AUTHD_LOG_INFO, "accepted", s->index);
        }
    }
}

/* Reads once, feeds the reassembler, dispatches every complete frame.
 * Returns 0 to keep the slot, -1 to close it. */
static int slot_readable(evloop_t *ev, authd_slot_t *s, uint64_t now_ms)
{
    uint8_t buf[READ_CHUNK];
    ssize_t n;
    do {
        n = read(s->fd, buf, sizeof buf);
    } while (n < 0 && errno == EINTR);

    if (n == 0) {
        return -1;                       /* peer closed */
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    const conn_io_status_t cs = conn_io_push(&s->io, buf, (size_t)n);
    sodium_memzero(buf, sizeof buf);
    if (cs != CONN_IO_OK) {
        ev->closed_protocol++;
        authd_log_slot_detail(AUTHD_LOG_WARN, "closed-protocol", s->index, conn_io_status_name(cs));
        return -1;
    }

    /* The client address is decided the instant the PROXY preamble settles --
     * before the upgrade is answered, and therefore before
     * handshake_responder_create_server_hello() spends a signature on a probe.
     * §7.3 assigns that cost to the rate limiter by name; a limiter that acted
     * on the ClientHello would already have paid it. */
    if (!s->addr_settled && conn_io_proxy_settled(&s->io)) {
        s->addr_settled = 1;
        if (ev->on_addr != NULL && ev->on_addr(ev->user, s) == EV_ACTION_CLOSE) {
            ev->closed_refused_addr++;
            s->state = SLOT_DRAINING;   /* flush the refusal, then close */
            return 0;
        }
    }

    for (;;) {
        const uint8_t *payload = NULL;
        size_t len = 0;
        const int have = (s->kind == SLOT_KIND_LOCAL)
                             ? conn_io_next_line(&s->io, &payload, &len)
                             : conn_io_next_frame(&s->io, &payload, &len);
        if (!have) {
            break;
        }
        const ev_action_t act = (s->kind == SLOT_KIND_LOCAL)
                                    ? ev->on_line(ev->user, s, payload, len)
                                    : ev->on_frame(ev->user, s, payload, len);
        if (s->kind == SLOT_KIND_LOCAL) {
            conn_io_consume_line(&s->io);
        } else {
            conn_io_consume_frame(&s->io);
        }
        /* A frame was served: re-arm the idle deadline. */
        s->deadline_ms = (ev->idle_timeout_ms > 0u) ? now_ms + (uint64_t)ev->idle_timeout_ms : 0u;
        if (act == EV_ACTION_CLOSE) {
            s->state = SLOT_DRAINING;
            break;
        }
        /* Half-duplex: if a reply is queued, stop consuming input until it has
         * gone out. Otherwise a peer that pipelines could make us queue over an
         * unsent reply (conn_io_queue would return BUSY) or buffer unboundedly. */
        if (conn_io_pending(&s->io) > 0u) {
            break;
        }
    }
    return 0;
}

/* Returns 0 to keep the slot, -1 to close it. */
static int slot_writable(evloop_t *ev, authd_slot_t *s)
{
    const size_t pending = conn_io_pending(&s->io);
    if (pending == 0u) {
        return (s->state == SLOT_DRAINING) ? -1 : 0;
    }
    ssize_t n;
    do {
        n = write(s->fd, conn_io_pending_ptr(&s->io), pending);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;                    /* partial send resumes next iteration */
        }
        return -1;
    }
    conn_io_sent(&s->io, (size_t)n);
    if (conn_io_pending(&s->io) == 0u && s->state == SLOT_DRAINING) {
        return -1;                       /* everything flushed; close */
    }
    (void)ev;
    return 0;
}

int evloop_run_once(evloop_t *ev, int poll_timeout_ms, uint64_t now_ms)
{
    if (ev == NULL) {
        return -1;
    }
    /* Poll set, rebuilt each iteration from the slot table (the only source of
     * truth). Both arrays are static and sized from the compile-time maximum,
     * so a full pool costs no stack and no allocation. */
    static struct pollfd all[AUTHD_MAX_LISTENERS + AUTHD_SLOTS_POLL_MAX];
    size_t npfd = 0;
    size_t listener_count = 0;

    if (!ev->stopping) {
        for (size_t i = 0; i < ev->n_listeners; i++) {
            if (ev->listen_fd[i] >= 0) {
                all[npfd].fd = ev->listen_fd[i];
                all[npfd].events = POLLIN;
                all[npfd].revents = 0;
                npfd++;
                listener_count++;
            }
        }
    }

    /* Both pools are polled in ONE set. slot_ref[] remembers which pool each
     * pollfd came from, so a bug here cannot silently stop serving one of
     * them -- the mixed-kind test exists for exactly this. */
    static authd_slot_t *slot_ref[AUTHD_SLOTS_POLL_MAX];
    size_t nspfd = 0;

    for (int pool = 0; pool < 2; pool++) {
        authd_slot_t *arr = (pool == 0) ? ev->slots : ev->local_slots;
        const size_t n = (pool == 0) ? ev->n_slots : ev->n_local_slots;
        /* Each pool is bounded by ITS OWN maximum, so a full protocol pool can
         * never consume the local pool's share of the set (F62). With the
         * array now sized from the sum and both maxima enforced at
         * registration, this is belt to those braces -- and it is the half a
         * test can actually observe. */
        const size_t pool_max = (pool == 0) ? AUTHD_SLOTS_MAX : AUTHD_LOCAL_SLOTS_MAX;
        size_t taken = 0;
        if (arr == NULL) {
            continue;
        }
        for (size_t i = 0; i < n && taken < pool_max; i++) {
            authd_slot_t *s = &arr[i];
            if (s->state == SLOT_FREE || s->fd < 0) {
                continue;
            }
            if (s->state == SLOT_DRAINING && conn_io_pending(&s->io) == 0u) {
                evloop_close_slot(ev, s);   /* nothing left to flush */
                continue;
            }
            short events = 0;
            if (conn_io_pending(&s->io) > 0u) {
                events |= POLLOUT;          /* half-duplex: finish the reply first */
            } else if (s->state == SLOT_ACTIVE) {
                events |= POLLIN;
            }
            all[npfd + nspfd].fd = s->fd;
            all[npfd + nspfd].events = events;
            all[npfd + nspfd].revents = 0;
            slot_ref[nspfd] = s;
            nspfd++;
            taken++;
        }
    }

    const size_t total = npfd + nspfd;
    int rc = 0;
    if (total > 0u) {
        do {
            rc = poll(all, (nfds_t)total, poll_timeout_ms);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0) {
            return -1;
        }
    }

    int activity = 0;

    for (size_t i = 0; i < listener_count; i++) {
        if ((all[i].revents & POLLIN) != 0) {
            accept_ready(ev, i, now_ms);
            activity++;
        }
    }

    for (size_t i = 0; i < nspfd; i++) {
        authd_slot_t *s = slot_ref[i];
        if (s->state == SLOT_FREE) {
            continue;
        }
        const short re = all[npfd + i].revents;
        if (re == 0) {
            continue;
        }
        activity++;
        int closed = 0;

        if ((re & POLLOUT) != 0) {
            if (slot_writable(ev, s) < 0) {
                evloop_close_slot(ev, s);
                closed = 1;
            }
        }
        if (!closed && (re & POLLIN) != 0) {
            if (slot_readable(ev, s, now_ms) < 0) {
                evloop_close_slot(ev, s);
                closed = 1;
            }
        }
        if (!closed && (re & (POLLERR | POLLNVAL)) != 0) {
            evloop_close_slot(ev, s);
            closed = 1;
        }
        if (!closed && (re & POLLHUP) != 0 && conn_io_pending(&s->io) == 0u) {
            evloop_close_slot(ev, s);
        }
    }

    /* deadlines last, so a frame served this iteration has already re-armed */
    for (int pool = 0; pool < 2; pool++) {
        authd_slot_t *arr = (pool == 0) ? ev->slots : ev->local_slots;
        const size_t n = (pool == 0) ? ev->n_slots : ev->n_local_slots;
        if (arr == NULL) {
            continue;
        }
        for (size_t i = 0; i < n; i++) {
            authd_slot_t *s = &arr[i];
            if (s->state == SLOT_FREE || s->deadline_ms == 0u) {
                continue;
            }
            if (now_ms >= s->deadline_ms) {
                ev->closed_deadline++;
                authd_log_slot(AUTHD_LOG_INFO, "closed-deadline", s->index);
                evloop_close_slot(ev, s);
                activity++;
            }
        }
    }

    return activity;
}
