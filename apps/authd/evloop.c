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
    if (ev == NULL || slots == NULL || n_slots == 0u || on_frame == NULL) {
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
        ev->listen_uid[i] = (uid_t)-1;
    }
    return 0;
}

int evloop_add_listener(evloop_t *ev, int fd, uid_t require_uid)
{
    if (ev == NULL || fd < 0 || ev->n_listeners >= AUTHD_MAX_LISTENERS) {
        return -1;
    }
    ev->listen_fd[ev->n_listeners] = fd;
    ev->listen_uid[ev->n_listeners] = require_uid;
    ev->n_listeners++;
    return 0;
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
    conn_io_reset(&s->io);
    s->state = SLOT_FREE;
    s->deadline_ms = 0;
    s->opened_ms = 0;
    s->user = NULL;
    if (ev->in_use > 0u) {
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
}

void evloop_stop(evloop_t *ev)
{
    if (ev == NULL) {
        return;
    }
    ev->stopping = 1;
    /* Connections with nothing queued go now; the rest flush first. */
    for (size_t i = 0; i < ev->n_slots; i++) {
        authd_slot_t *s = &ev->slots[i];
        if (s->state == SLOT_ACTIVE) {
            s->state = SLOT_DRAINING;
        }
    }
}

static authd_slot_t *take_slot(evloop_t *ev)
{
    for (size_t i = 0; i < ev->n_slots; i++) {
        if (ev->slots[i].state == SLOT_FREE) {
            return &ev->slots[i];
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
        int cfd = -1;
        const listener_status_t st = listener_accept(ev->listen_fd[li], ev->listen_uid[li], &cfd);
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
        authd_slot_t *s = take_slot(ev);
        if (s == NULL) {
            /* Refusing is the correct behaviour at capacity: closing at once
             * is cheaper for us than for the peer, and nothing is allocated. */
            (void)close(cfd);
            ev->refused_no_slot++;
            authd_log_event(AUTHD_LOG_WARN, "accept-refused-no-slot");
            continue;
        }
        conn_io_reset(&s->io);
        s->fd = cfd;
        s->state = SLOT_ACTIVE;
        s->opened_ms = now_ms;
        s->deadline_ms = (ev->handshake_timeout_ms > 0u)
                             ? now_ms + (uint64_t)ev->handshake_timeout_ms
                             : 0u;
        s->user = NULL;
        ev->in_use++;
        ev->accepted++;
        authd_log_slot(AUTHD_LOG_INFO, "accepted", s->index);
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

    for (;;) {
        const uint8_t *payload = NULL;
        size_t len = 0;
        if (!conn_io_next_frame(&s->io, &payload, &len)) {
            break;
        }
        const ev_action_t act = ev->on_frame(ev->user, s, payload, len);
        conn_io_consume_frame(&s->io);
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
    static size_t slot_idx[AUTHD_SLOTS_POLL_MAX];
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

    size_t nspfd = 0;
    for (size_t i = 0; i < ev->n_slots && nspfd < AUTHD_SLOTS_POLL_MAX; i++) {
        authd_slot_t *s = &ev->slots[i];
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
        slot_idx[nspfd] = i;
        nspfd++;
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
        authd_slot_t *s = &ev->slots[slot_idx[i]];
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
    for (size_t i = 0; i < ev->n_slots; i++) {
        authd_slot_t *s = &ev->slots[i];
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

    return activity;
}
