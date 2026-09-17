#ifndef MLDSA_AUTHD_EVLOOP_H
#define MLDSA_AUTHD_EVLOOP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "conn_io.h"
#include "listener.h"

/*
 * The daemon's single-threaded poll() event loop and its fixed slot pool
 * (V4-8a).
 *
 * One thread, one loop, no locking anywhere -- which is how spec-v2 §6.3.6's
 * "confine a handshake context to one event loop" is satisfied by
 * construction rather than by discipline.
 *
 * Slots are a caller-provided array, allocated once at startup and never
 * grown. After evloop_init() the loop performs NO allocation at all: a
 * connection is a slot index, and running out of slots is a clean refusal
 * rather than memory pressure. Each slot carries ~24 KB of I/O buffers, so
 * the operator's max_slots is a memory budget they can compute.
 *
 * TIME IS AN ARGUMENT, not a syscall: evloop_run_once() takes `now_ms`. That
 * is what makes deadline behaviour testable exactly -- a test can prove a
 * connection is still alive one millisecond before its deadline and gone one
 * millisecond after, which a wall-clock test could only do flakily.
 */

typedef enum {
    SLOT_FREE = 0,
    SLOT_ACTIVE,      /* reading frames / writing replies */
    SLOT_DRAINING     /* flush what is queued, then close */
} slot_state_t;

/* Which pool a slot belongs to, and therefore how its bytes are framed. */
typedef enum {
    SLOT_KIND_PROTO = 0,   /* framed: the handshake/record listeners */
    SLOT_KIND_LOCAL        /* line-oriented: the local API sockets (spec 8) */
} slot_kind_t;

typedef struct {
    int          fd;            /* -1 when free */
    slot_kind_t  kind;
    listener_peer_t peer;       /* LOCAL only: uid/pid, for the log (spec 8) */
    int          is_admin;      /* LOCAL only: which dispatch table applies */
    slot_state_t state;
    conn_io_t    io;
    uint64_t     deadline_ms;   /* absolute; 0 = none */
    uint64_t     opened_ms;
    size_t       index;
    void        *user;          /* V4-8b hangs the connection state machine here */
} authd_slot_t;

typedef enum {
    EV_ACTION_CONTINUE = 0,   /* keep the connection open */
    EV_ACTION_CLOSE           /* finish sending anything queued, then close */
} ev_action_t;

/* Called for each complete frame. The callback may queue exactly one reply
 * with conn_io_queue(&slot->io, ...). It must not block. */
typedef ev_action_t (*evloop_on_frame_fn)(void *user, authd_slot_t *slot,
                                          const uint8_t *payload, size_t len);

/* Called for each complete LF-terminated request line on a LOCAL slot. Same
 * contract as on_frame: queue at most one reply, never block. */
typedef ev_action_t (*evloop_on_line_fn)(void *user, authd_slot_t *slot,
                                         const uint8_t *line, size_t len);

/* Called when a slot is released, so V4-8b can wipe its handshake state. */
typedef void (*evloop_on_close_fn)(void *user, authd_slot_t *slot);

/* Four: the loopback/tunnel listener, the proxy-facing Unix socket, and the
 * two local-API sockets (site + admin). V4-8a sized this at 2 when only the
 * protocol listeners existed; the local API needs two more, and exceeding it
 * is a silent no-service rather than an error, so the number is stated here
 * next to what occupies it. */
#define AUTHD_MAX_LISTENERS 4u

/* Upper bound on slots the loop will poll in one iteration. Equal to
 * AUTHD_SLOTS_MAX in authd_config.h; the poll arrays are static and sized from
 * it, so the loop allocates nothing even at maximum capacity. */
#define AUTHD_SLOTS_POLL_MAX 4096u

typedef struct {
    authd_slot_t *slots;         /* PROTO pool */
    size_t        n_slots;
    size_t        in_use;

    /* The local API gets its OWN pool. Sharing one would let a burst of
     * handshakes occupy every slot and lock the site out of EXCHANGE -- the
     * site would be unable to complete a login precisely when logins are
     * busiest. Separate pools make that impossible rather than unlikely. */
    authd_slot_t *local_slots;
    size_t        n_local_slots;
    size_t        local_in_use;

    int         listen_fd[AUTHD_MAX_LISTENERS];
    slot_kind_t listen_kind[AUTHD_MAX_LISTENERS];
    int         listen_is_admin[AUTHD_MAX_LISTENERS];
    uid_t       listen_allow[AUTHD_MAX_LISTENERS][LISTENER_MAX_ALLOW];
    size_t      listen_n_allow[AUTHD_MAX_LISTENERS];
    size_t n_listeners;

    uint32_t handshake_timeout_ms;   /* deadline applied to a fresh connection */
    uint32_t idle_timeout_ms;        /* deadline re-armed after each frame */

    int stopping;                    /* set by evloop_stop(): drain, accept no more */

    evloop_on_frame_fn on_frame;
    evloop_on_line_fn  on_line;
    evloop_on_close_fn on_close;
    void *user;

    /* counters, for tests and for the operator */
    uint64_t accepted;
    uint64_t refused_no_slot;
    uint64_t closed_deadline;
    uint64_t closed_protocol;
    uint64_t closed_peer;
    uint64_t local_accepted;
    uint64_t local_refused_no_slot;
} evloop_t;

/* `slots` must have room for `n_slots` and outlive the loop. */
int evloop_init(evloop_t *ev, authd_slot_t *slots, size_t n_slots,
                uint32_t handshake_timeout_ms, uint32_t idle_timeout_ms,
                evloop_on_frame_fn on_frame, evloop_on_close_fn on_close, void *user);

/* Registers a framed listener (no peer check). At most AUTHD_MAX_LISTENERS. */
int evloop_add_listener(evloop_t *ev, int fd, uid_t require_uid);

/* Registers a LINE-oriented local-API listener: its connections come from the
 * local pool, are dispatched to on_line, and are accepted only from a uid in
 * `allow`. `is_admin` selects the dispatch table -- admin commands are absent
 * from the site table rather than refused by a flag (Req 11). */
int evloop_add_local_listener(evloop_t *ev, int fd, const uid_t *allow, size_t n_allow, int is_admin);

/* Attaches the local pool and the line callback. Both are required before a
 * local listener is added. */
int evloop_set_local(evloop_t *ev, authd_slot_t *local_slots, size_t n_local_slots,
                     evloop_on_line_fn on_line);

size_t evloop_local_active(const evloop_t *ev);

/* One iteration: poll, accept, read, dispatch frames, write, expire deadlines.
 * `poll_timeout_ms` is passed to poll() (-1 blocks). Returns the number of
 * slots that saw activity, or -1 on a fatal error. */
int evloop_run_once(evloop_t *ev, int poll_timeout_ms, uint64_t now_ms);

/* Begin a graceful drain: stop accepting, let queued writes flush, close
 * connections as they finish. evloop_active() reaches 0 when done. */
void evloop_stop(evloop_t *ev);

size_t evloop_active(const evloop_t *ev);

/* Closes every slot (and calls on_close for each). Listeners are NOT closed
 * here -- the caller owns them. */
void evloop_close_all(evloop_t *ev);

/* Immediately releases one slot: wipes its buffers, closes its fd. */
void evloop_close_slot(evloop_t *ev, authd_slot_t *s);

#endif /* MLDSA_AUTHD_EVLOOP_H */
