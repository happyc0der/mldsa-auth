#ifndef MLDSA_AUTHD_SDNOTIFY_H
#define MLDSA_AUTHD_SDNOTIFY_H

#include <stdint.h>

/*
 * systemd's readiness notification, without libsystemd (V4-104).
 *
 * The unit is Type=notify, so `systemctl start` and `restart` return only
 * once the daemon has said READY=1 -- after its key is unsealed and every
 * listener is bound -- rather than as soon as the process forks. Before this
 * a login sent straight after a restart found nothing listening (measured in
 * the runbook rehearsal: `cannot connect`), because unsealing the server key
 * is an Argon2id of 256 MiB.
 *
 * The protocol is one datagram to the AF_UNIX socket named by $NOTIFY_SOCKET:
 * an absolute path, or '@' for Linux's abstract namespace. Anything else (a
 * relative path, vsock:...) is refused rather than guessed at.
 *
 * Returns 1 when the datagram was sent, 0 when $NOTIFY_SOCKET is unset or
 * empty (not under systemd -- nothing to do), -1 when it is set and the
 * notification could not be sent.
 *
 * The socket is opened by the first call that sends and KEPT (F437), so a
 * later shortage of descriptors, the process's or the system's, cannot stop
 * the watchdog ping. authd_sd_notify_close() closes it: at exit, and in tests.
 */
int authd_sd_notify(const char *msg);

/* F702 (V4-347): 0 if $NOTIFY_SOCKET is set to something authd_sd_notify
 * can never use (a relative path, one longer than sun_path), 1 otherwise --
 * unset, empty, or usable. For the caller that would otherwise go on
 * trying. */
int authd_sd_notify_usable(void);
void authd_sd_notify_close(void);

/*
 * systemd's watchdog (F209, V4-126). A unit with WatchdogSec= expects
 * WATCHDOG=1 on the same socket more often than that, and kills a service
 * that stops sending it -- which is what restarts a daemon that hangs.
 *
 * Returns how often to send it, in milliseconds, or 0 when no watchdog is
 * set for this process: $WATCHDOG_USEC must be a positive decimal number
 * and nothing else, $WATCHDOG_PID (when set) must name this process, and
 * $NOTIFY_SOCKET must be set. The period is a quarter of the timeout, at
 * least 1 ms and at most AUTHD_SD_WATCHDOG_MAX_MS -- the event loop turns
 * at least that often, so a longer period would buy nothing.
 */
#define AUTHD_SD_WATCHDOG_MAX_MS 1000u
unsigned authd_sd_watchdog_period_ms(void);

/*
 * How long the loop may sleep with nothing to do: `idle_ms`, or less when a
 * ping falls due sooner. `since_ms` is the time since the last ping. F340:
 * the loop slept its whole idle wait whenever a ping was not yet due, so a
 * wake a millisecond early put the next ping a whole period late -- pings
 * up to twice the period apart, where spec 16 says a quarter of the
 * interval and never more than 1 s. With no watchdog (period 0), `idle_ms`.
 */
int authd_sd_watchdog_wait_ms(unsigned period_ms, uint64_t since_ms, int idle_ms);

/*
 * A ping from inside one long turn (V4-315, F541). The loop pings between
 * turns, and a BACKUP copies the whole store inside one: past WatchdogSec
 * systemd killed the daemon for a copy that was going well. The store calls
 * this back while it copies (store_set_backup_tick), with `ctx` an
 * authd_wd_tick_t. `period_ms` is authd_sd_watchdog_period_ms(); with 0
 * nothing is sent. `clock_ms` is the caller's monotonic clock.
 *
 * authd_sd_watchdog_tick_at is the decision with the time as an argument:
 * 1 when a ping was due and was sent (or tried), 0 when none was due.
 */
typedef struct {
    unsigned period_ms;
    uint64_t last_ms;
    uint64_t (*clock_ms)(void);
} authd_wd_tick_t;
int authd_sd_watchdog_tick_at(authd_wd_tick_t *t, uint64_t now_ms);
void authd_sd_watchdog_tick(void *ctx);

#endif /* MLDSA_AUTHD_SDNOTIFY_H */
