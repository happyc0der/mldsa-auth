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
 */
int authd_sd_notify(const char *msg);

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

#endif /* MLDSA_AUTHD_SDNOTIFY_H */
