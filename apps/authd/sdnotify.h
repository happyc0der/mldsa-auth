#ifndef MLDSA_AUTHD_SDNOTIFY_H
#define MLDSA_AUTHD_SDNOTIFY_H

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

#endif /* MLDSA_AUTHD_SDNOTIFY_H */
