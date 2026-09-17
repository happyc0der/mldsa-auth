/*
 * mldsa-authd (V4-8a): the daemon's entry point, its listeners and its loop.
 *
 * V4-8a is the TRANSPORT SKELETON. It validates configuration, opens the
 * listeners, accepts connections into a fixed slot pool, reassembles frames,
 * enforces deadlines and drains cleanly on SIGTERM. It does NOT yet speak the
 * protocol: a complete frame is logged and the connection is closed. V4-8b
 * replaces the frame handler with the connection state machine (handshake,
 * decoy flow, LOGIN_CODE) and that is when the daemon becomes usable.
 *
 * Saying that here, rather than shipping a handler that looks like it works,
 * is the point: a half-implemented protocol that answers is worse than one
 * that refuses.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_config.h"
#include "authd_log.h"
#include "conn_io.h"
#include "evloop.h"
#include "listener.h"

/* Set by the signal handler; read by the loop. sig_atomic_t and nothing else
 * happens in the handler -- no logging, no allocation, no close(). */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
    }
#endif
    return 0u;
}

static ev_action_t frame_not_implemented(void *user, authd_slot_t *slot,
                                         const uint8_t *payload, size_t len)
{
    (void)user; (void)payload;
    authd_log_num(AUTHD_LOG_WARN, "frame-not-implemented", "bytes", (uint64_t)len);
    authd_log_slot(AUTHD_LOG_INFO, "closing-unserved", slot->index);
    return EV_ACTION_CLOSE;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s --config PATH [--check-config]\n"
            "  --config PATH    the daemon configuration file\n"
            "  --check-config   validate the configuration and exit (0 = valid)\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *cfg_path = NULL;
    int check_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (strcmp(argv[i], "--check-config") == 0) {
            check_only = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (cfg_path == NULL) {
        usage(argv[0]);
        return 2;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "mldsa-authd: libsodium failed to initialise\n");
        return 1;
    }
    authd_log_init(stderr, AUTHD_LOG_INFO);

    authd_config_t cfg;
    size_t err_line = 0;
    const authd_config_status_t cs = authd_config_load(cfg_path, &cfg, &err_line);
    if (cs != AUTHD_CFG_OK) {
        /* The operator sees the refusal before systemd starts the service --
         * which is the whole reason --check-config exists. */
        fprintf(stderr, "mldsa-authd: %s: %s", cfg_path, authd_config_status_name(cs));
        if (err_line > 0u) {
            fprintf(stderr, " at line %zu", err_line);
        }
        fprintf(stderr, "\n");
        return 1;
    }
    if (check_only) {
        printf("mldsa-authd: %s is valid (max_slots=%u handshake_timeout_ms=%u "
               "idle_timeout_ms=%u pad_bucket=%u)\n",
               cfg_path, cfg.max_slots, cfg.handshake_timeout_ms,
               cfg.idle_timeout_ms, cfg.pad_bucket);
        return 0;
    }

    /* Slots: one allocation, at startup, sized by the operator's budget. After
     * this the loop allocates nothing. */
    authd_slot_t *slots = calloc((size_t)cfg.max_slots, sizeof *slots);
    if (slots == NULL) {
        fprintf(stderr, "mldsa-authd: cannot allocate %u slots\n", cfg.max_slots);
        return 1;
    }

    evloop_t ev;
    if (evloop_init(&ev, slots, (size_t)cfg.max_slots,
                    cfg.handshake_timeout_ms, cfg.idle_timeout_ms,
                    frame_not_implemented, NULL, NULL) != 0) {
        free(slots);
        fprintf(stderr, "mldsa-authd: event loop init failed\n");
        return 1;
    }

    int tcp_fd = -1, unix_fd = -1;
    const char *unix_path = (cfg.listen_unix[0] != '\0') ? cfg.listen_unix : NULL;

    if (cfg.listen_port != 0u) {
        uint16_t bound = 0;
        const listener_status_t ls = listener_open_loopback(cfg.listen_port, 64, &tcp_fd, &bound);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: loopback listener: %s\n", listener_status_name(ls));
            free(slots);
            return 1;
        }
        (void)evloop_add_listener(&ev, tcp_fd, (uid_t)-1);
        authd_log_num(AUTHD_LOG_INFO, "listening-loopback", "port", (uint64_t)bound);
    }
    if (unix_path != NULL) {
        const listener_status_t ls = listener_open_unix(unix_path, 64, &unix_fd);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: unix listener %s: %s\n", unix_path, listener_status_name(ls));
            listener_close(&tcp_fd, NULL);
            free(slots);
            return 1;
        }
        /* V4-8b adds the proxy uid check; V4-8a relies on the 0660 mode. */
        (void)evloop_add_listener(&ev, unix_fd, (uid_t)-1);
        authd_log_event(AUTHD_LOG_INFO, "listening-unix");
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);   /* a peer that vanishes mid-write is routine */

    authd_log_event(AUTHD_LOG_INFO, "started");

    int draining = 0;
    for (;;) {
        if (g_stop && !draining) {
            authd_log_event(AUTHD_LOG_INFO, "draining");
            evloop_stop(&ev);
            draining = 1;
        }
        if (draining && evloop_active(&ev) == 0u) {
            break;
        }
        if (evloop_run_once(&ev, draining ? 50 : 1000, now_ms()) < 0) {
            if (errno == EINTR) {
                continue;
            }
            authd_log_event(AUTHD_LOG_ERROR, "loop-failed");
            break;
        }
    }

    authd_log_num(AUTHD_LOG_INFO, "stopped", "accepted", ev.accepted);
    evloop_close_all(&ev);
    listener_close(&tcp_fd, NULL);
    listener_close(&unix_fd, unix_path);
    free(slots);
    return 0;
}
