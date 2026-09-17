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
#include "authd_conn.h"
#include "authd_log.h"
#include "authd_secret.h"
#include "conn_io.h"
#include "evloop.h"
#include "keyfile.h"
#include "listener.h"
#include "localapi.h"
#include "tokens.h"
#include "secure_mem.h"
#include "store.h"

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
        /* Spec 13: 3 = configuration error, distinct from 1 = operation
         * failed. An operator's start-up script can tell "your config is
         * wrong" from "the key would not open" without parsing prose. */
        return 3;
    }
    /* The filesystem half of validation, shared with authd_admin --check-config
     * so there is ONE validator with two entry points. It catches the case
     * AUTHD_PATH_MAX (255) makes possible and sun_path (104/108) makes fatal:
     * a socket path every byte-level check accepts and no kernel can bind. */
    {
        char detail[AUTHD_CONFIG_DETAIL_MAX];
        const authd_config_status_t ps = authd_config_check_paths(&cfg, detail, sizeof detail);
        if (ps != AUTHD_CFG_OK) {
            fprintf(stderr, "mldsa-authd: %s: %s\n", cfg_path, detail);
            return 3;
        }
    }
    if (check_only) {
        printf("mldsa-authd: %s is valid (max_slots=%u handshake_timeout_ms=%u "
               "idle_timeout_ms=%u pad_bucket=%u)\n",
               cfg_path, cfg.max_slots, cfg.handshake_timeout_ms,
               cfg.idle_timeout_ms, cfg.pad_bucket);
        return 0;
    }

    /* The pending ledger caps CONCURRENT handshakes at HANDSHAKE_PENDING_MAX
     * (256) regardless of max_slots, until V4-12's init_ext. Its TTL is the
     * handshake timeout, and the library requires the timeout not to exceed
     * the TTL -- the same invariant demo_app.c enforces -- so a config that
     * violates it is refused HERE rather than producing expired entries under
     * load. */
    const size_t ledger_cap = ((size_t)cfg.max_slots < (size_t)HANDSHAKE_PENDING_MAX)
                                  ? (size_t)cfg.max_slots
                                  : (size_t)HANDSHAKE_PENDING_MAX;

    /* Slots and connections: two allocations, at startup, sized by the
     * operator's budget. After this neither the loop nor the connection layer
     * allocates anything per connection. */
    authd_slot_t *slots = calloc((size_t)cfg.max_slots, sizeof *slots);
    authd_conn_t *conns = calloc((size_t)cfg.max_slots, sizeof *conns);
    if (slots == NULL || conns == NULL) {
        fprintf(stderr, "mldsa-authd: cannot allocate %u slots\n", cfg.max_slots);
        free(slots); free(conns);
        return 1;
    }

    /* The server identity: opened from its MLDSAEK1 envelope with the
     * passphrase file, returning the KEK so the store can derive its audit
     * key (spec 9.2.4). The passphrase and the KEK are wiped as soon as they
     * have done their jobs; the secret key stays in secure memory. */
    static authd_app_t app;
    memset(&app, 0, sizeof app);

    mldsa_keypair_t server_kp;
    memset(&server_kp, 0, sizeof server_kp);
    uint8_t *kek = secure_mem_alloc(STORE_KEK_BYTES);
    if (kek == NULL) {
        free(slots); free(conns);
        return 1;
    }
    {
        size_t pass_len = 0;
        uint8_t *pass = NULL;
        const authd_secret_status_t ps = authd_secret_read(cfg.key_passphrase_file, &pass, &pass_len);
        if (ps != AUTHD_SECRET_OK) {
            fprintf(stderr, "mldsa-authd: passphrase file %s: %s\n",
                    cfg.key_passphrase_file, authd_secret_status_name(ps));
            secure_mem_free(kek, STORE_KEK_BYTES);
            free(slots); free(conns);
            return 3;
        }
        const keyfile_status_t ks = keyfile_open(cfg.key_path, cfg.server_id, cfg.server_id_len,
                                                 (const char *)pass, pass_len, &server_kp, kek);
        authd_secret_free(pass, pass_len);
        if (ks != KEYFILE_OK) {
            fprintf(stderr, "mldsa-authd: %s: %s\n", cfg.key_path, keyfile_status_name(ks));
            secure_mem_free(kek, STORE_KEK_BYTES);
            free(slots); free(conns);
            return 1;
        }
    }

    store_t *store = NULL;
    {
        const store_status_t ss = store_open(cfg.store_path, kek, &store);
        secure_mem_free(kek, STORE_KEK_BYTES);   /* the store holds its own derived key now */
        kek = NULL;
        if (ss != STORE_OK) {
            fprintf(stderr, "mldsa-authd: %s: %s\n", cfg.store_path, store_status_name(ss));
            mldsa_keypair_free(&server_kp);
            free(slots); free(conns);
            return 1;
        }
    }

    app.conns = conns;
    app.n_conns = (size_t)cfg.max_slots;
    app.store = store;
    app.server_kp = &server_kp;
    app.server_id = cfg.server_id;
    app.server_id_len = cfg.server_id_len;
    app.pad_bucket = cfg.pad_bucket;
    app.code_ttl_s = AUTHD_LOGIN_CODE_TTL_S;
    app.now_ms = now_ms();
    app.now_unix = (int64_t)time(NULL);
    app.started_ms = app.now_ms;

    static handshake_pending_store_t pending;
    if (handshake_pending_store_init(&pending, ledger_cap, (uint64_t)cfg.handshake_timeout_ms,
                                     authd_app_clock, &app) != PENDING_OK) {
        fprintf(stderr, "mldsa-authd: pending ledger init failed\n");
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns);
        return 1;
    }
    app.pending = &pending;

    /* The local API gets its own pool, so a burst of handshakes can never lock
     * the site out of EXCHANGE (spec 8 / V4-9a decision 1). */
    authd_slot_t *local_slots = calloc((size_t)cfg.max_local_slots, sizeof *local_slots);
    if (local_slots == NULL) {
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns);
        return 1;
    }

    evloop_t ev;
    if (evloop_init(&ev, slots, (size_t)cfg.max_slots,
                    cfg.handshake_timeout_ms, cfg.idle_timeout_ms,
                    authd_conn_on_frame, authd_conn_on_close, &app) != 0) {
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns); free(local_slots);
        fprintf(stderr, "mldsa-authd: event loop init failed\n");
        return 1;
    }
    app.ev = &ev;
    if (evloop_set_local(&ev, local_slots, (size_t)cfg.max_local_slots, localapi_on_line) != 0) {
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns); free(local_slots);
        fprintf(stderr, "mldsa-authd: local pool init failed\n");
        return 1;
    }

    /* All four listener fds and paths are declared TOGETHER, before the first
     * failure path that can jump to listener_failed. Declaring the local pair
     * further down would mean a goto from the protocol listeners jumped over
     * their initialisers, and the epilogue would then close indeterminate
     * descriptors -- a worse bug than the leak this epilogue exists to fix. */
    int tcp_fd = -1, unix_fd = -1, site_fd = -1, admin_fd = -1;
    const char *unix_path = (cfg.listen_unix[0] != '\0') ? cfg.listen_unix : NULL;
    const char *site_path = (cfg.site_socket[0] != '\0') ? cfg.site_socket : NULL;
    const char *admin_path = (cfg.admin_socket[0] != '\0') ? cfg.admin_socket : NULL;

    if (cfg.listen_port != 0u) {
        uint16_t bound = 0;
        const listener_status_t ls = listener_open_loopback(cfg.listen_port, 64, &tcp_fd, &bound);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: loopback listener: %s\n", listener_status_name(ls));
            goto listener_failed;
        }
        /* Checked, like the two local listeners below. AUTHD_MAX_LISTENERS is
         * finite and a silent -1 here would leave a bound socket that nothing
         * ever polls: the daemon would log "listening" and serve nobody. That
         * exact defect cost V4-9a a debugging session when the limit was 2. */
        if (evloop_add_listener(&ev, tcp_fd, (uid_t)-1) != 0) {
            fprintf(stderr, "mldsa-authd: cannot register the loopback listener\n");
            goto listener_failed;
        }
        authd_log_num(AUTHD_LOG_INFO, "listening-loopback", "port", (uint64_t)bound);
    }
    if (unix_path != NULL) {
        const listener_status_t ls = listener_open_unix(unix_path, 64, LISTENER_MODE_GROUP, &unix_fd);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: unix listener %s: %s\n", unix_path, listener_status_name(ls));
            goto listener_failed;
        }
        /* V4-10 adds the proxy uid check; today this relies on the 0660 mode. */
        if (evloop_add_listener(&ev, unix_fd, (uid_t)-1) != 0) {
            fprintf(stderr, "mldsa-authd: cannot register the unix listener\n");
            goto listener_failed;
        }
        authd_log_event(AUTHD_LOG_INFO, "listening-unix");
    }

    /* The two local sockets. site.sock is 0660 (the site's group), admin.sock
     * is 0600 (spec 8), and each has its own uid allowlist; the admin table is
     * simply not reachable from the site socket. */
    if (site_path != NULL) {
        const listener_status_t ls = listener_open_unix(site_path, 16, LISTENER_MODE_GROUP, &site_fd);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: site socket %s: %s\n", site_path, listener_status_name(ls));
            goto listener_failed;
        }
        if (evloop_add_local_listener(&ev, site_fd, cfg.site_uids, cfg.n_site_uids, 0) != 0) {
            fprintf(stderr, "mldsa-authd: cannot register the site listener\n");
            goto listener_failed;
        }
        authd_log_event(AUTHD_LOG_INFO, "listening-site");
    }
    if (admin_path != NULL) {
        const listener_status_t ls = listener_open_unix(admin_path, 16, LISTENER_MODE_PRIVATE, &admin_fd);
        if (ls != LISTENER_OK) {
            fprintf(stderr, "mldsa-authd: admin socket %s: %s\n", admin_path, listener_status_name(ls));
            goto listener_failed;
        }
        if (evloop_add_local_listener(&ev, admin_fd, cfg.admin_uids, cfg.n_admin_uids, 1) != 0) {
            fprintf(stderr, "mldsa-authd: cannot register the admin listener\n");
            goto listener_failed;
        }
        authd_log_event(AUTHD_LOG_INFO, "listening-admin");
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
        /* One clock, pushed to both: the loop and the connection layer see
         * the same instant, so ledger expiry, session limits and login-code
         * expiry cannot disagree. */
        app.now_ms = now_ms();
        app.now_unix = (int64_t)time(NULL);
        authd_app_maybe_sweep(&app);
        if (evloop_run_once(&ev, draining ? 50 : 1000, app.now_ms) < 0) {
            if (errno == EINTR) {
                continue;
            }
            authd_log_event(AUTHD_LOG_ERROR, "loop-failed");
            break;
        }
    }

    authd_log_num(AUTHD_LOG_INFO, "stopped", "accepted", ev.accepted);
    authd_log_num(AUTHD_LOG_INFO, "stopped", "logins", app.logins_issued);
    evloop_close_all(&ev);
    listener_close(&tcp_fd, NULL);
    listener_close(&unix_fd, unix_path);
    listener_close(&site_fd, site_path);
    listener_close(&admin_fd, admin_path);
    handshake_pending_store_wipe(&pending);
    store_close(store);
    mldsa_keypair_free(&server_kp);
    sodium_memzero(conns, (size_t)cfg.max_slots * sizeof *conns);
    free(conns);
    free(slots);
    free(local_slots);
    return 0;

listener_failed:
    listener_close(&site_fd, site_path);
    listener_close(&admin_fd, admin_path);
    listener_close(&tcp_fd, NULL);
    listener_close(&unix_fd, unix_path);
    handshake_pending_store_wipe(&pending);
    store_close(store);
    mldsa_keypair_free(&server_kp);
    free(conns); free(slots); free(local_slots);
    return 1;
}
