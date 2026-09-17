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

#include <fcntl.h>
#include <sys/stat.h>

#include "authd_config.h"
#include "authd_conn.h"
#include "authd_log.h"
#include "conn_io.h"
#include "evloop.h"
#include "keyfile.h"
#include "listener.h"
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

/* Reads the passphrase file into secure memory. Refuses anything that is not
 * a regular 0600 file of at most AUTHD_PASSPHRASE_MAX bytes: a passphrase that
 * any other user can read is not a passphrase. A single trailing newline is
 * stripped, because every editor and `systemd-creds` adds one and an operator
 * should not have to know that. Caller wipes and frees. */
static uint8_t *read_passphrase(const char *path, size_t *len_out)
{
    *len_out = 0;
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "mldsa-authd: passphrase file %s: cannot open\n", path);
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "mldsa-authd: passphrase file %s: not a regular file\n", path);
        (void)close(fd);
        return NULL;
    }
    if ((st.st_mode & 077) != 0) {
        fprintf(stderr, "mldsa-authd: passphrase file %s: mode must be 0600\n", path);
        (void)close(fd);
        return NULL;
    }
    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX) {
        fprintf(stderr, "mldsa-authd: passphrase file %s: empty or over %u bytes\n",
                path, (unsigned)AUTHD_PASSPHRASE_MAX);
        (void)close(fd);
        return NULL;
    }
    uint8_t *buf = secure_mem_alloc((size_t)st.st_size);
    if (buf == NULL) {
        (void)close(fd);
        return NULL;
    }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        const ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
    }
    (void)close(fd);
    if (got != (size_t)st.st_size) {
        secure_mem_free(buf, (size_t)st.st_size);
        return NULL;
    }
    if (got > 0u && buf[got - 1u] == (uint8_t)'\n') {
        got--;
    }
    *len_out = got;
    return buf;
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
        uint8_t *pass = read_passphrase(cfg.key_passphrase_file, &pass_len);
        if (pass == NULL) {
            secure_mem_free(kek, STORE_KEK_BYTES);
            free(slots); free(conns);
            return 1;
        }
        const keyfile_status_t ks = keyfile_open(cfg.key_path, cfg.server_id, cfg.server_id_len,
                                                 (const char *)pass, pass_len, &server_kp, kek);
        secure_mem_free(pass, pass_len);
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

    static handshake_pending_store_t pending;
    if (handshake_pending_store_init(&pending, ledger_cap, (uint64_t)cfg.handshake_timeout_ms,
                                     authd_app_clock, &app) != PENDING_OK) {
        fprintf(stderr, "mldsa-authd: pending ledger init failed\n");
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns);
        return 1;
    }
    app.pending = &pending;

    evloop_t ev;
    if (evloop_init(&ev, slots, (size_t)cfg.max_slots,
                    cfg.handshake_timeout_ms, cfg.idle_timeout_ms,
                    authd_conn_on_frame, authd_conn_on_close, &app) != 0) {
        store_close(store); mldsa_keypair_free(&server_kp);
        free(slots); free(conns);
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
        /* One clock, pushed to both: the loop and the connection layer see
         * the same instant, so ledger expiry, session limits and login-code
         * expiry cannot disagree. */
        app.now_ms = now_ms();
        app.now_unix = (int64_t)time(NULL);
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
    handshake_pending_store_wipe(&pending);
    store_close(store);
    mldsa_keypair_free(&server_kp);
    sodium_memzero(conns, (size_t)cfg.max_slots * sizeof *conns);
    free(conns);
    free(slots);
    return 0;
}
