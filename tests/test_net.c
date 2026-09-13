/*
 * Step 6 reference transport tests (spec §6.5): framing, socket I/O, the
 * reference server/client connection logic, and demo key files -- over real
 * loopback TCP.
 *
 * Topology: the parent generates identities A (client "alice"), B (server
 * "bob") and C (impostor "carol") in memory -- no key file is ever written
 * outside a mkdtemp() directory. A forked SERVER child runs
 * demo_server_handle_connection() once and reports its result over a pipe.
 * An optional forked PROXY child sits between client and server and injects
 * faults deterministically (1-byte fragmentation, byte flips, dropped frames,
 * closes at exact byte offsets). RAW peers drive the library directly to
 * send hand-built frames. Processes, not threads: no threading library is used.
 *
 * No hangs: every blocking call has a deadline, and the parent kills any
 * child that has not reported within CHILD_WAIT_MS. SIGPIPE is deliberately
 * NOT ignored in this test: an unprotected write to a closed socket would
 * kill the process and fail the run.
 *
 * Numbering follows the approved Step 6 plan (T1-T16; E2E is
 * tests/demo_e2e.sh).
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sodium.h>

#include "demo_app.h"
#include "demo_keys.h"
#include "frame.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "session.h"
#include "transcript.h"

static int g_failures = 0;

#define CHECK(cond, name)                    \
    do {                                      \
        if (cond) {                           \
            printf("PASS: %s\n", name);       \
        } else {                               \
            printf("FAIL: %s\n", name);       \
            g_failures++;                      \
        }                                      \
    } while (0)

static void fatal(const char *what) {
    fprintf(stderr, "FATAL fixture failure: %s (errno %d)\n", what, errno);
    exit(EXIT_FAILURE);
}

/* ---------------------------------------------------------------------
 * Fixture
 * ------------------------------------------------------------------- */

static const uint8_t ID_A[] = {'a', 'l', 'i', 'c', 'e'};
static const uint8_t ID_B[] = {'b', 'o', 'b'};
/* C ("carol") is only ever used as a KEY: the wrong key pinned for alice or bob. */

static mldsa_keypair_t g_kp_a, g_kp_b, g_kp_c;
static keystore_t g_srv_pins_ok;    /* alice -> A */
static keystore_t g_srv_pins_wrong; /* alice -> C's key */
static keystore_t g_cli_pins_ok;    /* bob -> B */
static keystore_t g_cli_pins_wrong; /* bob -> C's key */
static handshake_pending_store_t g_child_store;  /* used by server children */
static handshake_pending_store_t g_parent_store; /* in-process handshakes (T8a) */
static demo_buffers_t *g_cli_buf;

#define TEST_HS_MS 2000u
#define TEST_IDLE_MS 2000u
#define CHILD_WAIT_MS 20000u
#define OPS_MS 5000u

/* Exact frame sizes for alice <-> bob (ML-DSA-65 signatures are fixed-length). */
#define CH_PAYLOAD \
    (1u + 1u + sizeof(ID_A) + WIRE_X25519_PUB_LEN + WIRE_MLKEM_EK_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN)
#define CH_FRAME (FRAME_HEADER_BYTES + CH_PAYLOAD)
#define CA_FRAME (FRAME_HEADER_BYTES + CLIENT_AUTH_MAX_ENCODED_LEN)
#define CONFIRM_FRAME (FRAME_HEADER_BYTES + FRAME_CONFIRM_LEN)
static size_t sh_frame_len(void) {
    return FRAME_HEADER_BYTES + transcript_server_hello_unsigned_len((uint8_t)sizeof(ID_B)) + 2u +
           MLDSA_SIGNATURE_MAX_BYTES;
}

/* ---- log capture ---------------------------------------------------------- */

typedef struct {
    char data[16384];
    size_t len;
} logcap_t;

static void logcap_fn(void *ctx, const char *line) {
    logcap_t *l = (logcap_t *)ctx;
    const size_t n = strlen(line);
    if (l->len + n + 2u < sizeof(l->data)) {
        memcpy(l->data + l->len, line, n);
        l->len += n;
        l->data[l->len++] = '\n';
        l->data[l->len] = '\0';
    }
}

static demo_config_t make_cfg(int client, const keystore_t *pins, uint64_t hs_ms, uint64_t idle_ms, logcap_t *log) {
    demo_config_t c;
    memset(&c, 0, sizeof(c));
    c.local_id = client ? ID_A : ID_B;
    c.local_id_len = client ? sizeof(ID_A) : sizeof(ID_B);
    c.local_kp = client ? &g_kp_a : &g_kp_b;
    c.pins = pins;
    if (client) {
        c.peer_id = ID_B;
        c.peer_id_len = sizeof(ID_B);
    }
    c.handshake_timeout_ms = hs_ms;
    c.idle_timeout_ms = idle_ms;
    c.log.fn = logcap_fn; /* every test captures its logs (T10 inspects them) */
    c.log.ctx = log;
    return c;
}

/* ---- EINTR storm (T12) ----------------------------------------------------- */

static volatile sig_atomic_t g_alarms = 0;
static void on_alarm(int sig) {
    (void)sig;
    g_alarms = g_alarms + 1;
}
static void storm_start(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* NO SA_RESTART: blocking calls fail with EINTR */
    if (sigaction(SIGALRM, &sa, NULL) != 0) {
        fatal("sigaction");
    }
    struct itimerval it;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 500;
    it.it_value = it.it_interval;
    if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
        fatal("setitimer");
    }
}
static void storm_stop(void) {
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    (void)setitimer(ITIMER_REAL, &it, NULL);
}

/* ---- child plumbing ---------------------------------------------------------- */

typedef struct {
    pid_t pid;
    int fd; /* read end of the result pipe */
} child_t;

static void write_full(int fd, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    size_t off = 0;
    while (off < n) {
        const ssize_t w = write(fd, b + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            _exit(3);
        }
        off += (size_t)w;
    }
}

static int read_full_timeout(int fd, void *p, size_t n, uint64_t timeout_ms) {
    uint8_t *b = (uint8_t *)p;
    size_t off = 0;
    const uint64_t deadline = net_deadline_in(timeout_ms);
    while (off < n) {
        const uint64_t now = net_now_ms();
        if (now >= deadline) {
            return -1;
        }
        struct pollfd pf = {fd, POLLIN, 0};
        const int pr = poll(&pf, 1, (int)(deadline - now));
        if (pr < 0 && errno == EINTR) {
            continue;
        }
        if (pr <= 0) {
            return -1;
        }
        const ssize_t r = read(fd, b + off, n - off);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

/* Reads the child's report, then reaps it. A child that does not report in
 * time is killed. Returns 1 iff the report arrived and the child exited 0. */
static int collect(child_t *c, void *out, size_t len) {
    const int got = (read_full_timeout(c->fd, out, len, CHILD_WAIT_MS) == 0);
    if (!got) {
        (void)kill(c->pid, SIGKILL);
    }
    int st = 0;
    while (waitpid(c->pid, &st, 0) < 0 && errno == EINTR) {
    }
    (void)close(c->fd);
    return got && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static child_t spawn(void (*body)(int wfd, const void *arg), const void *arg) {
    int p[2];
    if (pipe(p) != 0) {
        fatal("pipe");
    }
    const pid_t pid = fork();
    if (pid < 0) {
        fatal("fork");
    }
    if (pid == 0) {
        (void)close(p[0]);
        body(p[1], arg);
        _exit(0);
    }
    (void)close(p[1]);
    child_t c = {pid, p[0]};
    return c;
}

/* ---- server child ------------------------------------------------------------ */

typedef struct {
    int listen_fd;
    const keystore_t *pins;
    uint64_t hs_ms;
    uint64_t idle_ms;
    int storm;
} server_opts_t;

typedef struct {
    int accepted;
    demo_result_t res;
    int buffers_zero;
    uint64_t elapsed_ms; /* accept -> handler return */
    logcap_t log;
} server_report_t;

static server_report_t g_srv_rep;

static void server_body(int wfd, const void *arg) {
    const server_opts_t *o = (const server_opts_t *)arg;
    server_report_t *rep = calloc(1, sizeof(*rep));
    demo_buffers_t *buf = calloc(1, sizeof(*buf));
    if (rep == NULL || buf == NULL ||
        handshake_pending_store_init(&g_child_store, 8, HANDSHAKE_PENDING_TTL_MS_DEFAULT, NULL, NULL) != PENDING_OK) {
        _exit(4);
    }
    demo_config_t cfg = make_cfg(0, o->pins, o->hs_ms, o->idle_ms, &rep->log);
    if (o->storm) {
        storm_start();
    }
    net_conn_t conn;
    if (net_accept(o->listen_fd, net_deadline_in(OPS_MS), &conn) == NET_OK) {
        rep->accepted = 1;
        const uint64_t t0 = net_now_ms();
        (void)demo_server_handle_connection(&cfg, &g_child_store, &conn, buf, &rep->res);
        rep->elapsed_ms = net_now_ms() - t0;
        rep->buffers_zero = sodium_is_zero((const unsigned char *)buf, sizeof(*buf));
    }
    storm_stop();
    write_full(wfd, rep, sizeof(*rep));
}

/* Listens on an ephemeral loopback port and forks the server child. */
static child_t start_server(const keystore_t *pins, uint64_t hs_ms, uint64_t idle_ms, int storm, uint16_t *port) {
    int lfd = -1;
    if (net_listen_loopback(0, 4, &lfd, port) != NET_OK) {
        fatal("listen (server)");
    }
    server_opts_t o = {lfd, pins, hs_ms, idle_ms, storm};
    child_t c = spawn(server_body, &o);
    net_close_fd(&lfd);
    return c;
}

/* ---- proxy child (fault injector) --------------------------------------------- */

enum { C2S = 0, S2C = 1 };

typedef struct {
    size_t chunk;         /* forward in pieces of this many bytes (0 = whole frame) */
    unsigned delay_us;    /* pause between pieces */
    int flip_dir;         /* -1: none */
    int flip_frame;
    size_t flip_offset;   /* offset within the frame, header included */
    int drop_dir;         /* -1: none */
    int drop_frame;
    int close_dir;        /* -1: none. Close both sides right after forwarding */
    uint64_t close_after; /*     exactly this many bytes in close_dir. */
} proxy_rules_t;

typedef struct {
    uint64_t frames_seen[2];
    uint64_t bytes_seen[2];
    uint64_t bytes_fwd[2];
    size_t partial[2];
    size_t sh_len;
    size_t ca_len;
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
} proxy_report_t;

typedef struct {
    int listen_fd;
    uint16_t server_port;
    proxy_rules_t rules;
} proxy_opts_t;

static proxy_report_t g_prx_rep;

static proxy_rules_t no_faults(void) {
    proxy_rules_t r;
    memset(&r, 0, sizeof(r));
    r.flip_dir = r.drop_dir = r.close_dir = -1;
    return r;
}

/* Forwards one complete frame (applying rules). Returns 0 to continue, 1 to
 * close both sides now. */
static int proxy_forward(net_conn_t *dst, int dir, uint8_t *frame, size_t flen, const proxy_rules_t *r,
                         proxy_report_t *rep) {
    const uint64_t idx = rep->frames_seen[dir] - 1u;
    if (r->drop_dir == dir && (uint64_t)r->drop_frame == idx) {
        return 0;
    }
    if (r->flip_dir == dir && (uint64_t)r->flip_frame == idx && r->flip_offset < flen) {
        frame[r->flip_offset] ^= 0x01u;
    }
    size_t off = 0;
    while (off < flen) {
        size_t piece = (r->chunk == 0) ? flen - off : r->chunk;
        if (piece > flen - off) {
            piece = flen - off;
        }
        if (r->close_dir == dir) {
            const uint64_t allowed = r->close_after - rep->bytes_fwd[dir];
            if (piece > allowed) {
                piece = (size_t)allowed;
            }
        }
        if (piece > 0) {
            if (net_write_all(dst, frame + off, piece, net_deadline_in(OPS_MS)) != NET_OK) {
                return 1;
            }
            rep->bytes_fwd[dir] += piece;
            off += piece;
        }
        if (r->close_dir == dir && rep->bytes_fwd[dir] >= r->close_after) {
            return 1;
        }
        if (r->delay_us != 0 && off < flen) {
            (void)usleep(r->delay_us);
        }
    }
    return 0;
}

static void proxy_body(int wfd, const void *arg) {
    const proxy_opts_t *o = (const proxy_opts_t *)arg;
    proxy_report_t *rep = calloc(1, sizeof(*rep));
    uint8_t *fbuf[2] = {malloc(FRAME_BUF_BYTES), malloc(FRAME_BUF_BYTES)};
    size_t have[2] = {0, 0};
    net_conn_t side[2]; /* side[C2S] = client socket (source of C2S), side[S2C] = server socket */
    if (rep == NULL || fbuf[0] == NULL || fbuf[1] == NULL) {
        _exit(4);
    }
    if (net_accept(o->listen_fd, net_deadline_in(OPS_MS), &side[C2S]) != NET_OK) {
        _exit(5);
    }
    if (net_connect_loopback(o->server_port, net_deadline_in(OPS_MS), &side[S2C]) != NET_OK) {
        _exit(6);
    }
    const uint64_t deadline = net_deadline_in(CHILD_WAIT_MS - 2000u);
    int done = 0;
    while (!done && net_now_ms() < deadline) {
        struct pollfd pf[2] = {{side[C2S].fd, POLLIN, 0}, {side[S2C].fd, POLLIN, 0}};
        const int pr = poll(pf, 2, 100);
        if (pr < 0 && errno != EINTR) {
            break;
        }
        for (int dir = 0; dir < 2 && !done && pr > 0; dir++) {
            if ((pf[dir].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                continue;
            }
            /* Read no further than the end of the current frame. */
            size_t want = FRAME_HEADER_BYTES - have[dir];
            if (have[dir] >= FRAME_HEADER_BYTES) {
                const uint32_t len = frame_get_header(fbuf[dir]);
                if (len > FRAME_MAX_PAYLOAD) {
                    done = 1;
                    break;
                }
                want = FRAME_HEADER_BYTES + len - have[dir];
            }
            const ssize_t n = recv(side[dir].fd, fbuf[dir] + have[dir], want, 0);
            if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                done = 1; /* EOF or error from one side: close both */
                break;
            }
            if (n < 0) {
                continue;
            }
            rep->bytes_seen[dir] += (uint64_t)n;
            have[dir] += (size_t)n;
            if (have[dir] >= FRAME_HEADER_BYTES &&
                have[dir] == FRAME_HEADER_BYTES + frame_get_header(fbuf[dir])) {
                const size_t flen = have[dir];
                rep->frames_seen[dir]++;
                if (dir == S2C && rep->frames_seen[dir] == 1u && flen - FRAME_HEADER_BYTES <= sizeof(rep->sh)) {
                    rep->sh_len = flen - FRAME_HEADER_BYTES;
                    memcpy(rep->sh, fbuf[dir] + FRAME_HEADER_BYTES, rep->sh_len);
                }
                if (dir == C2S && rep->frames_seen[dir] == 2u && flen - FRAME_HEADER_BYTES <= sizeof(rep->ca)) {
                    rep->ca_len = flen - FRAME_HEADER_BYTES;
                    memcpy(rep->ca, fbuf[dir] + FRAME_HEADER_BYTES, rep->ca_len);
                }
                have[dir] = 0;
                if (proxy_forward(&side[1 - dir], dir, fbuf[dir], flen, &o->rules, rep) != 0) {
                    done = 1;
                }
            }
        }
    }
    rep->partial[C2S] = have[C2S];
    rep->partial[S2C] = have[S2C];
    net_close(&side[C2S]);
    net_close(&side[S2C]);
    write_full(wfd, rep, sizeof(*rep));
}

/* ---- scenario runner ------------------------------------------------------------ */

typedef struct {
    const keystore_t *srv_pins;
    const keystore_t *cli_pins;
    uint64_t srv_hs_ms;
    uint64_t cli_hs_ms;
    int use_proxy;
    proxy_rules_t rules;
    const demo_message_t *msgs;
    size_t n_msgs;
    int storm;
    logcap_t *cli_log;
} scenario_t;

typedef struct {
    demo_result_t cli;
    int srv_ok;
    int prx_ok;
    int cli_bufs_zero;
    uint64_t cli_elapsed_ms;
} outcome_t;

static scenario_t default_scenario(void) {
    scenario_t s;
    memset(&s, 0, sizeof(s));
    s.srv_pins = &g_srv_pins_ok;
    s.cli_pins = &g_cli_pins_ok;
    s.srv_hs_ms = TEST_HS_MS;
    s.cli_hs_ms = TEST_HS_MS;
    s.rules = no_faults();
    return s;
}

static void run_scenario(const scenario_t *sc, outcome_t *out) {
    memset(out, 0, sizeof(out[0]));
    memset(&g_srv_rep, 0, sizeof(g_srv_rep));
    memset(&g_prx_rep, 0, sizeof(g_prx_rep));
    uint16_t srv_port = 0;
    child_t srv = start_server(sc->srv_pins, sc->srv_hs_ms, TEST_IDLE_MS, sc->storm, &srv_port);
    child_t prx = {-1, -1};
    uint16_t port = srv_port;
    if (sc->use_proxy) {
        int plfd = -1;
        if (net_listen_loopback(0, 4, &plfd, &port) != NET_OK) {
            fatal("listen (proxy)");
        }
        proxy_opts_t po = {plfd, srv_port, sc->rules};
        prx = spawn(proxy_body, &po);
        net_close_fd(&plfd);
    }

    logcap_t quiet;
    memset(&quiet, 0, sizeof(quiet));
    demo_config_t cfg = make_cfg(1, sc->cli_pins, sc->cli_hs_ms, TEST_IDLE_MS, sc->cli_log ? sc->cli_log : &quiet);
    if (sc->storm) {
        storm_start();
    }
    const uint64_t t0 = net_now_ms();
    net_conn_t conn;
    if (net_connect_loopback(port, net_deadline_in(OPS_MS), &conn) == NET_OK) {
        (void)demo_client_run(&cfg, &conn, sc->msgs, sc->n_msgs, g_cli_buf, &out->cli);
    } else {
        out->cli.status = DEMO_ERR_IO;
    }
    out->cli_elapsed_ms = net_now_ms() - t0;
    storm_stop();
    out->cli_bufs_zero = sodium_is_zero((const unsigned char *)g_cli_buf, sizeof(*g_cli_buf));

    out->srv_ok = collect(&srv, &g_srv_rep, sizeof(g_srv_rep));
    out->prx_ok = sc->use_proxy ? collect(&prx, &g_prx_rep, sizeof(g_prx_rep)) : 1;
}

/* ---- raw peers ------------------------------------------------------------------- */

static uint8_t g_raw[FRAME_BUF_BYTES];

static int raw_connect(uint16_t port, net_conn_t *c) {
    return net_connect_loopback(port, net_deadline_in(OPS_MS), c) == NET_OK ? 0 : -1;
}

static int raw_send(net_conn_t *c, const void *p, size_t n) {
    return net_write_all(c, (const uint8_t *)p, n, net_deadline_in(OPS_MS)) == NET_OK ? 0 : -1;
}

static int raw_send_header(net_conn_t *c, uint32_t len) {
    uint8_t h[FRAME_HEADER_BYTES];
    frame_put_header(h, len);
    return raw_send(c, h, sizeof(h));
}

/* A valid ClientHello from a throwaway initiator (alice -> bob). */
static size_t valid_client_hello(uint8_t *out) {
    handshake_ctx_t hs;
    size_t len = 0;
    if (handshake_initiator_init(&hs, ID_A, sizeof(ID_A), &g_kp_a, &g_cli_pins_ok, ID_B, sizeof(ID_B)) !=
            HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&hs, out, CLIENT_HELLO_MAX_ENCODED_LEN, &len) != HANDSHAKE_OK) {
        fatal("valid_client_hello");
    }
    handshake_ctx_wipe(&hs);
    return len;
}

/* Full initiator handshake + confirmation over c, driving the library
 * directly. Returns 0 on success with *s ACTIVE and confirmed. */
static int raw_initiator(net_conn_t *c, session_t *s) {
    handshake_ctx_t hs;
    size_t len = 0;
    size_t pt_len = 0;
    uint8_t pt[1];
    const uint64_t dl = net_deadline_in(OPS_MS);
    memset(s, 0, sizeof(*s));
    int ok = handshake_initiator_init(&hs, ID_A, sizeof(ID_A), &g_kp_a, &g_cli_pins_ok, ID_B, sizeof(ID_B)) ==
                 HANDSHAKE_OK &&
             handshake_initiator_create_client_hello(&hs, g_raw + 4, FRAME_MAX_PAYLOAD, &len) == HANDSHAKE_OK &&
             frame_send(c, g_raw, len, dl) == FRAME_OK &&
             frame_recv(c, g_raw, 1, FRAME_MAX_SERVER_HELLO, &len, dl) == FRAME_OK &&
             handshake_initiator_verify_server_hello(&hs, g_raw + 4, len) == HANDSHAKE_OK &&
             handshake_initiator_create_client_auth(&hs, g_raw + 4, FRAME_MAX_PAYLOAD, &len) == HANDSHAKE_OK &&
             frame_send(c, g_raw, len, dl) == FRAME_OK && handshake_initiator_finish(&hs) == HANDSHAKE_OK &&
             session_init_from_handshake(s, &hs, NULL, NULL, NULL) == SESSION_OK &&
             frame_recv(c, g_raw, FRAME_CONFIRM_LEN, FRAME_CONFIRM_LEN, &len, dl) == FRAME_OK &&
             session_open(s, g_raw + 4, len, pt, sizeof(pt), &pt_len) == SESSION_OK && pt_len == 0 &&
             session_is_peer_confirmed(s);
    handshake_ctx_wipe(&hs);
    return ok ? 0 : -1;
}

typedef enum { RAW_SRV_CLOSE_AFTER_CH, RAW_SRV_OVERSIZE_SH_HEADER, RAW_SRV_GARBAGE_SH } raw_srv_mode_t;
typedef struct {
    int listen_fd;
    raw_srv_mode_t mode;
} raw_srv_opts_t;

static void raw_server_body(int wfd, const void *arg) {
    const raw_srv_opts_t *o = (const raw_srv_opts_t *)arg;
    uint8_t status = 1;
    net_conn_t c;
    size_t len = 0;
    if (net_accept(o->listen_fd, net_deadline_in(OPS_MS), &c) == NET_OK &&
        frame_recv(&c, g_raw, 1, FRAME_MAX_CLIENT_HELLO, &len, net_deadline_in(OPS_MS)) == FRAME_OK) {
        status = 0;
        if (o->mode == RAW_SRV_OVERSIZE_SH_HEADER) {
            (void)raw_send_header(&c, (uint32_t)FRAME_MAX_SERVER_HELLO + 1u);
        } else if (o->mode == RAW_SRV_GARBAGE_SH) {
            memset(g_raw + 4, 0x7F, 100);
            (void)frame_send(&c, g_raw, 100, net_deadline_in(OPS_MS));
        }
        if (o->mode != RAW_SRV_CLOSE_AFTER_CH) {
            uint8_t sink[64];
            size_t got = 0;
            (void)net_read_exact(&c, sink, sizeof(sink), net_deadline_in(OPS_MS), &got); /* until the client closes */
        }
    }
    net_close(&c);
    write_full(wfd, &status, sizeof(status));
}

static child_t start_raw_server(raw_srv_mode_t mode, uint16_t *port) {
    int lfd = -1;
    if (net_listen_loopback(0, 4, &lfd, port) != NET_OK) {
        fatal("listen (raw server)");
    }
    raw_srv_opts_t o = {lfd, mode};
    child_t c = spawn(raw_server_body, &o);
    net_close_fd(&lfd);
    return c;
}

/* Client run against a raw server child. */
static void client_vs_raw_server(raw_srv_mode_t mode, demo_result_t *res, uint64_t *elapsed) {
    uint16_t port = 0;
    child_t rs = start_raw_server(mode, &port);
    logcap_t quiet;
    memset(&quiet, 0, sizeof(quiet));
    demo_config_t cfg = make_cfg(1, &g_cli_pins_ok, TEST_HS_MS, TEST_IDLE_MS, &quiet);
    net_conn_t conn;
    memset(res, 0, sizeof(*res));
    const uint64_t t0 = net_now_ms();
    if (net_connect_loopback(port, net_deadline_in(OPS_MS), &conn) == NET_OK) {
        (void)demo_client_run(&cfg, &conn, NULL, 0, g_cli_buf, res);
    } else {
        res->status = DEMO_ERR_IO;
    }
    *elapsed = net_now_ms() - t0;
    uint8_t st = 0;
    (void)collect(&rs, &st, sizeof(st));
}

/* ---- messages --------------------------------------------------------------------- */

static uint8_t g_big[DEMO_MAX_MESSAGE_BYTES];
static uint8_t g_kb[1024];
static const uint8_t g_one[1] = {0x5A};

static int server_ok(const outcome_t *o) {
    return o->srv_ok && g_srv_rep.accepted;
}

/* =====================================================================
 * T1 success, T16 buffer hygiene
 * =================================================================== */

static void test_t1_success(void) {
    const demo_message_t msgs[3] = {{g_one, sizeof(g_one)}, {g_kb, sizeof(g_kb)}, {g_big, sizeof(g_big)}};
    scenario_t sc = default_scenario();
    sc.msgs = msgs;
    sc.n_msgs = 3;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == DEMO_OK && o.cli.stage == DEMO_STAGE_GOODBYE && o.cli.messages_echoed == 3,
          "T1: client authenticates the server, is confirmed, gets 3 authenticated echoes (1 B, 1 KB, 65535 B) "
          "and exchanges GOODBYE");
    CHECK(server_ok(&o) && g_srv_rep.res.status == DEMO_OK && g_srv_rep.res.stage == DEMO_STAGE_GOODBYE &&
              g_srv_rep.res.messages_echoed == 3,
          "T1: server authenticates the client, echoes 3 messages, exchanges GOODBYE");
    CHECK(server_ok(&o) && g_srv_rep.res.pending_active_after == 0,
          "T1: no live pending-handshake entry remains on the server");
    CHECK(o.cli_bufs_zero && server_ok(&o) && g_srv_rep.buffers_zero,
          "T16: both sides' frame/plaintext buffers are all-zero after a successful connection");
}

/* =====================================================================
 * T2 fragmented delivery
 * =================================================================== */

static void test_t2_fragmented(void) {
    static const uint8_t m300[300] = {1};
    const demo_message_t msgs[2] = {{g_one, sizeof(g_one)}, {m300, sizeof(m300)}};
    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.chunk = 1;
    sc.rules.delay_us = 200;
    /* ~7 KB of handshake crosses the proxy one byte at a time: allow for it. */
    sc.srv_hs_ms = 15000;
    sc.cli_hs_ms = 15000;
    sc.msgs = msgs;
    sc.n_msgs = 2;
    outcome_t o;
    run_scenario(&sc, &o);
    char name[200];
    snprintf(name, sizeof(name),
             "T2: handshake, confirmation, 2 echoes and GOODBYE succeed with every byte delivered separately "
             "(client %s, server %s, %llu ms)",
             demo_status_name(o.cli.status), demo_status_name(g_srv_rep.res.status),
             (unsigned long long)o.cli_elapsed_ms);
    CHECK(o.cli.status == DEMO_OK && server_ok(&o) && g_srv_rep.res.status == DEMO_OK && o.prx_ok, name);
    snprintf(name, sizeof(name),
             "T2: partial reads really happened (client %llu recv calls for 5 frames, server %llu for 5 frames)",
             (unsigned long long)o.cli.net.recv_calls, (unsigned long long)g_srv_rep.res.net.recv_calls);
    CHECK(o.cli.net.recv_calls > 100u && g_srv_rep.res.net.recv_calls > 100u, name);
}

/* =====================================================================
 * T3 oversize / zero-length frames
 * =================================================================== */

static void server_vs_header(uint32_t len, const char *name) {
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, TEST_HS_MS, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    int sent = raw_connect(port, &c) == 0 && raw_send_header(&c, len) == 0;
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    net_close(&c);
    char full[240];
    snprintf(full, sizeof(full), "%s (rejected after %llu ms, no payload read)", name,
             (unsigned long long)g_srv_rep.elapsed_ms);
    CHECK(sent && ok && g_srv_rep.res.status == DEMO_ERR_FRAME_SIZE && g_srv_rep.res.frame_status == FRAME_BAD_LENGTH &&
              g_srv_rep.res.stage == DEMO_STAGE_CLIENT_HELLO && g_srv_rep.elapsed_ms < 500u &&
              g_srv_rep.res.pending_active_after == 0,
          full);
}

static void test_t3_oversize(void) {
    server_vs_header((uint32_t)FRAME_MAX_CLIENT_HELLO + 1u,
                     "T3: ClientHello-state header 1331 (one over the 1330 limit) -> FRAME_BAD_LENGTH");
    server_vs_header((uint32_t)FRAME_MAX_PAYLOAD + 1u, "T3: ClientHello-state header 65562 -> FRAME_BAD_LENGTH");
    server_vs_header(0xFFFFFFFFu, "T3: ClientHello-state header 0xFFFFFFFF -> FRAME_BAD_LENGTH");
    server_vs_header(0u, "T3: zero-length frame -> FRAME_BAD_LENGTH");

    /* Session state. */
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, TEST_HS_MS, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    session_t sess;
    const int hs = raw_connect(port, &c) == 0 && raw_initiator(&c, &sess) == 0;
    const uint64_t t0 = net_now_ms();
    const int sent = hs && raw_send_header(&c, (uint32_t)FRAME_MAX_RECORD + 1u) == 0;
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    const uint64_t dt = net_now_ms() - t0;
    net_close(&c);
    session_wipe(&sess);
    CHECK(sent && ok && g_srv_rep.res.status == DEMO_ERR_FRAME_SIZE && g_srv_rep.res.stage == DEMO_STAGE_SESSION &&
              dt < 500u,
          "T3: session-state header 65562 (one over the record maximum) -> FRAME_BAD_LENGTH, no payload read");

    /* Client side: ServerHello header one over its limit. */
    demo_result_t r;
    uint64_t elapsed = 0;
    client_vs_raw_server(RAW_SRV_OVERSIZE_SH_HEADER, &r, &elapsed);
    CHECK(r.status == DEMO_ERR_FRAME_SIZE && r.frame_status == FRAME_BAD_LENGTH && r.stage == DEMO_STAGE_SERVER_HELLO &&
              elapsed < 500u,
          "T3: client rejects a ServerHello header of 4546 (one over the 4545 limit) immediately");
}

/* =====================================================================
 * T4 malformed handshake frames
 * =================================================================== */

static void server_vs_payload(const uint8_t *payload, size_t len, const char *name) {
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, TEST_HS_MS, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    memcpy(g_raw + 4, payload, len);
    const int sent = raw_connect(port, &c) == 0 && frame_send(&c, g_raw, len, net_deadline_in(OPS_MS)) == FRAME_OK;
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    net_close(&c);
    CHECK(sent && ok && g_srv_rep.res.status == DEMO_ERR_HANDSHAKE &&
              g_srv_rep.res.hs_status == HANDSHAKE_ERR_MALFORMED && g_srv_rep.res.stage == DEMO_STAGE_CLIENT_HELLO &&
              g_srv_rep.res.pending_active_after == 0,
          name);
}

static void test_t4_malformed(void) {
    uint8_t p[FRAME_MAX_CLIENT_HELLO + 1u];
    memset(p, 0x7F, 50);
    server_vs_payload(p, 50, "T4: garbage ClientHello frame -> MALFORMED, no pending entry");

    size_t n = valid_client_hello(p);
    p[0] = MSG_TYPE_SERVER_HELLO;
    server_vs_payload(p, n, "T4: type 0x02 in the ClientHello slot -> MALFORMED");

    n = valid_client_hello(p);
    p[n] = 0x00;
    server_vs_payload(p, n + 1u, "T4: valid ClientHello plus one trailing byte in the frame -> MALFORMED");

    demo_result_t r;
    uint64_t elapsed = 0;
    client_vs_raw_server(RAW_SRV_GARBAGE_SH, &r, &elapsed);
    CHECK(r.status == DEMO_ERR_HANDSHAKE && r.hs_status == HANDSHAKE_ERR_MALFORMED && r.stage == DEMO_STAGE_SERVER_HELLO,
          "T4: client rejects a garbage ServerHello frame -> MALFORMED");
}

/* =====================================================================
 * T5 tampered records; T6/T7 wrong pins
 * =================================================================== */

static void test_t5_tampered(void) {
    const demo_message_t msgs[1] = {{g_kb, 64}};
    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.flip_dir = C2S;
    sc.rules.flip_frame = 2; /* CH, CA, then the first MSG record */
    sc.rules.flip_offset = FRAME_HEADER_BYTES + 20u;
    sc.msgs = msgs;
    sc.n_msgs = 1;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(server_ok(&o) && g_srv_rep.res.status == DEMO_ERR_SESSION && g_srv_rep.res.sess_status == SESSION_ERR_AUTH &&
              g_srv_rep.res.stage == DEMO_STAGE_SESSION && g_srv_rep.res.messages_echoed == 0,
          "T5: a flipped bit in the client's first record -> server SESSION_ERR_AUTH, nothing echoed");
    CHECK(o.cli.status != DEMO_OK && o.cli.messages_echoed == 0, "T5: ...and the client does not succeed");

    sc.rules = no_faults();
    sc.rules.flip_dir = S2C;
    sc.rules.flip_frame = 1; /* SH, then the confirmation record */
    sc.rules.flip_offset = FRAME_HEADER_BYTES + 10u;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == DEMO_ERR_SESSION && o.cli.sess_status == SESSION_ERR_AUTH && o.cli.stage == DEMO_STAGE_CONFIRM,
          "T5: a flipped bit in the confirmation record -> client SESSION_ERR_AUTH at confirm");
    CHECK(o.prx_ok && g_prx_rep.frames_seen[C2S] == 2u && g_prx_rep.partial[C2S] == 0 &&
              g_prx_rep.bytes_seen[C2S] == CH_FRAME + CA_FRAME,
          "T5: ...and the client sent 0 application bytes (only ClientHello and ClientAuth)");
}

static void test_t6_t7_wrong_pins(void) {
    scenario_t sc = default_scenario();
    sc.cli_pins = &g_cli_pins_wrong;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == DEMO_ERR_HANDSHAKE && o.cli.hs_status == HANDSHAKE_ERR_SIGNATURE &&
              o.cli.stage == DEMO_STAGE_SERVER_HELLO,
          "T6: client pinned the wrong key for 'bob' -> sig_B rejected at ServerHello");
    CHECK(server_ok(&o) && g_srv_rep.res.status == DEMO_ERR_PEER_CLOSED && g_srv_rep.res.stage == DEMO_STAGE_CLIENT_AUTH &&
              g_srv_rep.res.pending_active_after == 0,
          "T6: server saw the client leave before any ClientAuth; its pending entry was cancelled");

    sc = default_scenario();
    sc.srv_pins = &g_srv_pins_wrong;
    run_scenario(&sc, &o);
    CHECK(server_ok(&o) && g_srv_rep.res.status == DEMO_ERR_HANDSHAKE &&
              g_srv_rep.res.hs_status == HANDSHAKE_ERR_SIGNATURE && g_srv_rep.res.stage == DEMO_STAGE_CLIENT_AUTH,
          "T7: server pinned the wrong key for 'alice' -> sig_A rejected at ClientAuth, connection closed");
    CHECK(server_ok(&o) && g_srv_rep.res.pending_active_after == 0,
          "T7: ...and the pending entry was cancelled (no live ledger entry left)");
    CHECK(o.cli.status == DEMO_ERR_PEER_CLOSED && o.cli.stage == DEMO_STAGE_CONFIRM,
          "T7: client sees the connection close while waiting for confirmation");
    CHECK(o.cli_bufs_zero && server_ok(&o) && g_srv_rep.buffers_zero,
          "T16: buffers are all-zero after a failed connection too");
}

/* =====================================================================
 * T8 no application data before confirmation
 * =================================================================== */

static void test_t8_confirmation_gate(void) {
    /* (a) in-process sessions over a socketpair */
    handshake_ctx_t ini;
    handshake_ctx_t res;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t chl = 0;
    size_t shl = 0;
    size_t cal = 0;
    if (handshake_initiator_init(&ini, ID_A, sizeof(ID_A), &g_kp_a, &g_cli_pins_ok, ID_B, sizeof(ID_B)) != HANDSHAKE_OK ||
        handshake_responder_init(&res, ID_B, sizeof(ID_B), &g_kp_b, &g_srv_pins_ok, &g_parent_store) != HANDSHAKE_OK ||
        handshake_initiator_create_client_hello(&ini, ch, sizeof(ch), &chl) != HANDSHAKE_OK ||
        handshake_responder_accept_client_hello(&res, ch, chl) != HANDSHAKE_OK ||
        handshake_responder_create_server_hello(&res, sh, sizeof(sh), &shl) != HANDSHAKE_OK ||
        handshake_initiator_verify_server_hello(&ini, sh, shl) != HANDSHAKE_OK ||
        handshake_initiator_create_client_auth(&ini, ca, sizeof(ca), &cal) != HANDSHAKE_OK ||
        handshake_responder_verify_client_auth(&res, ca, cal) != HANDSHAKE_OK ||
        handshake_responder_finish(&res) != HANDSHAKE_OK || handshake_initiator_finish(&ini) != HANDSHAKE_OK) {
        fatal("T8 in-process handshake");
    }
    session_t si;
    session_t sr;
    memset(&si, 0, sizeof(si));
    memset(&sr, 0, sizeof(sr));
    if (session_init_from_handshake(&si, &ini, NULL, NULL, NULL) != SESSION_OK ||
        session_init_from_handshake(&sr, &res, NULL, NULL, NULL) != SESSION_OK) {
        fatal("T8 session init");
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fatal("socketpair");
    }
    net_conn_t a;
    net_conn_init(&a);
    a.fd = sv[0];
    const demo_status_t before = demo_send_app(&si, &a, g_cli_buf, DEMO_OP_MSG, g_kb, 16, net_deadline_in(OPS_MS));
    struct pollfd pf = {sv[1], POLLIN, 0};
    const int readable = poll(&pf, 1, 0);
    CHECK(before == DEMO_ERR_NOT_CONFIRMED && readable == 0 && a.stats.send_calls == 0,
          "T8(a): demo_send_app on an unconfirmed initiator session -> NOT_CONFIRMED, 0 bytes written");

    uint8_t rec[SESSION_OVERHEAD_BYTES];
    uint8_t pt[1];
    size_t rl = 0;
    size_t pl = 0;
    const int confirmed = session_seal(&sr, NULL, 0, rec, sizeof(rec), &rl) == SESSION_OK &&
                          session_open(&si, rec, rl, pt, sizeof(pt), &pl) == SESSION_OK;
    const demo_status_t after = demo_send_app(&si, &a, g_cli_buf, DEMO_OP_MSG, g_kb, 16, net_deadline_in(OPS_MS));
    CHECK(confirmed && after == DEMO_OK && poll(&pf, 1, 0) == 1,
          "T8(a): after the confirmation record opens, the same call sends");
    (void)close(sv[0]);
    (void)close(sv[1]);
    session_wipe(&si);
    session_wipe(&sr);
    sodium_memzero(g_cli_buf, sizeof(*g_cli_buf));

    /* (b) the confirmation frame never arrives */
    const demo_message_t msgs[1] = {{g_kb, 32}};
    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.drop_dir = S2C;
    sc.rules.drop_frame = 1;
    sc.cli_hs_ms = 500;
    sc.msgs = msgs;
    sc.n_msgs = 1;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == DEMO_ERR_TIMEOUT && o.cli.stage == DEMO_STAGE_CONFIRM,
          "T8(b): with the confirmation record dropped, the client times out at confirm");
    CHECK(o.prx_ok && g_prx_rep.bytes_seen[C2S] == CH_FRAME + CA_FRAME && g_prx_rep.partial[C2S] == 0,
          "T8(b): ...having sent 0 application bytes after ClientAuth");
}

/* =====================================================================
 * T9 peer close at every handshake stage
 * =================================================================== */

static void close_row_server(int dir, uint64_t after, demo_status_t want, demo_stage_t stage, const char *name) {
    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.close_dir = dir;
    sc.rules.close_after = after;
    const demo_message_t msgs[1] = {{g_kb, 16}};
    sc.msgs = msgs;
    sc.n_msgs = 1;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(server_ok(&o) && g_srv_rep.res.status == want && g_srv_rep.res.stage == stage && o.cli.status != DEMO_OK &&
              g_srv_rep.res.pending_active_after == 0,
          name);
}

static void close_row_client(int dir, uint64_t after, demo_status_t want, demo_stage_t stage, const char *name) {
    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.close_dir = dir;
    sc.rules.close_after = after;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == want && o.cli.stage == stage && server_ok(&o) && g_srv_rep.res.status != DEMO_OK &&
              g_srv_rep.res.pending_active_after == 0,
          name);
}

static void test_t9_close_every_stage(void) {
    const size_t SH = sh_frame_len();

    /* Client goes away. */
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, TEST_HS_MS, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    const int conn_ok = raw_connect(port, &c) == 0;
    net_close(&c);
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    CHECK(conn_ok && ok && g_srv_rep.res.status == DEMO_ERR_PEER_CLOSED && g_srv_rep.res.stage == DEMO_STAGE_CLIENT_HELLO &&
              g_srv_rep.res.pending_active_after == 0,
          "T9: client connects and closes before sending -> server PEER_CLOSED at client-hello");
    close_row_server(C2S, 2, DEMO_ERR_TRUNCATED, DEMO_STAGE_CLIENT_HELLO,
                     "T9: client closes mid-ClientHello header -> server TRUNCATED at client-hello");
    close_row_server(S2C, SH, DEMO_ERR_PEER_CLOSED, DEMO_STAGE_CLIENT_AUTH,
                     "T9: client closes after receiving ServerHello -> server PEER_CLOSED at client-auth, entry cancelled");
    close_row_server(C2S, CH_FRAME + 100u, DEMO_ERR_TRUNCATED, DEMO_STAGE_CLIENT_AUTH,
                     "T9: client closes mid-ClientAuth -> server TRUNCATED at client-auth, entry cancelled");

    scenario_t sc = default_scenario();
    sc.use_proxy = 1;
    sc.rules.close_dir = C2S;
    sc.rules.close_after = CH_FRAME + CA_FRAME;
    outcome_t o;
    run_scenario(&sc, &o);
    CHECK(o.cli.status == DEMO_ERR_PEER_CLOSED && o.cli.stage == DEMO_STAGE_CONFIRM && server_ok(&o) &&
              g_srv_rep.res.status != DEMO_OK && g_srv_rep.res.stage >= DEMO_STAGE_CONFIRM &&
              g_srv_rep.res.pending_active_after == 0,
          "T9: connection closes right after ClientAuth -> client PEER_CLOSED at confirm; server fails after "
          "verifying (no SIGPIPE)");

    close_row_server(S2C, SH + CONFIRM_FRAME, DEMO_ERR_PEER_CLOSED, DEMO_STAGE_SESSION,
                     "T9: close after the confirmation, before any GOODBYE -> server PEER_CLOSED at session "
                     "(truncation detected)");

    /* Server goes away. */
    demo_result_t r;
    uint64_t elapsed = 0;
    client_vs_raw_server(RAW_SRV_CLOSE_AFTER_CH, &r, &elapsed);
    CHECK(r.status == DEMO_ERR_PEER_CLOSED && r.stage == DEMO_STAGE_SERVER_HELLO,
          "T9: server closes after reading ClientHello -> client PEER_CLOSED at server-hello");
    close_row_client(S2C, 100, DEMO_ERR_TRUNCATED, DEMO_STAGE_SERVER_HELLO,
                     "T9: server closes mid-ServerHello -> client TRUNCATED at server-hello");
    close_row_client(S2C, SH + 10u, DEMO_ERR_TRUNCATED, DEMO_STAGE_CONFIRM,
                     "T9: server closes mid-confirmation -> client TRUNCATED at confirm");
}

/* =====================================================================
 * T10 no secrets in logs
 * =================================================================== */

static int contains_hex_window(const char *log, const uint8_t *bytes, size_t len) {
    char hex[17];
    static const char lo[] = "0123456789abcdef";
    static const char up[] = "0123456789ABCDEF";
    for (size_t i = 0; i + 8u <= len; i++) {
        for (int pass = 0; pass < 2; pass++) {
            const char *d = pass ? up : lo;
            for (size_t k = 0; k < 8u; k++) {
                hex[2 * k] = d[bytes[i + k] >> 4];
                hex[2 * k + 1] = d[bytes[i + k] & 0x0Fu];
            }
            hex[16] = '\0';
            if (strstr(log, hex) != NULL) {
                return 1;
            }
        }
    }
    return 0;
}

static int only_printable_no_hex_runs(const char *log, size_t len) {
    size_t run = 0;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)log[i];
        if (!(c == '\n' || (c >= 0x20u && c < 0x7fu))) {
            return 0;
        }
        const int hexd = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        run = hexd ? run + 1u : 0u;
        if (run >= 16u) {
            return 0;
        }
    }
    return 1;
}

static void test_t10_no_secrets_in_logs(void) {
    static const char canary[] = "T10-CANARY-PLAINTEXT-4b1d";
    static logcap_t cli_log;
    static char all[sizeof(cli_log.data) * 2u];
    memset(&cli_log, 0, sizeof(cli_log));
    const demo_message_t msgs[1] = {{(const uint8_t *)canary, sizeof(canary) - 1u}};
    scenario_t sc = default_scenario();
    sc.use_proxy = 1; /* captures the ServerHello and ClientAuth, i.e. both signatures */
    sc.msgs = msgs;
    sc.n_msgs = 1;
    sc.cli_log = &cli_log;
    outcome_t o;
    run_scenario(&sc, &o);
    const int ran = o.cli.status == DEMO_OK && server_ok(&o) && g_srv_rep.res.status == DEMO_OK && o.prx_ok &&
                    g_prx_rep.sh_len > MLDSA_SIGNATURE_MAX_BYTES && g_prx_rep.ca_len == CLIENT_AUTH_MAX_ENCODED_LEN &&
                    cli_log.len > 0 && g_srv_rep.log.len > 0;
    snprintf(all, sizeof(all), "%s%s", cli_log.data, g_srv_rep.log.data);
    const size_t all_len = strlen(all);

    char canary_hex[2 * sizeof(canary)];
    sodium_bin2hex(canary_hex, sizeof(canary_hex), (const unsigned char *)canary, sizeof(canary) - 1u);
    const uint8_t *sig_b = g_prx_rep.sh + g_prx_rep.sh_len - MLDSA_SIGNATURE_MAX_BYTES;
    const uint8_t *sig_a = g_prx_rep.ca + g_prx_rep.ca_len - MLDSA_SIGNATURE_MAX_BYTES;

    CHECK(ran, "T10: logged run succeeded on both sides (logs captured, both signatures captured by the proxy)");
    CHECK(ran && strstr(all, canary) == NULL && strstr(all, canary_hex) == NULL,
          "T10: the decrypted payload canary appears in neither log, raw or hex");
    CHECK(ran && !contains_hex_window(all, g_kp_a.secret_key, MLDSA_SECRET_KEY_BYTES) &&
              !contains_hex_window(all, g_kp_b.secret_key, MLDSA_SECRET_KEY_BYTES),
          "T10: no 8-byte window of either ML-DSA secret key appears in hex");
    CHECK(ran && !contains_hex_window(all, sig_a, MLDSA_SIGNATURE_MAX_BYTES) &&
              !contains_hex_window(all, sig_b, MLDSA_SIGNATURE_MAX_BYTES),
          "T10: no 8-byte window of either signature appears in hex");
    CHECK(ran && only_printable_no_hex_runs(all, all_len),
          "T10: logs are printable text with no hex run of >= 16 digits (so no key, session key, nonce or "
          "signature can appear raw or hex-encoded)");
}

/* =====================================================================
 * T11 handshake timeout
 * =================================================================== */

static void test_t11_timeout(void) {
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, 300, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    const size_t n = valid_client_hello(ch);
    const int sent = raw_connect(port, &c) == 0 && raw_send_header(&c, (uint32_t)n) == 0 && raw_send(&c, ch, 40) == 0;
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    net_close(&c);
    char name[200];
    snprintf(name, sizeof(name), "T11: half a ClientHello then silence -> server TIMEOUT after %llu ms (limit 300)",
             (unsigned long long)g_srv_rep.elapsed_ms);
    CHECK(sent && ok && g_srv_rep.res.status == DEMO_ERR_TIMEOUT && g_srv_rep.res.stage == DEMO_STAGE_CLIENT_HELLO &&
              g_srv_rep.elapsed_ms >= 250u && g_srv_rep.elapsed_ms < 1000u &&
              g_srv_rep.res.pending_active_after == 0,
          name);

    /* Trickle: one byte every 100 ms cannot extend an absolute deadline. */
    s = start_server(&g_srv_pins_ok, 300, TEST_IDLE_MS, 0, &port);
    int trickled = 0;
    if (raw_connect(port, &c) == 0 && raw_send_header(&c, (uint32_t)n) == 0) {
        for (size_t i = 0; i < 30u; i++) {
            if (raw_send(&c, ch + i, 1) != 0) {
                break;
            }
            trickled++;
            (void)usleep(100000);
            struct pollfd pf = {c.fd, POLLIN, 0};
            if (poll(&pf, 1, 0) == 1) {
                break; /* the server closed */
            }
        }
    }
    const int ok2 = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    net_close(&c);
    snprintf(name, sizeof(name),
             "T11: trickling 1 byte / 100 ms -> server still TIMEOUT after %llu ms (%d bytes trickled)",
             (unsigned long long)g_srv_rep.elapsed_ms, trickled);
    CHECK(ok2 && g_srv_rep.res.status == DEMO_ERR_TIMEOUT && g_srv_rep.elapsed_ms < 1000u && trickled < 30, name);
}

/* =====================================================================
 * T12 EINTR storm
 * =================================================================== */

static void test_t12_eintr(void) {
    const demo_message_t msgs[2] = {{g_kb, 64}, {g_kb, sizeof(g_kb)}};
    scenario_t sc = default_scenario();
    sc.storm = 1;
    sc.msgs = msgs;
    sc.n_msgs = 2;
    g_alarms = 0;
    outcome_t o;
    run_scenario(&sc, &o);
    char name[200];
    snprintf(name, sizeof(name),
             "T12: SIGALRM every 500 us without SA_RESTART: both sides succeed (EINTR retries: client %llu, "
             "server %llu; %d alarms in the client)",
             (unsigned long long)o.cli.net.eintr_retries, (unsigned long long)g_srv_rep.res.net.eintr_retries,
             (int)g_alarms);
    CHECK(o.cli.status == DEMO_OK && server_ok(&o) && g_srv_rep.res.status == DEMO_OK &&
              o.cli.net.eintr_retries + g_srv_rep.res.net.eintr_retries > 0u,
          name);
}

/* =====================================================================
 * T13 framing unit tests (socketpair)
 * =================================================================== */

static void pair(net_conn_t *r, int *w) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || fcntl(sv[0], F_SETFL, O_NONBLOCK) != 0) {
        fatal("socketpair");
    }
    net_conn_init(r);
    r->fd = sv[0];
    *w = sv[1];
}

typedef struct {
    int wfd;
} split_writer_opts_t;

static void split_writer_body(int wfd_report, const void *arg) {
    const split_writer_opts_t *o = (const split_writer_opts_t *)arg;
    uint8_t hdr[4];
    uint8_t payload[50];
    frame_put_header(hdr, sizeof(payload));
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(i * 7u + 1u);
    }
    for (size_t i = 0; i < 4u; i++) {
        write_full(o->wfd, hdr + i, 1);
        (void)usleep(5000);
    }
    for (size_t off = 0; off < sizeof(payload); off += 7u) {
        const size_t n = (sizeof(payload) - off < 7u) ? sizeof(payload) - off : 7u;
        write_full(o->wfd, payload + off, n);
        (void)usleep(5000);
    }
    const uint8_t done = 0;
    write_full(wfd_report, &done, 1);
}

static frame_status_t recv_after_writing(const uint8_t *bytes, size_t n, int close_writer, size_t min_len,
                                         size_t max_len, size_t *len) {
    net_conn_t r;
    int w = -1;
    pair(&r, &w);
    if (n > 0) {
        write_full(w, bytes, n);
    }
    if (close_writer) {
        (void)close(w);
        w = -1;
    }
    const frame_status_t st = frame_recv(&r, g_raw, min_len, max_len, len, net_deadline_in(200));
    net_close(&r);
    if (w >= 0) {
        (void)close(w);
    }
    return st;
}

static void test_t13_framing(void) {
    uint8_t h[4];
    frame_put_header(h, 0x01020304u);
    CHECK(h[0] == 0x01 && h[1] == 0x02 && h[2] == 0x03 && h[3] == 0x04 && frame_get_header(h) == 0x01020304u,
          "T13: frame header is 4-byte big-endian and round-trips");

    net_conn_t r;
    int w = -1;
    pair(&r, &w);
    net_conn_t wc;
    net_conn_init(&wc);
    wc.fd = w;
    memcpy(g_raw + 4, "hello", 5);
    uint8_t raw[9];
    size_t got = 0;
    const int sent = frame_send(&wc, g_raw, 5, net_deadline_in(OPS_MS)) == FRAME_OK;
    const int rd = net_read_exact(&r, raw, sizeof(raw), net_deadline_in(OPS_MS), &got) == NET_OK;
    CHECK(sent && rd && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 5 && memcmp(raw + 4, "hello", 5) == 0,
          "T13: frame_send writes exactly 00 00 00 05 'hello'");
    net_close(&r);
    net_close(&wc);

    /* Header split 1+1+1+1, payload in 7-byte pieces, from another process. */
    pair(&r, &w);
    split_writer_opts_t so = {w};
    child_t sw = spawn(split_writer_body, &so);
    (void)close(w);
    size_t len = 0;
    const frame_status_t st = frame_recv(&r, g_raw, 1, 100, &len, net_deadline_in(OPS_MS));
    int bytes_ok = (len == 50);
    for (size_t i = 0; bytes_ok && i < 50u; i++) {
        bytes_ok = g_raw[4 + i] == (uint8_t)(i * 7u + 1u);
    }
    char name[200];
    snprintf(name, sizeof(name),
             "T13: header delivered 1+1+1+1 and payload in 7-byte pieces reassemble exactly (%llu recv calls)",
             (unsigned long long)r.stats.recv_calls);
    CHECK(st == FRAME_OK && bytes_ok && r.stats.recv_calls >= 6u, name);
    uint8_t d = 0;
    (void)collect(&sw, &d, 1);
    net_close(&r);

    uint8_t b[64];
    memset(b, 0xAB, sizeof(b));
    CHECK(recv_after_writing(NULL, 0, 1, 1, 100, &len) == FRAME_EOF && len == 0,
          "T13: EOF before any header byte -> FRAME_EOF (clean boundary)");
    CHECK(recv_after_writing(b, 2, 1, 1, 100, &len) == FRAME_TRUNCATED, "T13: EOF mid-header -> FRAME_TRUNCATED");
    frame_put_header(b, 10);
    CHECK(recv_after_writing(b, 4 + 5, 1, 1, 100, &len) == FRAME_TRUNCATED && len == 0,
          "T13: EOF mid-payload -> FRAME_TRUNCATED");
    frame_put_header(b, 40);
    CHECK(recv_after_writing(b, 44, 0, 1, 40, &len) == FRAME_OK && len == 40, "T13: length == max_len -> accepted");
    frame_put_header(b, 41);
    CHECK(recv_after_writing(b, 45, 0, 1, 40, &len) == FRAME_BAD_LENGTH && len == 0,
          "T13: length == max_len + 1 -> FRAME_BAD_LENGTH");
    frame_put_header(b, 24);
    CHECK(recv_after_writing(b, 28, 0, 25, 40, &len) == FRAME_BAD_LENGTH, "T13: length < min_len -> FRAME_BAD_LENGTH");
    frame_put_header(b, 0);
    CHECK(recv_after_writing(b, 4, 0, 1, 40, &len) == FRAME_BAD_LENGTH, "T13: length 0 -> FRAME_BAD_LENGTH");

    pair(&r, &w);
    CHECK(frame_recv(&r, g_raw, 0, 10, &len, net_deadline_in(50)) == FRAME_INVALID_ARG &&
              frame_recv(&r, g_raw, 1, FRAME_MAX_PAYLOAD + 1u, &len, net_deadline_in(50)) == FRAME_INVALID_ARG &&
              frame_recv(&r, g_raw, 11, 10, &len, net_deadline_in(50)) == FRAME_INVALID_ARG &&
              frame_send(&r, g_raw, 0, net_deadline_in(50)) == FRAME_INVALID_ARG &&
              frame_send(&r, g_raw, FRAME_MAX_PAYLOAD + 1u, net_deadline_in(50)) == FRAME_INVALID_ARG,
          "T13: invalid bounds (min 0, max over the frame cap, min > max) and empty/oversize sends are refused");
    const uint64_t t0 = net_now_ms();
    const frame_status_t tst = frame_recv(&r, g_raw, 1, 10, &len, net_deadline_in(50));
    const uint64_t dt = net_now_ms() - t0;
    CHECK(tst == FRAME_TIMEOUT && dt >= 40u && dt < 1000u, "T13: nothing arrives -> FRAME_TIMEOUT at the deadline");
    net_close(&r);
    (void)close(w);
}

/* =====================================================================
 * T14 demo key files
 * =================================================================== */

static int copy_with_edit(const char *from, const char *to, long truncate_by, int append, int flip_first) {
    static uint8_t data[16384];
    FILE *f = fopen(from, "rb");
    if (f == NULL) {
        return -1;
    }
    const size_t n = fread(data, 1, sizeof(data), f);
    fclose(f);
    size_t out = n - (size_t)truncate_by;
    if (append) {
        data[out++] = 0x00;
    }
    if (flip_first) {
        data[0] ^= 0x01;
    }
    const int fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    write_full(fd, data, out);
    (void)close(fd);
    return 0;
}

/* ---- Step 7.1: MLDSASK2 layout, derived INDEPENDENTLY of demo_keys.c ------ */

/* The test's own copy of the label and its own length arithmetic: a label,
 * length or NUL mistake in demo_keys.c (made identically by keygen and the
 * loader) still makes the file's digest disagree with this one. */
static const char T14_LABEL[] = "mldsa-auth/v1/demo-key-integrity";
#define T14_LABEL_LEN (sizeof(T14_LABEL) - 1u)
#define T14_HDR 9u /* "MLDSASK2" + id_len */
#define T14_BODY(idl) (T14_HDR + (size_t)(idl) + MLDSA_PUBLIC_KEY_BYTES + MLDSA_SECRET_KEY_BYTES)
#define T14_FILE(idl) (T14_BODY(idl) + 32u)
#define T14_SK_OFF(idl) (T14_HDR + (size_t)(idl) + MLDSA_PUBLIC_KEY_BYTES)

static uint8_t g_kf[16384];

static size_t t14_read(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fatal("T14 read");
    }
    const size_t n = fread(g_kf, 1, sizeof(g_kf), f);
    fclose(f);
    return n;
}

static void t14_write(const char *path, const uint8_t *data, size_t n) {
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fatal("T14 write");
    }
    write_full(fd, data, n);
    (void)close(fd);
}

/* SHA-256(label || 0x00 || file bytes [8, body_end)) -- id_len, id, pk, sk. */
static void t14_digest(uint8_t out[32], const uint8_t *file, size_t body_end) {
    static const uint8_t zero = 0x00;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)T14_LABEL, T14_LABEL_LEN);
    crypto_hash_sha256_update(&st, &zero, 1);
    crypto_hash_sha256_update(&st, file + 8, body_end - 8);
    crypto_hash_sha256_final(&st, out);
}

static int t14_rejected_cleanly(const char *path, const uint8_t *id, size_t idl, demo_keys_status_t want) {
    mldsa_keypair_t kp;
    memset(&kp, 0xA5, sizeof(kp.public_key));
    kp.secret_key = NULL;
    const demo_keys_status_t st = demo_keys_load_identity(path, id, idl, &kp);
    const int clean = kp.secret_key == NULL && sodium_is_zero(kp.public_key, sizeof(kp.public_key));
    if (st == DEMO_KEYS_OK) {
        mldsa_keypair_free(&kp);
    }
    return st == want && clean;
}

static void test_t14_demo_keys(void) {
    char dir[512];
    char path[512];
    char p2[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s/mldsa-t14-XXXXXX", (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    if (mkdtemp(dir) == NULL) {
        fatal("mkdtemp");
    }
    mldsa_keypair_t kp;
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    const uint8_t alice[] = "alice";
    const uint8_t bob[] = "bob";

    CHECK(demo_keys_generate_files(dir, alice, 5) == DEMO_KEYS_OK &&
              demo_keys_generate_files(dir, bob, 3) == DEMO_KEYS_OK,
          "T14: keygen writes two identities");
    struct stat st;
    snprintf(path, sizeof(path), "%s/alice.sk", dir);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "T14: the secret key file is mode 0600");
    CHECK(demo_keys_generate_files(dir, alice, 5) == DEMO_KEYS_ERR_EXISTS, "T14: keygen refuses to overwrite");
    {
        int hidden = 0;
        DIR *d = opendir(dir);
        struct dirent *e;
        while (d != NULL && (e = readdir(d)) != NULL) {
            hidden += (e->d_name[0] == '.' && strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0);
        }
        if (d != NULL) {
            closedir(d);
        }
        CHECK(hidden == 0, "T14.1: keygen leaves no temporary files behind (atomic temp + link publish)");
    }

    /* Step 7.1: exact MLDSASK2 layout and an independently computed digest. */
    {
        uint8_t want[32];
        const size_t n = t14_read(path);
        t14_digest(want, g_kf, T14_BODY(5));
        CHECK(n == T14_FILE(5) && n == 6030u && memcmp(g_kf, "MLDSASK2", 8) == 0 && g_kf[8] == 5 &&
                  memcmp(g_kf + 9, "alice", 5) == 0 && memcmp(g_kf + T14_BODY(5), want, 32) == 0,
              "T14.1: MLDSASK2 layout is exact (6025 + id_len bytes) and its digest matches one computed "
              "independently with the literal label");
    }

    const demo_keys_status_t ls = demo_keys_load_identity(path, alice, 5, &kp);
    snprintf(p2, sizeof(p2), "%s/alice.pub", dir);
    const demo_keys_status_t lp = demo_keys_load_public(p2, alice, 5, pk);
    uint8_t sig[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sl = 0;
    CHECK(ls == DEMO_KEYS_OK && lp == DEMO_KEYS_OK && memcmp(pk, kp.public_key, sizeof(pk)) == 0 &&
              mldsa_sign(sig, &sl, (const uint8_t *)"m", 1, &kp) == 0 && mldsa_verify((const uint8_t *)"m", 1, sig, sl, pk) == 0,
          "T14: identity and public key load back and sign/verify");
    mldsa_keypair_free(&kp);

    (void)chmod(path, 0644);
    CHECK(demo_keys_load_identity(path, alice, 5, &kp) == DEMO_KEYS_ERR_PERMISSIONS && kp.secret_key == NULL,
          "T14: a group/other-readable secret key file is refused");
    (void)chmod(path, 0600);

    snprintf(p2, sizeof(p2), "%s/t.sk", dir);
    copy_with_edit(path, p2, 1, 0, 0);
    CHECK(demo_keys_load_identity(p2, alice, 5, &kp) == DEMO_KEYS_ERR_FORMAT, "T14: truncated secret key file -> FORMAT");
    copy_with_edit(path, p2, 0, 1, 0);
    CHECK(demo_keys_load_identity(p2, alice, 5, &kp) == DEMO_KEYS_ERR_FORMAT, "T14: oversize secret key file -> FORMAT");
    copy_with_edit(path, p2, 32, 0, 0);
    CHECK(t14_rejected_cleanly(p2, alice, 5, DEMO_KEYS_ERR_FORMAT), "T14.1: digest stripped (truncated by 32) -> FORMAT");
    copy_with_edit(path, p2, 0, 0, 1);
    CHECK(demo_keys_load_identity(p2, alice, 5, &kp) == DEMO_KEYS_ERR_FORMAT, "T14: wrong magic -> FORMAT");
    CHECK(demo_keys_load_identity(path, bob, 3, &kp) == DEMO_KEYS_ERR_ID_MISMATCH,
          "T14: loading alice.sk as 'bob' -> ID_MISMATCH");

    /* Step 7.1: every covered region and both ends of the digest are checked. */
    {
        const size_t n = t14_read(path);
        const struct {
            size_t off;
            const char *what;
        } flips[] = {
            {9u + 2u, "T14.1: one byte changed in the id -> INTEGRITY, nothing left loaded"},
            {9u + 5u + 100u, "T14.1: one byte changed in the public key -> INTEGRITY, nothing left loaded"},
            {T14_SK_OFF(5) + 100u, "T14.1: one byte changed in the secret key -> INTEGRITY, nothing left loaded"},
            {T14_BODY(5), "T14.1: first digest byte changed -> INTEGRITY"},
            {T14_BODY(5) + 31u, "T14.1: LAST digest byte changed -> INTEGRITY (all 32 bytes are compared)"},
        };
        for (size_t i = 0; i < sizeof(flips) / sizeof(flips[0]); i++) {
            memcpy(g_kf + 8192, g_kf, n); /* scratch copy */
            g_kf[8192 + flips[i].off] ^= 0x01;
            t14_write(p2, g_kf + 8192, n);
            CHECK(t14_rejected_cleanly(p2, alice, 5, DEMO_KEYS_ERR_INTEGRITY), flips[i].what);
        }
        memcpy(g_kf + 8192, g_kf, n);
        g_kf[8192 + 8] = 6; /* id_len 5 -> 6: the size no longer matches */
        t14_write(p2, g_kf + 8192, n);
        CHECK(t14_rejected_cleanly(p2, alice, 5, DEMO_KEYS_ERR_FORMAT), "T14.1: id_len changed (5 -> 6) -> FORMAT");

        /* Legacy MLDSASK1: the Step 6 layout (no digest). */
        memcpy(g_kf + 8192, g_kf, n - 32u);
        memcpy(g_kf + 8192, "MLDSASK1", 8);
        t14_write(p2, g_kf + 8192, n - 32u);
        const demo_keys_status_t legacy = demo_keys_load_identity(p2, alice, 5, &kp);
        const char *msg = demo_keys_status_name(legacy);
        CHECK(legacy == DEMO_KEYS_ERR_UNSUPPORTED_VERSION && kp.secret_key == NULL && strstr(msg, "MLDSASK1") != NULL &&
                  strstr(msg, "keygen") != NULL,
              "T14.1: a legacy MLDSASK1 secret key file -> UNSUPPORTED_VERSION with a clear 'regenerate with keygen' "
              "message");
    }

    /* Step 7.1: the recorded fuzz finding -- t0 bytes 70 3c 8d at secret-key
     * offset 2642 -- is now rejected deterministically (was ~75% accepted). */
    {
        int rejected = 0;
        for (int k = 0; k < 5; k++) {
            char kid[8];
            char kpath[600];
            snprintf(kid, sizeof(kid), "t0k%d", k);
            if (demo_keys_generate_files(dir, (const uint8_t *)kid, 4) != DEMO_KEYS_OK) {
                fatal("T14 t0 keygen");
            }
            snprintf(kpath, sizeof(kpath), "%s/%s.sk", dir, kid);
            const size_t n = t14_read(kpath);
            const uint8_t t0bytes[3] = {0x70, 0x3c, 0x8d};
            memcpy(g_kf + T14_SK_OFF(4) + 2642u, t0bytes, sizeof(t0bytes));
            t14_write(p2, g_kf, n);
            rejected += t14_rejected_cleanly(p2, (const uint8_t *)kid, 4, DEMO_KEYS_ERR_INTEGRITY);
            (void)unlink(kpath);
            snprintf(kpath, sizeof(kpath), "%s/%s.pub", dir, kid);
            (void)unlink(kpath);
        }
        CHECK(rejected == 5, "T14.1: the recorded t0 corruption is rejected at load time -> INTEGRITY (5/5 keys)");
    }

    /* alice's secret key with bob's public key AND a recomputed valid digest:
     * integrity passes, so the self-test must still catch the mismatch. */
    {
        uint8_t bob_pk[MLDSA_PUBLIC_KEY_BYTES];
        char pubb[512];
        snprintf(pubb, sizeof(pubb), "%s/bob.pub", dir);
        const size_t n = t14_read(path);
        if (demo_keys_load_public(pubb, bob, 3, bob_pk) != DEMO_KEYS_OK || n != T14_FILE(5)) {
            fatal("T14 fixture");
        }
        memcpy(g_kf + 9u + 5u, bob_pk, sizeof(bob_pk));
        t14_digest(g_kf + T14_BODY(5), g_kf, T14_BODY(5));
        t14_write(p2, g_kf, n);
        CHECK(demo_keys_load_identity(p2, alice, 5, &kp) == DEMO_KEYS_ERR_KEY_MISMATCH && kp.secret_key == NULL,
              "T14: secret key paired with the wrong public key (valid digest) -> KEY_MISMATCH (sign/verify self-test)");
    }
    sodium_memzero(g_kf, sizeof(g_kf));
    snprintf(p2, sizeof(p2), "%s/link.sk", dir);
    (void)symlink(path, p2);
    CHECK(demo_keys_load_identity(p2, alice, 5, &kp) != DEMO_KEYS_OK, "T14: a symlinked key file is refused (O_NOFOLLOW)");
    CHECK(demo_keys_load_public(path, alice, 5, pk) == DEMO_KEYS_ERR_FORMAT,
          "T14: a secret key file offered as a public key -> FORMAT");

    /* keygen creates missing parent directories, each 0700. */
    char nested[512];
    snprintf(nested, sizeof(nested), "%s/a/b", dir);
    snprintf(p2, sizeof(p2), "%s/a/b/carol.sk", dir);
    const demo_keys_status_t nst = demo_keys_generate_files(nested, (const uint8_t *)"carol", 5);
    struct stat nd;
    CHECK(nst == DEMO_KEYS_OK && stat(p2, &st) == 0 && stat(nested, &nd) == 0 && (nd.st_mode & 0777) == 0700,
          "T14: keygen into a missing nested directory creates it (mode 0700) and writes the identity");
    (void)unlink(p2);
    snprintf(p2, sizeof(p2), "%s/a/b/carol.pub", dir);
    (void)unlink(p2);
    (void)rmdir(nested);
    snprintf(p2, sizeof(p2), "%s/a", dir);
    (void)rmdir(p2);

    static const char *names[] = {"alice.sk", "alice.pub", "bob.sk", "bob.pub", "t.sk", "link.sk"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p2, sizeof(p2), "%s/%s", dir, names[i]);
        (void)unlink(p2);
    }
    CHECK(rmdir(dir) == 0, "T14: temporary key directory removed (nothing else was written)");
}

/* =====================================================================
 * T15 orderly close vs truncation
 * =================================================================== */

static void test_t15_orderly_close(void) {
    uint16_t port = 0;
    child_t s = start_server(&g_srv_pins_ok, TEST_HS_MS, TEST_IDLE_MS, 0, &port);
    net_conn_t c;
    session_t sess;
    const int hs = raw_connect(port, &c) == 0 && raw_initiator(&c, &sess) == 0;
    net_close(&c); /* confirmed session, then EOF instead of GOODBYE */
    const int ok = collect(&s, &g_srv_rep, sizeof(g_srv_rep));
    session_wipe(&sess);
    CHECK(hs && ok && g_srv_rep.res.status == DEMO_ERR_PEER_CLOSED && g_srv_rep.res.stage == DEMO_STAGE_SESSION,
          "T15: EOF after confirmation without GOODBYE -> PEER_CLOSED, never success");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return EXIT_FAILURE;
    }
    if (mldsa_keypair_generate(&g_kp_a) != 0 || mldsa_keypair_generate(&g_kp_b) != 0 ||
        mldsa_keypair_generate(&g_kp_c) != 0) {
        fatal("mldsa_keypair_generate");
    }
    keystore_init(&g_srv_pins_ok);
    keystore_init(&g_srv_pins_wrong);
    keystore_init(&g_cli_pins_ok);
    keystore_init(&g_cli_pins_wrong);
    if (keystore_add(&g_srv_pins_ok, ID_A, sizeof(ID_A), g_kp_a.public_key) != KEYSTORE_OK ||
        keystore_add(&g_srv_pins_wrong, ID_A, sizeof(ID_A), g_kp_c.public_key) != KEYSTORE_OK ||
        keystore_add(&g_cli_pins_ok, ID_B, sizeof(ID_B), g_kp_b.public_key) != KEYSTORE_OK ||
        keystore_add(&g_cli_pins_wrong, ID_B, sizeof(ID_B), g_kp_c.public_key) != KEYSTORE_OK) {
        fatal("keystore_add");
    }
    if (handshake_pending_store_init(&g_parent_store, 8, HANDSHAKE_PENDING_TTL_MS_DEFAULT, NULL, NULL) != PENDING_OK) {
        fatal("pending store");
    }
    g_cli_buf = calloc(1, sizeof(*g_cli_buf));
    if (g_cli_buf == NULL) {
        fatal("calloc");
    }
    randombytes_buf(g_big, sizeof(g_big));
    randombytes_buf(g_kb, sizeof(g_kb));

    test_t13_framing();
    test_t14_demo_keys();
    test_t1_success();
    test_t2_fragmented();
    test_t3_oversize();
    test_t4_malformed();
    test_t5_tampered();
    test_t6_t7_wrong_pins();
    test_t8_confirmation_gate();
    test_t9_close_every_stage();
    test_t10_no_secrets_in_logs();
    test_t11_timeout();
    test_t12_eintr();
    test_t15_orderly_close();

    free(g_cli_buf);
    handshake_pending_store_wipe(&g_parent_store);
    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);
    mldsa_keypair_free(&g_kp_c);

    if (g_failures > 0) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return EXIT_FAILURE;
    }
    printf("\nAll checks passed\n");
    return EXIT_SUCCESS;
}
