/*
 * Handshake latency: each phase in isolation, the full mutual handshake
 * in process, and the same handshake over a real TCP loopback connection
 * with Step 6 framing (spec §5.1, §8 Step 8).
 *
 * The in-process end-to-end median is the number compared against the
 * spec's 15 ms target: it is the protocol's own cost, with no sockets in
 * the way. The loopback row adds framing and syscalls, and the difference
 * between them is the transport's contribution.
 *
 * Every phase needs its own fresh state, so all rows here use the
 * prepare-callback form of bench_run: setup runs outside the timed region.
 */

#include "bench_common.h"

#include "frame.h"
#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "transcript.h"

#include <sodium.h>

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t ID_A[] = "bench-initiator";
static const uint8_t ID_B[] = "bench-responder";
#define ID_A_LEN (sizeof(ID_A) - 1u)
#define ID_B_LEN (sizeof(ID_B) - 1u)

#define PENDING_CAP 32u
#define PENDING_TTL_MS 60000u
#define HS_DEADLINE_MS 15000u

/* Requested socket buffer, matching the fixed-size pattern in
 * tests/fuzz/fuzz_frame.c. See setup_loopback() for why the size is decided
 * and checked up front rather than handled if it goes wrong. */
#define SOCK_BUF (256 * 1024)

static mldsa_keypair_t g_kp_a;
static mldsa_keypair_t g_kp_b;
static keystore_t g_ks;
static handshake_pending_store_t g_store;

typedef struct {
    handshake_ctx_t ini;
    handshake_ctx_t res;
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ch_len;
    size_t sh_len;
    size_t ca_len;
} pair_t;

static pair_t g_p;

/* ---- fixture ------------------------------------------------------------- */

static void pair_wipe(pair_t *p) {
    handshake_ctx_wipe(&p->ini);
    handshake_ctx_wipe(&p->res); /* cancels any pending entry this context owns */
}

static void pair_init(pair_t *p) {
    memset(p, 0, sizeof(*p));
    /* A consumed pending entry is tombstoned until its TTL expires (replay
     * protection), so thousands of samples would exhaust any capacity. The
     * store is rebuilt per sample instead -- inside the UNTIMED prepare, so
     * it cannot affect a measurement. */
    BENCH_REQUIRE(handshake_pending_store_init(&g_store, PENDING_CAP, PENDING_TTL_MS, NULL, NULL) ==
                      PENDING_OK,
                  "handshake_pending_store_init");
    BENCH_REQUIRE(handshake_initiator_init(&p->ini, ID_A, ID_A_LEN, &g_kp_a, &g_ks, ID_B, ID_B_LEN) ==
                      HANDSHAKE_OK,
                  "handshake_initiator_init");
    BENCH_REQUIRE(handshake_responder_init(&p->res, ID_B, ID_B_LEN, &g_kp_b, &g_ks, &g_store) ==
                      HANDSHAKE_OK,
                  "handshake_responder_init");
}

/* Drives the handshake forward to (but not including) `stop`. */
typedef enum { AT_CH, AT_CH_ACCEPTED, AT_SH, AT_SH_VERIFIED, AT_CA, AT_CA_VERIFIED, AT_DONE } stage_t;

static void advance_to(pair_t *p, stage_t stop) {
    pair_init(p);
    if (stop == AT_CH) {
        return;
    }
    BENCH_REQUIRE(handshake_initiator_create_client_hello(&p->ini, p->ch, sizeof(p->ch), &p->ch_len) ==
                      HANDSHAKE_OK,
                  "create_client_hello");
    if (stop == AT_CH_ACCEPTED) {
        return;
    }
    BENCH_REQUIRE(handshake_responder_accept_client_hello(&p->res, p->ch, p->ch_len) == HANDSHAKE_OK,
                  "accept_client_hello");
    if (stop == AT_SH) {
        return;
    }
    BENCH_REQUIRE(handshake_responder_create_server_hello(&p->res, p->sh, sizeof(p->sh), &p->sh_len) ==
                      HANDSHAKE_OK,
                  "create_server_hello");
    if (stop == AT_SH_VERIFIED) {
        return;
    }
    BENCH_REQUIRE(handshake_initiator_verify_server_hello(&p->ini, p->sh, p->sh_len) == HANDSHAKE_OK,
                  "verify_server_hello");
    if (stop == AT_CA) {
        return;
    }
    BENCH_REQUIRE(handshake_initiator_create_client_auth(&p->ini, p->ca, sizeof(p->ca), &p->ca_len) ==
                      HANDSHAKE_OK,
                  "create_client_auth");
    if (stop == AT_CA_VERIFIED) {
        return;
    }
    BENCH_REQUIRE(handshake_responder_verify_client_auth(&p->res, p->ca, p->ca_len) == HANDSHAKE_OK,
                  "verify_client_auth");
}

/* ---- per-phase rows ------------------------------------------------------ */

#define PHASE(fn_name, stage, body)                    \
    static void prep_##fn_name(void *ctx, size_t k) {  \
        (void)ctx;                                     \
        (void)k;                                       \
        pair_wipe(&g_p);                               \
        advance_to(&g_p, (stage));                     \
    }                                                  \
    static void w_##fn_name(void *ctx, size_t k) {     \
        (void)ctx;                                     \
        (void)k;                                       \
        body                                           \
    }

PHASE(create_ch, AT_CH, {
    BENCH_REQUIRE(handshake_initiator_create_client_hello(&g_p.ini, g_p.ch, sizeof(g_p.ch),
                                                          &g_p.ch_len) == HANDSHAKE_OK,
                  "create_client_hello");
})

PHASE(accept_ch, AT_CH_ACCEPTED, {
    BENCH_REQUIRE(handshake_responder_accept_client_hello(&g_p.res, g_p.ch, g_p.ch_len) == HANDSHAKE_OK,
                  "accept_client_hello");
})

PHASE(create_sh, AT_SH, {
    BENCH_REQUIRE(handshake_responder_create_server_hello(&g_p.res, g_p.sh, sizeof(g_p.sh),
                                                          &g_p.sh_len) == HANDSHAKE_OK,
                  "create_server_hello");
})

PHASE(verify_sh, AT_SH_VERIFIED, {
    BENCH_REQUIRE(handshake_initiator_verify_server_hello(&g_p.ini, g_p.sh, g_p.sh_len) == HANDSHAKE_OK,
                  "verify_server_hello");
})

PHASE(create_ca, AT_CA, {
    BENCH_REQUIRE(handshake_initiator_create_client_auth(&g_p.ini, g_p.ca, sizeof(g_p.ca),
                                                         &g_p.ca_len) == HANDSHAKE_OK,
                  "create_client_auth");
})

PHASE(verify_ca, AT_CA_VERIFIED, {
    BENCH_REQUIRE(handshake_responder_verify_client_auth(&g_p.res, g_p.ca, g_p.ca_len) == HANDSHAKE_OK,
                  "verify_client_auth");
})

/* Both finish calls, from a fully verified pair. */
static void prep_finish(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    pair_wipe(&g_p);
    advance_to(&g_p, AT_DONE);
}

static void w_finish_ini(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    BENCH_REQUIRE(handshake_initiator_finish(&g_p.ini) == HANDSHAKE_OK, "initiator_finish");
}

static void w_finish_res(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    BENCH_REQUIRE(handshake_responder_finish(&g_p.res) == HANDSHAKE_OK, "responder_finish");
}

/* ---- in-process end-to-end ----------------------------------------------- */

static void prep_e2e(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    pair_wipe(&g_p);
    pair_init(&g_p);
}

static void w_e2e(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    pair_t *p = &g_p;
    BENCH_REQUIRE(
        handshake_initiator_create_client_hello(&p->ini, p->ch, sizeof(p->ch), &p->ch_len) == HANDSHAKE_OK &&
            handshake_responder_accept_client_hello(&p->res, p->ch, p->ch_len) == HANDSHAKE_OK &&
            handshake_responder_create_server_hello(&p->res, p->sh, sizeof(p->sh), &p->sh_len) == HANDSHAKE_OK &&
            handshake_initiator_verify_server_hello(&p->ini, p->sh, p->sh_len) == HANDSHAKE_OK &&
            handshake_initiator_create_client_auth(&p->ini, p->ca, sizeof(p->ca), &p->ca_len) == HANDSHAKE_OK &&
            handshake_responder_verify_client_auth(&p->res, p->ca, p->ca_len) == HANDSHAKE_OK &&
            handshake_initiator_finish(&p->ini) == HANDSHAKE_OK &&
            handshake_responder_finish(&p->res) == HANDSHAKE_OK,
        "in-process handshake");
    BENCH_REQUIRE(handshake_get_state(&p->ini) == HANDSHAKE_STATE_ESTABLISHED &&
                      handshake_get_state(&p->res) == HANDSHAKE_STATE_ESTABLISHED,
                  "both sides must reach ESTABLISHED");
}

/* ---- loopback end-to-end -------------------------------------------------- */

static net_conn_t g_client;
static net_conn_t g_server;
static int g_listen_fd = -1;
static uint8_t g_txbuf[FRAME_BUF_BYTES];
static uint8_t g_rxbuf[FRAME_BUF_BYTES];

/*
 * Fix the socket buffers at setup and PROVE they are big enough, instead of
 * discovering mid-run that a send blocked.
 *
 * This benchmark drives both ends of the connection from one process, in
 * strict request/response order, so it never reads and writes concurrently.
 * That is only safe while every message fits in the kernel's socket buffer:
 * a send larger than the buffer would block forever with nobody to drain it.
 * The largest handshake message is a ServerHello (~3.4 KB), so 256 KiB is
 * ample -- but setsockopt() is advisory, so the granted size is read back
 * and checked here. If a kernel ever granted less than the margin below,
 * this aborts at startup rather than deadlocking or silently changing the
 * shape of the measurement. There is deliberately no fallback path and no
 * forked variant: the single-process control flow is guaranteed for every
 * run by construction.
 */
static int granted_buf(int fd, int opt) {
    int v = 0;
    socklen_t len = sizeof(v);
    BENCH_REQUIRE(getsockopt(fd, SOL_SOCKET, opt, &v, &len) == 0, "getsockopt");
    return v;
}

static void setup_loopback(void) {
    uint16_t port = 0;
    BENCH_REQUIRE(net_listen_loopback(0, 4, &g_listen_fd, &port) == NET_OK, "net_listen_loopback");
    net_conn_init(&g_client);
    net_conn_init(&g_server);
    BENCH_REQUIRE(net_connect_loopback(port, net_deadline_in(HS_DEADLINE_MS), &g_client) == NET_OK,
                  "net_connect_loopback");
    BENCH_REQUIRE(net_accept(g_listen_fd, net_deadline_in(HS_DEADLINE_MS), &g_server) == NET_OK,
                  "net_accept");

    const int want = SOCK_BUF;
    const int fds[2] = {g_client.fd, g_server.fd};
    for (int i = 0; i < 2; i++) {
        BENCH_REQUIRE(setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &want, sizeof(want)) == 0 &&
                          setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &want, sizeof(want)) == 0,
                      "setsockopt(SO_SNDBUF/SO_RCVBUF)");
    }
    /* Every handshake message must fit with room to spare: the largest is a
     * ServerHello, and 4x that is the margin this benchmark insists on. */
    const int need = 4 * (int)(FRAME_HEADER_BYTES + SERVER_HELLO_MAX_ENCODED_LEN);
    int min_granted = 0;
    for (int i = 0; i < 2; i++) {
        const int snd = granted_buf(fds[i], SO_SNDBUF);
        const int rcv = granted_buf(fds[i], SO_RCVBUF);
        BENCH_REQUIRE(snd >= need && rcv >= need,
                      "socket buffers too small for single-process operation: fd %d granted "
                      "SO_SNDBUF=%d SO_RCVBUF=%d, need >= %d (requested %d). Refusing to run: a "
                      "send could block with no concurrent reader.",
                      fds[i], snd, rcv, need, want);
        if (min_granted == 0 || snd < min_granted) {
            min_granted = snd;
        }
        if (rcv < min_granted) {
            min_granted = rcv;
        }
    }
    bench_env_line("socket buffers", "requested %d B, granted >= %d B per direction (need >= %d B)",
                   want, min_granted, need);
}

static void teardown_loopback(void) {
    net_close(&g_client);
    net_close(&g_server);
    net_close_fd(&g_listen_fd);
}

static void send_msg(net_conn_t *c, const uint8_t *msg, size_t len) {
    memcpy(g_txbuf + FRAME_HEADER_BYTES, msg, len);
    BENCH_REQUIRE(frame_send(c, g_txbuf, len, net_deadline_in(HS_DEADLINE_MS)) == FRAME_OK, "frame_send");
}

static size_t recv_msg(net_conn_t *c, size_t max_len) {
    size_t got = 0;
    BENCH_REQUIRE(frame_recv(c, g_rxbuf, 1u, max_len, &got, net_deadline_in(HS_DEADLINE_MS)) == FRAME_OK,
                  "frame_recv");
    return got;
}

static void w_e2e_loopback(void *ctx, size_t k) {
    (void)ctx;
    (void)k;
    pair_t *p = &g_p;
    BENCH_REQUIRE(handshake_initiator_create_client_hello(&p->ini, p->ch, sizeof(p->ch), &p->ch_len) ==
                      HANDSHAKE_OK,
                  "create_client_hello");
    send_msg(&g_client, p->ch, p->ch_len);
    size_t n = recv_msg(&g_server, CLIENT_HELLO_MAX_ENCODED_LEN);
    BENCH_REQUIRE(handshake_responder_accept_client_hello(&p->res, g_rxbuf + FRAME_HEADER_BYTES, n) ==
                      HANDSHAKE_OK,
                  "accept_client_hello");
    BENCH_REQUIRE(handshake_responder_create_server_hello(&p->res, p->sh, sizeof(p->sh), &p->sh_len) ==
                      HANDSHAKE_OK,
                  "create_server_hello");
    send_msg(&g_server, p->sh, p->sh_len);
    n = recv_msg(&g_client, SERVER_HELLO_MAX_ENCODED_LEN);
    BENCH_REQUIRE(handshake_initiator_verify_server_hello(&p->ini, g_rxbuf + FRAME_HEADER_BYTES, n) ==
                      HANDSHAKE_OK,
                  "verify_server_hello");
    BENCH_REQUIRE(handshake_initiator_create_client_auth(&p->ini, p->ca, sizeof(p->ca), &p->ca_len) ==
                      HANDSHAKE_OK,
                  "create_client_auth");
    send_msg(&g_client, p->ca, p->ca_len);
    n = recv_msg(&g_server, CLIENT_AUTH_MAX_ENCODED_LEN);
    BENCH_REQUIRE(handshake_responder_verify_client_auth(&p->res, g_rxbuf + FRAME_HEADER_BYTES, n) ==
                          HANDSHAKE_OK &&
                      handshake_initiator_finish(&p->ini) == HANDSHAKE_OK &&
                      handshake_responder_finish(&p->res) == HANDSHAKE_OK,
                  "loopback handshake completion");
}

/* Connection setup, measured separately so the handshake row above is not
 * charged for it (the connection is established once and reused). */
static void w_connect(void *ctx, size_t k) {
    (void)ctx;
    for (size_t i = 0; i < k; i++) {
        int lfd = -1;
        uint16_t port = 0;
        net_conn_t c;
        net_conn_t s;
        net_conn_init(&c);
        net_conn_init(&s);
        BENCH_REQUIRE(net_listen_loopback(0, 4, &lfd, &port) == NET_OK &&
                          net_connect_loopback(port, net_deadline_in(HS_DEADLINE_MS), &c) == NET_OK &&
                          net_accept(lfd, net_deadline_in(HS_DEADLINE_MS), &s) == NET_OK,
                      "loopback connect/accept");
        net_close(&c);
        net_close(&s);
        net_close_fd(&lfd);
    }
}

/* ---- main ---------------------------------------------------------------- */

int main(int argc, char **argv) {
    bench_init(argc, argv, "handshake");

    BENCH_REQUIRE(mldsa_keypair_generate(&g_kp_a) == 0 && mldsa_keypair_generate(&g_kp_b) == 0,
                  "identity keypairs");
    keystore_init(&g_ks);
    BENCH_REQUIRE(keystore_add(&g_ks, ID_A, ID_A_LEN, g_kp_a.public_key) == KEYSTORE_OK &&
                      keystore_add(&g_ks, ID_B, ID_B_LEN, g_kp_b.public_key) == KEYSTORE_OK,
                  "keystore_add");
    BENCH_REQUIRE(handshake_pending_store_init(&g_store, PENDING_CAP, PENDING_TTL_MS, NULL, NULL) ==
                      PENDING_OK,
                  "handshake_pending_store_init");
    memset(&g_p, 0, sizeof(g_p));

    bench_section("Handshake phases (each timed alone, state prepared untimed)");
    bench_result_t r = bench_run("initiator: create ClientHello", "", prep_create_ch, w_create_ch, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("responder: accept ClientHello", "", prep_accept_ch, w_accept_ch, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("responder: create ServerHello", "sign", prep_create_sh, w_create_sh, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("initiator: verify ServerHello", "verify", prep_verify_sh, w_verify_sh, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("initiator: create ClientAuth", "sign", prep_create_ca, w_create_ca, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("responder: verify ClientAuth", "verify", prep_verify_ca, w_verify_ca, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("initiator: finish (X25519 + KDF)", "", prep_finish, w_finish_ini, NULL, 1, 0.0);
    bench_report(&r);
    r = bench_run("responder: finish", "", prep_finish, w_finish_res, NULL, 1, 0.0);
    bench_report(&r);

    bench_section("Full mutual handshake");
    r = bench_run("end-to-end, in process (no sockets)", "", prep_e2e, w_e2e, NULL, 1, 0.0);
    bench_report(&r);
    const double e2e_median_ns = r.median_ns;

    setup_loopback();
    r = bench_run("end-to-end, TCP loopback + framing", "", prep_e2e, w_e2e_loopback, NULL, 1, 0.0);
    bench_report(&r);
    const double loop_median_ns = r.median_ns;
    r = bench_run("loopback connect + accept", "", NULL, w_connect, NULL, 1, 0.0);
    bench_report(&r);
    teardown_loopback();

    if (!bench_csv_mode) {
        printf("\n  in-process median %.3f ms vs the spec's 15 ms target: %s\n",
               e2e_median_ns / 1e6, (e2e_median_ns < 15e6) ? "PASS" : "MISS");
        printf("  transport adds %.3f ms (loopback %.3f ms - in process %.3f ms)\n",
               (loop_median_ns - e2e_median_ns) / 1e6, loop_median_ns / 1e6, e2e_median_ns / 1e6);
    }

    pair_wipe(&g_p);
    handshake_pending_store_wipe(&g_store);
    keystore_wipe(&g_ks);
    mldsa_keypair_free(&g_kp_a);
    mldsa_keypair_free(&g_kp_b);
    bench_finish("handshake");
    return 0;
}
