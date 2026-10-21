/*
 * V4-8a: the daemon's transport skeleton -- config, frame reassembly, the
 * poll() event loop and its slot pool.
 *
 * Two habits from earlier steps are deliberate here:
 *
 *  - Every deadline check carries a LOWER BOUND. Asserting only "the peer was
 *    closed after N ms" is satisfied by a daemon that closes everything
 *    instantly, so each one first proves the connection is still alive one
 *    millisecond BEFORE its deadline. Time is an argument to
 *    evloop_run_once(), so this is exact rather than wall-clock flaky.
 *  - The log-hygiene check has a PRESENT CANARY. It first proves the canary is
 *    observable in the daemon's own output, then proves the secret never is --
 *    otherwise "nothing leaked" could be true because nothing was logged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>

#include <sodium.h>

#include "authd_config.h"
#include "conn_io.h"
#include "evloop.h"
#include "listener.h"
#include "authd_log.h"
#include "memlock.h"

static int g_fail = 0;
static int g_checks = 0;

static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) {
        printf("FAIL: %s\n", what);
        g_fail = 1;
    }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

/* ------------------------------------------------------------------ config */

static authd_config_status_t parse_str(const char *s, authd_config_t *cfg, size_t *line)
{
    return authd_config_parse((const uint8_t *)s, strlen(s), cfg, line);
}

#define BASE "store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = sid\nlisten_port = 9\n"

static void test_config(void)
{
    authd_config_t cfg;
    size_t line = 0;

    CHECK(parse_str(BASE, &cfg, &line) == AUTHD_CFG_OK, "cfg: a minimal valid config parses");
    CHECK(strcmp(cfg.store_path, "/s") == 0 && strcmp(cfg.key_path, "/k") == 0 &&
          cfg.server_id_len == 3 && memcmp(cfg.server_id, "sid", 3) == 0 && cfg.listen_port == 9,
          "cfg: values land in the right fields");
    CHECK(cfg.max_slots == 256u && cfg.handshake_timeout_ms == 10000u &&
          cfg.idle_timeout_ms == 60000u && cfg.pad_bucket == 256u,
          "cfg: documented defaults apply to the optional keys");

    /* strictness */
    CHECK(parse_str("listen_port = 9\n", &cfg, &line) == AUTHD_CFG_ERR_MISSING,
          "cfg: a missing required key is refused");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\n", &cfg, &line) == AUTHD_CFG_ERR_MISSING,
          "cfg: a config with no listener at all is refused");
    CHECK(parse_str(BASE "nope = 1\n", &cfg, &line) == AUTHD_CFG_ERR_UNKNOWN_KEY,
          "cfg: an unknown key is refused");
    CHECK(parse_str(BASE "store_path = /t\n", &cfg, &line) == AUTHD_CFG_ERR_DUPLICATE_KEY,
          "cfg: a duplicate key is refused");
    CHECK(parse_str("store_path\n", &cfg, &line) == AUTHD_CFG_ERR_SYNTAX,
          "cfg: a line with no '=' is refused");
    CHECK(parse_str(" = /s\n", &cfg, &line) == AUTHD_CFG_ERR_SYNTAX,
          "cfg: an empty key is refused");

    /* bounds, each at and just past the edge */
    CHECK(parse_str(BASE "max_slots = 0\n", &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: max_slots 0 is out of range");
    CHECK(parse_str(BASE "max_slots = 4097\n", &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: max_slots 4097 is out of range");
    CHECK(parse_str(BASE "max_slots = 4096\n", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: max_slots 4096 is accepted");
    CHECK(parse_str(BASE "handshake_timeout_ms = 99\n", &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: a timeout under the floor is refused");
    CHECK(parse_str(BASE "idle_timeout_ms = 600001\n", &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: a timeout over the ceiling is refused");
    CHECK(parse_str(BASE "pad_bucket = 32\n", &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: pad_bucket 32 is refused (a range check alone would admit it)");
    CHECK(parse_str(BASE "pad_bucket = 4096\n", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: pad_bucket 4096 is accepted");
    CHECK(parse_str(BASE "listen_port = 65536\n", &cfg, &line) == AUTHD_CFG_ERR_DUPLICATE_KEY,
          "cfg: duplicate detection precedes range checking");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 99999999999\n",
                    &cfg, &line) == AUTHD_CFG_ERR_RANGE,
          "cfg: a number that would overflow is refused");

    /* the passphrase file is required: the daemon cannot open its key without
     * one, and V4-8b deliberately offers no env/argv alternative */
    CHECK(parse_str("store_path = /s\nkey_path = /k\nserver_id = s\nlisten_port = 9\n", &cfg, &line)
              == AUTHD_CFG_ERR_MISSING,
          "cfg: key_passphrase_file is required");
    CHECK(parse_str(BASE, &cfg, &line) == AUTHD_CFG_OK &&
          strcmp(cfg.key_passphrase_file, "/p") == 0,
          "cfg: key_passphrase_file is parsed into its own field");

    /* V4-13d: what the journal may say about a peer (spec §15). The default is
     * what every earlier release logged, so an upgrade changes nothing. */
    CHECK(parse_str(BASE, &cfg, &line) == AUTHD_CFG_OK &&
          cfg.log_identities == AUTHD_LOG_IDS_FULL && cfg.log_client_ip == AUTHD_LOG_IP_FULL,
          "cfg: log_identities and log_client_ip default to full");
    CHECK(parse_str(BASE "log_identities = hashed\nlog_client_ip = prefix\n", &cfg, &line) == AUTHD_CFG_OK &&
          cfg.log_identities == AUTHD_LOG_IDS_HASHED && cfg.log_client_ip == AUTHD_LOG_IP_PREFIX,
          "cfg: log_identities = hashed and log_client_ip = prefix parse");
    CHECK(parse_str(BASE "log_identities = off\nlog_client_ip = off\n", &cfg, &line) == AUTHD_CFG_OK &&
          cfg.log_identities == AUTHD_LOG_IDS_OFF && cfg.log_client_ip == AUTHD_LOG_IP_OFF,
          "cfg: both switches accept off");
    CHECK(parse_str(BASE "log_identities = full\nlog_client_ip = full\n", &cfg, &line) == AUTHD_CFG_OK &&
          cfg.log_identities == AUTHD_LOG_IDS_FULL && cfg.log_client_ip == AUTHD_LOG_IP_FULL,
          "cfg: both switches accept full");
    CHECK(parse_str(BASE "log_identities = yes\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE &&
          parse_str(BASE "log_identities = Hashed\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE &&
          parse_str(BASE "log_identities = prefix\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE &&
          parse_str(BASE "log_identities = \n", &cfg, &line) == AUTHD_CFG_ERR_VALUE,
          "cfg: log_identities refuses anything but its three words (one of ip's included)");
    CHECK(parse_str(BASE "log_client_ip = /24\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE &&
          parse_str(BASE "log_client_ip = hashed\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE &&
          parse_str(BASE "log_client_ip = prefixes\n", &cfg, &line) == AUTHD_CFG_ERR_VALUE,
          "cfg: log_client_ip refuses anything but its three words (one of ids' included)");
    CHECK(parse_str(BASE "log_client_ip = off\nlog_client_ip = full\n", &cfg, &line) == AUTHD_CFG_ERR_DUPLICATE_KEY,
          "cfg: a repeated log switch is a duplicate key");

    /* V4-14c, F92: an empty allowlist checks no peer credentials at all (Req
     * 11), so leaving it out is refused rather than silently accepted. */
    CHECK(parse_str(BASE "site_socket = /run/s.sock\n", &cfg, &line) == AUTHD_CFG_ERR_MISSING,
          "cfg: a site socket without site_uids is refused (Req 11)");
    CHECK(parse_str(BASE "site_socket = /run/s.sock\nsite_uids = 33\n", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: ...and accepted once site_uids names who may use it");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = sid\n"
                    "listen_unix = /run/p.sock\nproxy_protocol = v2\n", &cfg, &line) == AUTHD_CFG_ERR_MISSING,
          "cfg: proxy_protocol = v2 without proxy_uids is refused (Req 11)");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = sid\n"
                    "listen_unix = /run/p.sock\nproxy_protocol = v2\nproxy_uids = 33\n", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: ...and accepted once proxy_uids names the proxy");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = sid\n"
                    "listen_unix = /run/p.sock\n", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: a proxy-facing listener WITHOUT proxy_protocol still needs no proxy_uids (the development shape)");

    /* the contract the fuzzer found broken: a failed parse applies nothing */
    {
        authd_config_t def;
        authd_config_defaults(&def);
        CHECK(parse_str(BASE "nope = 1\n", &cfg, &line) == AUTHD_CFG_ERR_UNKNOWN_KEY &&
              memcmp(&cfg, &def, sizeof cfg) == 0,
              "cfg: a failed parse leaves NOTHING applied, not even the good keys before it");
    }

    /* comments, blanks, no trailing newline, CRLF */
    CHECK(parse_str("# c\n\n" BASE, &cfg, &line) == AUTHD_CFG_OK, "cfg: comments and blank lines");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 9", &cfg, &line) == AUTHD_CFG_OK,
          "cfg: a final line without a newline still parses");
    CHECK(parse_str("store_path = /s\r\nkey_path = /k\r\nkey_passphrase_file = /p\r\nserver_id = s\r\nlisten_port = 9\r\n", &cfg, &line)
              == AUTHD_CFG_OK,
          "cfg: CRLF line endings are accepted");
    CHECK(parse_str(BASE "server_id = \n", &cfg, &line) == AUTHD_CFG_ERR_DUPLICATE_KEY,
          "cfg: an empty value on a duplicate key still reports the duplicate");
    CHECK(parse_str("store_path = /s\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = \nlisten_port = 9\n", &cfg, &line)
              == AUTHD_CFG_ERR_VALUE,
          "cfg: an empty required value is refused");
    /* a NUL inside a value must not be stored and handed to open() later */
    {
        const char raw[] = "store_path = /a\0b\nkey_path = /k\nkey_passphrase_file = /p\nserver_id = s\nlisten_port = 9\n";
        CHECK(authd_config_parse((const uint8_t *)raw, sizeof raw - 1u, &cfg, &line) == AUTHD_CFG_ERR_VALUE,
              "cfg: a NUL byte inside a value is refused");
    }
}

/* ----------------------------------------------------------------- conn_io */

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void test_conn_io(void)
{
    conn_io_t c;

    /* one whole frame in one push */
    conn_io_reset(&c);
    {
        uint8_t f[4 + 5];
        put_be32(f, 5);
        memcpy(f + 4, "hello", 5);
        CHECK(conn_io_push(&c, f, sizeof f) == CONN_IO_OK, "io: push a complete frame");
        const uint8_t *p = NULL; size_t n = 0;
        CHECK(conn_io_next_frame(&c, &p, &n) == 1 && n == 5 && memcmp(p, "hello", 5) == 0,
              "io: the frame comes back intact");
        conn_io_consume_frame(&c);
        CHECK(conn_io_next_frame(&c, &p, &n) == 0, "io: nothing left after consuming");
    }

    /* EVERY split point of a two-frame stream must reassemble identically */
    {
        uint8_t stream[(4 + 3) + (4 + 4)];
        put_be32(stream, 3); memcpy(stream + 4, "abc", 3);
        put_be32(stream + 7, 4); memcpy(stream + 11, "wxyz", 4);
        int all_ok = 1;
        for (size_t cut = 0; cut <= sizeof stream; cut++) {
            conn_io_reset(&c);
            if (conn_io_push(&c, stream, cut) != CONN_IO_OK) { all_ok = 0; break; }
            if (conn_io_push(&c, stream + cut, sizeof stream - cut) != CONN_IO_OK) { all_ok = 0; break; }
            const uint8_t *p = NULL; size_t n = 0;
            if (!conn_io_next_frame(&c, &p, &n) || n != 3 || memcmp(p, "abc", 3) != 0) { all_ok = 0; break; }
            conn_io_consume_frame(&c);
            if (!conn_io_next_frame(&c, &p, &n) || n != 4 || memcmp(p, "wxyz", 4) != 0) { all_ok = 0; break; }
            conn_io_consume_frame(&c);
            if (conn_io_next_frame(&c, &p, &n)) { all_ok = 0; break; }
        }
        CHECK(all_ok, "io: two frames reassemble identically at every one of the 16 split points");
    }

    /* byte-at-a-time delivery */
    {
        conn_io_reset(&c);
        uint8_t f[4 + 6];
        put_be32(f, 6); memcpy(f + 4, "abcdef", 6);
        int ok = 1;
        for (size_t i = 0; i < sizeof f; i++) {
            if (conn_io_push(&c, f + i, 1) != CONN_IO_OK) { ok = 0; break; }
            const uint8_t *p = NULL; size_t n = 0;
            const int have = conn_io_next_frame(&c, &p, &n);
            if (i + 1u < sizeof f && have) { ok = 0; break; }      /* not before the last byte */
            if (i + 1u == sizeof f && !have) { ok = 0; break; }    /* exactly at the last byte */
        }
        CHECK(ok, "io: a frame becomes available on exactly its final byte, not before");
    }

    /* illegal declared lengths are terminal and sticky */
    conn_io_reset(&c);
    { uint8_t h[4]; put_be32(h, 0);
      CHECK(conn_io_push(&c, h, 4) == CONN_IO_ERR_PROTOCOL, "io: a zero-length frame is refused"); }
    conn_io_reset(&c);
    { uint8_t h[4]; put_be32(h, (uint32_t)AUTHD_FRAME_MAX + 1u);
      CHECK(conn_io_push(&c, h, 4) == CONN_IO_ERR_PROTOCOL, "io: a frame one byte over the cap is refused");
      uint8_t good[4]; put_be32(good, 1);
      CHECK(conn_io_push(&c, good, 4) == CONN_IO_ERR_PROTOCOL,
            "io: the protocol error is sticky -- a good frame after a bad one is still refused"); }
    conn_io_reset(&c);
    { uint8_t h[4]; put_be32(h, (uint32_t)AUTHD_FRAME_MAX);
      CHECK(conn_io_push(&c, h, 4) == CONN_IO_OK, "io: a frame exactly at the cap is accepted"); }

    /* outbound: queue, partial send, completion, BUSY */
    conn_io_reset(&c);
    {
        const uint8_t body[4] = { 1, 2, 3, 4 };
        CHECK(conn_io_queue(&c, body, sizeof body) == CONN_IO_OK, "io: queue a reply");
        CHECK(conn_io_pending(&c) == 8u, "io: pending is header + payload");
        CHECK(conn_io_queue(&c, body, sizeof body) == CONN_IO_ERR_BUSY,
              "io: queueing over an unsent reply is BUSY");
        conn_io_sent(&c, 3);
        CHECK(conn_io_pending(&c) == 5u, "io: a partial send leaves the remainder pending");
        CHECK(conn_io_pending_ptr(&c) == c.out + 3, "io: the pending pointer advances");
        conn_io_sent(&c, 5);
        CHECK(conn_io_pending(&c) == 0u, "io: the reply completes");
        CHECK(conn_io_queue(&c, body, sizeof body) == CONN_IO_OK, "io: a new reply can be queued after flush");
        CHECK(conn_io_queue(&c, body, 0) == CONN_IO_ERR_ARG, "io: a zero-length reply is rejected");
    }
}

/* ------------------------------------------------------------------ evloop */

typedef struct {
    int frames;
    int close_calls;
    size_t last_len;
    int echo;
    int close_after;
    const char *canary;       /* if set, on_frame records whether it is in the slot */
    int canary_seen_live;
    const char *ahead;        /* V4-54: bytes expected BEHIND the frame being served ... */
    int ahead_at;             /* ... when h->frames reaches this */
    int ahead_seen;
} harness_t;

static ev_action_t on_frame(void *user, authd_slot_t *slot, const uint8_t *payload, size_t len)
{
    harness_t *h = (harness_t *)user;
    h->frames++;
    h->last_len = len;
    if (h->canary != NULL &&
        memmem(slot->io.in, sizeof slot->io.in, h->canary, strlen(h->canary)) != NULL) {
        /* observed while the frame is genuinely in the slot's buffer -- this is
         * what stops the post-close absence check below from being vacuous */
        h->canary_seen_live = 1;
    }
    if (h->ahead != NULL && h->frames == h->ahead_at &&
        memmem(payload + len, (size_t)(slot->io.in + slot->io.in_len - (payload + len)),
               h->ahead, strlen(h->ahead)) != NULL) {
        h->ahead_seen = 1;
    }
    if (h->echo) {
        (void)conn_io_queue(&slot->io, payload, len);
    }
    return h->close_after ? EV_ACTION_CLOSE : EV_ACTION_CONTINUE;
}

static void on_close(void *user, authd_slot_t *slot)
{
    (void)slot;
    ((harness_t *)user)->close_calls++;
}

static int dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) { (void)close(fd); return -1; }
    return fd;
}

/* Runs the loop until `pred` holds, holding time fixed so only I/O
 * progresses. V4-37: these were fixed counts of three to six turns, and the
 * comment here promised a predicate the function never took. A loaded
 * machine (a busy CI runner, the sanitizers, a parallel ctest) can need more
 * turns than a count allows, and the test then fails for a reason that is
 * not a defect. The ceiling -- 2,000 turns, at most 10 ms each -- bounds a
 * predicate that never holds, and that is a FAILED CHECK of its own, named by
 * the predicate: a wait that never ends as intended must not pass just
 * because the check after it happens to hold anyway. */
#define PUMP_UNTIL(ev, now, pred) ({ int _ok = 0;                                  \
    for (int _i = 0; _i < 2000; _i++) {                                         \
        if (pred) { _ok = 1; break; }                                            \
        (void)evloop_run_once((ev), 10, (now));                                  \
    }                                                                            \
    check(_ok, "ev: the loop reached, within 2,000 turns: " #pred);              \
    _ok; })

/* A fixed number of turns, for the one place nothing is awaited. */
static void pump_n(evloop_t *ev, uint64_t now, int iters)
{
    for (int i = 0; i < iters; i++) {
        (void)evloop_run_once(ev, 10, now);
    }
}

static int partial_buffered(const authd_slot_t *slots, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (memmem(slots[i].io.in, sizeof slots[i].io.in, "PART", 4) != NULL) { return 1; }
    }
    return 0;
}

static void test_evloop(void)
{
    enum { NSLOTS = 2 };
    static authd_slot_t slots[NSLOTS];
    evloop_t ev;
    harness_t h;
    int lfd = -1;
    uint16_t port = 0;

    memset(&h, 0, sizeof h);
    h.echo = 1;

    CHECK(listener_open_loopback(0, 8, &lfd, &port) == LISTENER_OK && port != 0,
          "ev: loopback listener binds an ephemeral port");
    CHECK(evloop_init(&ev, slots, NSLOTS, 5000u, 20000u, on_frame, on_close, &h) == 0, "ev: init");
    CHECK(evloop_add_listener(&ev, lfd, (uid_t)-1) == 0, "ev: listener registered");

    /* accept + echo one frame */
    int c1 = dial(port);
    CHECK(c1 >= 0, "ev: client connects");
    (void)PUMP_UNTIL(&ev, 1000, evloop_active(&ev) == 1u);
    CHECK(evloop_active(&ev) == 1u, "ev: the connection occupies exactly one slot");
    CHECK(slots[0].deadline_ms == 1000u + 5000u,
          "ev: a fresh connection gets the HANDSHAKE deadline");

    {
        uint8_t f[4 + 5];
        put_be32(f, 5); memcpy(f + 4, "hello", 5);
        CHECK(write(c1, f, sizeof f) == (ssize_t)sizeof f, "ev: client sends a frame");
        /* Until the reply is written too: the read below blocks, and an
         * unflushed reply would hang it rather than fail. */
        (void)PUMP_UNTIL(&ev, 1000, h.frames >= 1 && conn_io_pending(&slots[0].io) == 0u);
        CHECK(h.frames == 1 && h.last_len == 5, "ev: the loop delivered exactly one 5-byte frame");
        uint8_t back[4 + 5];
        ssize_t got = read(c1, back, sizeof back);
        CHECK(got == (ssize_t)sizeof back && memcmp(back + 4, "hello", 5) == 0,
              "ev: the echoed reply arrives complete");
    }

    /* the deadline, with its lower bound */
    {
        /* the frame above re-armed it to the idle timeout */
        CHECK(slots[0].deadline_ms == 1000u + 20000u,
              "ev: serving a frame re-arms the deadline to the IDLE timeout");
        const uint64_t dl = slots[0].deadline_ms;
        (void)evloop_run_once(&ev, 0, dl - 1u);
        CHECK(evloop_active(&ev) == 1u, "ev: the connection is STILL OPEN one ms before its deadline");
        (void)evloop_run_once(&ev, 0, dl);
        CHECK(evloop_active(&ev) == 0u, "ev: the connection is closed at its deadline");
        CHECK(ev.closed_deadline == 1u, "ev: the deadline close is counted");
        CHECK(h.close_calls == 1, "ev: on_close ran for the expired slot");
    }
    (void)close(c1);

    /* slot exhaustion: NSLOTS accepted, the next refused */
    {
        int a = dial(port), b = dial(port), c = dial(port);
        CHECK(a >= 0 && b >= 0 && c >= 0, "ev: three clients connect");
        (void)PUMP_UNTIL(&ev, 2000, evloop_active(&ev) == (size_t)NSLOTS && ev.refused_no_slot >= 1u);
        CHECK(evloop_active(&ev) == (size_t)NSLOTS, "ev: only max_slots connections are held");
        CHECK(ev.refused_no_slot >= 1u, "ev: the connection beyond capacity is refused, not queued");
        (void)close(a); (void)close(b); (void)close(c);
        (void)PUMP_UNTIL(&ev, 2000, evloop_active(&ev) == 0u);
    }

    /* a slot is wiped before reuse -- with a present canary so it is not vacuous */
    {
        evloop_close_all(&ev);
        pump_n(&ev, 3000, 2);   /* nothing to await: close_all is synchronous */
        int d = dial(port);
        CHECK(d >= 0, "ev: reuse client connects");
        (void)PUMP_UNTIL(&ev, 3000, evloop_active(&ev) == 1u);
        uint8_t f[4 + 6];
        put_be32(f, 6); memcpy(f + 4, "SECRET", 6);
        h.canary = "SECRET";
        h.canary_seen_live = 0;
        CHECK(write(d, f, sizeof f) == (ssize_t)sizeof f, "ev: reuse client sends a marker frame");
        (void)PUMP_UNTIL(&ev, 3000, h.canary_seen_live == 1);
        CHECK(h.canary_seen_live == 1,
              "ev: the canary IS observable in the live slot (the wipe check is not vacuous)");
        (void)close(d);
        evloop_close_all(&ev);
        int still = 0;
        for (int i = 0; i < NSLOTS; i++) {
            if (memmem(slots[i].io.in, sizeof slots[i].io.in, "SECRET", 6) != NULL ||
                memmem(slots[i].io.out, sizeof slots[i].io.out, "SECRET", 6) != NULL) {
                still = 1;
            }
        }
        CHECK(!still, "ev: closing a slot wipes its buffers, so the next connection cannot see them");
    }

    /* The case the wipe-on-close actually exists for: a PARTIAL frame that
     * never completes. A consumed frame is already zeroed by
     * conn_io_consume_frame, so it cannot distinguish the close-wipe; bytes
     * that were never consumed can, and only evloop_close_slot clears them. */
    {
        int d = dial(port);
        CHECK(d >= 0, "ev: partial-frame client connects");
        (void)PUMP_UNTIL(&ev, 5000, evloop_active(&ev) == 1u);
        uint8_t part[4 + 4];
        put_be32(part, 32);                    /* declares 32 bytes ... */
        memcpy(part + 4, "PART", 4);           /* ... but sends only 4 */
        CHECK(write(d, part, sizeof part) == (ssize_t)sizeof part,
              "ev: client sends an incomplete frame");
        (void)PUMP_UNTIL(&ev, 5000, partial_buffered(slots, NSLOTS));
        int live = 0;
        for (int i = 0; i < NSLOTS; i++) {
            if (memmem(slots[i].io.in, sizeof slots[i].io.in, "PART", 4) != NULL) { live = 1; }
        }
        CHECK(live, "ev: the unconsumed partial frame IS buffered (this check is not vacuous)");
        (void)close(d);
        evloop_close_all(&ev);
        int left = 0;
        for (int i = 0; i < NSLOTS; i++) {
            if (memmem(slots[i].io.in, sizeof slots[i].io.in, "PART", 4) != NULL) { left = 1; }
        }
        CHECK(!left, "ev: an UNCONSUMED partial frame is wiped when the slot is released");
    }

    /* graceful drain: stop accepting, existing connections finish */
    {
        int e = dial(port);
        CHECK(e >= 0, "ev: drain client connects");
        (void)PUMP_UNTIL(&ev, 4000, evloop_active(&ev) == 1u);
        CHECK(evloop_active(&ev) == 1u, "ev: drain client is accepted before the stop");
        evloop_stop(&ev);
        int late = dial(port);
        (void)PUMP_UNTIL(&ev, 4000, evloop_active(&ev) == 0u);
        CHECK(ev.accepted >= 1u, "ev: accepted counter is live");
        CHECK(evloop_active(&ev) == 0u, "ev: after the drain every slot is released");
        if (late >= 0) { (void)close(late); }
        (void)close(e);
    }

    evloop_close_all(&ev);
    listener_close(&lfd, NULL);
}

/* ----------------------------------- V4-54: peers that pipeline or never read
 *
 * The loop is half-duplex: once a served frame's reply is queued, it neither
 * polls for nor consumes input until that reply has gone out, and conn_io holds
 * one reply at a time. Nothing drove either half of that before V4-54: no
 * test had ever filled a socket the daemon writes to.
 * What it must give a peer:
 *  - frames sent back to back are all served, in order, without the peer having
 *    to send anything more -- a peer that pipelines and then waits must not wait
 *    for its deadline;
 *  - a peer that sends and never reads stops being served, holds at most one
 *    unsent reply, and is still closed at its deadline;
 *  - when it does read, every reply arrives byte for byte, however the writes
 *    were split. */

/* A Unix stream socket, not loopback TCP: TCP's buffers autotune (macOS gave a
 * 4096-byte SO_RCVBUF 326,640 bytes and absorbed every reply), and a Unix
 * socket's hold what they are set to, so "the peer's buffers are full" is a
 * state the test can reach on purpose. */
static int dial_unix_small(const char *path, int bufsz)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    (void)snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) != 0) { (void)close(fd); return -1; }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) { (void)close(fd); return -1; }
    return fd;
}

static authd_slot_t *live_slot(authd_slot_t *slots, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (slots[i].state != SLOT_FREE) { return &slots[i]; }
    }
    return NULL;
}

/* Reads until `want` bytes have arrived, pumping the loop between reads;
 * returns how many did. */
static size_t pump_read(evloop_t *ev, uint64_t now, int fd, uint8_t *buf, size_t want)
{
    size_t got = 0;
    for (int turn = 0; turn < 4000 && got < want; turn++) {
        (void)evloop_run_once(ev, 1, now);
        struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 1) == 1) {
            const ssize_t r = read(fd, buf + got, want - got);
            if (r <= 0) { break; }
            got += (size_t)r;
        }
    }
    return got;
}

static void test_pipelined(void)
{
    static authd_slot_t slots[1];
    evloop_t ev;
    harness_t h;
    int lfd = -1;
    uint16_t port = 0;
    memset(&h, 0, sizeof h);
    h.echo = 1;
    CHECK(listener_open_loopback(0, 8, &lfd, &port) == LISTENER_OK && port != 0, "pipe: listener binds");
    CHECK(evloop_init(&ev, slots, 1, 5000u, 20000u, on_frame, on_close, &h) == 0, "pipe: init");
    CHECK(evloop_add_listener(&ev, lfd, (uid_t)-1) == 0, "pipe: listener registered");

    /* Two small frames in one write, then two maximum-size ones: a maximum
     * frame fills the input buffer exactly, so the bytes pipelined behind it
     * must wait for room rather than overflow it. */
    static uint8_t big[2 * (4 + AUTHD_FRAME_MAX)], back[sizeof big];
    struct { const char *what; size_t len; } runs[] = {
        { "two small frames", 5u },
        { "two maximum-size frames", AUTHD_FRAME_MAX },
    };
    for (size_t r = 0; r < sizeof runs / sizeof runs[0]; r++) {
        const size_t one = 4u + runs[r].len, both = 2u * one;
        for (int i = 0; i < 2; i++) {
            put_be32(big + (size_t)i * one, (uint32_t)runs[r].len);
            memset(big + (size_t)i * one + 4, i ? 'B' : 'A', runs[r].len);
        }
        int c = dial(port);
        CHECK(c >= 0, "pipe: client connects");
        (void)PUMP_UNTIL(&ev, 1000, evloop_active(&ev) == 1u);
        const int before = h.frames;
        /* The small pair fits one read; the probe says it arrived as one, so
         * the check below is about a frame that was already here. */
        h.ahead = (r == 0) ? "BBBBB" : NULL;
        h.ahead_at = before + 1;
        h.ahead_seen = 0;
        size_t off = 0;
        while (off < both) {
            const ssize_t w = write(c, big + off, both - off);
            if (w <= 0) { break; }
            off += (size_t)w;
        }
        char what[160];
        (void)snprintf(what, sizeof what, "pipe: %s written back to back", runs[r].what);
        CHECK(off == both, what);
        const size_t got = pump_read(&ev, 1000, c, back, both);
        (void)snprintf(what, sizeof what,
                       "pipe: %s are both served without the peer sending more (served %d, %zu of %zu bytes back)",
                       runs[r].what, h.frames - before, got, both);
        CHECK(h.frames - before == 2 && got == both, what);
        (void)snprintf(what, sizeof what, "pipe: %s: both replies arrive in order, byte for byte", runs[r].what);
        CHECK(got == both && memcmp(back, big, both) == 0, what);
        if (r == 0) {
            CHECK(h.ahead_seen, "pipe: the second frame was already buffered when the first was served (not vacuous)");
        }
        (void)close(c);
        (void)PUMP_UNTIL(&ev, 1000, evloop_active(&ev) == 0u);
    }
    evloop_close_all(&ev);
    listener_close(&lfd, NULL);
}

/* Each reply larger than the whole socket buffer, so it cannot go out in one
 * write: Linux doubles a 4096-byte SO_SNDBUF to 8192, and there a 6004-byte
 * reply went out whole every time (0 of 64 writes partial, measured on WSL 2's
 * 6.18 kernel), which would leave the part-sent check below with nothing to see. */
enum { BP_FRAMES = 64, BP_LEN = 10000, BP_FRAME = 4 + BP_LEN };

/* Writes what the socket takes and pumps, until neither the client's sending
 * nor the daemon's serving has moved for 300 turns. */
static void bp_stall(evloop_t *ev, uint64_t now, int c, const uint8_t *sent, size_t total, size_t *off,
                     const harness_t *h, const authd_slot_t *s, int *partial, size_t *max_pending)
{
    int still = 0;
    for (int turn = 0; turn < 20000 && still < 300; turn++) {
        const size_t off0 = *off;
        const int f0 = h->frames;
        if (*off < total) {
            const ssize_t w = write(c, sent + *off, total - *off);
            if (w > 0) { *off += (size_t)w; }
        }
        (void)evloop_run_once(ev, 1, now);
        const size_t p = conn_io_pending(&s->io);
        if (p > *max_pending) { *max_pending = p; }
        if (p > 0u && p < (size_t)BP_FRAME) { *partial = 1; }
        still = (*off == off0 && h->frames == f0) ? still + 1 : 0;
    }
}

static void test_backpressure(void)
{
    enum { NSLOTS = 2 };
    static authd_slot_t slots[NSLOTS];
    static uint8_t sent[BP_FRAMES * BP_FRAME], recvd[BP_FRAMES * BP_FRAME];
    const size_t total = sizeof sent;
    evloop_t ev;
    harness_t h;
    int lfd = -1;
    memset(&h, 0, sizeof h);
    h.echo = 1;
    /* mkdtemp, not a pid-keyed name (audit F114). */
    char dir[] = "/tmp/authd-evl-XXXXXX", path[64];
    CHECK(mkdtemp(dir) != NULL, "bp: a scratch directory for the socket");
    (void)snprintf(path, sizeof path, "%s/bp.sock", dir);
    CHECK(listener_open_unix(path, 8, LISTENER_MODE_PRIVATE, &lfd) == LISTENER_OK, "bp: a Unix listener");
    CHECK(evloop_init(&ev, slots, NSLOTS, 5000u, 20000u, on_frame, on_close, &h) == 0, "bp: init");
    CHECK(evloop_add_listener(&ev, lfd, (uid_t)-1) == 0, "bp: listener registered");
    for (int i = 0; i < BP_FRAMES; i++) {
        uint8_t *f = sent + (size_t)i * BP_FRAME;
        put_be32(f, BP_LEN);
        memset(f + 4, 0x21 + (i % 90), BP_LEN);       /* each frame its own bytes */
        f[4] = (uint8_t)i;
    }

    /* 1. Everything the socket will take, and nothing read. */
    const int small = 4096;
    int c = dial_unix_small(path, small);
    CHECK(c >= 0, "bp: a non-blocking client connects with a small receive buffer");
    (void)PUMP_UNTIL(&ev, 1000, evloop_active(&ev) == 1u);
    authd_slot_t *s = live_slot(slots, NSLOTS);
    CHECK(s != NULL && setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0,
          "bp: the daemon's side gets a small send buffer");
    if (s == NULL) { (void)close(c); listener_close(&lfd, path); (void)rmdir(dir); return; }
    size_t off = 0, max_pending = 0;
    int partial = 0;
    bp_stall(&ev, 1000, c, sent, total, &off, &h, s, &partial, &max_pending);
    const int served = h.frames;
    char what[200];
    (void)snprintf(what, sizeof what,
                   "bp: a peer that reads nothing stops being served (%d of %d frames served, %zu of %zu bytes sent)",
                   served, BP_FRAMES, off, total);
    CHECK(served < BP_FRAMES && conn_io_pending(&s->io) > 0u, what);
    pump_n(&ev, 1000, 200);
    CHECK(h.frames == served, "bp: ...and stays unserved: no frame is consumed while its reply waits");
    CHECK(max_pending <= (size_t)BP_FRAME, "bp: the daemon never holds more than one unsent reply");
    CHECK(evloop_active(&ev) == 1u, "bp: the stalled peer is still connected before its deadline");

    /* 2. The peer reads: everything is served and comes back exact. */
    size_t got = 0;
    for (int turn = 0; turn < 40000 && got < total; turn++) {
        const ssize_t r = read(c, recvd + got, total - got);
        if (r > 0) { got += (size_t)r; }
        if (off < total) {
            const ssize_t w = write(c, sent + off, total - off);
            if (w > 0) { off += (size_t)w; }
        }
        (void)evloop_run_once(&ev, 1, 1000);
        const size_t p = conn_io_pending(&s->io);
        if (p > 0u && p < (size_t)BP_FRAME) { partial = 1; }
    }
    (void)snprintf(what, sizeof what,
                   "bp: once the peer reads, all %d frames are served and every reply arrives (%d served, %zu of %zu bytes)",
                   BP_FRAMES, h.frames, got, total);
    CHECK(h.frames == BP_FRAMES && got == total, what);
    CHECK(got == total && memcmp(recvd, sent, total) == 0,
          "bp: ...in order, byte for byte, however the writes were split");
    CHECK(partial, "bp: a reply was seen part-sent (the resumed-write path ran, so the check above is not vacuous)");
    (void)close(c);
    (void)PUMP_UNTIL(&ev, 1000, evloop_active(&ev) == 0u);

    /* 3. A peer that never reads is still closed at its deadline. */
    int d = dial_unix_small(path, small);
    CHECK(d >= 0, "bp: a second stalling client connects");
    (void)PUMP_UNTIL(&ev, 50000, evloop_active(&ev) == 1u);
    s = live_slot(slots, NSLOTS);
    CHECK(s != NULL && setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0,
          "bp: its side gets a small send buffer too");
    if (s != NULL) {
        off = 0;
        bp_stall(&ev, 50000, d, sent, total, &off, &h, s, &partial, &max_pending);
        CHECK(conn_io_pending(&s->io) > 0u, "bp: the second peer is stalled with a reply unsent");
        const uint64_t dl = s->deadline_ms;
        CHECK(dl == 50000u + 20000u, "bp: its deadline is the idle timeout from its last served frame");
        const uint64_t closed0 = ev.closed_deadline;
        (void)evloop_run_once(&ev, 0, dl - 1u);
        CHECK(evloop_active(&ev) == 1u, "bp: a stalled peer is still open one ms before its deadline");
        (void)evloop_run_once(&ev, 0, dl);
        CHECK(evloop_active(&ev) == 0u && ev.closed_deadline == closed0 + 1u,
              "bp: a peer that never reads is closed at its deadline, its reply unsent");
    }
    (void)close(d);

    /* 4. A peer that vanishes with a reply still unsent (V4-56). Nothing can
     * reach it any more, so the slot must go at once -- not be polled until
     * its deadline. macOS reports such a socket as POLLHUP alone, with no
     * POLLOUT and no POLLERR, so a loop that writes only on POLLOUT and closes
     * on POLLHUP only when nothing is pending kept it, and poll() returned at
     * once on every turn: a spin until the deadline. */
    int e = dial_unix_small(path, small);
    CHECK(e >= 0, "bp: a third stalling client connects");
    (void)PUMP_UNTIL(&ev, 90000, evloop_active(&ev) == 1u);
    s = live_slot(slots, NSLOTS);
    CHECK(s != NULL && setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0,
          "bp: its side gets a small send buffer too");
    if (s != NULL) {
        off = 0;
        bp_stall(&ev, 90000, e, sent, total, &off, &h, s, &partial, &max_pending);
        CHECK(conn_io_pending(&s->io) > 0u, "bp: the third peer is stalled with a reply unsent");
        const uint64_t closed0 = ev.closed_deadline;
        (void)close(e);
        e = -1;
        int turns = 0;
        struct timeval t0, t1;
        (void)gettimeofday(&t0, NULL);
        while (turns < 200 && evloop_active(&ev) != 0u) {
            (void)evloop_run_once(&ev, 10, 90000);
            turns++;
        }
        (void)gettimeofday(&t1, NULL);
        const long ms = (long)(t1.tv_sec - t0.tv_sec) * 1000L + (long)(t1.tv_usec - t0.tv_usec) / 1000L;
        char what[200];
        (void)snprintf(what, sizeof what,
                       "bp: a peer that vanishes with a reply unsent frees its slot at once (%d turns in %ld ms), not at its deadline",
                       turns, ms);
        CHECK(evloop_active(&ev) == 0u && turns <= 3 && ev.closed_deadline == closed0, what);
    }
    if (e >= 0) { (void)close(e); }

    /* 5. ...but a peer that only half-closes -- sends its frame, then shuts
     * down its sending side -- still gets its reply. Closing every slot on
     * POLLHUP would also have ended 4's spin, and would have broken this. */
    int f = dial_unix_small(path, small);
    CHECK(f >= 0, "bp: a half-closing client connects");
    (void)PUMP_UNTIL(&ev, 90000, evloop_active(&ev) == 1u);
    {
        const size_t one = (size_t)BP_FRAME;
        size_t woff = 0;
        for (int turn = 0; turn < 2000 && woff < one; turn++) {
            const ssize_t w = write(f, sent + woff, one - woff);
            if (w > 0) { woff += (size_t)w; }
            (void)evloop_run_once(&ev, 1, 90000);
        }
        CHECK(woff == one && shutdown(f, SHUT_WR) == 0, "bp: it sends one frame and shuts down its sending side");
        const size_t got5 = pump_read(&ev, 90000, f, recvd, one);
        CHECK(got5 == one && memcmp(recvd, sent, one) == 0,
              "bp: a peer that half-closes after its frame still gets the whole reply");
    }
    if (f >= 0) { (void)close(f); }
    evloop_close_all(&ev);
    listener_close(&lfd, path);
    (void)rmdir(dir);
}

/* ------------------------------------------------------------- log hygiene */

static void test_log_hygiene(void)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (f == NULL) {
        printf("SKIP: open_memstream unavailable; log hygiene not checked\n");
        return;
    }
    authd_log_init(f, AUTHD_LOG_INFO);

    /* PRESENT CANARY: an identifier IS logged, so the absence checks below are
     * checking a stream that actually contains something. */
    const uint8_t id[] = { 'o','p','e','r','a','t','o','r','-','1' };
    authd_log_slot_id(AUTHD_LOG_INFO, "peer-identified", 3, id, sizeof id);
    fflush(f);
    CHECK(len > 0 && strstr(buf, "operator-1") != NULL,
          "log: an identity IS logged (the never-list check is not vacuous)");

    /* a hostile identifier cannot inject a newline or smuggle binary */
    const uint8_t evil[] = { 'a', '\n', 'e','v','e','n','t','=','f','a','k','e', 0x00, 'b' };
    authd_log_slot_id(AUTHD_LOG_WARN, "peer-identified", 4, evil, sizeof evil);
    fflush(f);
    CHECK(strstr(buf, "\nevent=fake") == NULL,
          "log: a newline inside an identifier is escaped, not passed through");

    /* over-long identifiers are truncated and marked */
    uint8_t longid[200];
    memset(longid, 'x', sizeof longid);
    authd_log_slot_id(AUTHD_LOG_INFO, "peer-identified", 5, longid, sizeof longid);
    fflush(f);
    CHECK(strstr(buf, "~") != NULL, "log: an over-long identifier is truncated and marked");

    /* level filtering */
    authd_log_init(f, AUTHD_LOG_ERROR);
    const size_t before = len;
    authd_log_event(AUTHD_LOG_INFO, "should-not-appear");
    fflush(f);
    CHECK(len == before, "log: an INFO event is suppressed at ERROR level");
    authd_log_event(AUTHD_LOG_ERROR, "should-appear");
    fflush(f);
    CHECK(len > before, "log: an ERROR event is still emitted");

    fclose(f);
    free(buf);
    authd_log_init(stderr, AUTHD_LOG_ERROR);
}

/* ---------------------------------------------------------------- memlock */

/*
 * V4-11 / finding F6. The hazard S1 measured is that a too-small
 * RLIMIT_MEMLOCK is SILENT: every sodium_malloc still succeeds and the
 * secrets simply stop being locked. So the check has to be driven under a
 * limit that is genuinely lowered, not merely asserted about the ambient one
 * -- which is also what stops this test passing for the wrong reason on a
 * host that happens to run unlimited.
 *
 * Lowering the soft limit is permitted to an unprivileged process; raising it
 * back is permitted only up to the hard limit, which is why the original is
 * captured and restored rather than guessed.
 */
/* ------------------------------------------------------- F62: poll fairness */

/*
 * Audit finding F62. The two slot pools exist so that a burst of handshakes
 * cannot lock the site out of the local API -- but both were polled through
 * ONE array bounded by a single 4096 constant, filled protocol-pool-first. At
 * max_slots = 4096 with every protocol slot busy the array was full before the
 * local pool was reached, which is the very failure the pools prevent.
 *
 * The test needs a FULL protocol pool, and that is the only expensive part.
 * It does NOT need 4096 file descriptors: poll() accepts the same fd many
 * times over, and the set builder reads only fd/state/kind. One quiet socket
 * stands in for every protocol slot; one chatty socket carries the local
 * request that must still be seen.
 */
static int g_f62_lines = 0;
static char g_f62_last[32];

static ev_action_t f62_on_line(void *user, authd_slot_t *slot, const uint8_t *line, size_t len)
{
    (void)user; (void)slot;
    g_f62_lines++;
    const size_t n = (len < sizeof g_f62_last - 1u) ? len : sizeof g_f62_last - 1u;
    memcpy(g_f62_last, line, n);
    g_f62_last[n] = '\0';
    return EV_ACTION_CONTINUE;
}

static void test_poll_fairness(void)
{
    /* Registration bounds first: they are what makes the array's own bound
     * unreachable by CONTRACT rather than by coincidence. */
    {
        evloop_t ev;
        static authd_slot_t one[1];
        /* Sized for the OVER-limit call, not for the legal one. evloop_set_local
         * memsets every slot it is given, so a 1-element array claimed as 65
         * would overrun the moment a mutation removes the bound -- and an ASan
         * abort is a weaker verdict than the named refusal this is testing. */
        static authd_slot_t lone[AUTHD_LOCAL_SLOTS_MAX + 1u];
        CHECK(evloop_init(&ev, one, (size_t)AUTHD_SLOTS_MAX + 1u, 5000u, 20000u,
                          on_frame, on_close, NULL) == -1,
              "ev: evloop_init refuses a protocol pool over AUTHD_SLOTS_MAX");
        CHECK(evloop_init(&ev, one, 1u, 5000u, 20000u, on_frame, on_close, NULL) == 0,
              "ev: ...and accepts one at the limit (canary: the check is not always-refuse)");
        CHECK(evloop_set_local(&ev, lone, (size_t)AUTHD_LOCAL_SLOTS_MAX + 1u, f62_on_line) == -1,
              "ev: evloop_set_local refuses a local pool over AUTHD_LOCAL_SLOTS_MAX");
        CHECK(evloop_set_local(&ev, lone, 1u, f62_on_line) == 0,
              "ev: ...and accepts one at the limit");
    }

    authd_slot_t *proto = calloc((size_t)AUTHD_SLOTS_MAX, sizeof *proto);
    authd_slot_t *local = calloc(4u, sizeof *local);
    if (proto == NULL || local == NULL) {
        free(proto); free(local);
        printf("SKIP: ev: F62 needs ~100 MB for a full protocol pool\n");
        return;
    }

    int quiet[2] = { -1, -1 };
    int chatty[2] = { -1, -1 };
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, quiet) == 0, "ev: F62 quiet socketpair");
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, chatty) == 0, "ev: F62 chatty socketpair");

    evloop_t ev;
    CHECK(evloop_init(&ev, proto, (size_t)AUTHD_SLOTS_MAX, 5000u, 20000u,
                      on_frame, on_close, NULL) == 0, "ev: F62 init at AUTHD_SLOTS_MAX");
    CHECK(evloop_set_local(&ev, local, 4u, f62_on_line) == 0, "ev: F62 local pool registered");

    /* Every protocol slot busy, on one fd that never becomes readable. Only
     * the five scalars the set builder reads are written, so the 24 KB of I/O
     * buffers in each slot stay untouched -- calloc already left them zeroed,
     * which is the state conn_io_reset produces. */
    for (size_t i = 0; i < (size_t)AUTHD_SLOTS_MAX; i++) {
        proto[i].fd = quiet[0];
        proto[i].kind = SLOT_KIND_PROTO;
        proto[i].state = SLOT_ACTIVE;
        proto[i].index = i;
        proto[i].deadline_ms = 1000u * 1000u;
    }
    local[0].fd = chatty[0];
    local[0].kind = SLOT_KIND_LOCAL;
    local[0].state = SLOT_ACTIVE;
    local[0].deadline_ms = 1000u * 1000u;

    g_f62_lines = 0;
    g_f62_last[0] = '\0';
    CHECK(write(chatty[1], "PING\n", 5) == 5, "ev: F62 the local peer sends a request");
    (void)evloop_run_once(&ev, 0, 1000u);

    /* THE check. Before the fix, nspfd hit 4096 inside the protocol pool and
     * the local slot was never appended, so this line never fired. */
    CHECK(g_f62_lines == 1 && strcmp(g_f62_last, "PING") == 0,
          "ev: a local slot is still polled when the protocol pool is full (F62)");

    close(quiet[0]); close(quiet[1]); close(chatty[0]); close(chatty[1]);
    free(proto); free(local);
}

static void test_memlock(void)
{
    /* The derived need, from literals rather than from the macros the
     * implementation uses -- otherwise a mutation to the formula would move
     * the test's expectation with it and could never be caught. */
    CHECK(memlock_required_bytes(1u) == 40960u,
          "memlock: 1 slot needs 40960 B (4096 x 10)");
    CHECK(memlock_required_bytes(256u) == 10485760u,
          "memlock: the default 256 slots need 10485760 B (10 MiB)");
    CHECK(memlock_required_bytes(4096u) == 167772160u,
          "memlock: the 4096-slot ceiling needs 167772160 B (160 MiB)");
    CHECK(memlock_required_bytes(0u) == 0u,
          "memlock: no slots need nothing");

    struct rlimit saved;
    if (getrlimit(RLIMIT_MEMLOCK, &saved) != 0) {
        printf("SKIP: memlock: getrlimit(RLIMIT_MEMLOCK) unavailable on this platform\n");
        return;
    }

    struct rlimit rl = saved;
    const rlim_t want = 1u << 20; /* 1 MiB: under 256 slots, over 16 */
    if (saved.rlim_max != RLIM_INFINITY && saved.rlim_max < want) {
        printf("SKIP: memlock: hard limit below 1 MiB; cannot stage the test\n");
        return;
    }
    rl.rlim_cur = want;
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        printf("SKIP: memlock: setrlimit(RLIMIT_MEMLOCK) refused on this platform\n");
        return;
    }

    uint64_t limit = 0u, need = 0u;

    /* PRESENT CANARY: at a slot count the staged limit DOES cover, the very
     * same call must answer OK. Without this, "LOW" below could be true
     * because the check answers LOW unconditionally. */
    CHECK(memlock_check(16u, &limit, &need) == MEMLOCK_OK,
          "memlock: 16 slots fit inside a 1 MiB limit (canary: OK is reachable)");
    CHECK(limit == (uint64_t)want, "memlock: the staged 1 MiB limit is reported back");
    CHECK(need == 655360u, "memlock: 16 slots derive a 655360 B need");

    CHECK(memlock_check(256u, &limit, &need) == MEMLOCK_LOW,
          "memlock: the default 256 slots do NOT fit inside 1 MiB");
    CHECK(need == 10485760u, "memlock: the reported need is the 256-slot need");
    CHECK(limit == (uint64_t)want, "memlock: the reported limit is the staged one");

    /* The boundary, both sides, from literals: 1 MiB covers exactly 26 slots
     * (26 x 40960 = 1064960 > 1048576, so 25 is the last that fits). */
    CHECK(memlock_check(25u, NULL, NULL) == MEMLOCK_OK,
          "memlock: 25 slots (1024000 B) fit in 1048576 B");
    CHECK(memlock_check(26u, NULL, NULL) == MEMLOCK_LOW,
          "memlock: 26 slots (1064960 B) do not");

    /* NULL outputs are accepted -- the daemon's startup path passes both, but
     * nothing should require them. */
    CHECK(memlock_check(1u, NULL, NULL) == MEMLOCK_OK, "memlock: NULL outputs are accepted");

    /* The insufficient case must be LOUD -- the whole point of the line. The
     * ambient limit differs by platform, so this is pinned here by naming the
     * status directly rather than by reading a real daemon's journal. */
    CHECK(memlock_log_level(MEMLOCK_LOW) == AUTHD_LOG_WARN,
          "memlock: a limit below the requirement is logged at WARN");
    CHECK(memlock_log_level(MEMLOCK_OK) == AUTHD_LOG_INFO,
          "memlock: a sufficient limit is logged at INFO");
    CHECK(memlock_log_level(MEMLOCK_UNLIMITED) == AUTHD_LOG_INFO,
          "memlock: an unlimited limit is logged at INFO, not WARN");
    CHECK(memlock_log_level(MEMLOCK_UNKNOWN) == AUTHD_LOG_INFO,
          "memlock: an unknowable limit is logged at INFO, not WARN");

    CHECK(strcmp(memlock_status_name(MEMLOCK_OK), "ok") == 0, "memlock: OK names itself");
    CHECK(strcmp(memlock_status_name(MEMLOCK_LOW), "below-requirement") == 0,
          "memlock: LOW names itself");
    CHECK(strcmp(memlock_status_name(MEMLOCK_UNLIMITED), "unlimited") == 0,
          "memlock: UNLIMITED names itself");
    CHECK(strcmp(memlock_status_name(MEMLOCK_UNKNOWN), "unknown") == 0,
          "memlock: UNKNOWN names itself");

    /* An unlimited limit is not "very large": it is its own answer, and the
     * daemon must not warn about it. Only reachable when the hard limit allows
     * it, which is the common case for a developer shell on macOS. */
    if (saved.rlim_max == RLIM_INFINITY) {
        rl.rlim_cur = RLIM_INFINITY;
        if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
            CHECK(memlock_check(4096u, &limit, &need) == MEMLOCK_UNLIMITED,
                  "memlock: RLIM_INFINITY answers UNLIMITED, not OK");
            CHECK(limit == UINT64_MAX, "memlock: unlimited is reported as UINT64_MAX");
        }
    }

    (void)setrlimit(RLIMIT_MEMLOCK, &saved);
}

int main(void)
{
    /* Unbuffered, so every PASS/FAIL line already reported survives even if a
     * later check crashes the process. Under ctest stdout is a pipe and fully
     * buffered, and Linux ASan exits without flushing it: v52's P4 lost its
     * named failure that way on the nightly while macOS kept it. */
    setvbuf(stdout, NULL, _IONBF, 0);
    /* As mldsa-authd does (authd_main.c): a write to a peer that has gone is
     * EPIPE, a status the loop handles, not a signal that ends the process. */
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }
    /* keep the daemon's own chatter out of the test output */
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    test_config();
    test_conn_io();
    test_evloop();
    test_pipelined();
    test_backpressure();
    test_log_hygiene();
    test_poll_fairness();
    test_memlock();

    printf("%s: test_authd_evloop (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
