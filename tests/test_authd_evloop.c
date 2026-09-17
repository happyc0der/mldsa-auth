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

#include <sodium.h>

#include "authd_config.h"
#include "conn_io.h"
#include "evloop.h"
#include "listener.h"
#include "authd_log.h"

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

/* Runs the loop until `pred` holds or `max` iterations pass, holding time
 * fixed so only I/O progresses. */
static void pump(evloop_t *ev, uint64_t now, int iters)
{
    for (int i = 0; i < iters; i++) {
        (void)evloop_run_once(ev, 10, now);
    }
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
    pump(&ev, 1000, 3);
    CHECK(evloop_active(&ev) == 1u, "ev: the connection occupies exactly one slot");
    CHECK(slots[0].deadline_ms == 1000u + 5000u,
          "ev: a fresh connection gets the HANDSHAKE deadline");

    {
        uint8_t f[4 + 5];
        put_be32(f, 5); memcpy(f + 4, "hello", 5);
        CHECK(write(c1, f, sizeof f) == (ssize_t)sizeof f, "ev: client sends a frame");
        pump(&ev, 1000, 5);
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
        pump(&ev, 2000, 6);
        CHECK(evloop_active(&ev) == (size_t)NSLOTS, "ev: only max_slots connections are held");
        CHECK(ev.refused_no_slot >= 1u, "ev: the connection beyond capacity is refused, not queued");
        (void)close(a); (void)close(b); (void)close(c);
        pump(&ev, 2000, 6);
    }

    /* a slot is wiped before reuse -- with a present canary so it is not vacuous */
    {
        evloop_close_all(&ev);
        pump(&ev, 3000, 2);
        int d = dial(port);
        CHECK(d >= 0, "ev: reuse client connects");
        pump(&ev, 3000, 3);
        uint8_t f[4 + 6];
        put_be32(f, 6); memcpy(f + 4, "SECRET", 6);
        h.canary = "SECRET";
        h.canary_seen_live = 0;
        CHECK(write(d, f, sizeof f) == (ssize_t)sizeof f, "ev: reuse client sends a marker frame");
        pump(&ev, 3000, 4);
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
        pump(&ev, 5000, 3);
        uint8_t part[4 + 4];
        put_be32(part, 32);                    /* declares 32 bytes ... */
        memcpy(part + 4, "PART", 4);           /* ... but sends only 4 */
        CHECK(write(d, part, sizeof part) == (ssize_t)sizeof part,
              "ev: client sends an incomplete frame");
        pump(&ev, 5000, 4);
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
        pump(&ev, 4000, 3);
        CHECK(evloop_active(&ev) == 1u, "ev: drain client is accepted before the stop");
        evloop_stop(&ev);
        int late = dial(port);
        pump(&ev, 4000, 4);
        CHECK(ev.accepted >= 1u, "ev: accepted counter is live");
        CHECK(evloop_active(&ev) == 0u, "ev: after the drain every slot is released");
        if (late >= 0) { (void)close(late); }
        (void)close(e);
    }

    evloop_close_all(&ev);
    listener_close(&lfd, NULL);
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

int main(void)
{
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }
    /* keep the daemon's own chatter out of the test output */
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    test_config();
    test_conn_io();
    test_evloop();
    test_log_hygiene();

    printf("%s: test_authd_evloop (%d checks)\n", g_fail ? "FAIL" : "PASS", g_checks);
    return g_fail ? 1 : 0;
}
