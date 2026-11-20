#include "authd_log.h"

#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <sodium.h>

#include "mldsa_wrap.h"
#include "proxy_v2.h"

_Static_assert(AUTHD_FP_PK_BYTES == MLDSA_PUBLIC_KEY_BYTES,
               "a fingerprint is of an ML-DSA-65 public key, all of it");
_Static_assert(sizeof(authd_fp_t) == crypto_hash_sha256_BYTES,
               "a fingerprint is a SHA-256 and nothing wider");

static FILE *g_dest = NULL;
static authd_log_level_t g_min = AUTHD_LOG_INFO;
static authd_log_ids_t g_ids = AUTHD_LOG_IDS_FULL;
static authd_log_ip_t g_ip = AUTHD_LOG_IP_FULL;
static authd_log_pseudonym_fn g_pseud = NULL;
static void *g_pseud_ctx = NULL;

#define ID_FIELD_MAX 64u

static const char *level_name(authd_log_level_t l)
{
    switch (l) {
    case AUTHD_LOG_ERROR: return "error";
    case AUTHD_LOG_WARN:  return "warn";
    case AUTHD_LOG_INFO:  return "info";
    default:              return "info";
    }
}

void authd_log_init(FILE *dest, authd_log_level_t min_level)
{
    if (dest != NULL) {
        g_dest = dest;
    }
    g_min = min_level;
}

int authd_log_set_privacy(authd_log_ids_t ids, authd_log_ip_t ip,
                          authd_log_pseudonym_fn fn, void *ctx)
{
    if ((ids != AUTHD_LOG_IDS_FULL && ids != AUTHD_LOG_IDS_HASHED && ids != AUTHD_LOG_IDS_OFF) ||
        (ip != AUTHD_LOG_IP_FULL && ip != AUTHD_LOG_IP_PREFIX && ip != AUTHD_LOG_IP_OFF) ||
        (ids == AUTHD_LOG_IDS_HASHED && fn == NULL)) {
        return -1;
    }
    g_ids = ids;
    g_ip = ip;
    g_pseud = fn;
    g_pseud_ctx = ctx;
    return 0;
}

const char *authd_log_ids_name(authd_log_ids_t m)
{
    switch (m) {
    case AUTHD_LOG_IDS_FULL:   return "full";
    case AUTHD_LOG_IDS_HASHED: return "hashed";
    case AUTHD_LOG_IDS_OFF:    return "off";
    default:                   return "?";
    }
}

const char *authd_log_ip_name(authd_log_ip_t m)
{
    switch (m) {
    case AUTHD_LOG_IP_FULL:   return "full";
    case AUTHD_LOG_IP_PREFIX: return "prefix";
    case AUTHD_LOG_IP_OFF:    return "off";
    default:                  return "?";
    }
}

static int word_is(const uint8_t *v, size_t n, const char *w)
{
    const size_t wn = strlen(w);
    return v != NULL && n == wn && memcmp(v, w, wn) == 0;
}

int authd_log_ids_parse(const uint8_t *v, size_t n, authd_log_ids_t *out)
{
    if (out == NULL) { return -1; }
    if (word_is(v, n, "full"))   { *out = AUTHD_LOG_IDS_FULL;   return 0; }
    if (word_is(v, n, "hashed")) { *out = AUTHD_LOG_IDS_HASHED; return 0; }
    if (word_is(v, n, "off"))    { *out = AUTHD_LOG_IDS_OFF;    return 0; }
    return -1;
}

int authd_log_ip_parse(const uint8_t *v, size_t n, authd_log_ip_t *out)
{
    if (out == NULL) { return -1; }
    if (word_is(v, n, "full"))   { *out = AUTHD_LOG_IP_FULL;   return 0; }
    if (word_is(v, n, "prefix")) { *out = AUTHD_LOG_IP_PREFIX; return 0; }
    if (word_is(v, n, "off"))    { *out = AUTHD_LOG_IP_OFF;    return 0; }
    return -1;
}

static FILE *out(void)
{
    return (g_dest != NULL) ? g_dest : stderr;
}

/* F691, F692 (V4-345): what happens after a line that could not be written.
 * The daemon's handlers do not restart interrupted calls once it runs
 * (F679), so a line waiting on a standard error nobody reads is ended by a
 * signal, and lost.
 *   - On macOS stdio then refused every later write to the stream, with the
 *     pipe long since emptied: one interrupted line and the daemon logged
 *     nothing more for as long as it ran. The error is cleared.
 *   - And if the signal was the one that asks the daemon to stop, the log
 *     is closed for what is left of this process: the lines of a shutdown
 *     (draining, stopped) would each wait in their turn, one more signal
 *     apiece, and a stop that was asked for once would end in systemd's
 *     timeout. A daemon that is stopping says nothing more to a log that is
 *     not being read.
 *
 * F700 (V4-347): and the line gets its signal from HERE if nobody sends
 * one. V4-345 closed the log when a line was ended by a signal with the
 * stop flag set, which needs a signal to arrive while the line waits. A
 * daemon that was idle when it was told to stop took its SIGTERM in poll(),
 * began to write `draining`, and waited there with no second signal coming:
 * the ordinary case, and one SIGTERM did not stop it. So once the stop flag
 * is set, each line is given a quarter of a second. A timer ends the write
 * that outlasts it, and that is a line ended by a signal while stopping. */
static const volatile sig_atomic_t *g_stop_flag = NULL;
static int g_muted = 0;
/* F710 (V4-348): a line is being written. Read by the stop signal's handler. */
static volatile sig_atomic_t g_in_line = 0;

#define LOG_STOPPING_LINE_USEC 250000

/* F720 (V4-349): the timer ended this line -- not some other signal. */
static volatile sig_atomic_t g_timer_fired = 0;

static void on_line_timer(int sig)
{
    (void)sig;      /* its work is to end the write, and to say that it did */
    g_timer_fired = 1;
}

/* F711 (V4-348): an INTERVAL, not one shot. One shot could be spent before
 * the write it was for had begun -- a process kept off the CPU for a quarter
 * second between arming and writing, which is the kind of host a stalled
 * journal is found on -- or on the first part of a line a terminal took in
 * two; either way nothing ended the write that then waited. It fires until
 * the line is done. setitimer() is async-signal-safe: the handler of a stop
 * signal calls this too. */
/* F727 (V4-350): the line's timer is running. */
static volatile sig_atomic_t g_timer_armed = 0;

static void line_timer(long usec)
{
    struct itimerval tv;
    memset(&tv, 0, sizeof tv);
    tv.it_value.tv_usec = (suseconds_t)usec;
    tv.it_interval.tv_usec = (suseconds_t)usec;
    g_timer_armed = (usec != 0);
    (void)setitimer(ITIMER_REAL, &tv, NULL);
}

void authd_log_stop_flag(const volatile sig_atomic_t *flag)
{
    g_stop_flag = flag;
    g_muted = 0;
    if (flag != NULL) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_line_timer;      /* no SA_RESTART: it must end the write */
        (void)sigaction(SIGALRM, &sa, NULL);
        /* F712: and not blocked. A daemon started by hand from a shell that
         * had SIGALRM blocked inherited the mask, and the timer did nothing. */
        sigset_t one;
        (void)sigemptyset(&one);
        (void)sigaddset(&one, SIGALRM);
        (void)sigprocmask(SIG_UNBLOCK, &one, NULL);
    }
}

/* F710 (V4-348): called from the handler of a signal that stops the daemon.
 * A line that was ALREADY waiting when the signal came is not helped by a
 * timer armed when a line begins. While the daemon runs the signal itself
 * ends the write; while it starts, its handlers restart interrupted calls
 * (F657), so the write went on waiting and no number of SIGTERMs stopped a
 * daemon held on its first line. Only when a line is in flight: a timer
 * armed at any other moment would end some other call.
 *
 * F727 (V4-350): and only if the timer is not running already. Every stop
 * signal armed it afresh, so a line's quarter second began again with each
 * one: SIGTERM sent every tenth of a second -- `while kill -0 $pid; do kill
 * $pid; sleep 0.1; done`, a common way to stop a thing -- never ended a
 * daemon held on a line while it started. The time counts from the FIRST. */
void authd_log_on_stop_signal(void)
{
    if (g_in_line && !g_timer_armed) {
        line_timer(LOG_STOPPING_LINE_USEC);
    }
}

static void line_begin(FILE *f)
{
    clearerr(f);
    errno = 0;
    g_timer_fired = 0;
    g_in_line = 1;      /* before the look at the flag: see authd_log_on_stop_signal */
    if (g_stop_flag != NULL && *g_stop_flag) {
        line_timer(LOG_STOPPING_LINE_USEC);
    }
}

static void line_end(FILE *f)
{
    const int flushed = fflush(f);
    const int why = errno;
    g_in_line = 0;
    if (g_stop_flag != NULL) {
        line_timer(0);
    }
    /* F701: the stream's error flag was cleared when this line began, and
     * errno zeroed, so both are THIS line's. Judged on a flag an earlier,
     * direct write to the stream had left, a line written in full was taken
     * for an interrupted one. */
    if (flushed != 0 || ferror(f)) {
        clearerr(f);
        /* F720 (V4-349): the log is closed by a line that had its quarter
         * second and was not written, and by nothing less. It was closed by
         * ANY signal that ended a line while stopping, the stop signal
         * itself among them: a daemon that happened to be waiting in a line
         * when it was told to stop logged none of its shutdown, to a journal
         * that was read again ten milliseconds later. A line another signal
         * ends is lost; the next has its own quarter second. */
        if (why == EINTR && g_timer_fired && g_stop_flag != NULL && *g_stop_flag) {
            g_muted = 1;
        }
    }
}

static void line_done(void)
{
    line_end(out());
}

static int enabled(authd_log_level_t l)
{
    if (g_muted || (int)l > (int)g_min) {
        return 0;
    }
    line_begin(out());
    return 1;
}

/* F710 (V4-348): what the daemon says on standard error that is not an
 * event -- "created a new, empty store", "could not send READY=1", "stopped
 * by a signal before it had started". They were plain fprintf()s, with
 * neither the time limit nor the closed log of a stopping daemon, and a
 * daemon whose standard error nobody read waited in them for ever: in the
 * READY line after `started`, and in the very line that says it stopped. */
void authd_log_say(const char *fmt, ...)
{
    if (g_muted) {
        return;
    }
    line_begin(stderr);
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    line_end(stderr);
}

/* F369: `detail` is one word on the line, whatever the caller passes. It is
 * a literal or a status name, never a peer's bytes, and it was printed as it
 * came: two call sites passed "ok revoke=all" and "invalid (now locked)",
 * which put a `revoke` key the field list does not have, and bare tokens,
 * on a line a key=value reader takes apart. The same rule as `id`: a byte
 * outside printable ASCII, a space or an '=' becomes '.'. */
#define DETAIL_FIELD_MAX 64u
static const char *detail_word(const char *detail, const char *absent, char word[DETAIL_FIELD_MAX + 1u])
{
    if (detail == NULL) {
        return absent;
    }
    size_t j = 0;
    for (; j < DETAIL_FIELD_MAX && detail[j] != '\0'; j++) {
        const unsigned char ch = (unsigned char)detail[j];
        word[j] = (ch > 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.';
    }
    word[j] = '\0';
    return word;
}

void authd_log_event(authd_log_level_t lvl, const char *event)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s\n", level_name(lvl), event ? event : "?");
    line_done();
}

void authd_log_slot(authd_log_level_t lvl, const char *event, size_t slot)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s slot=%zu\n", level_name(lvl), event ? event : "?", slot);
    line_done();
}

void authd_log_slot_addr(authd_log_level_t lvl, const char *event, size_t slot,
                         const struct authd_addr *addr, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    char word[DETAIL_FIELD_MAX + 1u];
    if (g_ip == AUTHD_LOG_IP_OFF) {
        fprintf(out(), "%s event=%s slot=%zu detail=%s\n",
                level_name(lvl), event ? event : "?", slot, detail_word(detail, "-", word));
        line_done();
        return;
    }
    /* PREFIX renders a COPY with the host part zeroed -- the caller's address,
     * which the limiter still holds, is never modified -- and says how much
     * was kept, so `203.0.113.0/24` cannot be mistaken for a host. */
    authd_addr_t a;
    memset(&a, 0, sizeof a);
    const char *suffix = "";
    if (addr != NULL) {
        a = *(const authd_addr_t *)addr;
    }
    if (g_ip == AUTHD_LOG_IP_PREFIX) {
        if (a.family == 4u) {
            memset(a.addr + 3, 0, sizeof a.addr - 3u);
            suffix = "/24";
        } else if (a.family == 6u) {
            memset(a.addr + 6, 0, sizeof a.addr - 6u);
            suffix = "/48";
        }
    }
    char src[AUTHD_ADDR_STR_MAX];
    authd_addr_str(addr != NULL ? &a : NULL, src, sizeof src);
    fprintf(out(), "%s event=%s slot=%zu src=%s%s detail=%s\n",
            level_name(lvl), event ? event : "?", slot, src, suffix, detail_word(detail, "-", word));
    sodium_memzero(&a, sizeof a);
    line_done();
}

void authd_log_slot_detail(authd_log_level_t lvl, const char *event, size_t slot, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    char word[DETAIL_FIELD_MAX + 1u];
    fprintf(out(), "%s event=%s slot=%zu detail=%s\n",
            level_name(lvl), event ? event : "?", slot, detail_word(detail, "?", word));
    line_done();
}

void authd_log_slot_id(authd_log_level_t lvl, const char *event, size_t slot,
                       const uint8_t *id, size_t id_len)
{
    if (!enabled(lvl)) {
        return;
    }
    if (g_ids == AUTHD_LOG_IDS_OFF) {
        fprintf(out(), "%s event=%s slot=%zu\n", level_name(lvl), event ? event : "?", slot);
        line_done();
        return;
    }
    if (g_ids == AUTHD_LOG_IDS_HASHED) {
        /* Of the WHOLE identifier, not the escaped and truncated field: two ids
         * that differ only past byte 64, or only in an unprintable byte, are
         * different identities and get different pseudonyms. */
        static const char hexd[] = "0123456789abcdef";
        uint8_t p[AUTHD_LOG_PSEUDONYM_BYTES];
        char hex[2u * AUTHD_LOG_PSEUDONYM_BYTES + 1u];
        if (g_pseud == NULL || g_pseud(g_pseud_ctx, id, (id != NULL) ? id_len : 0u, p) != 0) {
            (void)snprintf(hex, sizeof hex, "unavailable");
        } else {
            for (size_t i = 0; i < AUTHD_LOG_PSEUDONYM_BYTES; i++) {
                hex[i * 2u] = hexd[(p[i] >> 4) & 0x0fu];
                hex[i * 2u + 1u] = hexd[p[i] & 0x0fu];
            }
            hex[2u * AUTHD_LOG_PSEUDONYM_BYTES] = '\0';
        }
        sodium_memzero(p, sizeof p);
        fprintf(out(), "%s event=%s slot=%zu idh=%s\n",
                level_name(lvl), event ? event : "?", slot, hex);
        line_done();
        return;
    }
    char field[ID_FIELD_MAX + 4u];
    size_t n = (id_len > ID_FIELD_MAX) ? ID_FIELD_MAX : id_len;
    size_t j = 0;
    for (size_t i = 0; i < n && id != NULL; i++) {
        /* Escape everything outside printable ASCII, and the two printable
         * bytes that delimit fields. A peer controls these bytes: a newline
         * would forge a second log line, and a space or '=' a second FIELD in
         * this one (`id=x event=login-code-issued id=op1`, V4-72, F141). */
        const uint8_t c = id[i];
        field[j++] = (c > 0x20u && c <= 0x7eu && c != (uint8_t)'=') ? (char)c : '.';
    }
    if (id_len > ID_FIELD_MAX) {
        field[j++] = '~';                  /* marks truncation */
    }
    field[j] = '\0';
    fprintf(out(), "%s event=%s slot=%zu id=%s\n",
            level_name(lvl), event ? event : "?", slot, field);
    line_done();
}

void authd_log_local(authd_log_level_t lvl, const char *event, const char *cmd,
                     unsigned long uid, long pid, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    /* The command name is the PEER's token: the request is logged before
     * the name is looked up, so that a command nobody knows is on record
     * too. It is at most 23 printable bytes by then, and it is escaped
     * here all the same, so it cannot add a field or a line. (This said the
     * name came from a fixed table; it never did. Corrected in V4-242.) */
    char safe[32];
    size_t j = 0;
    for (size_t i = 0; cmd != NULL && cmd[i] != '\0' && j + 1u < sizeof safe; i++) {
        const unsigned char ch = (unsigned char)cmd[i];
        safe[j++] = (ch > 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.';
    }
    safe[j] = '\0';
    if (pid > 0) {
        fprintf(out(), "%s event=%s cmd=%s uid=%lu pid=%ld detail=%s\n",
                level_name(lvl), event ? event : "?", safe, uid, pid, detail ? detail : "-");
    } else {
        fprintf(out(), "%s event=%s cmd=%s uid=%lu pid=unavailable detail=%s\n",
                level_name(lvl), event ? event : "?", safe, uid, detail ? detail : "-");
    }
    line_done();
}

void authd_fp_of_pk(authd_fp_t *out, const uint8_t pk[AUTHD_FP_PK_BYTES])
{
    crypto_hash_sha256(out->b, pk, AUTHD_FP_PK_BYTES);
}

void authd_log_fp(authd_log_level_t lvl, const char *event, const authd_fp_t *fp)
{
    if (fp == NULL || !enabled(lvl)) {       /* in this order: enabled() begins a line */
        return;
    }
    static const char hexd[] = "0123456789abcdef";
    char hex[65];
    for (size_t i = 0; i < sizeof fp->b; i++) {
        hex[i * 2u] = hexd[(fp->b[i] >> 4) & 0x0fu];
        hex[i * 2u + 1u] = hexd[fp->b[i] & 0x0fu];
    }
    hex[64] = '\0';
    fprintf(out(), "%s event=%s fp=%s\n", level_name(lvl), event ? event : "?", hex);
    line_done();
}

void authd_log_peer(authd_log_level_t lvl, const char *event, int uid_known,
                    unsigned long uid, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    if (uid_known) {
        fprintf(out(), "%s event=%s uid=%lu detail=%s\n",
                level_name(lvl), event ? event : "?", uid, detail ? detail : "-");
    } else {
        fprintf(out(), "%s event=%s uid=unavailable detail=%s\n",
                level_name(lvl), event ? event : "?", detail ? detail : "-");
    }
    line_done();
}

void authd_log_num(authd_log_level_t lvl, const char *event, const char *key, uint64_t value)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s %s=%llu\n",
            level_name(lvl), event ? event : "?", key ? key : "n",
            (unsigned long long)value);
    line_done();
}
