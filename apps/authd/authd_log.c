#include "authd_log.h"

#include <string.h>

#include <sodium.h>

#include "proxy_v2.h"

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

static int enabled(authd_log_level_t l)
{
    return (int)l <= (int)g_min;
}

void authd_log_event(authd_log_level_t lvl, const char *event)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s\n", level_name(lvl), event ? event : "?");
    fflush(out());
}

void authd_log_slot(authd_log_level_t lvl, const char *event, size_t slot)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s slot=%zu\n", level_name(lvl), event ? event : "?", slot);
    fflush(out());
}

void authd_log_slot_addr(authd_log_level_t lvl, const char *event, size_t slot,
                         const struct authd_addr *addr, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    if (g_ip == AUTHD_LOG_IP_OFF) {
        fprintf(out(), "%s event=%s slot=%zu detail=%s\n",
                level_name(lvl), event ? event : "?", slot, detail ? detail : "-");
        fflush(out());
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
            level_name(lvl), event ? event : "?", slot, src, suffix, detail ? detail : "-");
    sodium_memzero(&a, sizeof a);
    fflush(out());
}

void authd_log_slot_detail(authd_log_level_t lvl, const char *event, size_t slot, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s slot=%zu detail=%s\n",
            level_name(lvl), event ? event : "?", slot, detail ? detail : "?");
    fflush(out());
}

void authd_log_slot_id(authd_log_level_t lvl, const char *event, size_t slot,
                       const uint8_t *id, size_t id_len)
{
    if (!enabled(lvl)) {
        return;
    }
    if (g_ids == AUTHD_LOG_IDS_OFF) {
        fprintf(out(), "%s event=%s slot=%zu\n", level_name(lvl), event ? event : "?", slot);
        fflush(out());
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
        fflush(out());
        return;
    }
    char field[ID_FIELD_MAX + 4u];
    size_t n = (id_len > ID_FIELD_MAX) ? ID_FIELD_MAX : id_len;
    size_t j = 0;
    for (size_t i = 0; i < n && id != NULL; i++) {
        /* Escape everything outside printable ASCII. A peer controls these
         * bytes, so without this an identifier could carry a newline and forge
         * a second log line. */
        const uint8_t c = id[i];
        field[j++] = (c >= 0x20u && c <= 0x7eu) ? (char)c : '.';
    }
    if (id_len > ID_FIELD_MAX) {
        field[j++] = '~';                  /* marks truncation */
    }
    field[j] = '\0';
    fprintf(out(), "%s event=%s slot=%zu id=%s\n",
            level_name(lvl), event ? event : "?", slot, field);
    fflush(out());
}

void authd_log_local(authd_log_level_t lvl, const char *event, const char *cmd,
                     unsigned long uid, long pid, const char *detail)
{
    if (!enabled(lvl)) {
        return;
    }
    /* The command name is matched against a fixed table before it reaches
     * here, so it is one of a closed set of literals -- but it is escaped
     * anyway, because a malformed request reports "?" and the day someone
     * passes the raw token through, this should still not inject a line. */
    char safe[32];
    size_t j = 0;
    for (size_t i = 0; cmd != NULL && cmd[i] != '\0' && j + 1u < sizeof safe; i++) {
        const unsigned char ch = (unsigned char)cmd[i];
        safe[j++] = (ch >= 0x20u && ch <= 0x7eu && ch != ' ') ? (char)ch : '.';
    }
    safe[j] = '\0';
    if (pid > 0) {
        fprintf(out(), "%s event=%s cmd=%s uid=%lu pid=%ld detail=%s\n",
                level_name(lvl), event ? event : "?", safe, uid, pid, detail ? detail : "-");
    } else {
        fprintf(out(), "%s event=%s cmd=%s uid=%lu pid=unavailable detail=%s\n",
                level_name(lvl), event ? event : "?", safe, uid, detail ? detail : "-");
    }
    fflush(out());
}

void authd_log_fp(authd_log_level_t lvl, const char *event, const uint8_t fp[32])
{
    if (!enabled(lvl) || fp == NULL) {
        return;
    }
    static const char hexd[] = "0123456789abcdef";
    char hex[65];
    for (size_t i = 0; i < 32u; i++) {
        hex[i * 2u] = hexd[(fp[i] >> 4) & 0x0fu];
        hex[i * 2u + 1u] = hexd[fp[i] & 0x0fu];
    }
    hex[64] = '\0';
    fprintf(out(), "%s event=%s fp=%s\n", level_name(lvl), event ? event : "?", hex);
    fflush(out());
}

void authd_log_num(authd_log_level_t lvl, const char *event, const char *key, uint64_t value)
{
    if (!enabled(lvl)) {
        return;
    }
    fprintf(out(), "%s event=%s %s=%llu\n",
            level_name(lvl), event ? event : "?", key ? key : "n",
            (unsigned long long)value);
    fflush(out());
}
