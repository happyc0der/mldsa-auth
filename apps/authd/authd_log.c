#include "authd_log.h"

#include <string.h>

static FILE *g_dest = NULL;
static authd_log_level_t g_min = AUTHD_LOG_INFO;

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
