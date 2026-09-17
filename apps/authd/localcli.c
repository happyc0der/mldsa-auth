#include "localcli.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_io.h"

const char *localcli_status_name(localcli_status_t st)
{
    switch (st) {
    case LOCALCLI_OK:            return "ok";
    case LOCALCLI_ERR_ARG:       return "bad-argument";
    case LOCALCLI_ERR_CONNECT:   return "cannot-connect";
    case LOCALCLI_ERR_IO:        return "io-error";
    case LOCALCLI_ERR_TIMEOUT:   return "timeout";
    case LOCALCLI_ERR_TOO_LONG:  return "request-too-long";
    case LOCALCLI_ERR_RESPONSE:  return "malformed-response";
    }
    return "unknown";
}

/* THE authoritative set. See the header for why the reply cannot decide this. */
int localcli_is_list_command(const char *cmd)
{
    if (cmd == NULL) {
        return 0;
    }
    return strcmp(cmd, "LIST-USERS") == 0 ||
           strcmp(cmd, "LIST-DEVICES") == 0 ||
           strcmp(cmd, "AUDIT-TAIL") == 0;
}

int localcli_error_code(const char *resp, char *code_out, size_t cap)
{
    if (code_out != NULL && cap > 0u) {
        code_out[0] = '\0';
    }
    if (resp == NULL || strncmp(resp, "ERR code=", 9) != 0) {
        return 0;
    }
    const char *p = resp + 9;
    size_t n = 0;
    while (p[n] != '\0' && p[n] != '\n' && p[n] != ' ') {
        n++;
    }
    if (code_out != NULL && cap > 0u) {
        const size_t copy = (n < cap - 1u) ? n : cap - 1u;
        memcpy(code_out, p, copy);
        code_out[copy] = '\0';
    }
    return 1;
}

/* A complete response is: an ERR first line (always one line), OR -- for a
 * list command -- everything through a line that is exactly "END", OR the
 * first line. Returns 1 when `buf` (NUL-terminated, `len` bytes) holds one.
 *
 * The END test compares a whole LINE, never a substring. `detail=` is the one
 * field localapi does not hex-encode, so a substring search for "\nEND\n"
 * could in principle be satisfied by content rather than by framing. */
static int response_complete(const char *buf, size_t len, int is_list)
{
    const char *nl = memchr(buf, '\n', len);
    if (nl == NULL) {
        return 0;
    }
    if (strncmp(buf, "ERR ", 4) == 0 || !is_list) {
        return 1;
    }
    const char *line = nl + 1;                 /* skip the "OK count=" header */
    const char *end = buf + len;
    while (line < end) {
        const char *e = memchr(line, '\n', (size_t)(end - line));
        if (e == NULL) {
            return 0;
        }
        if ((size_t)(e - line) == 3u && memcmp(line, "END", 3) == 0) {
            return 1;
        }
        line = e + 1;
    }
    return 0;
}

localcli_status_t localcli_call(const char *sock_path, const char *cmd, const char *args,
                                uint64_t timeout_ms, char *out, size_t cap, size_t *out_len)
{
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (sock_path == NULL || cmd == NULL || out == NULL || cap == 0u) {
        return LOCALCLI_ERR_ARG;
    }
    out[0] = '\0';

    char req[AUTHD_LINE_MAX + 2u];
    const int rn = snprintf(req, sizeof req, "%s%s%s\n", cmd,
                            (args != NULL && args[0] != '\0') ? " " : "",
                            (args != NULL) ? args : "");
    if (rn < 0) {
        return LOCALCLI_ERR_ARG;
    }
    /* Spec 8 caps a request at 8192 bytes INCLUDING the LF. Refuse here rather
     * than let the daemon close the connection on us: the caller then gets a
     * status that names the real problem. */
    if ((size_t)rn > AUTHD_LINE_MAX) {
        return LOCALCLI_ERR_TOO_LONG;
    }

    const uint64_t deadline = net_deadline_in(timeout_ms);
    net_conn_t conn;
    net_conn_init(&conn);
    const net_status_t cs = net_connect_unix(sock_path, deadline, &conn);
    if (cs != NET_OK) {
        return (cs == NET_TIMEOUT) ? LOCALCLI_ERR_TIMEOUT : LOCALCLI_ERR_CONNECT;
    }
    if (net_write_all(&conn, (const uint8_t *)req, (size_t)rn, deadline) != NET_OK) {
        net_close(&conn);
        return LOCALCLI_ERR_IO;
    }

    const int is_list = localcli_is_list_command(cmd);
    size_t got = 0;
    localcli_status_t result = LOCALCLI_ERR_RESPONSE;
    for (;;) {
        if (got + 1u >= cap) {
            result = LOCALCLI_ERR_RESPONSE;    /* a reply larger than the caller's buffer */
            break;
        }
        struct pollfd p = { conn.fd, POLLIN, 0 };
        const uint64_t now = net_now_ms();
        if (now == UINT64_MAX || now >= deadline) {
            result = LOCALCLI_ERR_TIMEOUT;
            break;
        }
        uint64_t left = deadline - now;
        if (left > (uint64_t)INT32_MAX) {
            left = (uint64_t)INT32_MAX;
        }
        const int pr = poll(&p, 1, (int)left);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = LOCALCLI_ERR_IO;
            break;
        }
        if (pr == 0) {
            result = LOCALCLI_ERR_TIMEOUT;
            break;
        }
        const ssize_t n = recv(conn.fd, out + got, cap - got - 1u, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            result = LOCALCLI_ERR_IO;
            break;
        }
        if (n == 0) {
            /* The daemon closed. That is a complete response only if what we
             * already have is one -- otherwise it is a truncation, and saying
             * so beats handing the caller half a list. */
            result = (got > 0u && response_complete(out, got, is_list)) ? LOCALCLI_OK
                                                                       : LOCALCLI_ERR_RESPONSE;
            break;
        }
        got += (size_t)n;
        out[got] = '\0';
        if (response_complete(out, got, is_list)) {
            result = LOCALCLI_OK;
            break;
        }
    }
    net_close(&conn);
    out[(got < cap) ? got : cap - 1u] = '\0';
    if (out_len != NULL) {
        *out_len = got;
    }
    return result;
}
