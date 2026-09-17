#ifndef MLDSA_AUTHD_LOCALCLI_H
#define MLDSA_AUTHD_LOCALCLI_H

/*
 * The CLIENT half of the local socket protocol (spec mldsa-authd 8).
 *
 * localapi.c is the server; this is the one C client, used by every online
 * authd_admin subcommand. It exists as a library unit rather than as code
 * inside authd_admin.c for one reason: the framing rule below is subtle, has
 * already been got wrong twice, and must have exactly ONE definition.
 *
 *   response = "OK" (SP key=value)* LF  |  "ERR" SP "code=" name LF
 *   list     = ("OK" SP "count=" n LF) item* "END" LF
 *
 * THE FRAMING RULE. You cannot tell a list from a single line by looking at
 * the reply:
 *
 *   - REVOKE-TOKENS answers `OK count=N` on ONE line with no END, exactly like
 *     a list HEADER (localapi.c, h_revoke_tokens). A reader that waits for END
 *     whenever it sees "OK count=" hangs on it.
 *   - A REFUSED list command answers a single `ERR code=` line with no END, so
 *     a reader that always waits for END on a list command hangs on that. This
 *     is not hypothetical: it hung the Node handler's own test suite for 24
 *     seconds until the daemon exited.
 *
 * The CALLER knows which command it sent, so that is what decides:
 * localcli_is_list_command() is the authority, and an `ERR` first line always
 * terminates regardless. examples/site-node/authd.mjs keeps a copy of this set
 * because it is a different language; tests/authd_harness.h uses this one.
 */

#include <stddef.h>
#include <stdint.h>

#include "conn_io.h"   /* AUTHD_FRAME_MAX, AUTHD_LINE_MAX */

/* The response buffer must be sized from the RESPONSE bound, not the request
 * bound. AUTHD_LINE_MAX (8192) caps a REQUEST; localapi builds replies in an
 * AUTHD_FRAME_MAX buffer, and a 24-row LIST-DEVICES with 64-byte labels is
 * already over 8192 bytes. Sizing a client from the request cap truncates a
 * legal reply. */
#define LOCALCLI_RESP_MAX AUTHD_FRAME_MAX

typedef enum {
    LOCALCLI_OK = 0,          /* a complete response arrived; it may still be an ERR line */
    LOCALCLI_ERR_ARG,
    LOCALCLI_ERR_CONNECT,     /* no socket, wrong permissions, uid not allowed */
    LOCALCLI_ERR_IO,
    LOCALCLI_ERR_TIMEOUT,
    LOCALCLI_ERR_TOO_LONG,    /* the request would exceed AUTHD_LINE_MAX */
    LOCALCLI_ERR_RESPONSE     /* over LOCALCLI_RESP_MAX, or the peer closed mid-response */
} localcli_status_t;

const char *localcli_status_name(localcli_status_t st);

/* True for the three commands whose reply is terminated by a line "END".
 * Every other command answers exactly one line. */
int localcli_is_list_command(const char *cmd);

/* Sends "<cmd>[ <args>]\n" to the Unix socket at `sock_path` and reads one
 * complete response into `out` (always NUL-terminated on LOCALCLI_OK).
 *
 * `args` may be NULL or empty for a command that takes no keys. The whole
 * request is bounded by AUTHD_LINE_MAX and the whole exchange by
 * `timeout_ms`.
 *
 * LOCALCLI_OK means "a well-formed response arrived", NOT "the daemon agreed":
 * the caller inspects `out` for a leading "ERR ". That split is deliberate --
 * a transport failure and a refusal are different exit codes (spec 13). */
localcli_status_t localcli_call(const char *sock_path, const char *cmd, const char *args,
                                uint64_t timeout_ms, char *out, size_t cap, size_t *out_len);

/* Parses a response's first line. Returns 1 and copies the code into
 * `code_out` when it is an `ERR code=NAME` line; returns 0 otherwise.
 * `code_out` is always NUL-terminated. */
int localcli_error_code(const char *resp, char *code_out, size_t cap);

#endif /* MLDSA_AUTHD_LOCALCLI_H */
