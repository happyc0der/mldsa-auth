#ifndef MLDSA_AUTHD_LOCALAPI_H
#define MLDSA_AUTHD_LOCALAPI_H

#include <stddef.h>
#include <stdint.h>

#include "evloop.h"

/*
 * The local socket protocol (V4-9a), spec mldsa-authd §8.
 *
 *   request  = CMD SP key=value (SP key=value)* LF        <= 8192 bytes
 *   response = "OK" (SP key=value)* LF  |  "ERR" SP "code=" name LF
 *   list     = ("OK" SP "count=" n LF) item* "END" LF
 *
 * Binary values are lowercase hex. That is not an aesthetic choice: it means
 * there are NO escaping rules anywhere in the protocol, so there is exactly
 * one decoder to get right and to fuzz. Labels and reasons are hex too.
 *
 * TWO SOCKETS, TWO DISPATCH TABLES. Admin commands are not gated by a flag on
 * the site socket -- they are absent from its table. Req 11's "impossible from
 * the site's uid by construction" is a property of the lookup, not of a
 * conditional that someone could later invert.
 *
 * Every request is logged with the peer's uid and pid (§8). The VALUES on the
 * line are never logged: a token or a login code would otherwise reach the
 * journal, which the never-list (§15 / Req 13) forbids.
 */

/* Spec §8 fixes the line at 8192 bytes because a public key is 3904 hex
 * characters. A response is bounded by the connection's out buffer; a list
 * that would not fit is refused rather than truncated (see AUTHD_LIST_MAX). */
#define LOCALAPI_MAX_KEYS 12u

/* The largest number of items a list response will emit. A list is built in
 * one out buffer and sent as one reply, so this is a real bound rather than a
 * policy: exceeding it answers `ERR code=too-many` instead of silently
 * truncating, which would be the kind of quiet lie this project avoids.
 * V4-10/V4-11 can add streaming if a deployment ever needs more. */
#define AUTHD_LIST_MAX 24u

/* Dispatches one request line on a LOCAL slot. Wired to the event loop as its
 * evloop_on_line_fn; `user` is the authd_app_t. */
ev_action_t localapi_on_line(void *user, authd_slot_t *slot, const uint8_t *line, size_t len);

#endif /* MLDSA_AUTHD_LOCALAPI_H */
