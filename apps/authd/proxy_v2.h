#ifndef MLDSA_AUTHD_PROXY_V2_H
#define MLDSA_AUTHD_PROXY_V2_H

#include <stddef.h>
#include <stdint.h>

/*
 * PROXY protocol v2 (V4-10b), spec mldsa-authd §7.2 mechanism 1.
 *
 * WHY THIS EXISTS. The daemon sits behind the site's TLS proxy on a Unix
 * socket, so every connection it sees comes from the proxy and every peer
 * address it could read is the proxy's. Rate limiting (§7.3: "this costs one
 * signature per probe, which is the rate limiter's problem") needs the
 * client's address, and the only trustworthy way to get one is for the proxy
 * to state it before the client is allowed to write a byte. That is exactly
 * what PROXY v2 is: a fixed-layout binary preamble the proxy prepends, which
 * the client can never forge because it never gets to write first.
 *
 * §7.2 lists a second mechanism -- a proxy-set `X-Real-IP` header -- as a
 * fallback. It is deliberately NOT implemented: two trust paths for the same
 * fact is one more parser to attack and one more thing to get wrong, and the
 * header form additionally depends on the proxy remembering to overwrite a
 * client-supplied value. A deliberate subset of §7.2, recorded as such.
 *
 * WHAT IS PARSED, AND WHAT IS NOT. The 16-byte header, and the address block
 * for AF_INET and AF_INET6. Everything after the address block -- the TLV
 * region -- is SKIPPED BY LENGTH, never walked: nothing in this daemon wants a
 * TLV, and a parser that is not written cannot be wrong. AF_UNIX and
 * AF_UNSPEC parse structurally and yield NO address, as does the LOCAL
 * command (a health check).
 *
 * FAIL CLOSED (Req 12). A header that is absent, truncated, mis-signed or of
 * the wrong version is a protocol error and the connection is closed. A header
 * that is well-formed but carries no client address is reported distinctly --
 * PROXY_V2_NO_ADDR -- because the caller still closes the connection but the
 * operator's log should be able to tell "your health checker is talking to the
 * login socket" from "something sent us garbage".
 *
 * INCREMENTAL, because bytes arrive in whatever pieces the network chose. The
 * parser stages at most PROXY_V2_HDR_LEN + PROXY_V2_ADDR_MAX bytes -- 232 --
 * and counts the TLV remainder down as it goes, so a declared body length
 * cannot become a buffer size.
 */

#define PROXY_V2_SIG_LEN   12u
#define PROXY_V2_HDR_LEN   16u     /* signature + ver/cmd + fam/proto + length */
#define PROXY_V2_ADDR_MAX  216u    /* AF_UNIX's block, the largest defined */
/* A body larger than this is refused. The address block is at most 216 bytes;
 * the rest would be TLVs, and a proxy sending a kilobyte of them is not the
 * proxy this deployment has. Bounding it here is what stops a 16-bit length
 * field from deciding how long a connection may occupy a slot saying nothing. */
#define PROXY_V2_LEN_MAX   1024u
#define PROXY_V2_MAX_TOTAL (PROXY_V2_HDR_LEN + PROXY_V2_LEN_MAX)

/* A client address, or the absence of one.
 *
 * It is a STRUCT rather than a bare buffer for the reason authd_log.h's
 * fingerprint sink is not: a typed value cannot be conjured from a pointer to
 * something else, so `authd_log_slot_addr` can never be handed a session key
 * or a token by a caller who miscounted bytes. `family == 0` means "no
 * address", and every consumer must treat that as fail-closed, not as 0.0.0.0. */
typedef struct authd_addr {
    uint8_t family;      /* 0 = none, 4 = IPv4, 6 = IPv6 */
    uint8_t addr[16];    /* IPv4 occupies the first four bytes */
} authd_addr_t;

/* Renders `a` for the log: dotted quad, or RFC 5952 IPv6 text, or "none".
 * Always NUL-terminates and never emits a byte outside [0-9a-f.:], so it
 * cannot inject a field separator or a newline into a log line. */
#define AUTHD_ADDR_STR_MAX 46u
void authd_addr_str(const authd_addr_t *a, char *out, size_t cap);

/* The rate-limiting key for `a`: the four bytes of an IPv4 address, or the
 * first EIGHT of an IPv6 one.
 *
 * IPv6 is keyed on the /64 because that is the smallest unit a single customer
 * is routinely given: keying on the full 128 bits would let one host rotate
 * through 2^64 addresses and never meet the limiter at all. Returns the key
 * length, or 0 when there is no address. */
size_t authd_addr_key(const authd_addr_t *a, uint8_t out[16]);

typedef enum {
    PROXY_V2_NEED_MORE = 0,  /* nothing wrong; more bytes required */
    PROXY_V2_OK,             /* complete, and an address was established */
    PROXY_V2_NO_ADDR,        /* complete and well-formed, but no client address */
    PROXY_V2_ERR             /* terminal: the caller must poison the connection */
} proxy_v2_status_t;

const char *proxy_v2_status_name(proxy_v2_status_t st);

typedef struct {
    uint8_t  buf[PROXY_V2_HDR_LEN + PROXY_V2_ADDR_MAX];
    size_t   have;        /* bytes staged in buf */
    size_t   want;        /* bytes buf must hold before the next decision */
    size_t   skip;        /* body bytes still to be discarded (the TLV region) */
    int      hdr_ok;      /* the 16-byte fixed header has been validated */
    int      done;        /* the preamble has been fully consumed */
    proxy_v2_status_t result;
    authd_addr_t addr;
} proxy_v2_t;

void proxy_v2_init(proxy_v2_t *p);

/* Consumes as much of [data, data+n) as the preamble needs, writing the number
 * of bytes taken to *used -- the caller hands the remainder to whatever speaks
 * next. Once the preamble is complete this consumes nothing and keeps
 * returning the settled verdict, so a caller may call it unconditionally. */
proxy_v2_status_t proxy_v2_consume(proxy_v2_t *p, const uint8_t *data, size_t n, size_t *used);

#endif /* MLDSA_AUTHD_PROXY_V2_H */
