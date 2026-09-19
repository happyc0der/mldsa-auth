#include "proxy_v2.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* RFC-less but universal: the 12-byte signature from HAProxy's PROXY protocol
 * v2 specification. It begins "\r\n\r\n", which as a big-endian 32-bit integer
 * is 218,893,066 -- the reason the frame reassembler must never look at these
 * bytes, and the reason this parser owns its own staging buffer rather than
 * borrowing conn_io's `in`. */
static const uint8_t PROXY_V2_SIG[PROXY_V2_SIG_LEN] = {
    0x0du, 0x0au, 0x0du, 0x0au, 0x00u, 0x0du, 0x0au, 0x51u, 0x55u, 0x49u, 0x54u, 0x0au
};

const char *proxy_v2_status_name(proxy_v2_status_t st)
{
    switch (st) {
    case PROXY_V2_NEED_MORE: return "need-more";
    case PROXY_V2_OK:        return "ok";
    case PROXY_V2_NO_ADDR:   return "no-client-address";
    case PROXY_V2_ERR:       return "malformed";
    default:                 return "unknown";
    }
}

void proxy_v2_init(proxy_v2_t *p)
{
    if (p == NULL) {
        return;
    }
    memset(p, 0, sizeof *p);
    p->want = PROXY_V2_HDR_LEN;
    p->result = PROXY_V2_NEED_MORE;
}

void authd_addr_str(const authd_addr_t *a, char *out, size_t cap)
{
    if (out == NULL || cap == 0u) {
        return;
    }
    out[0] = '\0';
    if (a == NULL || a->family == 0u) {
        (void)snprintf(out, cap, "none");
        return;
    }
    const int af = (a->family == 4u) ? AF_INET : AF_INET6;
    if (inet_ntop(af, a->addr, out, (socklen_t)cap) == NULL) {
        /* Cannot happen for a 4- or 16-byte input into a 46-byte buffer, but a
         * renderer that silently produced an uninitialised log field would be
         * worse than one that says it failed. */
        (void)snprintf(out, cap, "unprintable");
    }
}

size_t authd_addr_key(const authd_addr_t *a, uint8_t out[16])
{
    if (a == NULL || out == NULL) {
        return 0u;
    }
    if (a->family == 4u) {
        memcpy(out, a->addr, 4);
        return 4u;
    }
    if (a->family == 6u) {
        memcpy(out, a->addr, 8);        /* the /64 -- see the header */
        return 8u;
    }
    return 0u;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]); }

/* How many bytes of address block a family declares. 0 means "none defined",
 * which is not an error: AF_UNSPEC is legal and simply carries no address. */
static size_t addr_block_len(uint8_t fam)
{
    switch (fam) {
    case 0x1u: return 12u;    /* AF_INET: 4 + 4 + 2 + 2 */
    case 0x2u: return 36u;    /* AF_INET6: 16 + 16 + 2 + 2 */
    case 0x3u: return 216u;   /* AF_UNIX */
    default:   return 0u;     /* AF_UNSPEC, or a family this parser does not know */
    }
}

/* One exit for every refusal, so a path cannot forget to mark the parser
 * settled and leave the caller looping on a header it has already rejected. */
static proxy_v2_status_t fail(proxy_v2_t *p, size_t consumed, size_t *used)
{
    p->done = 1;
    p->result = PROXY_V2_ERR;
    *used = consumed;
    return p->result;
}

/* Decides the verdict once `buf` holds the header plus whatever address block
 * the header declared. Never reads past p->have. */
static proxy_v2_status_t settle(proxy_v2_t *p)
{
    const uint8_t ver_cmd = p->buf[12];
    const uint8_t fam     = (uint8_t)(p->buf[13] >> 4);
    const uint8_t cmd     = (uint8_t)(ver_cmd & 0x0fu);

    if (cmd == 0x0u) {
        return PROXY_V2_NO_ADDR;      /* LOCAL: a health check, no client */
    }
    /* cmd 0x1 (PROXY) is the only other legal value; anything else was already
     * refused when the header was validated. */
    if (fam == 0x1u) {
        p->addr.family = 4u;
        memcpy(p->addr.addr, p->buf + PROXY_V2_HDR_LEN, 4);
        return PROXY_V2_OK;
    }
    if (fam == 0x2u) {
        p->addr.family = 6u;
        memcpy(p->addr.addr, p->buf + PROXY_V2_HDR_LEN, 16);
        return PROXY_V2_OK;
    }
    /* AF_UNIX and AF_UNSPEC: structurally fine, no client address. Treating
     * them as malformed would make a legitimate proxy configuration look like
     * an attack in the log; treating them as an address would violate Req 12. */
    return PROXY_V2_NO_ADDR;
}

proxy_v2_status_t proxy_v2_consume(proxy_v2_t *p, const uint8_t *data, size_t n, size_t *used)
{
    if (used != NULL) {
        *used = 0u;
    }
    if (p == NULL || (data == NULL && n != 0u) || used == NULL) {
        return PROXY_V2_ERR;
    }
    if (p->done) {
        return p->result;             /* settled; consumes nothing further */
    }

    size_t i = 0;

    /* --- 1. the 16-byte fixed header ------------------------------------- */
    if (!p->hdr_ok) {
        while (p->have < PROXY_V2_HDR_LEN && i < n) {
            p->buf[p->have++] = data[i++];
        }
        if (p->have < PROXY_V2_HDR_LEN) {
            *used = i;
            return PROXY_V2_NEED_MORE;
        }
        if (memcmp(p->buf, PROXY_V2_SIG, PROXY_V2_SIG_LEN) != 0) {
            return fail(p, i, used);
        }
        const uint8_t ver  = (uint8_t)(p->buf[12] >> 4);
        const uint8_t cmd  = (uint8_t)(p->buf[12] & 0x0fu);
        const size_t  blen = (size_t)be16(p->buf + 14);
        if (ver != 0x2u || (cmd != 0x0u && cmd != 0x1u) || blen > PROXY_V2_LEN_MAX) {
            return fail(p, i, used);
        }
        /* Only a PROXY command carries an address block; a LOCAL one declares a
         * body that is entirely TLVs, if it declares one at all. */
        const uint8_t fam = (uint8_t)(p->buf[13] >> 4);
        const size_t  blk = (cmd == 0x1u) ? addr_block_len(fam) : 0u;
        if (blk > blen) {
            /* The header names a family whose address block does not fit in the
             * body it also declared -- truncation dressed as a valid length. */
            return fail(p, i, used);
        }
        p->want = PROXY_V2_HDR_LEN + blk;
        p->skip = blen - blk;
        p->hdr_ok = 1;
    }

    /* --- 2. the address block, staged so settle() can read it ------------- */
    while (p->have < p->want && i < n) {
        p->buf[p->have++] = data[i++];
    }
    if (p->have < p->want) {
        *used = i;
        return PROXY_V2_NEED_MORE;
    }

    /* --- 3. the TLV region, counted down rather than stored --------------- */
    if (p->skip > 0u) {
        const size_t avail = n - i;
        const size_t take = (avail < p->skip) ? avail : p->skip;
        i += take;
        p->skip -= take;
        if (p->skip > 0u) {
            *used = i;
            return PROXY_V2_NEED_MORE;
        }
    }

    p->done = 1;
    p->result = settle(p);
    *used = i;
    return p->result;
}
