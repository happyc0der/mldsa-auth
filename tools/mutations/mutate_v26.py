#!/usr/bin/env python3
"""V2-6 mutations: record padding. One defect per run; the runner restores
byte-exactly afterwards. Every edit asserts its pattern matched exactly once."""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1])
WHICH = sys.argv[2]

def edit(rel, old, new):
    p = REPO / rel
    s = p.read_text()
    assert s.count(old) == 1, f"{rel}: pattern found {s.count(old)} times, expected 1"
    p.write_text(s.replace(old, new, 1))

M = {}

# Q1: the receiver accepts nonzero padding.
M["Q1"] = lambda: edit("src/protocol/session.c",
    "    if (pad_len != 0 &&\n"
    "        sodium_is_zero(pt_out + SESSION_CONTENT_LEN_BYTES + content_len, pad_len) != 1) {\n"
    "        sodium_memzero(pt_out, body);\n"
    "        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);\n"
    "    }",
    "    (void)pad_len; /* MUTATION: padding not checked */")

# Q2: the receiver does not bound content_len against the inner.
M["Q2"] = lambda: edit("src/protocol/session.c",
    "    if (content_len > body - SESSION_CONTENT_LEN_BYTES) {\n"
    "        sodium_memzero(pt_out, body);\n"
    "        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);\n"
    "    }",
    "    /* MUTATION: content_len not bounded */")

# Q3: the receiver insists the inner match ITS OWN bucket -- interop breaks.
M["Q3"] = lambda: edit("src/protocol/session.c",
    "    const size_t content_len = load_be16(pt_out);",
    "    const size_t content_len = load_be16(pt_out);\n"
    "    if (body != inner_len_for(content_len, s->limits.pad_bucket)) { /* MUTATION */\n"
    "        sodium_memzero(pt_out, body);\n"
    "        return terminate(s, SESSION_STATE_FAILED, SESSION_ERR_MALFORMED);\n"
    "    }")

# Q4: content_len written little-endian.
M["Q4"] = lambda: edit("src/protocol/session.c",
    "static void store_be16(uint8_t out[2], uint16_t v) {\n"
    "    out[0] = (uint8_t)(v >> 8);\n"
    "    out[1] = (uint8_t)v;\n"
    "}",
    "static void store_be16(uint8_t out[2], uint16_t v) {\n"
    "    out[0] = (uint8_t)v; /* MUTATION: little-endian */\n"
    "    out[1] = (uint8_t)(v >> 8);\n"
    "}")

# Q5: the padding region is left as whatever the caller's buffer held.
M["Q5"] = lambda: edit("src/protocol/session.c",
    "    memset(inner + used, 0, inner_len - used); /* padding: zero by definition */",
    "    /* MUTATION: padding left unwritten */")

# Q6: the minimum record length left at v1's 25.
M["Q6"] = lambda: edit("src/protocol/session.c",
    "    if (rec_len < SESSION_MIN_RECORD_BYTES || rec_len > SESSION_MAX_RECORD_BYTES ||",
    "    if (rec_len < SESSION_OVERHEAD_BYTES || rec_len > SESSION_MAX_RECORD_BYTES || /* MUTATION */")

# Q7: the tail after the content is not wiped -- prefix and padding linger.
M["Q7"] = lambda: edit("src/protocol/session.c",
    "    sodium_memzero(pt_out + content_len, body - content_len);",
    "    /* MUTATION: tail not wiped */")

# Q8: any pad bucket accepted.
M["Q8"] = lambda: edit("src/protocol/session.c",
    "    return bucket == 1u || bucket == 16u || bucket == 64u || bucket == 256u || bucket == 1024u ||\n"
    "           bucket == 4096u;",
    "    return bucket >= 1u; /* MUTATION */")

# Q9: the record label left at v1.
M["Q9"] = lambda: edit("src/protocol/session.h",
    '#define SESSION_AD_LABEL "mldsa-auth/v2/record"',
    '#define SESSION_AD_LABEL "mldsa-auth/v1/record"')

M[WHICH]()
print(f"applied {WHICH}")
