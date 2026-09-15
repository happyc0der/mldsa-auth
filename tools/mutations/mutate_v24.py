#!/usr/bin/env python3
"""V2-4 mutations. Each applies ONE defect to the working tree; the runner
restores byte-exactly afterwards. Every edit is asserted to change the file,
so a stale pattern fails loudly instead of producing a vacuous 'kill'."""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1])
WHICH = sys.argv[2]
MARK = "/* MUTATION */"

def edit(rel, old, new):
    p = REPO / rel
    s = p.read_text()
    assert s.count(old) == 1, f"{rel}: pattern found {s.count(old)} times, expected 1"
    p.write_text(s.replace(old, new + " " + MARK if new.rstrip().endswith(";") else new, 1))

M = {}

# M1: the hybrid combiner drops ss_k -- IKM is the X25519 secret alone.
M["M1"] = lambda: edit("src/crypto/kex.c",
    "    memcpy(ikm, ss_x, KEX_SHARED_SECRET_BYTES);\n"
    "    memcpy(ikm + KEX_SHARED_SECRET_BYTES, ss_k, KEX_SHARED_SECRET_BYTES);",
    "    memcpy(ikm, ss_x, KEX_SHARED_SECRET_BYTES);\n"
    "    memcpy(ikm + KEX_SHARED_SECRET_BYTES, ss_x, KEX_SHARED_SECRET_BYTES); /* MUTATION */")

# M2: the two secrets are concatenated in the wrong order.
M["M2"] = lambda: edit("src/crypto/kex.c",
    "    memcpy(ikm, ss_x, KEX_SHARED_SECRET_BYTES);\n"
    "    memcpy(ikm + KEX_SHARED_SECRET_BYTES, ss_k, KEX_SHARED_SECRET_BYTES);",
    "    memcpy(ikm, ss_k, KEX_SHARED_SECRET_BYTES);\n"
    "    memcpy(ikm + KEX_SHARED_SECRET_BYTES, ss_x, KEX_SHARED_SECRET_BYTES); /* MUTATION */")

# M3: the transcript digest is omitted from the v2 info.
M["M3"] = lambda: edit("src/crypto/kex.c",
    "    memcpy(out + off, th_client_auth, KEX_TRANSCRIPT_HASH_BYTES);\n"
    "    off += KEX_TRANSCRIPT_HASH_BYTES;",
    "    /* MUTATION: digest omitted */")

# M4: the v2 builder uses the v1 label.
M["M4"] = lambda: edit("src/crypto/kex.c",
    "    static const char kLabel[] = KEX_KDF_V2_LABEL;",
    "    static const char kLabel[] = KEX_KDF_LABEL;")

# M5: a transcript label left at v1.
M["M5"] = lambda: edit("src/protocol/transcript.h",
    '#define TRANSCRIPT_LABEL_SERVER_AUTH "mldsa-auth/v2/server-auth"',
    '#define TRANSCRIPT_LABEL_SERVER_AUTH "mldsa-auth/v1/server-auth"')

# M6: the ClientHello decoder's remaining-length check forgets mlkem_ek,
#     so a v1-length message gets past it.
M["M6"] = lambda: edit("src/protocol/transcript.c",
    "    if (len - off < WIRE_X25519_PUB_LEN + WIRE_MLKEM_EK_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN) {",
    "    if (len - off < WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN) {")

# M7: ek placed before the X25519 key in BOTH encoder and decoder --
#     a wrong layout that still round-trips perfectly.
def m7():
    edit("src/protocol/transcript.c",
        "    memcpy(out + off, msg->ephemeral_pub, WIRE_X25519_PUB_LEN);\n"
        "    off += WIRE_X25519_PUB_LEN;\n"
        "    memcpy(out + off, msg->mlkem_ek, WIRE_MLKEM_EK_LEN);\n"
        "    off += WIRE_MLKEM_EK_LEN;",
        "    memcpy(out + off, msg->mlkem_ek, WIRE_MLKEM_EK_LEN);\n"
        "    off += WIRE_MLKEM_EK_LEN;\n"
        "    memcpy(out + off, msg->ephemeral_pub, WIRE_X25519_PUB_LEN);\n"
        "    off += WIRE_X25519_PUB_LEN; /* MUTATION */")
    edit("src/protocol/transcript.c",
        "    memcpy(out->ephemeral_pub, buf + off, WIRE_X25519_PUB_LEN);\n"
        "    off += WIRE_X25519_PUB_LEN;\n"
        "    memcpy(out->mlkem_ek, buf + off, WIRE_MLKEM_EK_LEN);\n"
        "    off += WIRE_MLKEM_EK_LEN;",
        "    memcpy(out->mlkem_ek, buf + off, WIRE_MLKEM_EK_LEN);\n"
        "    off += WIRE_MLKEM_EK_LEN;\n"
        "    memcpy(out->ephemeral_pub, buf + off, WIRE_X25519_PUB_LEN);\n"
        "    off += WIRE_X25519_PUB_LEN; /* MUTATION */")
M["M7"] = m7

# M8: the ClientHello maximum left at the v1 formula.
M["M8"] = lambda: edit("src/protocol/transcript.h",
    "    (1u + 1u + WIRE_ID_MAX_LEN + WIRE_X25519_PUB_LEN + WIRE_MLKEM_EK_LEN + WIRE_SESSION_ID_LEN + \\\n"
    "     WIRE_NONCE_LEN)",
    "    (1u + 1u + WIRE_ID_MAX_LEN + WIRE_X25519_PUB_LEN + WIRE_SESSION_ID_LEN + WIRE_NONCE_LEN)")

M[WHICH]()
print(f"applied {WHICH}")
