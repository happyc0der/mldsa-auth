#!/usr/bin/env python3
"""V4-13a mutations: the client core, and the buffer paths under it.

Usage: mutate_v53.py <repo> <ID>

Letter F -- the last free letter. The next campaign needs a two-letter scheme,
or reuses a retired one; that is decided when it exists, not here.

EVERY MUTATION HERE CHANGES WHAT A VALUE IS; NONE DELETES A USE. The audit of
the V4-12 nightly (finding F79) found 12 of 180 mutations scoring
KILLED(compile): the replacement left a variable, parameter or function
unused, -Werror refused to build it, and the "kill" proved the compiler works
and nothing about any test. W14 had scored that way every night since V4-9c.
So each one below keeps every name it touches live -- a comparison widened
(F1, F7, F8), a condition weakened (F6, F10), a value changed (F2, F11), a
pointer dropped instead of a buffer freed (F3, F4), an argument replaced
(F9) -- and F12, the routing call, is replaced by `(void)&cc_oqs_rng;`, which
keeps the function referenced so its removal cannot be what fails the build.

What each one is, in the order the client meets it:

  F1  a frame's length header is no longer compared to the bytes present
  F2  a ServerHello may be any size a record may
  F3  the key the core opened is NOT freed when ClientAuth is built
  F4  ... nor on a refusal, nor by cc_wipe
  F5  the pinned server's MLDSAPK1 id is compared by length only
  F6  a first record that is not LOGIN_CODE is accepted
  F7  a ROTATE_ACK's key fingerprint is not compared
  F8  a ROTATE_ACK's handle is compared by length only
  F9  the injected clock never reaches the session
  F10 keyfile_write_sealed publishes without checking what it was given
  F11 the browser's Argon2id memory is 32 MiB, not spec 12's 64
  F12 liboqs is not routed to libsodium's generator

F11 and F12 are caught by the KAT's golden as well as by a named check, and
F12 ONLY by the KAT -- which is the reason the KAT exists: a routing mistake is
invisible to every test that uses a real generator, and would surface only as
a wasm build that cannot reproduce native output.

THREE EXPECTATIONS WERE WRONG ON THE FIRST RUN (9 killed, 3 SURVIVED(BAD)),
all defects in this campaign rather than in the tree:

  * F5 and F11 named two tests as `^(a|b)$`. The spec format's field
    separator IS `|`, so the runner split the regex mid-way and looked for
    `b)$` as a FAIL text. No earlier campaign had matched two tests, so no
    spec had ever tripped on it. Both now use a `|`-free form --
    `^test_(authd_keyfile)?(client_core)?$`, `^test_client_core(_kat)?$` --
    checked with `ctest -N -R` to select exactly the two tests meant.
  * F4 predicted that "cc_wipe frees the owned key" would fail. It cannot:
    cc_wipe zeroes the whole struct after wiping, so a LEAKED key's pointer
    reads NULL as well, and that check could never observe the free it was
    named for. It is renamed to what it does assert (the end state), and F4
    is killed where the free is observable -- on a refusal, before any wipe.
    A mutation that survives a check shows the check is weaker than its
    name; that is what this campaign exists to find, including in its own
    tests.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
CC = "apps/authd/client_core.c"
CH = "apps/authd/client_core.h"
KF = "apps/authd/keyfile.c"
DK = "apps/demo_keys.c"

M = {
 "F1": (CC, [("    if (claimed != msg_len - FRAME_HEADER_BYTES || claimed < min_len || claimed > max_len) {",
              "    if (claimed < min_len || claimed > max_len) { /* MUTATION F1: header not compared to size */")]),
 "F2": (CC, [("    if (take_frame(msg, msg_len, 1u, FRAME_MAX_SERVER_HELLO, &plen) != 0) {",
              "    if (take_frame(msg, msg_len, 1u, FRAME_MAX_PAYLOAD, &plen) != 0) { /* MUTATION F2 */")]),
 "F3": (CC, [("    if ((cc->flags & CC_KEEP_FOR_ROTATE) == 0u) {\n        release_key(cc);\n    }",
              "    if ((cc->flags & CC_KEEP_FOR_ROTATE) == 0u) {\n        cc->kp = NULL;   /* MUTATION F3: dropped, not freed */\n    }")]),
 "F4": (CC, [("static void wipe_secrets(cc_t *cc)\n{\n    release_key(cc);",
              "static void wipe_secrets(cc_t *cc)\n{\n    cc->kp = NULL;   /* MUTATION F4: dropped, not freed */")]),
 "F5": (DK, [("    if (idl != id_len || memcmp(buf + HDR_LEN, expect_id, idl) != 0) {",
              "    if (idl != id_len) { /* MUTATION F5: id compared by length only */")]),
 "F6": (CC, [("    if (as != AUTHMSG_OK) {\n        memset(code_out, 0, sizeof *code_out);",
              "    if (as != AUTHMSG_OK && pt_len == AUTHMSG_LOGIN_CODE_CONTENT_LEN) { /* MUTATION F6 */\n        memset(code_out, 0, sizeof *code_out);")]),
 "F7": (CC, [("            sodium_memcmp(ack.fp_new, cc->want_fp, sizeof cc->want_fp) == 0) {",
              "            (sodium_memcmp(ack.fp_new, cc->want_fp, sizeof cc->want_fp) == 0 || ack.rotated_at != 0u)) { /* MUTATION F7 */")]),
 "F8": (CC, [("        if (ack.handle_len == cc->hid_len && sodium_memcmp(ack.handle, cc->hid, cc->hid_len) == 0 &&",
              "        if (ack.handle_len == cc->hid_len && (sodium_memcmp(ack.handle, cc->hid, cc->hid_len) == 0 || ack.handle_len > 0u) && /* MUTATION F8 */")]),
 "F9": (CC, [("session_init_from_handshake(&cc->sess, &cc->hs, &lim, cc->clock_fn, cc->clock_ctx)",
              "session_init_from_handshake(&cc->sess, &cc->hs, &lim, NULL, cc->clock_ctx) /* MUTATION F9 */")]),
 "F10": (KF, [("    if (hs != KEYFILE_OK) {\n        return hs;\n    }\n    return publish(path, buf, len);",
               "    if (hs != KEYFILE_OK && hs == KEYFILE_ERR_ARG) { /* MUTATION F10 */\n        return hs;\n    }\n    return publish(path, buf, len);")]),
 "F11": (CH, [("#define CC_KDF_MEM_BROWSER (64u * 1024u * 1024u)",
               "#define CC_KDF_MEM_BROWSER (32u * 1024u * 1024u) /* MUTATION F11 */")]),
 "F12": (CC, [("    OQS_randombytes_custom_algorithm(cc_oqs_rng);",
               "    (void)&cc_oqs_rng; /* MUTATION F12: liboqs not routed */")]),
}

def apply(path, edits):
    f = REPO / path
    s = f.read_text()
    for old, new in edits:
        if s.count(old) != 1:
            sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
        s = s.replace(old, new, 1)
    f.write_text(s)

path, edits = M[MID]
apply(path, edits)
print(f"applied {MID} to {path}")
