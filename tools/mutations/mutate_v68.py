#!/usr/bin/env python3
"""V4-24a mutations: F111, and the claim map's P11 and D13 gaps.

Usage: mutate_v68.py <repo> <ID>

Two-letter IDs: CG = V4-24's Claim Gaps. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90). All five passed V4-23's whole suite.

    CG1   listener_open_unix's refusal of a mode outside spec 8's two can
          never hold, so 0666 opens a world-writable socket. Nothing called
          it with another mode until V4-24a (audit F111: the header named the
          wrong refusal).
    CG2   the initiator fails the handshake when the decapsulated secret's
          first two bytes are zero -- a "validation" of the secret's leading
          bits (P11). A random secret meets it once in 65,536 handshakes;
          the sweep chooses a ciphertext that meets it.
    CG3   on_rotate logs the decrypted ROTATE's first 32 bytes, through the
          fingerprint sink with a cast (the W12/G12/GC4 shape).
    CG4   on_record logs the first 32 ciphertext bytes of every record it
          receives: a raw frame in the journal.
    CG5   on_rotate logs the start of the ROTATE's sig_old -- the signature
          the journal scan had never looked for (audit F113).
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LI = "apps/authd/listener.c"
HS = "src/protocol/handshake.c"
CO = "apps/authd/authd_conn.c"
ROT = ("        return fail_with_error(slot, c, AUTHMSG_ERR_MALFORMED, \"rotate-malformed\");\n"
       "    }\n")

M = {
 "CG1": (LI, [("    if (mode != (mode_t)LISTENER_MODE_PRIVATE && mode != (mode_t)LISTENER_MODE_GROUP) {",
               "    if (mode != (mode_t)LISTENER_MODE_PRIVATE && mode != (mode_t)LISTENER_MODE_GROUP &&\n"
               "        mode == (mode_t)07777) { /* MUTATION CG1 */")]),
 "CG2": (HS, [("    if (derive_traffic_keys(keys, shared, ss_kem, ctx->session_id,",
               "    if (ss_kem[0] == 0x00 && ss_kem[1] == 0x00) { result = HANDSHAKE_ERR_INTERNAL; goto fail; } /* MUTATION CG2 */\n"
               "    if (derive_traffic_keys(keys, shared, ss_kem, ctx->session_id,")]),
 "CG3": (CO, [(ROT, ROT + "    authd_log_fp(AUTHD_LOG_INFO, \"rotate\", (const authd_fp_t *)pt); /* MUTATION CG3 */\n")]),
 "CG4": (CO, [("    const session_status_t ss = session_open(&c->sess, payload, len, pt, sizeof pt, &pt_len);\n",
               "    const session_status_t ss = session_open(&c->sess, payload, len, pt, sizeof pt, &pt_len);\n"
               "    authd_log_fp(AUTHD_LOG_INFO, \"record-rejected\", (const authd_fp_t *)(payload + SESSION_HEADER_BYTES)); /* MUTATION CG4 */\n")]),
 "CG5": (CO, [(ROT, ROT + "    authd_log_fp(AUTHD_LOG_INFO, \"rotate\", (const authd_fp_t *)m.sig_old); /* MUTATION CG5 */\n")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID}")
