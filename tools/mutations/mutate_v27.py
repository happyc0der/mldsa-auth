#!/usr/bin/env python3
"""V2-7 mutations R1-R6. Usage: mutate_v27.py <repo> <ID>

Each edit is a single, exact string replacement and carries a /* MUTATION */
marker so the runner's residue grep can prove the tree was restored.
"""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1])
MID = sys.argv[2]

M = {
    # R1 -- the demo layer ignores the configured bucket entirely.
    "R1": ("apps/demo_app.c",
           "    if (cfg->pad_bucket == 0u) {\n"
           "        return NULL;\n"
           "    }\n"
           "    session_default_limits(scratch);\n"
           "    scratch->pad_bucket = cfg->pad_bucket;\n"
           "    return scratch;\n",
           "    (void)cfg; /* MUTATION R1: the configured bucket never reaches the session */\n"
           "    (void)scratch;\n"
           "    return NULL;\n"),

    # R2 -- 0 is passed through as a literal bucket instead of NULL limits.
    "R2": ("apps/demo_app.c",
           "    if (cfg->pad_bucket == 0u) {\n"
           "        return NULL;\n"
           "    }\n"
           "    session_default_limits(scratch);\n",
           "    /* MUTATION R2: the 0-means-default translation is gone */\n"
           "    session_default_limits(scratch);\n"),

    # R3 -- config_valid() degrades to a range check, admitting e.g. 32.
    "R3": ("apps/demo_app.c",
           "           (c->pad_bucket == 0u || demo_pad_bucket_valid(c->pad_bucket)) &&\n",
           "           (c->pad_bucket <= SESSION_PAD_BUCKET_MAX) && /* MUTATION R3 */\n"),

    # R4 -- the caller-facing sizing macro subtracts the header, not the overhead.
    "R4": ("src/protocol/session.h",
           "#define SESSION_OPEN_CAP_FOR(max_record_len) ((max_record_len) - SESSION_OVERHEAD_BYTES)",
           "#define SESSION_OPEN_CAP_FOR(max_record_len) ((max_record_len) - SESSION_HEADER_BYTES) /* MUTATION R4 */"),

    # R5 -- the client's confirmation reader keeps v1's single-size expectation.
    "R5": ("apps/demo_app.c",
           "    if (recv_record(&sess, conn, buf, FRAME_CONFIRM_MIN, FRAME_CONFIRM_MAX, hs_deadline, &pt_len, &r) != DEMO_OK) {",
           "    if (recv_record(&sess, conn, buf, FRAME_CONFIRM_MIN, FRAME_CONFIRM_MIN, hs_deadline, &pt_len, &r) != DEMO_OK) { /* MUTATION R5 */"),

    # R6 -- the V2-6 regression itself: a confirmation buffer sized by content.
    "R6": ("tests/test_net.c",
           "#define CONFIRM_INNER SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX)",
           "#define CONFIRM_INNER 1u /* MUTATION R6: sized by the content, not the record */"),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
rel, old, new = M[MID]
p = REPO / rel
s = p.read_text()
n = s.count(old)
if n != 1:
    sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, rel, n))
p.write_text(s.replace(old, new, 1))
print("%s applied to %s" % (MID, rel))
