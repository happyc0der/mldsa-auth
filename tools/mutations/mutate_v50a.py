#!/usr/bin/env python3
"""V4-10a mutations for the WebSocket carrier.
Usage: mutate_v50a.py <repo> <ID>

Letter H (F, J, O and Z remain free).

Three things about this layer make its mutations unusual.

FIRST, the accept value cannot be checked by a round trip. Client and server
would compute the same wrong answer and agree, exactly as V4-9c's ROTATE digest
does. H1 and H2 are killed only by the RFC 6455 literal vector and the FIPS
180-1 SHA-1 vectors in test_authd_ws; a "WebSocket works end to end" test kills
neither, and authd_e2e -- which really does log in over WebSocket -- would stay
green through both.

SECOND, several properties are invisible unless the input is SPLIT. The daemon
reads whatever the kernel gives it, so a peer's upgrade request or frame may
arrive in any number of pieces. H7 and H8 restore defects that every
hand-written test missed for exactly this reason: their clients write the
request in one write(). fuzz_ws's chunking oracle is what kills them, and the
split-upgrade check in test_authd_ws is what names them.

THIRD, masking is not a security property but accepting an unmasked client
frame means accepting bytes no browser sends (RFC 6455 §5.1), so H4 is a
conformance defect with a real consequence: it is the difference between
speaking WebSocket and speaking something WebSocket-shaped.

NOT MUTATED, and the reason stated rather than implied:

  * "the server masks its own frames". ws_server_header never sets the MASK
    bit and there is no code path that could; adding masking is not a
    one-line defect but a new feature, and a mutation has to be a defect.

  * "SHA-1 is used somewhere else". Its scope is the control, and scope is not
    a runtime property -- `git grep sha1` is. The header says so and
    check_spec_constants.sh is where a scope check would belong, not here.

  * "a control reply overwrites a queued data reply". The collision needs a
    Ping to arrive in the same iteration as an unflushed reply, which the
    in-process harness cannot arrange deterministically -- it drives the loop
    by hand and drains between steps. Left out rather than campaigned against
    a check that could pass by timing; the `reply`/`out` separation is
    asserted structurally by test_authd_ws's Ping case instead.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
WS = "apps/authd/ws.c"
CI = "apps/authd/conn_io.c"
CN = "apps/authd/authd_conn.c"
SH = "apps/authd/sha1.c"

M = {
 # H1 -- the GUID is dropped from the accept computation. Client and server
 # would still agree if both did this; only the literal vector sees it.
 "H1": (WS, [("    memcpy(buf + WS_KEY_B64_LEN, WS_GUID, sizeof WS_GUID - 1u);\n    const size_t n = WS_KEY_B64_LEN + (sizeof WS_GUID - 1u);",
              "    const size_t n = WS_KEY_B64_LEN; /* MUTATION H1: the GUID is not appended */")]),

 # H2 -- SHA-1's round constants drift. Every FIPS vector dies; nothing else does.
 "H2": (SH, [("        else if (i < 40u) { f = bb ^ c ^ d;                      k = 0x6ed9eba1u; }",
          "        else if (i < 40u) { f = bb ^ c ^ d;                      k = 0x6ed9eba0u; } /* MUTATION H2 */")]),

 # H3 -- the version is not checked, so a version-8 client is "upgraded".
 "H3": (WS, [('            have_version = (vn == 2u && v[0] == \'1\' && v[1] == \'3\');',
              '            have_version = 1; /* MUTATION H3: any version accepted */')]),

 # H4 -- an UNMASKED client frame is accepted (RFC 6455 §5.1).
 "H4": (WS, [("                    const int masked = (b1 & 0x80u) != 0u;\n                    if (masked != (w->expect_mask != 0u)) { return WS_ERR_PROTOCOL; }",
              "                    const int masked = (b1 & 0x80u) != 0u; /* MUTATION H4: direction unchecked */")]),

 # H5 -- control payloads are fed to the protocol stream, so a Ping can inject
 # bytes into the frame reassembler.
 "H5": (WS, [("                if (w->is_control) {\n                    if (w->ctrl_len + chunk > WS_CTRL_MAX) {",
              "                if (0) { /* MUTATION H5: control payload reaches the data sink */\n                    if (w->ctrl_len + chunk > WS_CTRL_MAX) {")]),

 # H6 -- `state` is taken without its §7.1 bound, so a long URL value reaches
 # the login code binding.
 "H6": (WS, [("            if (vn > WS_STATE_MAX) {\n                return WS_ERR_PROTOCOL;     /* §7.1 bounds it at 64 */\n            }",
              "            if (vn > WS_STATE_MAX) { return WS_OK; } /* MUTATION H6: bound dropped */")]),

 # H7 -- the guard that stops a buffered HTTP request being read as a frame
 # header. Only a request SPLIT across reads exposes it.
 "H7": (CI, [("    if (c->mode == CONN_IO_MODE_WS && c->ws.stage == WS_STAGE_UPGRADE) {\n        return CONN_IO_OK;\n    }\n    if (c->frame_len != 0u",
              "    if (c->frame_len != 0u")]),

 # H8 -- the request cap is applied to the whole stream again, so an upgrade
 # pipelined with its first frame is refused.
 "H8": (CI, [("        if (c->in_len > WS_UPGRADE_MAX) {\n            c->failed = 1;\n            return CONN_IO_ERR_PROTOCOL;\n        }\n        return CONN_IO_OK;               /* still buffering the request */",
              "        return CONN_IO_OK;               /* still buffering the request */"),
             ("    if (req_len > WS_UPGRADE_MAX) {\n        c->failed = 1;\n        return CONN_IO_ERR_PROTOCOL;\n    }",
              "    if (c->in_len > WS_UPGRADE_MAX) { c->failed = 1; return CONN_IO_ERR_PROTOCOL; } /* MUTATION H8 */")]),

 # H9 -- the WebSocket listener binds the EMPTY state, so Req 5's login-CSRF
 # binding silently does nothing on the only transport a browser uses.
 "H9": (CN, [("    if (slot->io.mode == CONN_IO_MODE_WS) {\n        state = slot->io.ws.state;\n        state_len = slot->io.ws.state_len;\n    }",
              "    /* MUTATION H9: the WebSocket state is never bound */")]),

}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    n = s.count(old)
    if n != 1:
        sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, path, n))
    s = s.replace(old, new, 1)
f.write_text(s)
print("%s applied to %s" % (MID, path))
