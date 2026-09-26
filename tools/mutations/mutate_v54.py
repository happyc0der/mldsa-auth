#!/usr/bin/env python3
"""V4-13b mutations: the wasm export shim (apps/authd/client_wasm.c).

Usage: mutate_v54.py <repo> <ID>

THE FIRST TWO-LETTER CAMPAIGN. v53 took F, the last free single letter, so
from v54 an ID is a letter PAIR and a number: WA = "wasm shim". Pairs are
assigned per campaign and never reused, exactly as letters were; the runner
and check_mutation_anchors.py need no change, since an ID has only ever been
an opaque string. (tools/README.md records the scheme.)

Every mutation changes what a value is; none deletes a use (F79). Each is
aimed at one named check in test_client_wasm, which drives the shim natively
the way JavaScript drives it. The JavaScript transport and the module gates
are outside the runner's reach (it snapshots and rebuilds C); their controls
were run by hand in V4-13b and are recorded in its decisions entry.

  WA1  a login may begin before the caller has set the clock
  WA2  the clock may run backwards by up to a second
  WA3  a NaN time is accepted
  WA4  identities are sealed at the operator's 256 MiB, not the browser's 64
  WA5  ccw_init does not route liboqs to libsodium's generator
  WA6  a record refused for failing authentication leaves its code behind
  WA7  the ClientHello's reported length is one more than was written
  WA8  the pinned server key's id is checked against ITSELF, not the caller's
  WA9  a handle can be created before ccw_init
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
SH = "apps/authd/client_wasm.c"

M = {
 "WA1": (SH, [("    if (!h->clock_set) {\n        return CC_ERR_STATE;   /* the session's clock is the caller's: set it first */",
               "    if (!h->clock_set && h->now_ms != 0u) { /* MUTATION WA1 */\n        return CC_ERR_STATE;   /* the session's clock is the caller's: set it first */")]),
 "WA2": (SH, [("    if (h->clock_set && v < h->now_ms) {",
               "    if (h->clock_set && v + 1000u < h->now_ms) { /* MUTATION WA2 */")]),
 "WA3": (SH, [("    if (h == NULL || !isfinite(ms) || ms < 0.0 || ms > 9007199254740992.0) {",
               "    if (h == NULL || isinf(ms) || ms < 0.0 || ms > 9007199254740992.0) { /* MUTATION WA3 */")]),
 "WA4": (SH, [("                                                CC_KDF_OPS_BROWSER, CC_KDF_MEM_BROWSER,",
               "                                                CC_KDF_OPS_BROWSER, 4u * CC_KDF_MEM_BROWSER, /* MUTATION WA4 */")]),
 "WA5": (SH, [("    cc_use_sodium_rng_for_oqs();\n    g_ready = 1;",
               "    (void)&cc_use_sodium_rng_for_oqs; /* MUTATION WA5 */\n    g_ready = 1;")]),
 "WA6": (SH, [("    } else {\n        sodium_memzero(code_out, AUTHMSG_CODE_BYTES);",
               "    } else if (st != CC_ERR_SESSION) { /* MUTATION WA6 */\n        sodium_memzero(code_out, AUTHMSG_CODE_BYTES);")]),
 "WA7": (SH, [("    const cc_status_t st = cc_login_begin_sealed(&h->cc, hid, hid_len, ek, ek_len, pass, pass_len,\n                                                 keep_for_rotate ? CC_KEEP_FOR_ROTATE : 0u,\n                                                 out, out_cap, &n);\n    *out_len = (uint32_t)n;",
               "    const cc_status_t st = cc_login_begin_sealed(&h->cc, hid, hid_len, ek, ek_len, pass, pass_len,\n                                                 keep_for_rotate ? CC_KEEP_FOR_ROTATE : 0u,\n                                                 out, out_cap, &n);\n    *out_len = (uint32_t)n + (n != 0u); /* MUTATION WA7 */")]),
 "WA8": (SH, [("    cc_status_t st = cc_parse_server_pub(pub, pub_len, sid, sid_len, pk, &h->cc.diag);",
               "    cc_status_t st = cc_parse_server_pub(pub, pub_len, pub_len > 9u ? pub + 9 : sid, /* MUTATION WA8 */\n                                         pub_len > 9u ? pub[8] : sid_len, pk, &h->cc.diag);")]),
 "WA9": (SH, [("ccw_t *ccw_new(void)\n{\n    if (!g_ready) {",
               "ccw_t *ccw_new(void)\n{\n    if (g_ready < 0) { /* MUTATION WA9 */")]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
