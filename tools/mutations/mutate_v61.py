#!/usr/bin/env python3
"""V4-16 mutations: the secret scanner counts only wholly secret windows (F105).

Usage: mutate_v61.py <repo> <ID>

Two-letter IDs: SW = V4-16's secret windows. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90). All four are in tests/fuzz/fuzz_keys.c's --scan-secret gate.

V4-16 moved the scanner from V2-8's rule (keep every window holding a secret
byte, 3951) to the wholly-secret one (3906), which has a boundary V2-8's did
not: where K meets tr. v28 was re-anchored onto the new rule and covers the
other two; these cover the new boundary, the new control C8, and the old rule.

    SW1   the K|tr boundary off by one (window 49 kept), arithmetic unchanged:
          the in-loop count bound
    SW2   the K|tr boundary slips (window 48 dropped) AND the arithmetic is
          corrected to match, so only the boundary control can object: C5.5
    SW3   V2-8's rule restored, with its own arithmetic (66 / 3951): every
          count agrees, so only the straddling-window controls and C8 -- F105's
          case -- can object. This is the step's proof that the old rule is
          now caught by name.
    SW4   test-side: C8 expects the one window hit V2-8's rule produced
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
KEYS = "tests/fuzz/fuzz_keys.c"

RULE = "    return (o < SK_K_OFF) || (o + SCAN_WINDOW > SK_TR_OFF && o < SK_S1_OFF);"
PUB = "#define SCAN_PUBLIC_WINDOWS (SK_RHO_LEN + (SK_TR_LEN + SCAN_WINDOW - 1u))                              /* 32 + 79 */"
PUB_ASSERT = "_Static_assert(SCAN_PUBLIC_WINDOWS == 111u, \"32 windows touch rho, 79 touch tr\");"
KEPT_ASSERT = "_Static_assert(SCAN_KEPT_WINDOWS == 3906u, \"17 windows inside K, 3889 in s1|s2|t0\");"

M = {
 "SW1": (KEYS, [(RULE,
                 "    return (o < SK_K_OFF) ||\n"
                 "           (o + SCAN_WINDOW > SK_TR_OFF + 1u && o < SK_S1_OFF); /* MUTATION SW1 */")]),
 "SW2": (KEYS, [(RULE,
                 "    return (o < SK_K_OFF) ||\n"
                 "           (o + SCAN_WINDOW >= SK_TR_OFF && o < SK_S1_OFF); /* MUTATION SW2 */"),
                (PUB, "#define SCAN_PUBLIC_WINDOWS (SK_RHO_LEN + (SK_TR_LEN + SCAN_WINDOW)) /* MUTATION SW2 */"),
                (PUB_ASSERT, "_Static_assert(SCAN_PUBLIC_WINDOWS == 112u, \"MUTATION SW2\");"),
                (KEPT_ASSERT, "_Static_assert(SCAN_KEPT_WINDOWS == 3905u, \"MUTATION SW2\");")]),
 "SW3": (KEYS, [(RULE,
                 "    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);"
                 " /* MUTATION SW3: V2-8's rule */"),
                (PUB, "#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 1u) + (SK_TR_LEN - SCAN_WINDOW + 1u)) /* MUTATION SW3 */"),
                (PUB_ASSERT, "_Static_assert(SCAN_PUBLIC_WINDOWS == 66u, \"MUTATION SW3\");"),
                (KEPT_ASSERT, "_Static_assert(SCAN_KEPT_WINDOWS == 3951u, \"MUTATION SW3\");")]),
 "SW4": (KEYS, [("        ok &= control_check(\"C8\", \"a public-key file with the fixture's K[0] after rho (F105) is clean\",\n"
                 "                            control_scan(base, g_pubfile, pn), 0, 0, 0);",
                 "        ok &= control_check(\"C8\", \"a public-key file with the fixture's K[0] after rho (F105) is clean\",\n"
                 "                            control_scan(base, g_pubfile, pn), 0, 1, 0); /* MUTATION SW4 */")]),
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
