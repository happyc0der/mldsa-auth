#!/usr/bin/env python3
"""V4-13c mutations: the passphrase policy (apps/authd/passphrase.{c,h}) and
the shim's enforcement of it.

Usage: mutate_v55.py <repo> <ID>

Two-letter IDs (v54 onward): PP = passphrase policy. Every mutation changes a
value; none deletes a use (F79). Each is aimed at one rule of the policy and
the one check in test_passphrase (or test_client_wasm, for PP11) that isolates
that rule -- the test chooses its passphrases so that only the rule under test
can decide them.

  PP1   the minimum is 11 characters, not 12
  PP2   the minimum counts BYTES, so 11 non-ASCII characters pass
  PP3   the core is never stripped, so "password1234" is not recognised
  PP4   case is not folded, so "!!Password1234!!" hides its word
  PP5   HIGH surrogates are accepted as UTF-8
  PP6   overlong two-byte forms are accepted as UTF-8
  PP7   a repeated character counts as a fresh one
  PP8   keyboard walks are not recognised
  PP9   a repeated unit is not discounted
  PP10  the floor is 39 bits, not 50
  PP11  the shim seals under a passphrase the policy refuses
  PP12  the list lookup searches the wrong half

TWO DEFECTS IN THE FIRST RUN (10 killed by name, 1 KILLED(compile), 1
SURVIVED), both this campaign's or its test's, not the policy's:
  * PP5 first read `c >= 0xD800u && c <= 0xD7FFu` -- an EMPTY range, which
    clang refuses (-Wtautological-overlap-compare): a compile kill that
    tested nothing, the F79 shape this campaign was written to avoid. It
    now lets the HIGH surrogates through, which compiles and which the
    test's U+D800 exposes.
  * PP7 (no repeat discount) SURVIVED "zzzzzzzzzzzz", because that string is
    also one repeated unit and a second rule refuses it -- a case that
    cannot isolate the rule it is named for (v53 F4's shape). The test
    gained "ggggmmmmssssxxxx", which only the repeat discount decides.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
PC = "apps/authd/passphrase.c"
PH = "apps/authd/passphrase.h"
SH = "apps/authd/client_wasm.c"

M = {
 "PP1":  (PH, [("#define PP_MIN_CODE_POINTS 12u", "#define PP_MIN_CODE_POINTS 11u /* MUTATION PP1 */")]),
 "PP2":  (PC, [("    if ((size_t)n < PP_MIN_CODE_POINTS) {", "    if (len < PP_MIN_CODE_POINTS && n >= 0) { /* MUTATION PP2 */")]),
 "PP3":  (PC, [("        if (b - a >= 4u && !(a == 0 && b == n)) {", "        if (b - a >= 64u && !(a == 0 && b == n)) { /* MUTATION PP3 */")]),
 "PP4":  (PC, [("        w[i] = (char)fold(cp[i]);", "        w[i] = (char)cp[i]; /* MUTATION PP4 */")]),
 "PP5":  (PC, [("(c < 0x800u || (c >= 0xD800u && c <= 0xDFFFu))", "(c < 0x800u || (c >= 0xDC00u && c <= 0xDFFFu)) /* MUTATION PP5: high surrogates pass */")]),
 "PP6":  (PC, [("        else if (b >= 0xC2u && b <= 0xDFu) { c = b & 0x1Fu; need = 1; }",
                "        else if (b >= 0xC0u && b <= 0xDFu) { c = b & 0x1Fu; need = 1; } /* MUTATION PP6 */")]),
 "PP7":  (PC, [("            total += PREDICTED_MILLIBITS;\n            *reasons |= PP_R_REPEATS;",
                "            total += per; /* MUTATION PP7 */\n            *reasons |= PP_R_REPEATS;")]),
 "PP8":  (PC, [("        } else if (i >= 2 && keyboard_walk(cp[i - 2], cp[i - 1], cp[i])) {",
                "        } else if (i >= 2 && keyboard_walk(cp[i - 2], cp[i - 1], cp[i]) && i > n) { /* MUTATION PP8 */")]),
 "PP9":  (PC, [("            if (unit < millibits) {", "            if (unit < millibits / 4u) { /* MUTATION PP9 */")]),
 "PP10": (PH, [("#define PP_MIN_BITS        50u", "#define PP_MIN_BITS        39u /* MUTATION PP10 */")]),
 "PP11": (SH, [("    if (pp_check((const uint8_t *)pass, pass_len, NULL) != PP_OK) {",
                "    if (pp_check((const uint8_t *)pass, pass_len, NULL) != PP_OK && pass_len == 0u) { /* MUTATION PP11 */")]),
 "PP12": (PC, [("        if (r < 0) { hi = mid; } else { lo = mid + 1u; }", "        if (r > 0) { hi = mid; } else { lo = mid + 1u; } /* MUTATION PP12 */")]),
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
