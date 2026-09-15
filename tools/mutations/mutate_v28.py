#!/usr/bin/env python3
"""V2-8 mutations X1-X7. Usage: mutate_v28.py <repo> <ID>

One exact string replacement each, every edit carrying a /* MUTATION */
marker so the runner's residue grep can prove the tree was restored.
"""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1])
MID = sys.argv[2]
KEYS = "tests/fuzz/fuzz_keys.c"

M = {
    # X1 -- the exclusion is disabled: every window is kept, as before V2-8.
    "X1": (KEYS,
           "static int window_is_public(size_t o) {\n"
           "    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);\n"
           "}",
           "static int window_is_public(size_t o) {\n"
           "    (void)o; /* MUTATION X1: no window is treated as public */\n"
           "    return 0;\n"
           "}"),

    # X2 -- the layout rule never fires.
    "X2": (KEYS,
           "        if (looks_like_key_layout(b, n, o)) {",
           "        if (0 && looks_like_key_layout(b, n, o)) { /* MUTATION X2 */"),

    # X3 -- the window rule never fires (empty window table).
    "X3": (KEYS,
           "    FUZZ_ASSERT(w == SCAN_KEPT_WINDOWS, \"fewer kept windows than the layout arithmetic requires\");\n"
           "    s.nwin = w;",
           "    FUZZ_ASSERT(w == SCAN_KEPT_WINDOWS, \"fewer kept windows than the layout arithmetic requires\");\n"
           "    s.nwin = 0; /* MUTATION X3: the window rule never matches */"),

    # X4 -- rho exclusion off by one (one secret-touching window dropped).
    "X4": (KEYS,
           "    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);",
           "    return (o + SCAN_WINDOW <= SK_RHO_LEN + 1u) /* MUTATION X4 */ ||\n"
           "           (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);"),

    # X5 -- tr exclusion off by one.
    "X5": (KEYS,
           "    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);",
           "    return (o + SCAN_WINDOW <= SK_RHO_LEN) ||\n"
           "           (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN + 1u); /* MUTATION X5 */"),

    # X6 -- the derivability proof compares tr against the wrong offset.
    "X6": (KEYS,
           "    if (sodium_memcmp(tr, kp->secret_key + SK_TR_OFF, sizeof(tr)) != 0) {",
           "    if (sodium_memcmp(tr, kp->secret_key + SK_TR_OFF + 1u, sizeof(tr)) != 0) { /* MUTATION X6 */"),

    # X7 -- test-side: C3 expects the pre-V2-8 count, against correct code.
    "X7": (KEYS,
           "        ok &= control_check(id, what, control_scan(base, g_pubfile, pn), 0, 0, 0);",
           "        ok &= control_check(id, what, control_scan(base, g_pubfile, pn), 0, 17, 0); /* MUTATION X7 */"),
}


# --- follow-ups: keep the window arithmetic self-consistent so execution
# --- REACHES the controls, proving the controls themselves are load-bearing.

WIN_PUB = "static int window_is_public(size_t o) {\n    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);\n}"

M["X8"] = (KEYS, [
    (WIN_PUB,
     "static int window_is_public(size_t o) {\n    (void)o; /* MUTATION X8: no window is treated as public */\n    return 0;\n}"),
    ("    s.win = malloc(SCAN_KEPT_WINDOWS * sizeof(window_t));",
     "    s.win = malloc(SCAN_TOTAL_WINDOWS * sizeof(window_t)); /* MUTATION X8 */"),
    ("        FUZZ_ASSERT(w < SCAN_KEPT_WINDOWS, \"more kept windows than the layout arithmetic allows\");",
     "        FUZZ_ASSERT(w < SCAN_TOTAL_WINDOWS, \"more kept windows than the layout arithmetic allows\"); /* MUTATION X8 */"),
    ("    FUZZ_ASSERT(w == SCAN_KEPT_WINDOWS, \"fewer kept windows than the layout arithmetic requires\");",
     "    FUZZ_ASSERT(w == SCAN_TOTAL_WINDOWS, \"fewer kept windows than the layout arithmetic requires\"); /* MUTATION X8 */"),
])

# X9/X10: a boundary slips AND the arithmetic is "corrected" to match, so every
# count assertion and C1 still agree -- only the boundary controls can object.
M["X9"] = (KEYS, [
    ("    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);",
     "    return (o + SCAN_WINDOW <= SK_RHO_LEN + 1u) /* MUTATION X9 */ ||\n           (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);"),
    ("#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 1u) + (SK_TR_LEN - SCAN_WINDOW + 1u))         /* 17 + 49 */",
     "#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 2u) + (SK_TR_LEN - SCAN_WINDOW + 1u)) /* MUTATION X9 */"),
    ("_Static_assert(SCAN_PUBLIC_WINDOWS == 66u, \"17 windows inside rho, 49 inside tr\");",
     "_Static_assert(SCAN_PUBLIC_WINDOWS == 67u, \"MUTATION X9\");"),
    ("_Static_assert(SCAN_KEPT_WINDOWS == 3951u, \"every window holding at least one secret byte\");",
     "_Static_assert(SCAN_KEPT_WINDOWS == 3950u, \"MUTATION X9\");"),
])

M["X10"] = (KEYS, [
    ("    return (o + SCAN_WINDOW <= SK_RHO_LEN) || (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN);",
     "    return (o + SCAN_WINDOW <= SK_RHO_LEN) ||\n           (o >= SK_TR_OFF && o + SCAN_WINDOW <= SK_TR_OFF + SK_TR_LEN + 1u); /* MUTATION X10 */"),
    ("#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 1u) + (SK_TR_LEN - SCAN_WINDOW + 1u))         /* 17 + 49 */",
     "#define SCAN_PUBLIC_WINDOWS ((SK_RHO_LEN - SCAN_WINDOW + 1u) + (SK_TR_LEN - SCAN_WINDOW + 2u)) /* MUTATION X10 */"),
    ("_Static_assert(SCAN_PUBLIC_WINDOWS == 66u, \"17 windows inside rho, 49 inside tr\");",
     "_Static_assert(SCAN_PUBLIC_WINDOWS == 67u, \"MUTATION X10\");"),
    ("_Static_assert(SCAN_KEPT_WINDOWS == 3951u, \"every window holding at least one secret byte\");",
     "_Static_assert(SCAN_KEPT_WINDOWS == 3950u, \"MUTATION X10\");"),
])

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
entry = M[MID]
rel = entry[0]
edits = entry[1] if isinstance(entry[1], list) else [(entry[1], entry[2])]
p = REPO / rel
s = p.read_text()
for old, new in edits:
    n = s.count(old)
    if n != 1:
        sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, rel, n))
    s = s.replace(old, new, 1)
p.write_text(s)
print("%s applied to %s (%d edit(s))" % (MID, rel, len(edits)))
