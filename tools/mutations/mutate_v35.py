#!/usr/bin/env python3
"""V3-5 mutations U1-U3 (x86_64 backend reporting and the macOS core counts).

U2 and U3 are architecture-independent and listed in spec_v35.txt. U1 is
x86_64-only -- its branch does not compile on arm64 -- and is applied by hand
during the bench workflow's bring-up, where the agreement check kills it.

Usage: mutate_v35.py <repo> <ID>
"""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
BC = "bench/bench_common.c"

M = {
    # U1: the x86_64 branch reports the WRONG family. The binary still links
    # AVX2 code; only the line describing it lies -- which is precisely the
    # defect class an environment block exists to prevent.
    "U1": (BC, [(
        '#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)\n'
        '#if defined(OQS_DIST_BUILD)\n'
        '    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&\n'
        '        OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {\n'
        '        return "AVX2-optimized (x86_64)";\n'
        '    }\n'
        '    return "portable reference (C)";\n'
        '#else\n'
        '    return "AVX2-optimized (x86_64)";\n'
        '#endif',
        '#if defined(OQS_ENABLE_SIG_ml_dsa_65_x86_64)\n'
        '#if defined(OQS_DIST_BUILD)\n'
        '    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&\n'
        '        OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {\n'
        '        return "NEON-optimized (aarch64)"; /* MUTATION U1 */\n'
        '    }\n'
        '    return "portable reference (C)";\n'
        '#else\n'
        '    return "NEON-optimized (aarch64)"; /* MUTATION U1 */\n'
        '#endif')]),

    # U2: the absent-sysctl sentinel is printed raw again -- the exact defect
    # V3-3 observed on GitHub's macOS runner.
    "U2": (BC, [(
        '    if (v < 0) {\n'
        '        (void)snprintf(out, cap, "unknown (no %s)", name);\n'
        '    } else {\n'
        '        (void)snprintf(out, cap, "%ld", v);\n'
        '    }',
        '    (void)snprintf(out, cap, "%ld", v); /* MUTATION U2: sentinel printed raw */')]),

    # U3: the macOS cpu line is not printed at all (V3-2's V1, macOS side).
    "U3": (BC, [(
        '    bench_env_line("cpu", "%s (%s performance + %s efficiency cores)", cpu, p_cores, e_cores);',
        '    (void)cpu; (void)p_cores; (void)e_cores; /* MUTATION U3: cpu line dropped */')]),
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
