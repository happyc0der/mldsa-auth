#!/bin/sh
# The liboqs this project links contains ML-DSA and ML-KEM and nothing else
# that an advisory could land in (V4-14d, audit finding F91).
#
#   sh liboqs_minimal.sh <path to liboqs.a>
#
# liboqs 0.16.0 is in range of GHSA-wh5q-mpc8-67wf, an out-of-bounds read in
# LMS/HSS verification, and was in range of two XMSS advisories before it.
# This build is not exposed because OQS_MINIMAL_BUILD compiles neither -- but
# until now that was a claim resting on a CMake variable, which one edit could
# widen without any test noticing. This reads the ARCHIVE: no stateful-
# signature ALGORITHM (LMS, HSS, LM-OTS, XMSS, XMSS^MT) may be in it. liboqs'
# generic dispatcher (sig_stfl.c: OQS_SIG_STFL_new, _verify, the secret-key
# object) is compiled into every build and is allowed -- with no algorithm
# enabled it has nothing to dispatch to, and the advisories are in the
# algorithms, not in it.
#
# The present canary: ML-DSA and ML-KEM symbols MUST be found, so a wrong
# path, an empty archive or an nm that printed nothing fails rather than
# passing as "nothing forbidden found".
set -u
LIB="${1:-}"
fail() { echo "FAIL: $1"; exit 1; }
[ -f "$LIB" ] || fail "liboqs archive not found: $LIB"

SYMS=$(nm "$LIB" 2>/dev/null | awk 'NF >= 2 { print $NF }') || fail "nm could not read $LIB"
count() { printf '%s\n' "$SYMS" | grep -ciE "$1" || true; }

MLDSA=$(count 'ml_dsa')
MLKEM=$(count 'ml_kem')
[ "$MLDSA" -gt 0 ] || fail "no ML-DSA symbol in $LIB (the canary): wrong archive, or nm printed nothing"
[ "$MLKEM" -gt 0 ] || fail "no ML-KEM symbol in $LIB (the canary)"
echo "PASS: liboqs: the archive holds ML-DSA ($MLDSA symbols) and ML-KEM ($MLKEM) -- the canary"

STATEFUL=$(printf '%s\n' "$SYMS" | grep -iE '(^|_)(lms|hss|xmss|xmssmt|lm_ots|lmots)(_|$)' || true)
if [ -n "$STATEFUL" ]; then
    printf '%s\n' "$STATEFUL" | head -5
    fail "liboqs contains stateful-signature code (LMS/HSS/XMSS): the build is no longer minimal (F91)"
fi
echo "PASS: liboqs: no LMS, HSS, LM-OTS or XMSS symbol -- not exposed to GHSA-wh5q-mpc8-67wf or the XMSS advisories"
echo "All checks passed"
