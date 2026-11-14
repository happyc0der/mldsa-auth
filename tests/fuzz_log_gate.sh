#!/bin/sh
#
# V4-172 (F245): the fuzz-log gate can fail, and the nightly's fuzz matrix is
# the target list.
#
#   fuzz_log_gate.sh <repo>
#
# tests/fuzz/check_fuzz_log.sh is what CI's two fuzz steps now end with. Here
# it is fed logs as run_fuzz.sh writes them: one that must pass, and one for
# each way a run can fail to have fuzzed, every one of which the old gate (a
# grep for a crash, on a pipe that dropped the exit status) let through.
#
# The second half is drift: nightly.yml lists its fuzz targets by hand, one
# job each. A target in CMakeLists's FUZZ_TARGETS and not in that list would
# never get its 600 seconds, with nothing red.
set -u
REPO="${1:?usage: fuzz_log_gate.sh <repo>}"
GATE="$REPO/tests/fuzz/check_fuzz_log.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/fuzz-gate.XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM
fail=0
ok()   { echo "PASS: FUZZ-GATE: $1"; }
bad()  { echo "FAIL: FUZZ-GATE: $1"; fail=1; }

good() { printf 'fuzz_wire: 60 s, max_len 4096, log x\nfuzz_ws: 60 s, max_len 4096, log y\n---\nfuzz_wire: runs=120034 cov=311 ft=900 corpus=40/2Kb crashes=0 artifacts=0\nfuzz_ws: runs=98211 cov=205 ft=610 corpus=31/1Kb crashes=0 artifacts=0\n'; }

good > "$TMP/good.log"
if /bin/sh "$GATE" "$TMP/good.log" wire ws > "$TMP/out" 2>&1; then ok "a log with one clean summary line per target passes (the canary)"
else cat "$TMP/out"; bad "a clean log was refused (the canary)"; fi

refused() {   # refused <file> <what>
    if /bin/sh "$GATE" "$1" wire ws > "$TMP/out" 2>&1; then
        cat "$1"; bad "$2 PASSED the gate (F245)"
    else
        ok "$2 fails the gate (F245)"
    fi
}
printf 'FAIL: no FUZZ_MAXLEN_<t> in tests/fuzz/CMakeLists.txt for: ws\n' > "$TMP/nostart.log"
refused "$TMP/nostart.log" "a run that refused to start, with no summary line at all,"
good | sed 's/^fuzz_ws: runs=98211 /fuzz_ws: runs=? /' > "$TMP/died.log"
refused "$TMP/died.log" "a target whose fuzzer died before it reported a run count (runs=?)"
good | grep -v '^fuzz_ws: runs=' > "$TMP/missing.log"
refused "$TMP/missing.log" "a log with no summary line for one of the targets"
{ echo "SKIP: libFuzzer binary fuzz_wire not built in build-fuzz"; } > "$TMP/skip.log"
refused "$TMP/skip.log" "a run that SKIPped because the binaries were not built"
{ good; echo "SKIP: libFuzzer binary fuzz_ws not built in build-fuzz"; } > "$TMP/skipline.log"
refused "$TMP/skipline.log" "a log that is clean except for a SKIP: line"
{ echo "FAIL: no FUZZ_MAXLEN_<t> in tests/fuzz/CMakeLists.txt for: ws"; good; } > "$TMP/failline.log"
refused "$TMP/failline.log" "a log that is clean except for a FAIL: line"
good | sed 's/^fuzz_wire: runs=120034 /fuzz_wire: runs=0 /' > "$TMP/zero.log"
refused "$TMP/zero.log" "a target that executed zero inputs"
good | sed 's/crashes=0 artifacts=0$/crashes=1 artifacts=0/' > "$TMP/crash.log"
refused "$TMP/crash.log" "a log that reports a crash"
good | sed 's/crashes=0 artifacts=0$/crashes=0 artifacts=2/' > "$TMP/art.log"
refused "$TMP/art.log" "a log that reports an artifact"
if /bin/sh "$GATE" "$TMP/does-not-exist.log" wire > /dev/null 2>&1; then bad "a missing log PASSED the gate (F245)"
else ok "a missing log fails the gate (F245)"; fi

# ---- the nightly's fuzz matrix is FUZZ_TARGETS, both ways -----------------
want=$(sed -n 's/^[[:space:]]*set(FUZZ_TARGETS[[:space:]]\{1,\}\([^)]*\)).*/\1/p' "$REPO/tests/fuzz/CMakeLists.txt" | tr ' ' '\n' | sed '/^$/d' | sort)
have=$(awk '/^[[:space:]]*target: \[/{f=1} f{print} f&&/\]/{exit}' "$REPO/.github/workflows/nightly.yml" \
       | tr -d '\n' | sed -e 's/.*\[//' -e 's/\].*//' | tr ',' '\n' | tr -d ' ' | sed '/^$/d' | sort)
nw=$(printf '%s\n' "$want" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$nw" -lt 1 ]; then bad "FUZZ_TARGETS could not be read from tests/fuzz/CMakeLists.txt, so nothing was compared"
elif [ "$want" = "$have" ]; then ok "nightly.yml's fuzz matrix is exactly FUZZ_TARGETS ($nw targets)"
else
    echo "FUZZ_TARGETS: $(echo $want)"; echo "nightly matrix: $(echo $have)"
    bad "nightly.yml's fuzz matrix is not FUZZ_TARGETS: a target would never get its long run, or a job would fuzz nothing (F245)"
fi

# ---- ...and both workflows end their fuzz step with this gate, on a pipe
# ---- whose status they keep. A count of zero means the gate is not wired.
for wf in ci.yml nightly.yml; do
    f="$REPO/.github/workflows/$wf"
    g=$(grep -c 'tests/fuzz/check_fuzz_log.sh' "$f")
    p=$(grep -B3 'tests/fuzz/check_fuzz_log.sh' "$f" | grep -c 'set -o pipefail')
    r=$(grep -c 'run_fuzz.sh' "$f")
    if [ "$g" -ge 1 ] && [ "$p" -ge 1 ] && [ "$r" -ge 1 ]; then ok "$wf runs run_fuzz.sh under pipefail and ends with the gate"
    else bad "$wf does not run the fuzz gate under pipefail (gate lines $g, pipefail $p, run_fuzz lines $r) (F245)"; fi
done

[ "$fail" -eq 0 ] && echo "PASS: FUZZ-GATE: all" || { echo "FAIL: FUZZ-GATE"; exit 1; }
