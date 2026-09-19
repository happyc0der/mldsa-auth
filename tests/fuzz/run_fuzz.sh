#!/bin/sh
# Coverage-guided libFuzzer runs for the Step 7 targets.
#
#   tests/fuzz/run_fuzz.sh smoke <build-fuzz-dir> [targets...]   60 s per target
#   tests/fuzz/run_fuzz.sh local <build-fuzz-dir> [targets...]   600 s per target (spec §8 Step 7 exit criterion)
#
# Targets run in parallel, one process each. Seeds are regenerated at runtime
# into <build>/fuzz-corpus/<t>/seeds; the evolving corpus lives in
# <build>/fuzz-corpus/<t>/work; crashes go to <build>/fuzz-artifacts/<t>/.
# All of it is inside the (git-ignored) build directory.
#
# If the libFuzzer binaries were not built (a build without -DMLDSA_FUZZ=ON,
# or a compiler without the libFuzzer runtime), this prints SKIP and exits 0.
# "No crash in N minutes" is NOT evidence of correctness -- see README.md.
set -u

MODE="${1:-}"
BUILD="${2:-}"
case "$MODE" in
    smoke) SECONDS_PER_TARGET=60 ;;
    local) SECONDS_PER_TARGET=600 ;;
    *) echo "usage: $0 smoke|local <build-fuzz-dir> [targets...]"; exit 2 ;;
esac
[ -n "$BUILD" ] || { echo "usage: $0 smoke|local <build-fuzz-dir> [targets...]"; exit 2; }
shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
# The default target list is SINGLE-SOURCED from CMakeLists.txt's FUZZ_TARGETS.
# It used to be hardcoded here, and when V4-6 added `envelope` to CMake this
# line was not updated -- so `run_fuzz.sh smoke` (which is exactly what CI
# runs, with no target arguments) silently exercised five targets and never the
# sixth. Deriving it means a target added to the build can never be skipped
# here again. If the parse ever yields nothing, that is a hard failure rather
# than a silent empty run.
default_targets() {
    sed -n 's/^[[:space:]]*set(FUZZ_TARGETS[[:space:]]\{1,\}\([^)]*\)).*/\1/p' "$HERE/CMakeLists.txt"
}
TARGETS="${*:-$(default_targets)}"
if [ -z "$(printf '%s' "$TARGETS" | tr -d '[:space:]')" ]; then
    echo "FAIL: could not determine the fuzz target list from $HERE/CMakeLists.txt"
    exit 2
fi
BUILD=$(cd "$BUILD" 2>/dev/null && pwd) || { echo "SKIP: build directory not found"; exit 0; }

# The per-target bound is SINGLE-SOURCED from CMakeLists.txt's FUZZ_MAXLEN_<t>,
# for exactly the reason the target list above is -- and this function is the
# proof that deriving one of two neighbouring lists is not enough.
#
# It used to be a hardcoded `case` covering only the original five targets. For
# envelope, authd_config, authd_conn, localapi and authmsg it therefore printed
# NOTHING, the command became `-max_len=`, and libFuzzer said so in every log:
#
#   INFO: -max_len is not provided; libFuzzer will not generate inputs larger
#         than 4096 bytes
#
# Five targets had been fuzzed to 4096 instead of 8192-16384 since V4-6, and
# `wire` was given 8192 here against FUZZ_MAXLEN_wire=4096 in CMake -- the two
# sources disagreeing in both directions at once. Nothing was unsound, because
# each harness re-enforces fuzz_target_max_len itself, but every "600 s, 0
# crashes" line from V4-6 onward described a narrower run than it claimed.
# Finding F49.
#
# A target with no bound is a HARD FAILURE, never an empty string: an empty
# -max_len is precisely the silent degradation this replaces.
maxlen() {
    sed -n "s/^[[:space:]]*set(FUZZ_MAXLEN_$1[[:space:]]\{1,\}\([0-9]\{1,\}\)).*/\1/p" \
        "$HERE/CMakeLists.txt"
}

# Every target must have one, checked BEFORE any run starts so a missing bound
# cannot be discovered halfway through a 50-minute sweep.
check_bounds() {
    missing=""
    for t in $1; do
        if [ -z "$(maxlen "$t")" ]; then
            missing="$missing $t"
        fi
    done
    if [ -n "$missing" ]; then
        echo "FAIL: no FUZZ_MAXLEN_<t> in $HERE/CMakeLists.txt for:$missing"
        echo "      (an empty -max_len silently caps libFuzzer at 4096 -- see F49)"
        return 1
    fi
    return 0
}
check_bounds "$TARGETS" || exit 2

for t in $TARGETS; do
    if [ ! -x "$BUILD/tests/fuzz/fuzz_$t" ]; then
        echo "SKIP: libFuzzer binary fuzz_$t not built in $BUILD (configure with a libFuzzer-capable clang and -DMLDSA_FUZZ=ON)"
        exit 0
    fi
done

export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
LOGS="$BUILD/fuzz-logs"
mkdir -p "$LOGS"

PIDS=""
for t in $TARGETS; do
    C="$BUILD/fuzz-corpus/$t"
    A="$BUILD/fuzz-artifacts/$t"
    mkdir -p "$C/work" "$A"
    "$BUILD/tests/fuzz/fuzz_${t}_replay" --write-seeds "$C/seeds" > /dev/null
    echo "fuzz_$t: $SECONDS_PER_TARGET s, max_len $(maxlen "$t"), log $LOGS/$t-$MODE.log"
    "$BUILD/tests/fuzz/fuzz_$t" "$C/work" "$C/seeds" \
        -dict="$HERE/dict/$t.dict" -max_len="$(maxlen "$t")" \
        -artifact_prefix="$A/" -timeout=10 -rss_limit_mb=2048 \
        -max_total_time="$SECONDS_PER_TARGET" -print_final_stats=1 \
        > "$LOGS/$t-$MODE.log" 2>&1 &
    PIDS="$PIDS $!"
done

STATUS=0
for p in $PIDS; do
    wait "$p" || STATUS=1
done

echo "---"
for t in $TARGETS; do
    L="$LOGS/$t-$MODE.log"
    runs=$(grep -E '^stat::number_of_executed_units' "$L" | awk '{print $2}')
    cov=$(grep -E '#[0-9]+.*(DONE|pulse|NEW|REDUCE).*cov:' "$L" | tail -1 | sed -E 's/.*cov: ([0-9]+).*/\1/')
    ft=$(grep -E '#[0-9]+.*(DONE|pulse|NEW|REDUCE).*ft:' "$L" | tail -1 | sed -E 's/.*ft: ([0-9]+).*/\1/')
    corp=$(grep -E '#[0-9]+.*(DONE|pulse|NEW|REDUCE).*corp:' "$L" | tail -1 | sed -E 's/.*corp: ([0-9]+\/[0-9A-Za-z]+).*/\1/')
    arts=$(find "$BUILD/fuzz-artifacts/$t" -type f | wc -l | tr -d ' ')
    crash=$(grep -cE 'ERROR: (libFuzzer|AddressSanitizer|UndefinedBehaviorSanitizer)|FUZZ ORACLE FAILURE|runtime error' "$L")
    echo "fuzz_$t: runs=${runs:-?} cov=${cov:-?} ft=${ft:-?} corpus=${corp:-?} crashes=$crash artifacts=$arts"
    [ "$crash" -eq 0 ] && [ "$arts" -eq 0 ] || STATUS=1
done
exit $STATUS
