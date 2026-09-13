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
TARGETS="${*:-wire handshake session frame keys}"
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "$BUILD" 2>/dev/null && pwd) || { echo "SKIP: build directory not found"; exit 0; }

maxlen() {
    case "$1" in
        wire) echo 8192 ;; handshake) echo 16384 ;; session) echo 140000 ;; frame) echo 140000 ;; keys) echo 8192 ;;
    esac
}

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
