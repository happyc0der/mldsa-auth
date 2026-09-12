#!/bin/sh
# Step 8 benchmark runner (spec §5, §8 Step 8).
#
#   bench/run_bench.sh <build-dir> [repetitions]      default: 3
#
# Runs every bench binary REPETITIONS times, keeping one human-readable log
# and one CSV per repetition under <build-dir>/bench-results/. Numbers from
# a single run are not trustworthy on a laptop: compare the repetitions, and
# report the median run plus the spread, as bench/results.md does.
#
# Use a RELEASE build. A Debug build leaves liboqs unoptimized and its
# numbers describe nothing anyone would ship; the environment block in every
# log records the build type, so a mislabelled result is self-evident.
#
# "Fast in a quiet loop" is not "fast in production": these are single-
# machine, single-process measurements with no contention.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 <build-dir> [repetitions]"; exit 2; }
BUILD="$1"
REPS="${2:-3}"
BUILD=$(cd "$BUILD" 2>/dev/null && pwd) || { echo "build directory not found: $1"; exit 2; }
OUT="$BUILD/bench-results"

for t in primitives handshake session; do
    [ -x "$BUILD/bench/bench_$t" ] || {
        echo "bench_$t not built in $BUILD (configure with -DCMAKE_BUILD_TYPE=Release)"
        exit 2
    }
done

mkdir -p "$OUT"
echo "running 3 suites x $REPS repetition(s) from $BUILD"
i=1
while [ "$i" -le "$REPS" ]; do
    : > "$OUT/run-$i.txt"
    : > "$OUT/run-$i.csv"
    for t in primitives handshake session; do
        "$BUILD/bench/bench_$t" >> "$OUT/run-$i.txt" 2>&1
        "$BUILD/bench/bench_$t" --csv >> "$OUT/run-$i.csv" 2>&1
    done
    echo "  repetition $i -> $OUT/run-$i.txt, $OUT/run-$i.csv"
    i=$((i + 1))
done

echo "done. Headline (in-process handshake median, per repetition):"
grep -h "in-process median" "$OUT"/run-*.txt || true
