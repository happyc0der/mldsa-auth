#!/bin/bash
# V4-1 audit: measure line and branch coverage of src/ and apps/.
#
#   coverage.sh <build-cov-dir> [out-dir]
#
# This project has never measured coverage (V4-1 finding F5). Coverage is not
# a quality gate here -- the mutation campaigns are -- but an UNCOVERED branch
# is a branch no mutation could ever be killed in, so it maps the blind spots.
#
# The tree must be configured with -fprofile-instr-generate -fcoverage-mapping
# and is deliberately SEPARATE from build/, build-asan/, build-ubsan/ and
# build-fuzz/: instrumented objects would poison the mutation runner's
# fingerprints and the currency checker's no-op-rebuild proof.
set -u
BUILD="${1:?usage: coverage.sh <build-cov-dir> [out-dir]}"
OUT="${2:-$BUILD/coverage}"
BUILD=$(cd "$BUILD" && pwd) || exit 2
mkdir -p "$OUT/raw"
rm -f "$OUT"/raw/*.profraw 2>/dev/null || true

PROFDATA=$(xcrun -f llvm-profdata 2>/dev/null || command -v llvm-profdata) || { echo "FAIL: llvm-profdata not found"; exit 2; }
COV=$(xcrun -f llvm-cov 2>/dev/null || command -v llvm-cov) || { echo "FAIL: llvm-cov not found"; exit 2; }

# Every ctest test, each writing its own profile. ctest runs the fuzz replay
# drivers too (--ci replays every seed and committed regression), so the fuzz
# corpora contribute without a separate pass.
echo "### running the suite under instrumentation"
LLVM_PROFILE_FILE="$OUT/raw/%p-%m.profraw" ctest --test-dir "$BUILD" > "$OUT/ctest.log" 2>&1
rc=$?
grep -E "tests passed|tests failed" "$OUT/ctest.log" | tail -1

n=$(ls "$OUT/raw"/*.profraw 2>/dev/null | wc -l | tr -d ' ')
echo "profraw files: $n"
[ "$n" -eq 0 ] && { echo "FAIL: no profiles written -- the tree is not instrumented (vacuous-pass guard)"; exit 1; }

"$PROFDATA" merge -sparse "$OUT/raw"/*.profraw -o "$OUT/all.profdata" || exit 1

# Every project executable is a coverage target; liboqs/libsodium are excluded
# by only reporting on src/ and apps/ sources.
objs=()
while IFS= read -r f; do
  case "$(file -b "$f" 2>/dev/null)" in (*executable*) objs+=(-object "$f") ;; esac
done < <(find "$BUILD" -path "$BUILD/_deps" -prune -o -type f -perm -u+x -print 2>/dev/null | sort)
[ ${#objs[@]} -eq 0 ] && { echo "FAIL: no executables found"; exit 1; }

echo "### llvm-cov report (project sources only)"
"$COV" report "${objs[@]}" -instr-profile="$OUT/all.profdata" \
  -ignore-filename-regex='(_deps|/tests/|/bench/)' 2>/dev/null | tee "$OUT/report.txt" | tail -20

echo "### uncovered regions by function (top 25)"
"$COV" report "${objs[@]}" -instr-profile="$OUT/all.profdata" -show-functions \
  -ignore-filename-regex='(_deps|/tests/|/bench/)' src apps 2>/dev/null \
  | awk 'NR>2 && $NF ~ /%/ {print}' | sort -k7 -n | head -25 > "$OUT/functions.txt"
head -25 "$OUT/functions.txt"
echo "(full: $OUT/report.txt, $OUT/functions.txt)"
exit $rc
