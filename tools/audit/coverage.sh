#!/bin/bash
# V4-1 audit: measure line and branch coverage of src/ and apps/.
#
#   coverage.sh <build-cov-dir> [out-dir]
#
# This project has never measured coverage (V4-1 finding F5). Coverage is not
# a quality gate here -- the mutation campaigns are -- but an UNCOVERED branch
# is a branch no mutation could ever be killed in, so it maps the blind spots.
#
# The tree must be configured with -DMLDSA_COVERAGE=ON (V4-40), which
# instruments the project's own targets and nothing it depends on, and is
# deliberately SEPARATE from build/, build-asan/, build-ubsan/ and
# build-fuzz/: instrumented objects would poison the mutation runner's
# fingerprints and the currency checker's no-op-rebuild proof.
set -u
BUILD="${1:?usage: coverage.sh <build-cov-dir> [out-dir]}"
OUT="${2:-$BUILD/coverage}"
BUILD=$(cd "$BUILD" && pwd) || exit 2
grep -q '^MLDSA_COVERAGE:BOOL=ON$' "$BUILD/CMakeCache.txt" 2>/dev/null ||
  { echo "FAIL: $BUILD was not configured with -DMLDSA_COVERAGE=ON"; exit 2; }
REPO=$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$BUILD/CMakeCache.txt")
[ -d "$REPO/apps/authd" ] || { echo "FAIL: no source tree found for $BUILD"; exit 2; }
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

# Every project executable is a coverage target. _deps holds the
# dependencies and CMakeFiles holds CMake's own compiler probes, which until
# V4-40 were counted in the total.
objs=()
while IFS= read -r f; do
  case "$(file -b "$f" 2>/dev/null)" in (*executable*) objs+=(-object "$f") ;; esac
done < <(find "$BUILD" \( -path "$BUILD/_deps" -o -name CMakeFiles \) -prune -o -type f -perm -u+x -print 2>/dev/null | sort)
[ ${#objs[@]} -eq 0 ] && { echo "FAIL: no executables found"; exit 1; }
IGNORE='(_deps|/tests/|/bench/|CMakeFiles)'

echo "### llvm-cov report (project sources only)"
"$COV" report "${objs[@]}" -instr-profile="$OUT/all.profdata" \
  -ignore-filename-regex="$IGNORE" 2>/dev/null > "$OUT/report.txt"
tail -1 "$OUT/report.txt"

# The per-area totals and the least-covered functions, from the JSON export:
# the text report's columns cannot be parsed reliably under a path with
# spaces, and until V4-40 this list came out empty without saying so.
"$COV" export "${objs[@]}" -instr-profile="$OUT/all.profdata" \
  -ignore-filename-regex="$IGNORE" 2>/dev/null > "$OUT/export.json" || { echo "FAIL: llvm-cov export"; exit 1; }
python3 - "$OUT/export.json" "$REPO" "$OUT/functions.txt" <<'PY' || exit 1
import collections, json, sys
data, repo, out = json.load(open(sys.argv[1]))["data"][0], sys.argv[2].rstrip("/") + "/", sys.argv[3]
rel = lambda f: f[len(repo):] if f.startswith(repo) else f
def area(r):
    return "src/" if r.startswith("src/") else "apps/authd/" if r.startswith("apps/authd/") else \
           "apps/ (demo)" if r.startswith("apps/") else "other"
tot = collections.defaultdict(collections.Counter)
for f in data["files"]:
    for a in (area(rel(f["filename"])), "all"):
        for k in ("lines", "regions", "branches", "functions"):
            tot[a][k + "_n"] += f["summary"][k]["count"]
            tot[a][k + "_c"] += f["summary"][k]["covered"]
if tot["other"]["lines_n"]:
    sys.exit("FAIL: coverage outside src/ and apps/ was reported -- the filter is wrong")
print("### coverage by area (covered/total)")
for a in ("src/", "apps/authd/", "apps/ (demo)", "all"):
    t = tot[a]
    print("  %-13s" % a + "  ".join("%s %d/%d %.2f%%" % (k, t[k + "_c"], t[k + "_n"], 100.0 * t[k + "_c"] / t[k + "_n"])
                                    for k in ("lines", "regions", "branches", "functions") if t[k + "_n"]))
rows = []
for fn in data["functions"]:
    r = rel(fn["filenames"][0])
    if area(r) not in ("src/", "apps/authd/"):
        continue
    # Code regions only (kind 0), as llvm-cov's own region figures count:
    # expansion and gap records would count a one-line function many times.
    code = [g for g in fn["regions"] if g[7] == 0]
    n = len(code); hit = sum(1 for g in code if g[4] > 0)
    if n and hit / n < 0.8:
        rows.append((n - hit, hit, n, r, fn["name"].split(":")[-1], fn["count"]))
rows.sort(key=lambda x: (-x[0], x[3], x[4]))
with open(out, "w") as fh:
    for m, hit, n, r, name, calls in rows:
        fh.write("%4d missed of %4d regions  %-34s %-40s calls=%d\n" % (m, n, r, name, calls))
print("### src/ and apps/authd/ functions under 80%% region coverage: %d (most missed first)" % len(rows))
PY
head -25 "$OUT/functions.txt"
echo "(full: $OUT/report.txt, $OUT/functions.txt, $OUT/export.json)"
exit $rc
