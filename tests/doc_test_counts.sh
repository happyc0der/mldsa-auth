#!/bin/sh
# The test counts the documents state, checked against the tree that runs
# them (V4-41; audit F107, F116, F120).
#
#   sh doc_test_counts.sh <repo> <ctest> <build-dir> <node> <python3> <nm+file> <wasm> <browser> <fuzz>
#
# The last six are 0 or 1, as CMake configured this tree. The README states a
# count for each configuration, and REPRODUCE.md and the review packet repeat
# them. They drifted three times, each found by hand (F107, F116, F120), and
# V4-39 drifted them again. A count that depends on the configuration cannot
# be checked statically, so it is checked here, in the tree whose count it
# is: the README's number for THIS configuration must be the number of tests
# ctest registers. Every sentence must be found, so rewording one fails the
# test rather than retiring the check.
set -u
REPO="${1:-}"; CTEST="${2:-}"; BUILD="${3:-}"
NODE="${4:-}"; PY="${5:-}"; NMFILE="${6:-}"; WASM="${7:-}"; BROWSER="${8:-}"; FUZZ="${9:-}"
[ -f "$REPO/README.md" ] && [ -n "$CTEST" ] && [ -d "$BUILD" ] && [ -n "$FUZZ" ] ||
    { echo "FAIL: counts: usage: doc_test_counts.sh <repo> <ctest> <build> <node> <py> <nm+file> <wasm> <browser> <fuzz>"; exit 2; }
fails=0
pass() { echo "PASS: counts: $1"; }
fail() { echo "FAIL: counts: $1"; fails=$((fails + 1)); }

# README: "N tests in a native tree (M if no `node` is found: ...), W when it
# names a WebAssembly tree (...) and B when a Chromium-family browser is also
# found". The sentence is one line in the file.
line=$(grep -m1 ' tests in a native tree (' "$REPO/README.md")
N=$(printf '%s\n' "$line" | sed -nE 's/^([0-9]+) tests in a native tree \(.*/\1/p')
M=$(printf '%s\n' "$line" | sed -nE 's/^[0-9]+ tests in a native tree \(([0-9]+) if no `node` is found.*/\1/p')
W=$(printf '%s\n' "$line" | sed -nE 's/.*\), ([0-9]+) when it names a WebAssembly tree.*/\1/p')
B=$(printf '%s\n' "$line" | sed -nE 's/.* and ([0-9]+) when a Chromium-family browser is also found.*/\1/p')
if [ -n "$N" ] && [ -n "$M" ] && [ -n "$W" ] && [ -n "$B" ]; then
    pass "README states $N native, $M without node, $W with a wasm tree, $B with a browser"
else
    fail "README's count sentence was not found whole (native '$N', no-node '$M', wasm '$W', browser '$B')"
    echo "FAIL: counts: $fails check(s) failed"; exit 1
fi
printf '%s\n' "$line" | grep -qF 'one fewer without `python3`' ||
    fail "README no longer says python3 is worth one test"
printf '%s\n' "$line" | grep -qF 'one fewer without `nm` and `file`' ||
    fail "README no longer says nm and file are worth one test"

# This configuration's number, by the README's own rule.
if [ "$BROWSER" = 1 ]; then want=$B; why="with a browser"
elif [ "$WASM" = 1 ]; then want=$W; why="with a wasm tree"
elif [ "$NODE" = 1 ]; then want=$N; why="native"
else want=$M; why="native, without node"; fi
[ "$PY" = 1 ] || { want=$((want - 1)); why="$why, without python3"; }
[ "$NMFILE" = 1 ] || { want=$((want - 1)); why="$why, without nm and file"; }

count() { "$CTEST" --test-dir "$BUILD" -N "$@" 2>/dev/null | sed -n 's/^Total Tests: //p'; }
if [ "$FUZZ" = 1 ]; then
    # A fuzz tree registers its fuzz-labelled libFuzzer tests IN PLACE of the
    # skipped fuzz_libfuzzer placeholder every other tree has, so the
    # README's number is the unlabelled tests plus that placeholder.
    have=$(( $(count -LE fuzz) + 1 )); why="$why (fuzz tree: unlabelled + the fuzz_libfuzzer placeholder)"
    nf=$(count -L fuzz)
    rf=$(sed -nE 's/^cmake --build build-fuzz .*# 100% tests passed out of ([0-9]+).*/\1/p' "$REPO/docs/review/REPRODUCE.md")
    if [ -n "$rf" ] && [ "$nf" = "$rf" ]; then
        pass "the fuzz label holds $nf tests, as REPRODUCE.md says"
    else
        fail "the fuzz label holds $nf tests; REPRODUCE.md says '${rf}'"
    fi
else
    have=$(count)
fi
if [ -n "$have" ] && [ "$have" = "$want" ]; then
    pass "this tree registers $have tests, the README's count $why"
else
    fail "this tree registers ${have:-?} tests; the README's count $why is $want"
fi

# Every test this tree registers has a row in the README's table of tests:
# its name in the row's first cell, or a `prefix_*` there that covers it
# (F116 found five gates missing from the table; V4-41 found three more).
names=$(grep -E '^\| `' "$REPO/README.md" | cut -d'|' -f2 | grep -oE '`[A-Za-z0-9_*]+`' | tr -d '`')
missing=""
for t in $("$CTEST" --test-dir "$BUILD" -N 2>/dev/null | sed -n 's/^ *Test *#[0-9]*: //p'); do
    hit=0
    for nm in $names; do
        case "$nm" in
            *_\*) case "$t" in "${nm%\*}"*) hit=1 ;; esac ;;
            *) [ "$nm" = "$t" ] && hit=1 ;;
        esac
        [ "$hit" = 1 ] && break
    done
    [ "$hit" = 1 ] || missing="$missing $t"
done
[ -z "$missing" ] && pass "every registered test has a row in the README's table" ||
    fail "registered tests with no row in the README's table:$missing"

# The other documents repeat the README's numbers.
r=$(grep -m1 'tests passed out of [0-9]*` (' "$REPO/docs/review/REPRODUCE.md")
rn=$(printf '%s\n' "$r" | sed -nE 's/.*`100% tests passed out of ([0-9]+)` \(.*/\1/p')
rw=$(grep -A1 -F "$r" "$REPO/docs/review/REPRODUCE.md" | tr '\n' ' ' | sed -nE 's/.*\(([0-9]+) with[^0-9]*-DMLDSA_WASM_DIR.*/\1/p')
rb=$(grep -A2 -F "$r" "$REPO/docs/review/REPRODUCE.md" | tr '\n' ' ' | sed -nE 's/.*, ([0-9]+) with a Chromium-family browser.*/\1/p')
if [ "$rn" = "$N" ] && [ "$rw" = "$W" ] && [ "$rb" = "$B" ]; then
    pass "REPRODUCE.md states the same $N, $W and $B"
else
    fail "REPRODUCE.md states '$rn', '$rw', '$rb' where README states $N, $W, $B"
fi
rs=$(sed -nE 's/.*builds `ubsan_canary` -- and `100% tests passed out of ([0-9]+)`, or ([0-9]+) when.*/\1 \2/p' "$REPO/docs/review/REPRODUCE.md")
[ "$rs" = "$N $B" ] && pass "REPRODUCE.md's sanitizer trees state $N and $B" ||
    fail "REPRODUCE.md's sanitizer trees state '$rs' where README states $N and $B"
rg=$(sed -nE 's/^ctest --test-dir build-gcc16 .*# 100% tests passed out of ([0-9]+).*/\1/p' "$REPO/docs/review/REPRODUCE.md")
[ "$rg" = "$N" ] && pass "REPRODUCE.md's gcc 16 tree states $N" ||
    fail "REPRODUCE.md's gcc 16 tree states '$rg' where README states $N"
pk=$(sed -nE 's/.*The suite is ([0-9]+) tests with the$/\1/p' "$REPO/docs/review/README.md")
[ "$pk" = "$B" ] && pass "the review packet states $B with the browser client" ||
    fail "the review packet states '$pk' tests with the browser client where README states $B"

[ "$fails" -eq 0 ] && { echo "PASS: counts: all checks"; exit 0; }
echo "FAIL: counts: $fails check(s) failed"; exit 1
