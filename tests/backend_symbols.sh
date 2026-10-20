#!/bin/bash
# One ML-DSA-65 / ML-KEM-768 backend is linked, and it is the intended one
# (V4-39, CLAIMS P10; spec-v2 Security Req 4.10, Performance Req 3).
#
#   bash backend_symbols.sh <repo> <build-dir> <cc> <sysroot-or-empty> <aarch64|x86_64|c>
#
# Until V4-39 tools/check_backend_symbols.sh ran in two places, CI's Linux
# Release job and bench.yml, both on x86_64, and nothing had ever shown it
# fail. The macOS jobs build liboqs with MLDSA_OQS_OPT_TARGET=generic, and
# ci.yml only ASSERTED that this still selects the aarch64 backends. This
# runs it in every native tree, in two parts:
#
#  1. The tool itself, on executables planted in a temporary directory --
#     never in this tree, which part 2 scans -- each defining functions
#     under the symbol prefixes the tool looks for. Every verdict it can
#     give is asked for once, and each check reads the exit status AND the
#     line that explains it, so a branch that stops failing is named.
#  2. This tree, against the family CMake expects for it (tests/CMakeLists.txt
#     says how that is chosen): every executable that links a backend must
#     link that family and no other.
set -u
REPO="${1:-}"; BUILD="${2:-}"; CC="${3:-}"; SYSROOT="${4:-}"; EXPECT="${5:-}"
TOOL="$REPO/tools/check_backend_symbols.sh"
[ -f "$TOOL" ] && [ -d "$BUILD" ] && [ -n "$CC" ] && [ -n "$EXPECT" ] ||
    { echo "FAIL: backend: usage: backend_symbols.sh <repo> <build-dir> <cc> <sysroot> <family>"; exit 2; }
fails=0
pass() { echo "PASS: backend: $1"; }
fail() { echo "FAIL: backend: $1"; fails=$((fails + 1)); }

T=$(mktemp -d "${TMPDIR:-/tmp}/backend-selftest.XXXXXX") || { echo "FAIL: backend: mktemp"; exit 2; }
trap 'rm -rf "$T"' EXIT

DSA=PQCP_MLDSA_NATIVE_MLDSA65_
KEM=PQCP_MLKEM_NATIVE_MLKEM768_
# plant <dir> <name> <family>...: an executable defining, for each family,
# one ML-DSA and one ML-KEM function under that family's prefix.
plant() {
    local dir=$1 name=$2 src calls=""; shift 2
    mkdir -p "$dir"; src="$T/$name.c"; : > "$src"
    for fam in "$@"; do
        echo "int ${DSA}${fam}_planted(int x) { return x + 1; }" >> "$src"
        echo "int ${KEM}${fam}_planted(int x) { return x + 2; }" >> "$src"
        calls="$calls + ${DSA}${fam}_planted(argc) + ${KEM}${fam}_planted(argc)"
    done
    echo "int main(int argc, char **argv) { (void)argv; return 0 $calls; }" >> "$src"
    "$CC" ${SYSROOT:+-isysroot "$SYSROOT"} -o "$dir/$name" "$src" > "$T/$name.cc.log" 2>&1 ||
        { fail "the planted executable $name compiles: $(head -1 "$T/$name.cc.log")"; return 1; }
}
# expect <what> <want-exit> <line> -- <tool args>: run the tool, need both.
expect() {
    local what=$1 want=$2 line=$3 out ex; shift 4
    out=$("$TOOL" "$@" 2>&1); ex=$?
    if [ "$ex" -eq "$want" ] && printf '%s\n' "$out" | grep -qF -- "$line"; then
        pass "$what"
    else
        fail "$what (exit $ex, wanted $want and a line containing '$line')"
        printf '%s\n' "$out" | sed 's/^/          /'
    fi
}

plant "$T/arm"   arm_only    AARCH64
plant "$T/mixed" arm_only    AARCH64
plant "$T/mixed" c_beside    C
plant "$T/x86"   x86_only    X86_64
plant "$T/two"   two_fams    AARCH64 X86_64
plant "$T/split" arm_only    AARCH64
plant "$T/split" x86_only    X86_64
plant "$T/none"  no_backend
plant "$T/c"     c_only      C
mkdir -p "$T/empty"

expect "an aarch64 executable passes when aarch64 is expected" 0 \
       "OK: exactly one backend (aarch64) is linked in all 1 executable(s)" -- --expect aarch64 "$T/arm"
expect "a portable-C executable beside it fails, named" 1 \
       "FAIL c_beside" -- --expect aarch64 "$T/mixed"
expect "x86_64 symbols fail when aarch64 is expected" 1 \
       "FAIL x86_only" -- --expect aarch64 "$T/x86"
expect "two families in one executable fail when one is expected" 1 \
       "FAIL two_fams" -- --expect aarch64 "$T/two"
expect "an executable with no backend at all proves nothing" 1 \
       "no executable linked an ML-DSA/ML-KEM backend" -- --expect aarch64 "$T/none"
expect "a directory with no executables proves nothing" 1 \
       "no executables found" -- --expect aarch64 "$T/empty"
expect "a portable-C executable passes when c is expected (x86_64 generic)" 0 \
       "OK: exactly one backend (c) is linked in all 1 executable(s)" -- --expect c "$T/c"
expect "without --expect, portable C fails" 1 \
       "FAIL c_only: 2 portable-C backend symbol(s) linked" -- "$T/c"
expect "without --expect, one optimised family passes" 0 \
       "OK: exactly one optimized backend (aarch64)" -- "$T/arm"
expect "without --expect, two optimised families in one executable fail, named" 1 \
       "FAIL two_fams: both optimized families are present" -- "$T/two"
expect "without --expect, two optimised families in two executables fail" 1 \
       "both optimized families are present, in different executables" -- "$T/split"

# Part 2: this tree.
out=$("$TOOL" --expect "$EXPECT" "$BUILD" 2>&1); ex=$?
n=$(printf '%s\n' "$out" | sed -n 's/^OK: exactly one backend ([a-z0-9_]*) is linked in all \([0-9]*\) executable(s).*/\1/p')
if [ "$ex" -eq 0 ] && [ -n "$n" ] && [ "$n" -gt 0 ]; then
    pass "this tree links one backend, $EXPECT, in all $n executable(s) that link one"
else
    fail "this tree links one backend, $EXPECT, in every executable that links one (exit $ex)"
    printf '%s\n' "$out" | sed 's/^/          /'
fi

[ "$fails" -eq 0 ] && { echo "PASS: backend: all checks"; exit 0; }
echo "FAIL: backend: $fails check(s) failed"; exit 1
