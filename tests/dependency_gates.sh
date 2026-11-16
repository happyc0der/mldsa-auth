#!/bin/sh
# The two checks that decide which dependency bytes reach the linker, each
# shown able to fail (V4-229, audit F315 and F316).
#
#   sh dependency_gates.sh <repo> <cmake>
#
# 1. Where libsodium is built and installed: tests/check_sodium_dirs.cmake
#    asks cmake/SodiumDirs.cmake about hosts this one is not.
# 2. cmake/VerifyLiboqsCommit.cmake against a small repository made here:
#    it accepts the pinned commit with a clean tree, and refuses another
#    commit, a tracked file edited after checkout, and a file added to it.
#    The edited file is the case it used to accept.
set -u
REPO="${1:-}"
CMAKE="${2:-cmake}"
[ -f "$REPO/cmake/VerifyLiboqsCommit.cmake" ] && [ -f "$REPO/cmake/SodiumDirs.cmake" ] \
    || { echo "FAIL: DEPS: no cmake/ scripts under '$REPO'"; exit 2; }
command -v git >/dev/null 2>&1 || { echo "FAIL: DEPS: git is required (the build requires it too)"; exit 2; }
fail=0

out=$("$CMAKE" -DREPO="$REPO" -P "$REPO/tests/check_sodium_dirs.cmake" 2>&1)
rc=$?
printf '%s\n' "$out" | sed 's/^-- //' | grep -E '^(PASS|FAIL): ' || true
if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -q 'PASS: sodium-dirs: all checks'; then
    echo "FAIL: DEPS: the libsodium directory rule (exit $rc)"
    fail=1
fi

D=$(mktemp -d "${TMPDIR:-/tmp}/deps-gate.XXXXXX") || { echo "FAIL: DEPS: mktemp"; exit 2; }
trap 'rm -rf "$D"' EXIT INT TERM
g() { git -C "$D/src" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }
mkdir "$D/src" && g init -q . && printf 'int f(void) { return 1; }\n' > "$D/src/a.c" && g add a.c && g commit -q -m one \
    || { echo "FAIL: DEPS: could not make the stand-in repository"; exit 2; }
SHA=$(g rev-parse HEAD)
verify() { "$CMAKE" -DSOURCE_DIR="$D/src" -DEXPECTED_SHA="$1" -P "$REPO/cmake/VerifyLiboqsCommit.cmake" > "$D/out" 2>&1; }

if verify "$SHA" && grep -q "liboqs commit verified: $SHA" "$D/out"; then
    echo "PASS: DEPS: the pinned commit with a clean tree is accepted (the control)"
else
    echo "FAIL: DEPS: the pinned commit with a clean tree was refused: $(head -c 300 "$D/out")"; fail=1
fi
if verify "0000000000000000000000000000000000000000"; then
    echo "FAIL: DEPS: a tree at another commit was accepted"; fail=1
elif grep -q 'commit pin MISMATCH' "$D/out"; then
    echo "PASS: DEPS: a tree at another commit is refused, named a mismatch"
else
    echo "FAIL: DEPS: another commit was refused for some other reason: $(head -c 300 "$D/out")"; fail=1
fi
printf 'int f(void) { return 2; }\n' > "$D/src/a.c"
if verify "$SHA"; then
    echo "FAIL: DEPS: a tracked file edited after checkout was accepted (F316)"; fail=1
elif grep -q 'source tree MODIFIED' "$D/out" && grep -q 'a\.c' "$D/out"; then
    echo "PASS: DEPS: a tracked file edited after checkout is refused, and named (F316)"
else
    echo "FAIL: DEPS: the edited tree was refused for some other reason: $(head -c 300 "$D/out")"; fail=1
fi
g checkout -q -- a.c
printf 'int g(void) { return 3; }\n' > "$D/src/b.c"
if verify "$SHA"; then
    echo "FAIL: DEPS: a file added to the tree was accepted (F316)"; fail=1
elif grep -q 'source tree MODIFIED' "$D/out" && grep -q 'b\.c' "$D/out"; then
    echo "PASS: DEPS: a file added to the tree is refused, and named (F316)"
else
    echo "FAIL: DEPS: the added file was refused for some other reason: $(head -c 300 "$D/out")"; fail=1
fi
rm -f "$D/src/b.c"
if verify "$SHA"; then
    echo "PASS: DEPS: put back as it was, the tree is accepted again"
else
    echo "FAIL: DEPS: the restored tree was refused: $(head -c 300 "$D/out")"; fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: DEPS: all checks"
exit "$fail"
