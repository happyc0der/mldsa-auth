#!/bin/sh
# Three gates that said more than they checked, each now shown able to fail
# on the thing it names (V4-230, audit F319 to F321).
#
#   sh gate_claims.sh <repo> <build dir>
#
#   UNIT    tests/unit_directives.sh: the systemd unit against spec 16 by
#           value. It compared directive names only.
#   TARGET  tools/audit/check_hardening.sh --require: the CPU target spec 16
#           says it gates. It did not look at one.
#   HOOK    tools/check_store_fault_hook.sh: an artefact nm cannot read. Its
#           comment said that was a failure; it counted as "absent".
set -u
REPO="${1:-}"
BUILD="${2:-}"
[ -f "$REPO/deploy/mldsa-authd.service" ] || { echo "FAIL: GATES: no repo at '$REPO'"; exit 2; }
DAEMON="$BUILD/apps/authd/mldsa-authd"
LIB="$BUILD/apps/authd/libmldsa_authd.a"
STORE_TEST="$BUILD/tests/test_authd_store"
for f in "$DAEMON" "$LIB" "$STORE_TEST"; do
    [ -f "$f" ] || { echo "FAIL: GATES: $f is not built"; exit 2; }
done
D=$(mktemp -d "${TMPDIR:-/tmp}/gate-claims.XXXXXX") || { echo "FAIL: GATES: mktemp"; exit 2; }
trap 'rm -rf "$D"' EXIT INT TERM
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

# --- UNIT -------------------------------------------------------------------
U="$REPO/deploy/mldsa-authd.service"
if sh "$REPO/tests/unit_directives.sh" "$U" > "$D/u.out" 2>&1; then
    ok "UNIT: the shipped unit is as spec 16 requires (the control)"
else
    bad "UNIT: the shipped unit is refused: $(cat "$D/u.out")"
fi
unit_case() {   # $1 = what was done, $2 = text the refusal must contain, stdin = the weakened unit
    cat > "$D/weak.service"
    if cmp -s "$D/weak.service" "$U"; then bad "UNIT: the edit for '$1' changed nothing"; return; fi
    if sh "$REPO/tests/unit_directives.sh" "$D/weak.service" > "$D/u.out" 2>&1; then
        bad "UNIT: $1 -- accepted"
    elif grep -q "$2" "$D/u.out"; then
        ok "UNIT: $1 -- refused, naming it ($(sed 's/^FAIL: UNIT: //' "$D/u.out"))"
    else
        bad "UNIT: $1 -- refused, but not for that: $(cat "$D/u.out")"
    fi
}
sed 's/^NoNewPrivileges=yes$/NoNewPrivileges=no/' "$U" | unit_case "NoNewPrivileges=no" "NoNewPrivileges=no"
sed 's/^ProtectSystem=strict$/ProtectSystem=full/' "$U" | unit_case "ProtectSystem=full" "ProtectSystem=full"
sed 's/^CapabilityBoundingSet=$/CapabilityBoundingSet=CAP_NET_ADMIN/' "$U" | unit_case "a capability left in the bounding set" "CapabilityBoundingSet=CAP_NET_ADMIN"
grep -v '^ProtectProc=' "$U" | unit_case "ProtectProc removed" "ProtectProc(0x)"
sed 's/^\[Install\]$/MemoryDenyWriteExecute=no\
[Install]/' "$U" | unit_case "a second, later MemoryDenyWriteExecute=no" "MemoryDenyWriteExecute(2x)"

# --- TARGET -----------------------------------------------------------------
# A stand-in build tree holding one real executable, with each record of the
# CPU target in turn. Only the target's own lines are judged: whether this
# tree's executable carries the link hardening is another check's question.
T="$D/tree"
mkdir -p "$T/apps" && cp "$DAEMON" "$T/apps/mldsa-authd" && chmod +x "$T/apps/mldsa-authd"
target_case() { # $1 = CMakeCache line or "", $2 = expect: named | unchecked | refused, $3 = text that must appear
    rm -f "$T/CMakeCache.txt"
    [ -z "$1" ] || printf '%s\n' "$1" > "$T/CMakeCache.txt"
    bash "$REPO/tools/audit/check_hardening.sh" "$T" --require > "$D/t.out" 2>&1
    rc=$?
    refused=0
    grep -q '^FAIL: the CPU target is not a named one' "$D/t.out" && refused=1
    grep -q "$3" "$D/t.out" || { bad "TARGET: '$1' -- the report does not say '$3': $(tail -3 "$D/t.out" | tr '\n' ' ')"; return; }
    case "$2" in
      named)   if [ "$refused" -eq 0 ]; then ok "TARGET: '$1' -- reported as named"; else bad "TARGET: '$1' -- refused"; fi ;;
      unchecked) if [ "$refused" -eq 0 ]; then ok "TARGET: no CMakeCache.txt -- said not to be a build tree, and not judged"; else bad "TARGET: no CMakeCache.txt -- refused"; fi ;;
      refused) if [ "$refused" -eq 1 ] && [ "$rc" -ne 0 ]; then ok "TARGET: '$1' -- refused (exit $rc)"; else bad "TARGET: '$1' -- accepted (exit $rc)"; fi ;;
    esac
}
target_case "MLDSA_OQS_OPT_TARGET:STRING=x86-64-v3" named "CPU target: x86-64-v3 (named)"
target_case "MLDSA_OQS_OPT_TARGET:STRING=generic" named "CPU target: generic (named)"
target_case "MLDSA_OQS_OPT_TARGET:STRING=auto" refused "CPU target: auto"
target_case "CMAKE_BUILD_TYPE:STRING=Release" refused "does not record one"
target_case "" unchecked "not a build tree"

# --- HOOK -------------------------------------------------------------------
H="$D/hook"
mkdir -p "$H/apps/authd" "$H/tests" && cp "$LIB" "$H/apps/authd/" && cp "$DAEMON" "$H/apps/authd/" &&
    cp "$STORE_TEST" "$H/tests/" && chmod +x "$H/apps/authd/mldsa-authd" "$H/tests/test_authd_store"
if bash "$REPO/tools/check_store_fault_hook.sh" "$H" > "$D/h.out" 2>&1; then
    ok "HOOK: a tree of the real library, daemon and store test passes (the control)"
else
    bad "HOOK: the control tree is refused: $(grep FAIL "$D/h.out" | head -2 | tr '\n' ' ')"
fi
# Half an executable: `file` still calls it one, and nm cannot read it.
head -c 20000 "$DAEMON" > "$H/apps/authd/half" && chmod +x "$H/apps/authd/half"
if nm "$H/apps/authd/half" > /dev/null 2>&1; then
    bad "HOOK: nm reads the truncated executable on this platform, so this case shows nothing"
elif bash "$REPO/tools/check_store_fault_hook.sh" "$H" > "$D/h.out" 2>&1; then
    bad "HOOK: an executable nm cannot read was counted as free of the hook"
elif grep -q 'nm cannot read .*half' "$D/h.out"; then
    ok "HOOK: an executable nm cannot read is a failure, named"
else
    bad "HOOK: the tree was refused, but not for the unreadable file: $(grep FAIL "$D/h.out" | head -2 | tr '\n' ' ')"
fi
rm -f "$H/apps/authd/half" "$H/apps/authd/libmldsa_authd.a"
if bash "$REPO/tools/check_store_fault_hook.sh" "$H" > "$D/h.out" 2>&1; then
    bad "HOOK: a tree with no shipped library was accepted"
elif grep -q 'libmldsa_authd.a is not there' "$D/h.out"; then
    ok "HOOK: a tree with no shipped library is a failure, named"
else
    bad "HOOK: the tree was refused, but not for the missing library: $(grep FAIL "$D/h.out" | head -2 | tr '\n' ' ')"
fi

[ "$fail" -eq 0 ] && echo "PASS: GATES: all checks"
exit "$fail"
