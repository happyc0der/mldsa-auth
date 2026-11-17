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
# F377: as systemd reads a unit, not as grep does. White space round a line,
# a key or a value is stripped, the last assignment wins, and a key in a
# section that does not know it is ignored.
sed 's/^\[Install\]$/ NoNewPrivileges = no\
[Install]/' "$U" | unit_case "a later ' NoNewPrivileges = no', indented and spaced" "NoNewPrivileges(2x)"
sed 's/^\[Install\]$/MemoryDenyWriteExecute =no\
[Install]/' "$U" | unit_case "a later 'MemoryDenyWriteExecute =no'" "MemoryDenyWriteExecute(2x)"
sed 's/^ProtectSystem=strict$/ProtectSystem= full/' "$U" | unit_case "'ProtectSystem= full'" "ProtectSystem=full"
{ grep -v '^SystemCallFilter=' "$U"; echo 'SystemCallFilter=@system-service'; } |
    unit_case "SystemCallFilter moved under [Install], where systemd ignores it" "SystemCallFilter(outside-\[Service\])"

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

# --- NXSTACK (V4-248, audit F358) --------------------------------------------
# check_hardening.sh read "no GNU_STACK header" as a non-executable stack.
# ELF only. A stand-in readelf that leaves the header's line out shows the
# same executable with and without it; no linker that omits it is needed.
T="$D/tree"
nx_of() { awk '$1 == "mldsa-authd" { print $5 }' "$1"; }
case "$(uname -s)" in
  Linux)
    printf '#!/bin/sh\nreadelf "$@" | grep -v GNU_STACK\n' > "$D/readelf-nostack" && chmod +x "$D/readelf-nostack"
    bash "$REPO/tools/audit/check_hardening.sh" "$T" > "$D/nx.out" 2>&1
    with=$(nx_of "$D/nx.out")
    MLDSA_HARDENING_READELF="$D/readelf-nostack" bash "$REPO/tools/audit/check_hardening.sh" "$T" > "$D/nx0.out" 2>&1
    without=$(nx_of "$D/nx0.out")
    if [ "$with" = "yes" ]; then ok "NXSTACK: the daemon's stack is reported non-executable (the control)"
    else bad "NXSTACK: the control reports NX-STACK='$with': $(grep mldsa-authd "$D/nx.out")"; fi
    if [ "$without" = "no" ]; then ok "NXSTACK: with no GNU_STACK header the stack is not reported non-executable (F358)"
    else bad "NXSTACK: with no GNU_STACK header NX-STACK is '$without', wanted 'no' (F358)"; fi ;;
  *) echo "note: NXSTACK: GNU_STACK is an ELF header; this case runs on Linux" ;;
esac

# --- REGISTERED (V4-251, audit F364) -----------------------------------------
# Two tests exist only where CMake found a tool: backend_symbols (nm, file)
# and site_node_handler (node). CI's suite step must assert each is
# registered, on a line that is not a comment; a runner image without the
# tool would otherwise run a smaller suite and stay green.
CI="$REPO/.github/workflows/ci.yml"
asserted() { grep -v '^[[:space:]]*#' "$1" | grep -cF -- "-N -R '^$2\$' | grep -q 'Total Tests: 1'"; }
for t in backend_symbols site_node_handler; do
    if [ "$(asserted "$CI" "$t")" -ge 1 ]; then ok "REGISTERED: ci.yml asserts that $t is registered before the suite runs"
    else bad "REGISTERED: ci.yml does not assert that $t is registered (F364)"; fi
    sed "s|^\\([[:space:]]*\\)\\(ctest .*-N -R '^$t\\\$'\\)|\\1# \\2|" "$CI" > "$D/ci-off.yml"
    if cmp -s "$CI" "$D/ci-off.yml"; then bad "REGISTERED: the edit that comments out $t's assert changed nothing"
    elif [ "$(asserted "$D/ci-off.yml" "$t")" -eq 0 ]; then ok "REGISTERED: with that line commented out, $t counts as not asserted"
    else bad "REGISTERED: $t's assert, commented out, still counts as present (F364)"; fi
done

# --- HOOK -------------------------------------------------------------------
H="$D/hook"
mkdir -p "$H/apps/authd" "$H/tests" && cp "$LIB" "$H/apps/authd/" && cp "$DAEMON" "$H/apps/authd/" &&
    cp "$STORE_TEST" "$H/tests/" && chmod +x "$H/apps/authd/mldsa-authd" "$H/tests/test_authd_store"
if bash "$REPO/tools/check_store_fault_hook.sh" "$H" > "$D/h.out" 2>&1; then
    ok "HOOK: a tree of the real library, daemon and store test passes (the control)"
else
    bad "HOOK: the control tree is refused: $(grep FAIL "$D/h.out" | head -2 | tr '\n' ' ')"
fi
# An executable `file` still calls one and nm cannot read. Mach-O: the first
# 20000 bytes. ELF: the whole file with its section-header offset pointed
# past the end -- half an ELF loses the dynamic section `file` tells a PIE
# executable from a shared object by, and the check, rightly, only opens
# executables (so V4-230's first run on Linux skipped the stand-in and
# failed here).
case "$(file -b "$DAEMON")" in
    *ELF*) cp "$DAEMON" "$H/apps/authd/half" &&
           printf '\377\377\377\377\377\377\377\177' | dd of="$H/apps/authd/half" bs=1 seek=40 conv=notrunc 2>/dev/null ;;
    *)     head -c 20000 "$DAEMON" > "$H/apps/authd/half" ;;
esac
chmod +x "$H/apps/authd/half"
case "$(file -b "$H/apps/authd/half")" in
    *Mach-O*executable*|*ELF*executable*|*ELF*pie*) standin=1 ;;
    *) standin=0 ;;
esac
if [ "$standin" -eq 0 ]; then
    bad "HOOK: the stand-in is not an executable to \`file\` ($(file -b "$H/apps/authd/half" | cut -c1-80)), so this case shows nothing"
elif nm "$H/apps/authd/half" > /dev/null 2>&1; then
    bad "HOOK: nm reads the damaged executable on this platform, so this case shows nothing"
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
