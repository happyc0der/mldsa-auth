#!/bin/sh
#
# V4-173 (F247): the spec-constants gate can fail.
#
#   spec_constants_gate.sh <repo>
#
# tools/audit/check_spec_constants.sh re-derives the specification's numbers
# from the tree. It is run here against copies of the tree in which a number
# has been changed or can no longer be derived, each of which it must refuse.
# Before V4-173 it passed all of them: a #define that became an expression
# derived the empty string, and `grep -F ""` matches every file; and four
# values were looked for as bare numbers anywhere in the document, where
# "16", "34", "64" and "67" occur dozens of times.
set -u
REPO="${1:?usage: spec_constants_gate.sh <repo>}"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/spec-gate.XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM
fail=0
ok()  { echo "PASS: SPEC-GATE: $1"; }
bad() { echo "FAIL: SPEC-GATE: $1"; fail=1; }

copy() {   # copy <name>: the files the gate reads, nothing else
    mkdir -p "$TMP/$1/docs" "$TMP/$1/tools"
    cp "$REPO/docs/mldsa-authd-spec.md" "$TMP/$1/docs/" &&
    cp "$REPO/CMakeLists.txt" "$TMP/$1/" &&
    cp -R "$REPO/src" "$REPO/apps" "$TMP/$1/" &&
    cp -R "$REPO/tools/audit" "$TMP/$1/tools/"
}
gate() { /bin/bash "$REPO/tools/audit/check_spec_constants.sh" "$TMP/$1" > "$TMP/$1.out" 2>&1; }
edit() {   # edit <name> <file> <sed expression>; fails the test if nothing changed
    f="$TMP/$1/$2"
    cp "$f" "$f.before" && sed "$3" "$f.before" > "$f" || { bad "could not edit $2"; return; }
    cmp -s "$f" "$f.before" && bad "the edit to $2 changed nothing, so its case tests nothing"
    rm -f "$f.before"
}
refused() {   # refused <name> <what>
    if gate "$1"; then tail -3 "$TMP/$1.out"; bad "$2 PASSED the gate (F247)"
    else ok "$2 fails the gate (F247)"; fi
}

copy clean || { bad "could not copy the tree"; exit 1; }
if gate clean; then ok "the tree as it is passes (the canary)"
else tail -5 "$TMP/clean.out"; bad "the unedited tree was refused (the canary)"; fi

copy expr
edit expr src/protocol/session.h 's/^#define SESSION_OVERHEAD_BYTES 25u/#define SESSION_OVERHEAD_BYTES (9u + 16u)/'
refused expr "a size the gate can no longer derive (a #define rewritten as an expression)"

copy hsid
edit hsid src/protocol/transcript.h 's/^#define WIRE_HANDSHAKE_ID_LEN 16u/#define WIRE_HANDSHAKE_ID_LEN 32u/'
refused hsid "a handshake id of 32 bytes where the specification says 16"

copy idmax
edit idmax src/protocol/transcript.h 's/^#define WIRE_ID_MAX_LEN 64u/#define WIRE_ID_MAX_LEN 32u/'
refused idmax "an identity limit of 32 where the specification says 64"

copy rate
edit rate apps/authd/ratelimit.h 's/^\(#define RATELIMIT_BURST_DEFAULT[[:space:]]*\)[0-9][0-9]*u*/\1(4u + 4u)/'
refused rate "a rate-limit default the gate can no longer derive"

copy tok
edit tok apps/authd/tokens.h 's/^\(#define TOKEN_TTL_USER_S[[:space:]]*\)(12u \* 3600u)/\1(43200u)/'
refused tok "a token lifetime the gate can no longer derive"

copy code
edit code apps/authd/base32.h 's/^\(#define BASE32_CODE_BYTES[[:space:]]*\)[0-9][0-9]*u*/\1(5u + 5u)/'
refused code "a recovery-code size the gate can no longer derive (it is used in arithmetic)"

[ "$fail" -eq 0 ] && echo "PASS: SPEC-GATE: all" || { echo "FAIL: SPEC-GATE"; exit 1; }
