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

# V4-248 (F355): a number that is a prefix or a suffix of the one the
# specification states, or that another row states, or that rounds to it.
# The gate looked for each as a substring ("1 h" is in "12 h") and passed
# every one of these. `whole <name> <file> <define> <old> <new> <what>`.
whole_number() {
    copy "$1"
    edit "$1" "$2" "s/^\(#define $3[[:space:]]*\)$4/\1$5/"
    if gate "$1"; then tail -3 "$TMP/$1.out"; bad "$6 PASSED the gate (F355)"
    else ok "$6 fails the gate (F355)"; fi
    rm -rf "$TMP/$1"
}
T=apps/authd/tokens.h; RL=apps/authd/ratelimit.h; RC=apps/authd/recovery.h; CI=apps/authd/conn_io.h
whole_number w01 $T TOKEN_TTL_USER_S '(12u' '(1u' "a user token lifetime of 1 h where the specification says 12 h (a prefix)"
whole_number w02 $T TOKEN_TTL_USER_S '(12u' '(8u' "a user token lifetime of 8 h, which is the operator's"
whole_number w03 $T TOKEN_TTL_OPERATOR_S '(8u' '(12u' "an operator token lifetime of 12 h, which is the user's"
whole_number w04 $T TOKEN_IDLE_TTL_USER_S '(1u' '(12u' "a user idle window of 12 h where the specification says 1 h"
whole_number w05 $T TOKEN_IDLE_TTL_OPERATOR_S '(30u' '(0u' "an operator idle window of 0 min where the specification says 30 (a suffix)"
whole_number w06 $RL RATELIMIT_BURST_DEFAULT '10u' '1u' "a burst of 1 where the specification says 10"
whole_number w07 $RL RATELIMIT_GLOBAL_PER_SEC_DEF '50u' '5u' "a daemon-wide rate of 5 where the specification says 50"
whole_number w08 $RL RATELIMIT_GLOBAL_PER_SEC_DEF '50u' '180u' "a daemon-wide rate of 180, the rotation row's number"
whole_number w09 $RL RATELIMIT_MAX_CONNS_DEFAULT '8u' '50u' "a connection limit of 50, the daemon-wide rate's number"
whole_number w10 $RC RECOVERY_CODES_MAX '16u' '1u' "a limit of 1 recovery code where the specification says 16"
whole_number w11 $RC RECOVERY_TICKET_TTL_S '600' '30' "a ticket lifetime of 30 s where the specification says 10 minutes"
whole_number w12 $RC RECOVERY_TICKET_TTL_S '600' '659' "a ticket lifetime of 659 s, which is not 10 minutes"
whole_number w13 $RC RECOVERY_LOCK_THRESHOLD '5' '99' "a lockout after 99 failures where the specification says five"
whole_number w14 $RC RECOVERY_LOCK_SECONDS '3600' '7200' "a lockout of two hours where the specification says one"
whole_number w15 apps/authd/base32.h BASE32_CODE_CHARS '16u' '6u' "a recovery code of 6 characters where the specification says 16"
whole_number w16 apps/authd/authd_conn.h AUTHD_PIN_FLOOR_NS '10000u' '10999u' "a pin floor of 10.999 us where the specification says 10"
whole_number w17 $CI AUTHD_LINE_MAX '8192u' '192u' "a line limit of 192 B where the specification says 8192"
# The record size follows the content limit: with the limit and its own row
# changed together, the row beside it is wrong and used to pass.
copy w18
edit w18 $CI 's/^\(#define AUTHD_MAX_CONTENT[[:space:]]*\)9216u/\112288u/'
edit w18 docs/mldsa-authd-spec.md 's/| `AUTHD_MAX_CONTENT` | 9216 B |/| `AUTHD_MAX_CONTENT` | 12288 B |/'
if gate w18; then tail -3 "$TMP/w18.out"; bad "a content limit raised with its own row, the record size left as it was, PASSED the gate (F355)"
else ok "a content limit raised with its own row, the record size left as it was, fails the gate (F355)"; fi
grep -q 'AUTHD_MAX_RECORD' "$TMP/w18.out" && grep 'AUTHD_MAX_RECORD' "$TMP/w18.out" | grep -q FAIL \
    && ok "and the row it names is AUTHD_MAX_RECORD (F355)" || bad "the refusal does not name AUTHD_MAX_RECORD (F355)"
rm -rf "$TMP/w18"

[ "$fail" -eq 0 ] && echo "PASS: SPEC-GATE: all" || { echo "FAIL: SPEC-GATE"; exit 1; }
