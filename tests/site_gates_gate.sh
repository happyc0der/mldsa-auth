#!/bin/sh
#
# V4-183 (F260): the two site gates see a call on a line that begins with `*`.
#
#   site_gates_gate.sh <repo>
#
# tests/constant_time_sites.sh and tests/secure_mem_sites.sh skip comment
# lines, so that a comment may name a function without calling it. They took
# every line beginning with `*` for the inside of a block comment. A
# statement that assigns through a pointer begins the same way:
#
#     *key_out = sodium_malloc(32);
#     *same = sodium_memcmp(a, b, 32) == 0;
#
# so a raw libsodium allocation written like that passed the gate whose one
# job is to refuse it. Each gate is run here on a copy of src/ and apps/
# with one such line added, and must refuse the copy.
set -u
REPO="${1:?usage: site_gates_gate.sh <repo>}"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/site-gates.XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM
fail=0
ok()  { echo "PASS: SITE-GATES: $1"; }
bad() { echo "FAIL: SITE-GATES: $1"; fail=1; }

copy() { mkdir -p "$TMP/$1" && cp -R "$REPO/src" "$REPO/apps" "$TMP/$1/"; }
add()  { # add <copy> <line>: one more function at the end of a file both gates scan
    printf '\nvoid site_gates_gate_probe(void **p_out, int *same, const unsigned char *a, const unsigned char *b)\n{\n%s\n}\n' "$2" \
        >> "$TMP/$1/apps/authd/authd_secret.c"
}
ct()   { /bin/sh "$REPO/tests/constant_time_sites.sh" "$TMP/$1" > "$TMP/$1.out" 2>&1; }
sm()   { /bin/sh "$REPO/tests/secure_mem_sites.sh" "$TMP/$1" > "$TMP/$1.out" 2>&1; }

[ -f "$REPO/apps/authd/authd_secret.c" ] || { echo "FAIL: SITE-GATES: apps/authd/authd_secret.c is gone; pick another file to append to"; exit 1; }

copy clean
if ct clean && sm clean; then ok "both gates pass an unchanged copy of src/ and apps/ (the canary)"
else bad "an unchanged copy does not pass: $(cat "$TMP/clean.out")"; fi

copy c1; add c1 '    *same = sodium_memcmp(a, b, 32) == 0;'
if ct c1; then bad "constant_time_sites passed a sodium_memcmp call on a line beginning with * (F260)"
elif grep -q 'a constant-time comparison the list does not have.*\*same = sodium_memcmp' "$TMP/c1.out"; then
    ok "constant_time_sites reports an unlisted sodium_memcmp assigned through a pointer (F260)"
else bad "constant_time_sites failed, but not on that line: $(cat "$TMP/c1.out")"; fi

copy c2; add c2 '    *p_out = sodium_malloc(32);'
if sm c2; then bad "secure_mem_sites passed a raw sodium_malloc on a line beginning with * (F260)"
elif grep -q 'a raw libsodium allocator call outside secure_mem.c.*\*p_out = sodium_malloc' "$TMP/c2.out"; then
    ok "secure_mem_sites refuses a raw sodium_malloc assigned through a pointer (F260)"
else bad "secure_mem_sites failed, but not on that line: $(cat "$TMP/c2.out")"; fi

copy c3; add c3 '    *p_out = secure_mem_alloc(32);'
if sm c3; then bad "secure_mem_sites passed an unlisted secure_mem_alloc on a line beginning with * (F260)"
elif grep -q '\*p_out = secure_mem_alloc' "$TMP/c3.out"; then
    ok "secure_mem_sites reports an unlisted secure_mem_alloc assigned through a pointer (F260)"
else bad "secure_mem_sites failed, but not on that line: $(cat "$TMP/c3.out")"; fi

# What must still be skipped: the inside of a block comment naming the calls.
copy c4; add c4 '    /* A comment may name them:
     * sodium_memcmp(a, b, 32), sodium_malloc(32) and secure_mem_alloc(32)
     *
     */
    (void)p_out; (void)same; (void)a; (void)b;'
if ct c4 && sm c4; then ok "a block comment that names the calls is still not a call"
else bad "a block comment naming the calls was taken for code: $(cat "$TMP/c4.out")"; fi

[ "$fail" -eq 0 ] && echo "PASS: site_gates_gate" || echo "FAIL: site_gates_gate"
exit "$fail"
