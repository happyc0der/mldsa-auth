#!/bin/sh
# The secure-memory allocation sites, as a gate (V4-24b, CLAIMS P2/D2).
#
#   sh secure_mem_sites.sh <repo>
#
# Every secret this project holds on the heap -- keys, shared secrets,
# passphrases, plaintext key images -- is allocated with secure_mem_alloc,
# libsodium's guarded, locked and wiped-on-free memory. Nothing pinned that:
# a key moved to malloc works, passes every functional test, and leaves the
# key in ordinary heap, unwiped when freed. This gate compares the tree's
# secure_mem_alloc CALL SITES with secure_mem_sites.txt, both ways:
#
#   - a listed site that is gone: the secret moved out of secure memory, or
#     the code was deleted;
#   - a site the list lacks: read it, and list it in the same commit.
#
# It also refuses a raw sodium_malloc, sodium_allocarray or sodium_free
# outside src/util/secure_mem.c: an allocation the list cannot see. Comment
# lines are skipped -- a comment may NAME a function; only code calls it. A
# FAIL line prints a site as `file: call`. WHICH buffers belong on the list
# rests on reading, and a secret in a fixed-size array or on the stack is
# not an allocation at all (CLAIMS D2).
set -u
REPO="${1:-}"
HERE=$(cd "$(dirname "$0")" && pwd)
LIST="$HERE/secure_mem_sites.txt"
[ -d "$REPO/src" ] && [ -d "$REPO/apps" ] || { echo "FAIL: no src/ and apps/ under '$REPO'"; exit 2; }
[ -f "$LIST" ] || { echo "FAIL: the site list $LIST is missing"; exit 2; }

raw=$(cd "$REPO" && grep -rnE '\bsodium_(malloc|allocarray|free)[[:space:]]*\(' src apps --include='*.c' --include='*.h' |
      grep -v '^src/util/secure_mem\.[ch]:' |
      awk '{ i = index($0, ":"); r = substr($0, i + 1); j = index(r, ":"); t = substr(r, j + 1);
             gsub(/[ \t]+/, " ", t); sub(/^ /, "", t); if (t ~ /^(\/\*|\*|\/\/)/) next; print }')
if [ -n "$raw" ]; then
    printf '%s\n' "$raw" | while IFS= read -r l; do
        echo "FAIL: a raw libsodium allocator call outside secure_mem.c (the list cannot see it): $l"
    done
    exit 1
fi

(cd "$REPO" && grep -rE '\bsecure_mem_alloc[[:space:]]*\(' src apps --include='*.c' | grep -v '^src/util/secure_mem\.c:') |
awk -v list="$LIST" '
    BEGIN {
        while ((getline l < list) > 0) {
            if (l ~ /^#/ || l == "") { continue }
            want[l]++; nw++
            split(l, p, "|"); files[p[1]] = 1
        }
    }
    {
        i = index($0, ":"); f = substr($0, 1, i - 1); t = substr($0, i + 1)
        gsub(/[ \t]+/, " ", t); sub(/^ /, "", t); sub(/ $/, "", t)
        if (t ~ /^(\/\*|\*|\/\/)/) { next }
        have[f "|" t]++; nh++
    }
    END {
        if (nw == 0) { print "FAIL: the site list is empty -- this gate would check nothing"; exit 1 }
        if (nh == 0) { print "FAIL: no secure_mem_alloc call found at all -- wrong path, or the scan broke"; exit 1 }
        bad = 0
        for (k in want) {
            if (have[k] < want[k]) {
                shown = k; sub(/\|/, ": ", shown)
                print "FAIL: a listed secure allocation is gone (the secret moved out of secure memory, or was deleted): " shown; bad = 1
            }
        }
        for (k in have) {
            if (want[k] < have[k]) {
                shown = k; sub(/\|/, ": ", shown)
                print "FAIL: a secure allocation the list does not have (read it, then add it to secure_mem_sites.txt): " shown; bad = 1
            }
        }
        if (bad) { exit 1 }
        nf = 0; for (f in files) { nf++ }
        print "PASS: every listed secret is still allocated with secure_mem_alloc (" nw " sites in " nf " files)"
        print "PASS: every secure_mem_alloc call in src/ and apps/ is on the list"
        print "PASS: no file but src/util/secure_mem.c calls sodium_malloc, sodium_allocarray or sodium_free"
        print "All checks passed"
    }'
