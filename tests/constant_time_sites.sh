#!/bin/sh
# The constant-time comparison sites, as a gate (V4-15b, CLAIMS P3/D3).
#
#   sh constant_time_sites.sh <repo>
#
# tools/audit/constant_time_inventory.sh reports every comparison in src/ and
# apps/, but nothing ran it -- so a sodium_memcmp swapped for memcmp, the one
# defect in this area that changes no function's result, was the mutation
# v49c and v52 declined to make: "no test can observe it; the inventory is a
# report, not a gate". This is the gate. It compares the tree's
# sodium_memcmp/sodium_is_zero CALL SITES with constant_time_sites.txt, both
# ways:
#
#   - a listed site that is gone: swapped for memcmp, or deleted;
#   - a site the list lacks: the list is incomplete -- add it, same commit.
#
# Comment lines are skipped: a comment may NAME the function; only code may
# call it. A FAIL line prints a site as `file: call` -- the list's `|` is a
# field separator in the mutation specs that name these lines. Timing is still not measured -- this pins WHICH function compares,
# not how long it takes.
set -u
REPO="${1:-}"
HERE=$(cd "$(dirname "$0")" && pwd)
LIST="$HERE/constant_time_sites.txt"
[ -d "$REPO/src" ] && [ -d "$REPO/apps" ] || { echo "FAIL: no src/ and apps/ under '$REPO'"; exit 2; }
[ -f "$LIST" ] || { echo "FAIL: the site list $LIST is missing"; exit 2; }

(cd "$REPO" && grep -rE 'sodium_memcmp|sodium_is_zero' src apps --include='*.c' --include='*.h') |
awk -v list="$LIST" '
    BEGIN {
        while ((getline l < list) > 0) {
            if (l ~ /^#/ || l == "") { continue }
            want[l]++; nw++
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
        if (nh == 0) { print "FAIL: no sodium_memcmp or sodium_is_zero call found at all -- wrong path, or the scan broke"; exit 1 }
        bad = 0
        for (k in want) {
            if (have[k] < want[k]) {
                shown = k; sub(/\|/, ": ", shown)
                print "FAIL: a listed constant-time comparison is gone (swapped for memcmp, or deleted): " shown; bad = 1
            }
        }
        for (k in have) {
            if (want[k] < have[k]) {
                shown = k; sub(/\|/, ": ", shown)
                print "FAIL: a constant-time comparison the list does not have (add it to constant_time_sites.txt): " shown; bad = 1
            }
        }
        if (bad) { exit 1 }
        print "PASS: every listed constant-time comparison is still a sodium_memcmp or sodium_is_zero call (" nw " sites)"
        print "PASS: every sodium_memcmp and sodium_is_zero call in src/ and apps/ is on the list"
        print "All checks passed"
    }'
