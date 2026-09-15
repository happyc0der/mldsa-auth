#!/bin/bash
# V4-1 audit: re-derive the constant-time comparison inventory from the tree.
#
#   constant_time_inventory.sh <repo>
#
# Every comparison in src/ and apps/ is classified. The audit's table is a
# claim; this script is the evidence, and it is re-runnable, so the claim
# cannot rot silently the way an unversioned tool's claim did before V3-4.
#
# Classification is by call, not by judgement: sodium_memcmp/sodium_is_zero
# are constant-time; memcmp/strcmp/strncmp are not. Whether a given plain
# comparison is ACCEPTABLE (public constants, argv) is a human disposition
# recorded in docs/v4/audit.md -- this script only reports what is there.
set -u
REPO="${1:?usage: constant_time_inventory.sh <repo>}"
cd "$REPO" || exit 2

ct=0; plain=0
printf '%-44s %-6s %s\n' FILE:LINE KIND CALL
printf '%-44s %-6s %s\n' "--------" "----" "----"
while IFS= read -r hit; do
  loc=${hit%%:*}; rest=${hit#*:}; line=${rest%%:*}; text=${rest#*:}
  case "$text" in
    *sodium_memcmp*|*sodium_is_zero*) kind=CT;    ct=$((ct+1)) ;;
    *) kind=PLAIN; plain=$((plain+1)) ;;
  esac
  printf '%-44s %-6s %s\n' "$loc:$line" "$kind" "$(printf '%s' "$text" | sed 's/^[[:space:]]*//' | cut -c1-72)"
done < <(grep -rnE "sodium_memcmp|sodium_is_zero|\bmemcmp\(|\bstrcmp\(|\bstrncmp\(" src apps --include=*.c --include=*.h)

echo "---"
echo "constant-time calls: $ct"
echo "plain comparisons:   $plain"
# Vacuous-pass guard: finding nothing means the grep broke, not that the code is clean.
if [ "$ct" -eq 0 ]; then
  echo "FAIL: no constant-time comparisons found at all -- the inventory is broken, not the code"
  exit 1
fi
echo "OK: inventory derived from the tree ($((ct + plain)) comparison sites)"
