#!/bin/sh
#
# V4-182 (F258, F259): what the mutation runner refuses, and in what order.
#
#   mutation_runner_gate.sh <repo>
#
# tools/run_mutations_v2.sh is run here on a toy tree with no build
# directory, so nothing is compiled: every case ends at one of the runner's
# start-up refusals, or (the canary) at "clean tree does not build", the
# first thing after them.
#
#   F258  A tree that still holds a MUTATION marker is refused -- and the
#         snapshot an interrupted campaign left in the scratch directory
#         used to be deleted first. For an uncommitted fix that snapshot was
#         the only clean copy of the mutated file.
#   F259  A spec whose last line has no newline lost that mutation: `read`
#         answers false on it, the loop ended, and the campaign exited 0.
set -u
REPO="${1:?usage: mutation_runner_gate.sh <repo>}"
RUNNER="$REPO/tools/run_mutations_v2.sh"
[ -x /bin/bash ] || { echo "FAIL: RUNNER-GATE: /bin/bash not found (the runner needs it)"; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/runner-gate.XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM
fail=0
ok()  { echo "PASS: RUNNER-GATE: $1"; }
bad() { echo "FAIL: RUNNER-GATE: $1"; fail=1; }

T="$TMP/repo"; S="$TMP/scratch"; OLD="$S/snapshot_v2/src/a.c"
mkdir -p "$T/src" "$T/apps" "$T/tests" "$T/bench"
printf 'import sys\n' > "$TMP/mutate_toy.py"
printf 'X1|^t$|some check\nX2|^t$|another check\n' > "$TMP/good.txt"
printf 'X1|^t$|some check\nX2|^t$|another check' > "$TMP/nonl.txt"
: > "$TMP/empty.txt"
plant() { rm -rf "$S"; mkdir -p "$S/snapshot_v2/src"; echo "the only pristine copy" > "$OLD"; }
kept()  { [ -f "$OLD" ] && [ "$(cat "$OLD")" = "the only pristine copy" ]; }
run()   { /bin/bash "$RUNNER" "$T" "$S" "$TMP/mutate_toy.py" "$1" build > "$TMP/out" 2>&1; }

# The canary: a clean tree and a well-formed spec pass every refusal, the old
# snapshot is replaced by a new one, and the run ends at the build.
printf 'int a;\n' > "$T/src/a.c"; plant
run "$TMP/good.txt"; rc=$?
if [ "$rc" -eq 3 ] && grep -q '^FATAL: clean tree does not build$' "$TMP/out" && [ "$(cat "$OLD" 2>/dev/null)" = "int a;" ]; then
    ok "a clean tree with a well-formed spec reaches the build, with a fresh snapshot (the canary)"
else
    bad "the canary: exit $rc, output: $(cat "$TMP/out")"
fi

# F258: a mutated tree is refused and the old snapshot is still there.
printf 'int a; /* MUTATION X1 */\n' > "$T/src/a.c"; plant
run "$TMP/good.txt"; rc=$?
if [ "$rc" -eq 3 ] && grep -q '^FATAL: refusing to snapshot -- MUTATION marker already present in: src/a.c' "$TMP/out"; then
    ok "a tree that holds a MUTATION marker is refused, by name"
else
    bad "a mutated tree: exit $rc, output: $(cat "$TMP/out")"
fi
if kept; then ok "and the snapshot that was in the scratch directory is untouched (F258)"
else bad "refusing a mutated tree destroyed the snapshot already in the scratch directory (F258): $(ls -R "$S" 2>&1 | tr '\n' ' ')"; fi

# F259: a spec that does not end in a newline is refused, before anything else.
printf 'int a;\n' > "$T/src/a.c"; plant
run "$TMP/nonl.txt"; rc=$?
if [ "$rc" -eq 3 ] && grep -q 'does not end in a newline' "$TMP/out" && kept; then
    ok "a spec whose last line has no newline is refused, and nothing was touched (F259)"
else
    bad "a spec with no final newline was not refused (F259): exit $rc, output: $(cat "$TMP/out")"
fi
plant
run "$TMP/empty.txt"; rc=$?
if [ "$rc" -eq 3 ] && grep -q 'is empty or missing' "$TMP/out" && kept; then
    ok "an empty spec is refused"
else
    bad "an empty spec: exit $rc, output: $(cat "$TMP/out")"
fi
# F322: a spec with nothing but comments and blank lines names no mutation.
printf '# a campaign that was emptied\n\n# and nothing else\n' > "$TMP/comments.txt"
plant
run "$TMP/comments.txt"; rc=$?
if [ "$rc" -eq 3 ] && grep -q 'names no mutation' "$TMP/out" && kept; then
    ok "a spec of comments only is refused, and nothing was touched (F322)"
else
    bad "a spec of comments only was not refused (F322): exit $rc, output: $(cat "$TMP/out")"
fi
run "$TMP/absent.txt"; rc=$?
if [ "$rc" -eq 3 ] && kept; then ok "a spec that is not there is refused"
else bad "a missing spec: exit $rc, output: $(cat "$TMP/out")"; fi

# Every committed spec is one the runner will read whole.
n=0; short=""
for f in "$REPO"/tools/mutations/spec_*.txt; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    [ -z "$(tail -c 1 "$f")" ] || short="$short $(basename "$f")"
done
if [ "$n" -ge 80 ] && [ -z "$short" ]; then ok "all $n committed specs end in a newline"
else bad "committed specs: $n found; not ending in a newline:$short"; fi

[ "$fail" -eq 0 ] && echo "PASS: mutation_runner_gate" || echo "FAIL: mutation_runner_gate"
exit "$fail"
