#!/bin/sh
#
# The gate on a run_fuzz.sh log (V4-172, F245).
#
#   check_fuzz_log.sh LOG [target...]      targets default to FUZZ_TARGETS
#
# CI's two fuzz steps used to be `run_fuzz.sh ... | tee LOG` followed by a
# grep for "crashes=[1-9]|artifacts=[1-9]". The pipe took tee's status, so
# run_fuzz.sh's own exit code was discarded, and the grep only looked for
# evidence of a crash -- never for evidence that anything had run. A run that
# refused to start (a target with no FUZZ_MAXLEN: exit 2, no summary lines), a
# fuzzer that died without printing one of the grepped words (the summary then
# reads `runs=?`), or a SKIP because the binaries were not built, all passed.
#
# This asks for the positive: for EVERY expected target, exactly one summary
# line with a run count that is a number above zero and `crashes=0
# artifacts=0`; and no FAIL: or SKIP: line anywhere.
set -u
LOG="${1:-}"
[ -n "$LOG" ] && [ -f "$LOG" ] || { echo "FAIL: FUZZ-LOG: no log at '${LOG}'"; exit 1; }
shift
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$#" -eq 0 ]; then
    # shellcheck disable=SC2046
    set -- $(sed -n 's/^[[:space:]]*set(FUZZ_TARGETS[[:space:]]\{1,\}\([^)]*\)).*/\1/p' "$HERE/CMakeLists.txt")
fi
[ "$#" -gt 0 ] || { echo "FAIL: FUZZ-LOG: no targets to look for"; exit 1; }

bad=0
if grep -nE '^(FAIL|SKIP):' "$LOG"; then
    echo "FAIL: FUZZ-LOG: the run printed a FAIL: or SKIP: line (above)"
    bad=1
fi
for t in "$@"; do
    n=$(grep -cE "^fuzz_${t}: runs=" "$LOG")
    if [ "$n" -ne 1 ]; then
        echo "FAIL: FUZZ-LOG: $n summary lines for fuzz_$t, expected exactly 1 (it did not run, or ran twice)"
        bad=1
        continue
    fi
    line=$(grep -E "^fuzz_${t}: runs=" "$LOG")
    runs=$(printf '%s\n' "$line" | sed -n 's/^fuzz_[a-z_]*: runs=\([0-9][0-9]*\) .*/\1/p')
    if [ -z "$runs" ] || [ "$runs" -eq 0 ]; then
        echo "FAIL: FUZZ-LOG: fuzz_$t reports no executed inputs: $line"
        bad=1
    fi
    case "$line" in
        *" crashes=0 artifacts=0") ;;
        *) echo "FAIL: FUZZ-LOG: fuzz_$t produced a crash or an artifact: $line"; bad=1 ;;
    esac
done
[ "$bad" -eq 0 ] || exit 1
echo "PASS: FUZZ-LOG: $# target(s), each with one summary line, a run count above zero, no crash and no artifact"
