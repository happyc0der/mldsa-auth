#!/bin/sh
# ubsan_aborts (V4-24b, CLAIMS P8, audit F94): in a UBSan or fuzz tree,
# undefined behaviour must STOP the process. Runs tests/ubsan_canary.c's
# binary, a planted signed overflow, and needs a non-zero exit, UBSan's
# "runtime error" report, and no sign the canary went on past the overflow.
# UBSAN_OPTIONS is cleared for the run: halt_on_error in a caller's
# environment would stop the canary whatever the build was told, and it is
# the build that is under test.
#
#   tests/ubsan_aborts.sh <ubsan_canary binary>   # a UBSan or fuzz tree
#   tests/ubsan_aborts.sh -                        # any other tree: Skipped (77)

if [ "$1" = "-" ]; then
    echo "SKIP: ubsan_aborts: not a UBSan or fuzz tree -- no undefined behaviour is instrumented to stop"
    exit 77
fi
if [ ! -x "$1" ]; then
    echo "FAIL: ubsan_aborts: the canary binary is missing: $1"
    exit 1
fi
out=$(env -u UBSAN_OPTIONS "$1" 2>&1)
rc=$?
printf '%s\n' "$out" | sed 's/^/  | /'
fail=0
if [ "$rc" -eq 0 ]; then
    echo "FAIL: ubsan_aborts: a planted signed overflow did not stop the process -- a UB report would print and the test still pass (audit F94)"
    fail=1
fi
case "$out" in
    *"runtime error"*) ;;
    *) echo "FAIL: ubsan_aborts: no UBSan report for a planted signed overflow -- undefined behaviour is not instrumented"; fail=1 ;;
esac
case "$out" in
    *"survived the overflow"*)
        echo "FAIL: ubsan_aborts: the canary ran on past the overflow"; fail=1 ;;
esac
if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "PASS: ubsan_aborts: a planted signed overflow stops the process (exit $rc) with UBSan's report -- undefined behaviour cannot pass a test"
exit 0
