#!/bin/sh
# No test names its scratch directory after its pid (V4-28, audit F114).
#
#   sh scratch_dirs.sh <repo>
#
# Seven tests made "/tmp/<name>-<pid>" with mkdir and stopped at once if it
# existed. Their cleanup runs at the end of main, so a run that crashes -- as
# a mutant under ASan does -- leaves its directory behind, and a later run
# that draws the same pid failed before any check (V4-24a saw it). mkdtemp
# makes the name unique by construction, as the two daemon fixtures already
# did.
#
# The check: no line under tests/ or bench/ formats getpid() into a string.
# Its canary: each of the seven tests F114 named still makes its directory,
# with mkdtemp -- so the check cannot pass because a test stopped making one,
# or because the scan read nothing.
set -u
REPO="${1:-}"
[ -d "$REPO/tests" ] && [ -d "$REPO/bench" ] || { echo "FAIL: no tests/ and bench/ under '$REPO'"; exit 2; }
cd "$REPO" || exit 2
fail=0

for t in test_authd_cli test_authd_conn test_authd_keyfile test_authd_localapi test_authd_store \
         test_authd_ws test_client_core; do
    if ! grep -q 'mkdtemp(g_dir)' "tests/$t.c" 2>/dev/null; then
        echo "FAIL: tests/$t.c no longer makes its scratch directory with mkdtemp(g_dir) -- the check below would be vacuous for it"
        fail=1
    fi
done
[ "$fail" -eq 0 ] && echo "PASS: the seven tests F114 named each make their scratch directory with mkdtemp -- the canary"

hits=$(grep -rnE 'printf[[:space:]]*\(.*getpid[[:space:]]*\(' tests bench --include='*.c' --include='*.h' 2>/dev/null || true)
if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | while IFS= read -r l; do
        echo "FAIL: a pid formatted into a string, as F114's scratch directories were: $(printf '%s' "$l" | cut -c1-160)"
    done
    fail=1
else
    echo "PASS: no file under tests/ or bench/ formats getpid() into a name"
fi
exit "$fail"
