#!/bin/sh
# V4-356 (F748, F749): check_daemon_stderr.sh has been rewritten after each of
# five reviews, and each time it was shown red by hand. These are those
# controls, kept: every edit below is made to a scratch COPY of apps/ and
# src/, and the gate must fail on the copy with the text named. A control
# that passes the gate, or fails it for another reason, fails this script.
#
# Usage: check_daemon_stderr_controls.sh <repo>
set -eu
R="${1:?usage: check_daemon_stderr_controls.sh <repo>}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
BAD=0; N=0
fresh() { rm -rf "$W/t"; mkdir -p "$W/t/tools/audit"; cp -R "$R/apps" "$R/src" "$W/t/"; cp "$R/tools/audit/check_daemon_stderr.sh" "$W/t/tools/audit/"; }
ctl() { # name, the text the gate must fail with, a Python edit
  fresh; N=$((N + 1))
  if ! ( cd "$W/t" && python3 -c "$3" ); then echo "FAIL: control $1: its edit did not apply"; BAD=$((BAD + 1)); return 0; fi
  rc=0; out=$(sh "$W/t/tools/audit/check_daemon_stderr.sh" "$W/t" 2>&1) || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "$2"; then echo "ok: $1"
  else echo "FAIL: control $1 was not refused as '$2' (exit $rc): $(printf '%s' "$out" | head -2)"; BAD=$((BAD + 1)); fi
}
E='import pathlib,re; p=pathlib.Path("apps/authd/authd_main.c"); s=p.read_text()
def w(t): p.write_text(t)
U="#undef stderr\n#pragma GCC poison stderr perror psignal syslog vsyslog\n"
assert s.count(U)==1
i=s.index(U)+len(U)
'
fresh; sh "$W/t/tools/audit/check_daemon_stderr.sh" "$W/t" > "$W/base.out" 2>&1 \
    || { echo "FAIL: the gate refuses the unedited copy: $(cat "$W/base.out")"; exit 1; }
ctl comment "does not have, in its code" "$E"'w(s.replace(U,"/*\n"+U+"*/\n"))'
ctl fn-above "something other than #include" "$E"'j=s.index(U); w(s[:j]+"struct x *early(void) { return 0; }\n"+s[j:])'
ctl define-above "something other than #include" "$E"'j=s.index(U); w(s[:j]+"#define ERRS stderr\n"+s[j:])'
ctl include-after "#include, #pragma or #undef after" "$E"'w(s[:i]+"#include <err.h>\n"+s[i:])'
ctl pragma-after "#include, #pragma or #undef after" "$E"'w(s[:i]+"#pragma GCC diagnostic ignored \"-Wall\"\n"+s[i:])'
ctl cli-common "cli_common.h" "$E"'j=s.index(U); w(s[:j]+"#include \"cli_common.h\"\n"+s[j:])'
for call in 'dprintf(2, "x");' 'write(2, "x", 1);' 'fdopen(2, "w");' 'warnx("x");' 'assert(0);' 'fputs("x", __stderrp);' 'fputs("x", stdout);' 'write(STDERR_FILENO, "x", 1);' 'puts("x");'; do
  ctl "call[$call]" "by a name the poison does not cover" "$E"'import sys; w(s[:i]+"static void zz(void) { '"$(printf '%s' "$call" | sed 's/"/\\"/g')"' }\n"+s[i:])'
done
ctl cli-via-header "a header includes cli_common.h" 'import pathlib; p=pathlib.Path("apps/authd/evloop.h"); p.write_text("#include \"cli_common.h\"\n"+p.read_text())'
ctl printf2 "calls to printf past the poison" "$E"'w(s[:i]+"static void zz(void) { printf(\"x\"); }\n"+s[i:])'
ctl split-name "evloop.c" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); s=p.read_text(); p.write_text(s+"\nstatic void zz(void) { fputs(\"x\", std\\\nerr); }\n")'
ctl cpp-file "zz.cpp" 'import pathlib; pathlib.Path("apps/authd/zz.cpp").write_text("void zz(void) { fputs(\"x\", stderr); }\n")'
ctl contstring "evloop.c" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); s=p.read_text(); p.write_text(s+"\nstatic const char *zs = \"a\\\nb\"; static void zz(void) { perror(zs); }\n")'
[ "$BAD" -eq 0 ] || { echo "FAIL: $BAD of $N controls of check_daemon_stderr.sh were not refused"; exit 1; }
echo "OK: check_daemon_stderr.sh refuses all $N of its controls, each under its own message"
