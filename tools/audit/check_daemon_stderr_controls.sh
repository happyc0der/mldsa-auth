#!/bin/sh
# V4-356 (F748, F749): check_daemon_stderr.sh has been rewritten after each of
# five reviews, and each time it was shown red by hand. These are those
# controls, kept: every edit below is made to a scratch COPY of apps/ and
# src/, and the gate must fail on the copy with the text named for that
# control (several controls share a message: the nine calls do). A control
# that passes the gate, or fails it for another reason, fails this script.
#
# What these do NOT show is that the compiler refuses a poisoned name: that
# is campaign v195's RV1 to RV3, which must fail to compile.
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
m=s.index(U)+len(U)
k=s.index("#pragma GCC poison stdout ", m)
i=s.index("\n", k)+1
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
  ctl "call[$call]" "names an output stream past the poison" "$E"'import sys; w(s[:i]+"static void zz(void) { '"$(printf '%s' "$call" | sed 's/"/\\"/g')"' }\n"+s[i:])'
done
ctl cli-via-header "a header includes cli_common.h" 'import pathlib; p=pathlib.Path("apps/authd/evloop.h"); p.write_text("#include \"cli_common.h\"\n"+p.read_text())'
ctl printf "names an output stream past the poison" "$E"'w(s[:i]+"static void zz(void) { printf(\"x\"); }\n"+s[i:])'
ctl split-name "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); s=p.read_text(); p.write_text(s+"\nstatic void zz(void) { fputs(\"x\", std\\\nerr); }\n")'
ctl cpp-file "zz.cpp: [0-9]" 'import pathlib; pathlib.Path("apps/authd/zz.cpp").write_text("void zz(void) { fputs(\"x\", stderr); }\n")'
ctl contstring "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); s=p.read_text(); p.write_text(s+"\nstatic const char *zs = \"a\\\nb\"; static void zz(void) { perror(zs); }\n")'
# V4-357 (F754, F755): the second poison, and what review 97 wrote past the script.
ctl poison2-gone "no second" "$E"'w(s[:k]+"/* "+s[k:i-1]+" */\n"+s[i:])'
ctl poison2-short "does not name .write." "$E"'w(s[:k]+s[k:i].replace(" write "," ")+s[i:])'
ctl undef-gone "does not .#undef assert." "$E"'w(s.replace("#undef assert\n","",1))'
ctl between "other than #undef lines between" "$E"'w(s[:m]+"static int zz;\n"+s[m:])'
ctl digraph-include "#include, #pragma or #undef after" "$E"'w(s[:i]+"%:include <err.h>\n"+s[i:])'
ctl cli-angle "includes cli_common.h" "$E"'j=s.index(U); w(s[:j]+"#include <cli_common.h>\n"+s[j:])'
ctl cli-comment "includes cli_common.h" "$E"'j=s.index(U); w(s[:j]+"/**/#include \"cli_common.h\"\n"+s[j:])'
ctl cli-via-hpp "a header includes cli_common.h" 'import pathlib; pathlib.Path("apps/authd/zz.hpp").write_text("#include <cli_common.h>\n")'
for ext in cc inc cxx inl hpp hh hxx; do
  ctl "file.$ext" "zz.$ext: [0-9]" 'import pathlib; pathlib.Path("apps/authd/zz.'"$ext"'").write_text("void zz(void) { fputs(\"x\", stderr); }\n")'
done
# F761: standard output in another source, by a call and through a header's macro.
ctl stdout-call "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); p.write_text(p.read_text()+"\nstatic void zz(void) { printf(\"debug\\n\"); }\n")'
ctl stdout-name "localapi.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/localapi.c"); p.write_text(p.read_text()+"\nstatic void zz(void) { fflush(stdout); }\n")'
ctl stdout-macro "evloop.h: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.h"); p.write_text(p.read_text()+"\n#define EV_TRACE(w) printf(\"%s\\n\", (w))\n")'
# F767, F775: the calls that write to standard error without naming it. One
# control for every name the search holds, so that a slip in the list shows.
for name in psiginfo putchar_unlocked putc_unlocked err errx errc verr verrx verrc warn warnx warnc vwarn vwarnx vwarnc error error_at_line assert abort perror psignal syslog vsyslog vprintf puts putchar; do
  ctl "other[$name]" "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); p.write_text(p.read_text()+"\nstatic void zz(void) { '"$name"'(0); }\n")'
done
# F778: the six calls F775 added are searched for in authd_main.c too (and
# poisoned there); F782: the four other names of the two streams, in
# another source. Each had a control only on the other side.
for name in error error_at_line errc warnc verrc vwarnc; do
  ctl "main[$name]" "names an output stream past the poison" "$E"'w(s[:i]+"static void zz(void) { '"$name"'(0); }\n"+s[i:])'
  ctl "poison2[$name]" "does not name .$name." "$E"'w(s[:k]+s[k:i].replace(" '"$name"'\n"," \n").replace(" '"$name"' "," ")+s[i:])'
done
for name in __stderrp STDERR_FILENO __stdoutp STDOUT_FILENO; do
  ctl "othername[$name]" "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); p.write_text(p.read_text()+"\nstatic int zz(void) { return (int)sizeof('"$name"'); }\n")'
done
ctl symlink "zl.c: [0-9]" 'import os, pathlib; pathlib.Path("zz.txt").write_text("void zz(void) { fputs(\"x\", stderr); }\n"); os.symlink(os.path.abspath("zz.txt"), "apps/authd/zl.c")'
ctl crlf-split "evloop.c: [0-9]" 'import pathlib; p=pathlib.Path("apps/authd/evloop.c"); s=p.read_bytes(); p.write_bytes(s+b"\nstatic void zz(void) { fputs(\"x\", std\\\r\nerr); }\n")'
# A file that cannot be read fails the check (not for root, who can read it).
if [ "$(id -u)" -ne 0 ]; then
  ctl unreadable "evloop.c could not be read" 'import os; os.chmod("apps/authd/evloop.c", 0)'
  chmod -R u+rw "$W/t" 2>/dev/null || true
fi
[ "$BAD" -eq 0 ] || { echo "FAIL: $BAD of $N controls of check_daemon_stderr.sh were not refused"; exit 1; }
echo "OK: check_daemon_stderr.sh refuses all $N of its controls, each with the message named for it"
