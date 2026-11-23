#!/bin/sh
# check_daemon_stderr.sh <repo>
#
# F723 (V4-349), rewritten in V4-350 (F729) and again in V4-352 (F733).
# Spec §16: a daemon that has been told to stop gives each line it writes to
# standard error a quarter of a second. That is true only of lines written
# through authd_log_say() or an event writer in authd_log.c. A write to
# standard error by any other means, after the daemon has installed its
# signal handlers, is a line a daemon held on its standard error waits in
# for ever.
#
# So this looks for the NAME, in code -- not in comments or string
# literals, which a small tokenizer removes (escaped quotes, character
# literals, a // or /* inside a string, and comments over several lines all
# behave as in C): `stderr`, STDERR_FILENO, a write()/dprintf() whose first
# argument is the literal 2, perror, psignal, syslog, and the <err.h>
# family.
#   - In authd_main.c: none after the handlers go in, and none before
#     main() except in usage().
#   - In every other .c and .h under apps/authd, apps/authd/store, apps/ and
#     src/: none, except in the files listed in ALLOW below, each with its
#     reason.
#
# WHAT THIS DOES NOT SEE, said here and in tools/README.md so that nobody
# takes "OK" for more than it is:
#   - an alias (`FILE *e = stderr;` before the handlers, used after), a
#     macro that builds the name, or descriptor 2 held in a variable;
#   - standard OUTPUT, which is the same pipe when a daemon is started
#     with 2>&1 the wrong way round (the daemon writes nothing to it);
#   - what liboqs and the C library print on their way to exit()/abort().
# The first two are for a reviewer; the tree has none today.
set -eu
REPO="${1:-.}"
F="$REPO/apps/authd/authd_main.c"
[ -f "$F" ] || { echo "FAIL: $F not found"; exit 1; }
PAT='(^|[^A-Za-z0-9_])(stderr|STDERR_FILENO)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_.>])(perror|psignal|syslog|vsyslog|err|errx|warn|warnx|verr|vwarn)[ \t]*\(|(^|[^A-Za-z0-9_])(write|dprintf|vdprintf)[ \t]*\([ \t]*2[ \t]*,'
START=$(grep -n 'authd_log_stop_flag(&g_stop)' "$F" | head -1 | cut -d: -f1)
[ -n "$START" ] || { echo "FAIL: authd_log_stop_flag(&g_stop) not found in $F: the gate has nothing to stand on"; exit 1; }
MAIN=$(grep -n '^int main(' "$F" | head -1 | cut -d: -f1)
[ -n "$MAIN" ] && [ "$MAIN" -lt "$START" ] || { echo "FAIL: main() not found before the handlers in $F"; exit 1; }

# C source in, the same lines out with comments removed and the insides of
# string and character literals emptied. Line numbers are kept.
strip() {
    awk '
    BEGIN { st = 0 }   # 0 code, 1 string, 2 char, 3 block comment
    {
        line = $0; out = ""; n = length(line); i = 1
        while (i <= n) {
            c = substr(line, i, 1); d = substr(line, i, 2)
            if (st == 0) {
                if (d == "/*") { st = 3; i += 2; continue }
                if (d == "//") { break }
                if (c == "\"") { st = 1; out = out c; i++; continue }
                if (c == "\047") { st = 2; out = out c; i++; continue }
                out = out c; i++; continue
            }
            if (st == 1 || st == 2) {
                if (c == "\\") { i += 2; continue }
                if ((st == 1 && c == "\"") || (st == 2 && c == "\047")) { st = 0; out = out c }
                i++; continue
            }
            if (d == "*/") { st = 0; i += 2; out = out " "; continue }
            i++
        }
        if (st == 1 || st == 2) { st = 0 }     # an unterminated literal ends with its line
        print out
    }' "$1"
}

if ! strip "$F" > /dev/null 2>&1; then echo "FAIL: $F could not be read"; exit 1; fi

# 1. authd_main.c, after the handlers.
BAD=$(strip "$F" | awk -v s="$START" 'NR > s' | grep -nE "$PAT" | head -5 || true)
# 2. authd_main.c, before main(): only inside usage().
BAD2=$(strip "$F" | awk -v m="$MAIN" 'NR < m { if ($0 ~ /^[A-Za-z_].*\(/ && $0 !~ /;[ \t]*$/) fn = $0; print fn "\t" $0 }' \
        | grep -E "$PAT" | grep -vE '^static void usage\(' | cut -f2 | head -5 || true)

# 3. every other source and header. Each ALLOW entry has its reason.
#    authd_log.c            the log itself: the writers this gate sends everyone to
#    authd_cli.c/.h, cli_common.h, cli_prompt.c
#                           the command-line tools; the daemon reaches authd_cli.c only
#                           under --check-config, before it has a handler
#    authd_admin.c, client_cli.c, authd_client.c
#                           tools' own main()s and the client; not in the daemon
#    demo_app.c/.h, auth_client.c, auth_server.c
#                           the v2 demo programs; demo_app.c is in a library the daemon
#                           links, and nothing in the daemon calls its logging
ALLOW=' authd_log.c authd_cli.c authd_cli.h cli_common.h cli_prompt.c authd_admin.c client_cli.c authd_client.c demo_app.c demo_app.h auth_client.c auth_server.c '
BAD3=""
SCANNED=0
LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
{ find "$REPO/apps" -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \)
  find "$REPO/apps/authd" -type f \( -name '*.c' -o -name '*.h' \)
  find "$REPO/src" -type f \( -name '*.c' -o -name '*.h' \); } | sort > "$LIST"
while IFS= read -r f; do            # paths with spaces in them, too (F733)
    b=$(basename "$f")
    [ "$b" = authd_main.c ] && continue
    if ! strip "$f" > /dev/null 2>&1; then echo "FAIL: $f could not be read"; exit 1; fi
    SCANNED=$((SCANNED + 1))
    case "$ALLOW" in *" $b "*) continue ;; esac
    hit=$(strip "$f" | grep -nE "$PAT" | head -2 || true)
    if [ -n "$hit" ]; then
        BAD3="$BAD3
${f#"$REPO"/}: $hit"
    fi
done < "$LIST"

if [ -n "$BAD$BAD2$BAD3" ]; then
    echo "FAIL: standard error is named where the daemon could write to it past its signal handlers without authd_log_say():"
    printf '%s\n%s\n%s\n' "$BAD" "$BAD2" "$BAD3" | sed '/^$/d; s/^/    /'
    exit 1
fi
# It must be looking at the daemon: the lines it stands guard over are
# there, and so are the files.
N=$(awk -v s="$START" 'NR > s && /authd_log_say\(/' "$F" | wc -l | tr -d ' ')
[ "$N" -ge 30 ] || { echo "FAIL: only $N authd_log_say() lines after the handlers: the gate is looking at the wrong file or the wrong place"; exit 1; }
[ "$SCANNED" -ge 80 ] || { echo "FAIL: only $SCANNED other sources and headers were read: the gate did not find the tree"; exit 1; }
echo "OK: standard error is not named in code past the daemon's signal handlers ($N lines there go through authd_log_say()), nor in $SCANNED other sources and headers outside the listed tools"
