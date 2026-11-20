#!/bin/sh
# check_daemon_stderr.sh <repo>
#
# F723 (V4-349), rewritten in V4-350 (F729). Spec §16: a daemon that has been
# told to stop gives each line it writes to standard error a quarter of a
# second. That is true only of lines written through authd_log_say() or an
# event writer in authd_log.c. A write to standard error by any other means,
# after the daemon has installed its signal handlers, is a line a daemon
# held on its standard error waits in for ever.
#
# So this does not look for calls. It looks for the NAME: `stderr`,
# STDERR_FILENO, a write() or dprintf() to descriptor 2, perror, syslog.
#   - In authd_main.c, none after the handlers go in; before that, only in
#     main() itself and in usage(), which run and return before them.
#   - In every other source the daemon is linked from, none at all, except
#     the log itself and the command-line tools' files, which the daemon
#     reaches only under --check-config, before it has a handler.
# The first form of this gate (V4-349) matched five function names with
# `stderr` on the same line or the next and read one file; write(2, ...),
# putc(c, stderr), fputs("...",<newline>stderr) and an alias all passed it.
#
# NOT covered, and said in the spec: what liboqs and the C library print to
# descriptor 2 on their way to exit() or abort().
set -eu
REPO="${1:-.}"
F="$REPO/apps/authd/authd_main.c"
[ -f "$F" ] || { echo "FAIL: $F not found"; exit 1; }
PAT='(^|[^A-Za-z0-9_])(stderr|STDERR_FILENO|perror|syslog|vsyslog)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_])(write|dprintf|vdprintf)[ \t]*\([ \t]*2[ \t]*,'
START=$(grep -n 'authd_log_stop_flag(&g_stop)' "$F" | head -1 | cut -d: -f1)
[ -n "$START" ] || { echo "FAIL: authd_log_stop_flag(&g_stop) not found in $F: the gate has nothing to stand on"; exit 1; }
MAIN=$(grep -n '^int main(' "$F" | head -1 | cut -d: -f1)
[ -n "$MAIN" ] && [ "$MAIN" -lt "$START" ] || { echo "FAIL: main() not found before the handlers in $F"; exit 1; }
strip() {   # comments and string literals say what they like; line numbers are kept
    awk '{ line = $0; out = ""
           while (length(line) > 0) {
               if (inc) { i = index(line, "*/"); if (i) { line = substr(line, i + 2); inc = 0 } else { line = "" } }
               else     { i = index(line, "/*"); if (i) { out = out substr(line, 1, i - 1); line = substr(line, i + 2); inc = 1 }
                                                 else   { out = out line; line = "" } }
           }
           print out }' "$1" | sed -e 's|//.*$||' -e 's|"[^"]*"|""|g'
}
# 1. authd_main.c, after the handlers.
BAD=$(strip "$F" | awk -v s="$START" 'NR > s' | grep -nE "$PAT" | head -5 || true)
# 2. authd_main.c, before main(): only inside usage().
BAD2=$(strip "$F" | awk -v m="$MAIN" 'NR < m { if ($0 ~ /^[A-Za-z_].*\(/ && $0 !~ /;[ \t]*$/) fn = $0; print fn "\t" $0 }' \
        | grep -E "$PAT" | grep -vE '^static void usage\(' | cut -f2 | head -5 || true)
# 3. every other source of the daemon.
BAD3=""
for f in "$REPO"/apps/authd/*.c "$REPO"/apps/authd/store/*.c $(find "$REPO/src" -name '*.c' | sort); do
    case "$(basename "$f")" in
        authd_main.c|authd_log.c|authd_cli.c|authd_admin.c|client_cli.c|cli_prompt.c) continue ;;
    esac
    hit=$(strip "$f" | grep -nE "$PAT" | head -2 || true)
    [ -z "$hit" ] || BAD3="$BAD3
$(echo "$f" | sed "s|^$REPO/||"): $hit"
done
if [ -n "$BAD$BAD2$BAD3" ]; then
    echo "FAIL: standard error is named where the daemon could write to it past its signal handlers without authd_log_say():"
    printf '%s\n%s\n%s\n' "$BAD" "$BAD2" "$BAD3" | sed '/^$/d; s/^/    /'
    exit 1
fi
# It must be looking at the daemon: the lines it stands guard over are there.
N=$(awk -v s="$START" 'NR > s && /authd_log_say\(/' "$F" | wc -l | tr -d ' ')
[ "$N" -ge 30 ] || { echo "FAIL: only $N authd_log_say() lines after the handlers: the gate is looking at the wrong file or the wrong place"; exit 1; }
echo "OK: standard error is not named past the daemon's signal handlers, nor in any other source it is linked from; its $N lines there go through authd_log_say()"
