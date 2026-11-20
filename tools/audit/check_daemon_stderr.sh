#!/bin/sh
# check_daemon_stderr.sh <repo>
#
# F723 (V4-349): from the moment the daemon installs its signal handlers,
# everything it writes to standard error goes through authd_log_say() or an
# event writer, which give a stopping daemon's line a time limit. A plain
# fprintf(stderr, ...) after that point is a line a daemon held on its
# standard error waits in for ever. V4-348 converted them with a search for
# one spelling and missed the two that broke the line after the comma; this
# looks for every spelling, on every run.
set -eu
REPO="${1:-.}"
F="$REPO/apps/authd/authd_main.c"
[ -f "$F" ] || { echo "FAIL: $F not found"; exit 1; }
START=$(grep -n 'authd_log_stop_flag(&g_stop)' "$F" | head -1 | cut -d: -f1)
[ -n "$START" ] || { echo "FAIL: authd_log_stop_flag(&g_stop) not found in $F: the gate has nothing to stand on"; exit 1; }
# After the handlers, in main().
BAD=$(awk -v s="$START" 'NR > s && /(fprintf|fputs|fputc|vfprintf|fwrite|dprintf|perror)[ \t]*\(/ && (/stderr/ || /perror/ || /dprintf[ \t]*\([ \t]*2/)' "$F" | head -5)
# ... and a call whose first argument is on the next line.
BAD2=$(awk -v s="$START" 'NR > s { if (prev ~ /(fprintf|fputs|vfprintf|fwrite)[ \t]*\([ \t]*$/ && $0 ~ /^[ \t]*stderr/) print prev " " $0; prev = $0 }' "$F" | head -5)
# The helper that removes a created store is called from there too.
A=$(grep -n '^static void remove_created_store' "$F" | cut -d: -f1)
BAD3=""
if [ -n "$A" ]; then
    BAD3=$(awk -v a="$A" 'NR >= a { if (/fprintf[ \t]*\([ \t]*stderr/) print; if (NR > a && /^}/) exit }' "$F" | head -3)
fi
if [ -n "$BAD$BAD2$BAD3" ]; then
    echo "FAIL: the daemon writes to standard error past its signal handlers without authd_log_say():"
    printf '%s\n%s\n%s\n' "$BAD" "$BAD2" "$BAD3" | sed '/^$/d; s/^/    /'
    exit 1
fi
N=$(awk -v s="$START" 'NR > s && /authd_log_say\(/' "$F" | wc -l | tr -d ' ')
[ "$N" -ge 30 ] || { echo "FAIL: only $N authd_log_say() lines after the handlers: the gate is looking at the wrong file or the wrong place"; exit 1; }
echo "OK: the daemon's $N lines to standard error after its signal handlers all go through authd_log_say()"
