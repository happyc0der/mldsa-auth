#!/bin/sh
# check_daemon_stderr.sh <repo>
#
# Spec 16: a daemon that has been told to stop gives each line it writes to
# standard error a quarter of a second. That is true only of lines written
# through authd_log_say() or an event writer in authd_log.c; a write to
# standard error by any other means is a line a daemon held on its standard
# error waits in for ever (F710, F723).
#
# Since V4-353 (F740) the one file that has reason to print, authd_main.c,
# CANNOT: after its includes it says
#     #undef stderr
#     #pragma GCC poison stderr perror psignal syslog vsyslog
# and gcc and clang refuse every later use of those names, in a macro or
# out of one. That is the compiler's check, not this script's, and it
# replaces the three forms of this script (V4-349, V4-350, V4-352) that
# tried to recognise a write by reading the source, each of which a review
# then found a spelling for.
#
# What is left for this script:
#   1. that those two lines are in authd_main.c's code with nothing but
#      #include lines before them, and no #include, #pragma or #undef
#      after; and (1b) that the file reaches no output stream past them by
#      a name the poison does not cover: a descriptor, <err.h>, assert,
#      standard output (one call excepted);
#   2. that no OTHER source or header the daemon could be built from names
#      standard error at all (a plain search of the code, comments and
#      literals removed), except the files listed in ALLOW by their full
#      path, each with its reason.
# Part 2 is a search, with a search's limits, and they are these: it does
# not see descriptor 2 written to by number or through a copy of it, a
# FILE* obtained some other way (fdopen, /dev/stderr), or a name built by a
# macro. Nor does anything here cover what liboqs and the C library print
# on their way to exit() or abort(). The tree has none of the first kind
# today; a reviewer of a new daemon source should look for them.
set -eu
REPO="${1:-.}"
F="$REPO/apps/authd/authd_main.c"
[ -f "$F" ] || { echo "FAIL: $F not found"; exit 1; }

# C source in; the same lines out with comments removed and the insides of
# string and character literals emptied. A line that ends in a backslash is
# joined to the next first, as the compiler does (F749: `std\<newline>err`,
# and a string continued over a line, hid what followed), and an empty line
# is put out in its place so that line numbers hold.
strip() {
    awk '
    { if (held != "") { $0 = held $0; held = "" ; pad++ }
      if (substr($0, length($0), 1) == "\\") { held = substr($0, 1, length($0) - 1); next }
      print; while (pad > 0) { print ""; pad-- } }
    END { if (held != "") print held }' "$1" | awk '
    BEGIN { st = 0 }
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
        if (st == 1 || st == 2) { st = 0 }
        print out
    }'
}

# ---- 1. the poison is in place -------------------------------------------
# Looked for in the CODE (comments and literals removed): the two lines
# inside a comment passed this check and poisoned nothing (F748).
MAINC=$(mktemp)
LIST=$(mktemp)
trap 'rm -f "$MAINC" "$LIST"' EXIT
strip "$F" > "$MAINC" || { echo "FAIL: $F could not be read"; exit 1; }
UNDEF=$(grep -n '^#undef stderr[[:space:]]*$' "$MAINC" | head -1 | cut -d: -f1)
POISON=$(grep -n '^#pragma GCC poison stderr perror psignal syslog vsyslog[[:space:]]*$' "$MAINC" | head -1 | cut -d: -f1)
[ -n "$UNDEF" ] && [ -n "$POISON" ] && [ "$POISON" -eq $((UNDEF + 1)) ] \
    || { echo "FAIL: authd_main.c does not have, in its code, '#undef stderr' followed by '#pragma GCC poison stderr perror psignal syslog vsyslog'"; exit 1; }
# Nothing but preprocessor lines and blank lines may come before it: no
# function, no declaration, nothing that could use the name first. (The
# check used to guess what the first function looks like, and a function
# whose type it did not know went above the poison unseen: F748.) And no
# #define there: a macro defined before the poison may expand to the name
# after it.
EARLY=$(awk -v p="$UNDEF" 'NR < p && $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*#[[:space:]]*include[[:space:]]/' "$MAINC" | head -3)
[ -z "$EARLY" ] || { echo "FAIL: authd_main.c has something other than #include lines before the poison:"; printf '%s\n' "$EARLY" | sed 's/^/    /'; exit 1; }
LATE=$(awk -v p="$POISON" 'NR > p && /^[[:space:]]*#[[:space:]]*(include|pragma|undef)/' "$MAINC" | head -3)
[ -z "$LATE" ] || { echo "FAIL: authd_main.c has an #include, #pragma or #undef after the poison:"; printf '%s\n' "$LATE" | sed 's/^/    /'; exit 1; }
# cli_common.h's inline helpers print with fprintf(stderr, ...): the tools
# include it, the daemon's main must not.
# Read in the file as written (the stripped copy has no file names left in
# it), and in every header, since a header may bring it in for the file.
if grep -q '^[[:space:]]*#[[:space:]]*include[[:space:]]*"\(.*/\)\{0,1\}cli_common.h"' "$F"; then
    echo "FAIL: authd_main.c includes cli_common.h, whose inline functions write to standard error"; exit 1
fi
VIA=$(find "$REPO/apps" "$REPO/src" -type f -name '*.h' -exec grep -l '^[[:space:]]*#[[:space:]]*include[[:space:]]*"\(.*/\)\{0,1\}cli_common.h"' {} + | head -3 || true)
[ -z "$VIA" ] || { echo "FAIL: a header includes cli_common.h, so a file that includes that header has its standard-error helpers:"; printf '%s\n' "$VIA" | sed 's/^/    /'; exit 1; }

# ---- 1b. what the poison does not name, in the same file (F748) -----------
# The compiler refuses five names. Standard error can be reached without
# any of them, and this file was exempt from the search below: by
# descriptor, by another spelling of the symbol, through <err.h> or
# assert, or on standard output, which is the same journal under systemd.
# One call to standard output is expected, --check-config's "is valid".
MPAT='(^|[^A-Za-z0-9_])(__stderrp|STDERR_FILENO|stdout|__stdoutp|STDOUT_FILENO)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_.>])(dprintf|vdprintf|write|writev|pwrite|fdopen|dup|dup2|fileno)[[:space:]]*\(|(^|[^A-Za-z0-9_.>])(err|errx|warn|warnx|verr|vwarn|assert|abort|puts|putchar|fputs|fputc|putc|fwrite|fprintf|vfprintf|vprintf)[[:space:]]*\('
BADM=$(awk -v p="$POISON" 'NR > p { print NR ": " $0 }' "$MAINC" | grep -E "$MPAT" | head -5 || true)
[ -z "$BADM" ] || { echo "FAIL: authd_main.c reaches an output stream past the poison by a name the poison does not cover:"; printf '%s\n' "$BADM" | sed 's/^/    /'; exit 1; }
NPRINTF=$(awk -v p="$POISON" 'NR > p' "$MAINC" | grep -cE '(^|[^A-Za-z0-9_])printf[[:space:]]*\(' || true)
[ "$NPRINTF" -eq 1 ] || { echo "FAIL: authd_main.c has $NPRINTF calls to printf past the poison; exactly one is expected (--check-config's line on standard output)"; exit 1; }

# ---- 2. nobody else names it ---------------------------------------------
PAT='(^|[^A-Za-z0-9_])(stderr|__stderrp|STDERR_FILENO)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_.>])(perror|psignal|syslog|vsyslog)[[:space:]]*\('
# By full path. Why each may name standard error:
#   apps/authd/authd_main.c    checked in part 1: after its includes it cannot
#   apps/authd/authd_log.c     the log itself
#   apps/authd/authd_cli.c, apps/authd/cli_common.h
#                              the command-line tools; the daemon calls into authd_cli.c only
#                              under --check-config, before it installs a handler
#   apps/authd/authd_admin.c, apps/authd/client_cli.c, apps/authd_client.c
#                              tools and the client: their own programs, not the daemon
#   apps/demo_app.c, apps/auth_client.c, apps/auth_server.c
#                              the v2 demonstration programs; demo_app.c is in a library the
#                              daemon links, and nothing in the daemon calls what prints
ALLOW='
apps/authd/authd_main.c
apps/authd/authd_log.c
apps/authd/authd_cli.c
apps/authd/cli_common.h
apps/authd/authd_admin.c
apps/authd/client_cli.c
apps/authd_client.c
apps/demo_app.c
apps/auth_client.c
apps/auth_server.c
'
: > "$LIST"
for d in apps src; do
    # A find that fails (a directory that cannot be read) fails the gate.
    find "$REPO/$d" -type f \( -name '*.c' -o -name '*.h' -o -name '*.inc' -o -name '*.inl' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) ! -name '._*' >> "$LIST" \
        || { echo "FAIL: could not list the sources under $d"; exit 1; }
done
# The tree is the one expected: these are in the list, or the gate is not looking at it.
for must in apps/authd/evloop.c apps/authd/localapi.c apps/authd/store/store.c apps/authd/authd_conn.c \
            src/crypto/kex.c src/util/secure_mem.c src/protocol/handshake.c src/util/wire_int.c; do
    grep -qxF "$REPO/$must" "$LIST" || { echo "FAIL: $must is not among the sources found: the gate did not find the tree"; exit 1; }
done
BAD=""
SCANNED=0
while IFS= read -r f; do
    rel=${f#"$REPO"/}
    case "$ALLOW" in *"
$rel
"*) continue ;; esac
    if ! strip "$f" > /dev/null 2>&1; then echo "FAIL: $rel could not be read"; exit 1; fi
    SCANNED=$((SCANNED + 1))
    hit=$(strip "$f" | grep -nE "$PAT" | head -2 || true)
    if [ -n "$hit" ]; then
        BAD="$BAD
$rel: $hit"
    fi
done < "$LIST"
if [ -n "$BAD" ]; then
    echo "FAIL: standard error is named in a source the daemon could be built from, outside the log and the listed tools:"
    printf '%s\n' "$BAD" | sed '/^$/d; s/^/    /'
    exit 1
fi
echo "OK: authd_main.c cannot name standard error after its includes (the compiler's check), and none of the $SCANNED other sources and headers read names it"
