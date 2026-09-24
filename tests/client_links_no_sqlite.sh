#!/bin/sh
# client_links_no_sqlite.sh CLIENT DAEMON   (V4-13a)
#
# The device's tool must carry no store: no sqlite3_* symbol and no store_*
# function. DAEMON is the canary -- it MUST have both, or the symbol names
# this script looks for have drifted and a clean CLIENT would prove nothing.
set -u
CLIENT="${1:?usage: client_links_no_sqlite.sh CLIENT DAEMON}"
DAEMON="${2:?usage: client_links_no_sqlite.sh CLIENT DAEMON}"
for f in "$CLIENT" "$DAEMON"; do
    [ -f "$f" ] || { echo "FAIL: $f does not exist"; exit 1; }
done
# Defined symbols only; strip the leading underscore Mach-O adds.
syms() { nm -g "$1" 2>/dev/null | awk '$2 ~ /^[TtDdBbSs]$/ { s = $3; sub(/^_/, "", s); print s }'; }
count() { syms "$1" | grep -c -E "$2"; }
d_sql=$(count "$DAEMON" '^sqlite3_')
d_store=$(count "$DAEMON" '^store_(open|close|enroll_device)$')
if [ "$d_sql" -eq 0 ] || [ "$d_store" -eq 0 ]; then
    echo "FAIL: the canary $DAEMON shows sqlite3_=$d_sql store_=$d_store -- the check has gone blind"
    exit 1
fi
c_sql=$(count "$CLIENT" '^sqlite3_')
c_store=$(count "$CLIENT" '^store_[a-z_]+$')
echo "canary $(basename "$DAEMON"): sqlite3_ $d_sql, store_ $d_store"
echo "client $(basename "$CLIENT"): sqlite3_ $c_sql, store_ $c_store"
if [ "$c_sql" -ne 0 ] || [ "$c_store" -ne 0 ]; then
    echo "FAIL: $CLIENT links the store"
    exit 1
fi
echo "PASS: $(basename "$CLIENT") links no sqlite3 and no store"
