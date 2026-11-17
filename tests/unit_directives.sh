#!/bin/sh
# The systemd unit against spec 16, directive by directive AND value by value
# (V4-230, audit F319). No Docker: tests/deploy_checks.sh calls this, and so
# does ctest `gate_claims`, which also shows it refusing weakened units.
#
#   sh unit_directives.sh <unit file>
#
# It used to be `grep -q "^Name="`: `NoNewPrivileges=no` passed, and so did a
# second, later line undoing the first (systemd takes the last). Each
# directive must now appear exactly once with exactly the value spec 16
# gives. Those spec 16 names without a value are yes/no switches and must be
# yes; the five at the end are sized per deployment and must be present.
set -u
UNIT="${1:-}"
[ -f "$UNIT" ] || { echo "FAIL: UNIT: no unit file '$UNIT'"; exit 2; }
# F377: read as systemd reads it. The counts used to be `grep -c "^Name="`,
# which sees neither ` NoNewPrivileges = no` (systemd strips the white space
# round a line, a key and a value, and takes the last assignment) nor which
# section a line is in: the five sandbox switches moved under [Install], where
# systemd ignores them, passed. Every assignment is first reduced to
# "<section><TAB><key>=<value>".
N=$(mktemp "${TMPDIR:-/tmp}/unit-directives.XXXXXX") || { echo "FAIL: UNIT: mktemp"; exit 2; }
trap 'rm -f "$N"' EXIT INT TERM
awk '
    { sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "") }
    /^$/ || /^[#;]/ { next }
    /^\[.*\]$/ { section = substr($0, 2, length($0) - 2); next }
    {
        i = index($0, "=")
        if (i == 0) { next }
        key = substr($0, 1, i - 1); val = substr($0, i + 1)
        sub(/[ \t]+$/, "", key); sub(/^[ \t]+/, "", val)
        printf "%s\t%s=%s\n", section, key, val
    }' "$UNIT" > "$N"
TAB=$(printf '\t')
bad=""
count() {   # $1 = name: how often it is assigned in [Service]
    grep -c "^Service$TAB$1=" "$N" || true
}
elsewhere() {   # $1 = name: an assignment in any other section is not in force
    e=$(grep -v "^Service$TAB" "$N" | grep -c "$TAB$1=" || true)
    [ "$e" -eq 0 ] || bad="$bad $1(outside-[Service])"
}
want() {    # $1 = name, $2 = exact value
    elsewhere "$1"
    n=$(count "$1")
    if [ "$n" -ne 1 ]; then bad="$bad $1(${n}x)"; return; fi
    v=$(sed -n "s/^Service$TAB$1=//p" "$N")
    [ "$v" = "$2" ] || bad="$bad $1=$v"
}
present() { # $1 = name: once, with some value
    elsewhere "$1"
    n=$(count "$1")
    if [ "$n" -ne 1 ]; then bad="$bad $1(${n}x)"; return; fi
    [ -n "$(sed -n "s/^Service$TAB$1=//p" "$N")" ] || bad="$bad $1(empty)"
}
want Type notify
want NoNewPrivileges yes
want ProtectSystem strict
want ProtectHome yes
want PrivateTmp yes
want PrivateDevices yes
want ProtectKernelTunables yes
want ProtectKernelModules yes
want ProtectKernelLogs yes
want ProtectControlGroups yes
want ProtectProc invisible
want RestrictAddressFamilies "AF_UNIX AF_INET"
want RestrictNamespaces yes
want RestrictSUIDSGID yes
want LockPersonality yes
want MemoryDenyWriteExecute yes
want SystemCallFilter @system-service
want CapabilityBoundingSet ""
want UMask 0077
want LimitCORE 0
present LimitMEMLOCK
present RuntimeDirectory
present Restart
present WatchdogSec
present WatchdogSignal
if [ -n "$bad" ]; then
    echo "FAIL: UNIT: not as spec 16 requires:$bad"
    exit 1
fi
echo "PASS: UNIT: every directive spec 16 names is set once, to the value it gives (25 checked)"
