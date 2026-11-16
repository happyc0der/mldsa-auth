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
bad=""
want() {    # $1 = name, $2 = exact value
    n=$(grep -c "^$1=" "$UNIT" || true)
    if [ "$n" -ne 1 ]; then bad="$bad $1(${n}x)"; return; fi
    v=$(sed -n "s/^$1=//p" "$UNIT")
    [ "$v" = "$2" ] || bad="$bad $1=$v"
}
present() { # $1 = name: once, with some value
    n=$(grep -c "^$1=..*" "$UNIT" || true)
    [ "$n" -eq 1 ] || bad="$bad $1(${n}x)"
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
