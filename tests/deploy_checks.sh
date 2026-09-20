#!/bin/sh
#
# The deployment artefacts, checked rather than reviewed (V4-11).
#
#   sh tests/deploy_checks.sh
#
# Needs Docker: systemd's own analysers are the only things that know whether a
# unit file is valid, and they are not on a macOS host. Like tests/caddy_proxy.sh
# this is NOT a CTest — a suite gate that silently depends on a container
# registry fails for reasons that have nothing to do with the code.
#
# TWO GATES, and the first one is shaped by a measurement rather than a guess:
#
#   `systemd-analyze verify` EXITS 0 FOR AN UNKNOWN DIRECTIVE. Probed:
#   a unit with `BogusDirective=yes` produces
#       Unknown key name 'BogusDirective' in section 'Service', ignoring.
#   on stderr and exits 0. So the exit status is worthless as a gate and the
#   real signal is the OUTPUT: a clean unit produces none at all.
#
#   `systemd-analyze security --offline=true` scores the unit's exposure. The
#   threshold below is asserted, and the control removes one directive to show
#   the score move.
set -eu

IMAGE=ubuntu:24.04
NAME=mldsa-deploy-$$
REPO=$(cd "$(dirname "$0")/.." && pwd)
UNIT=deploy/mldsa-authd.service
# systemd's own scale: 0-2 "safe", 2-4 "OK", 4-6 "MEDIUM", 6-8 "EXPOSED".
# The unit measures well under this; the margin is deliberate so an unrelated
# systemd version bump does not turn the gate red for no reason.
MAX_EXPOSURE=4.0

skip() { echo "SKIP: DEPLOY: $1"; exit 0; }
fail() { echo "FAIL: DEPLOY: $1"; exit 1; }
inc()  { docker exec "$NAME" sh -c "$1"; }

command -v docker > /dev/null 2>&1 || skip "docker is not installed"
docker info > /dev/null 2>&1 || skip "no docker daemon is reachable"

cleanup() { docker rm -f "$NAME" > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker run -d --name "$NAME" "$IMAGE" sleep 900 > /dev/null
inc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y systemd > /dev/null" \
    || fail "could not install systemd in the container"
inc "mkdir -p /etc/systemd/system"
# The unit names a binary, a user and a credential file. `systemd-analyze
# verify` checks that they EXIST, and complaining that they do not would be a
# fact about this container rather than about the unit -- so the container is
# made to satisfy them. Filtering those diagnostics out instead would also
# filter out a real one, which is the opposite of what a gate is for.
inc "useradd --system --no-create-home --shell /usr/sbin/nologin mldsa-authd 2>/dev/null || true"
inc "install -d /etc/mldsa-authd && : > /etc/mldsa-authd/passphrase.cred"
inc "printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/mldsa-authd && chmod 0755 /usr/local/bin/mldsa-authd"
docker cp "$REPO/$UNIT" "$NAME:/etc/systemd/system/mldsa-authd.service" > /dev/null

# --- gate 1: verify, with OUTPUT as the signal ---------------------------
OUT=$(inc "systemd-analyze verify /etc/systemd/system/mldsa-authd.service 2>&1" || true)
if [ -n "$OUT" ]; then
    echo "$OUT"
    fail "systemd-analyze verify had something to say about the unit"
fi
echo "PASS: DEPLOY: systemd-analyze verify accepts the unit with no diagnostics"

# The control. A gate whose signal is "no output" is worthless until an error
# is shown to produce some -- and `verify` exits 0 either way, so without this
# the check could be passing on a unit systemd never read.
inc "sed 's/^NoNewPrivileges=yes/NoNewPrivileges=yes\nBogusDirective=yes/' \
     /etc/systemd/system/mldsa-authd.service > /etc/systemd/system/bogus.service"
BAD=$(inc "systemd-analyze verify /etc/systemd/system/bogus.service 2>&1" || true)
case "$BAD" in
    *BogusDirective*) : ;;
    *) fail "systemd-analyze verify said nothing about an unknown directive, so gate 1 proves nothing" ;;
esac
echo "PASS: DEPLOY: ...and it does object to an unknown directive (the gate is live)"

# --- gate 2: the exposure score ------------------------------------------
SEC=$(inc "systemd-analyze security --offline=true /etc/systemd/system/mldsa-authd.service 2>&1" || true)
SCORE=$(printf '%s\n' "$SEC" | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p' | head -1)
[ -n "$SCORE" ] || { printf '%s\n' "$SEC" | tail -5; fail "could not read an exposure score"; }
awk -v s="$SCORE" -v m="$MAX_EXPOSURE" 'BEGIN { exit !(s+0 <= m+0) }' \
    || fail "exposure level $SCORE is above the $MAX_EXPOSURE threshold"
echo "PASS: DEPLOY: exposure level $SCORE is within the $MAX_EXPOSURE threshold"

# The control for gate 2: drop one hardening directive and the score must rise.
# Without this the threshold could be passing on systemd's defaults rather than
# on anything this unit does.
#
# WHICH directive is a measured choice, not a guess. Removing each in turn from
# this unit (systemd 255, baseline 1.7):
#
#   CapabilityBoundingSet  3.4      RestrictAddressFamilies 2.1
#   SystemCallFilter       3.0      PrivateDevices          1.9
#   RestrictNamespaces     2.4      ProtectSystem/Home/Tmp  1.8
#   User                   2.0      MemoryDenyWriteExecute  1.7  (no change)
#                                   LockPersonality         1.7  (no change)
#
# The first attempt used MemoryDenyWriteExecute and the control silently did
# not move the score -- systemd's scorer does not credit it separately once
# SystemCallFilter is present. That does not make the directive useless (it is
# a real kernel restriction, and spec 16 requires it); it makes it useless AS A
# CONTROL, which is a different statement. CapabilityBoundingSet doubles the
# score and is therefore what the gate is shown to respond to.
inc "grep -v '^CapabilityBoundingSet=' /etc/systemd/system/mldsa-authd.service \
     > /etc/systemd/system/weak.service"
WEAK=$(inc "systemd-analyze security --offline=true /etc/systemd/system/weak.service 2>&1" || true)
WSCORE=$(printf '%s\n' "$WEAK" | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p' | head -1)
[ -n "$WSCORE" ] || fail "could not read the control's exposure score"
awk -v a="$SCORE" -v b="$WSCORE" 'BEGIN { exit !(b+0 > a+0) }' \
    || fail "removing CapabilityBoundingSet did not raise the score ($SCORE -> $WSCORE): the score measures nothing this unit sets"
echo "PASS: DEPLOY: removing one directive raises it to $WSCORE (the score is load-bearing)"

# --- the unit and the spec must name the same directives ------------------
# §16's list is normative. A unit that quietly dropped one would still score
# well and still verify; only a comparison catches it.
MISSING=""
for d in NoNewPrivileges ProtectSystem ProtectHome PrivateTmp PrivateDevices \
         ProtectControlGroups ProtectProc RestrictAddressFamilies RestrictNamespaces \
         RestrictSUIDSGID LockPersonality MemoryDenyWriteExecute SystemCallFilter \
         CapabilityBoundingSet UMask LimitCORE LimitMEMLOCK RuntimeDirectory; do
    grep -q "^${d}=" "$REPO/$UNIT" || MISSING="$MISSING $d"
done
[ -z "$MISSING" ] || fail "the unit omits directives spec 16 requires:$MISSING"
echo "PASS: DEPLOY: the unit sets every directive spec 16 names"
echo "PASS: DEPLOY: all checks"
