#!/bin/sh
#
# The offline dependency cache, proven rather than described (V4-11, F12/F72).
#
#   sh tests/offline_build.sh [deps-cache-dir]
#
# Needs Docker. Like tests/deploy_checks.sh and tests/caddy_proxy.sh this is
# NOT a CTest: a suite gate that silently depends on a container registry fails
# for reasons that have nothing to do with the code.
#
# WHY A CONTAINER AND NOT A LOCAL RUN. The claim is "this builds with no
# network and every pin still holds". A local build cannot demonstrate the
# first half -- there is no way to be sure nothing reached out -- so the build
# happens in a container whose network is DISCONNECTED, and the script first
# proves the disconnection by requiring a DNS lookup to fail. A proof that
# would also pass while online proves nothing.
#
# FOUR CHECKS. The last three are controls, and they are the point: an offline
# cache is the one place where a mistake would silently WEAKEN a pin, so each
# way the cache could be wrong is staged deliberately and the build is required
# to refuse it.
#
#   1. the real thing     configure + build with --network none
#   2. control            a cache git cannot read (owned by another user)
#   3. control            one byte of the libsodium tarball changed
#   4. control            the cached clone moved off the pinned commit
#
# Control 2 is finding F72, and it was not invented: it is what this script's
# first run actually did, because `docker cp` delivered the cache carrying the
# host's uid while the build ran as root. That is the same shape as an
# operator who populates a cache as themselves and builds as root.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
CACHE="${1:-}"
[ -n "$CACHE" ] || { echo "usage: $0 <deps-cache-dir>   (populate with deploy/fetch-deps.sh)"; exit 2; }
[ -d "$CACHE/liboqs.git" ] || { echo "FAIL: $CACHE holds no liboqs.git; run deploy/fetch-deps.sh first"; exit 1; }
command -v docker > /dev/null 2>&1 || { echo "SKIP: OFFLINE: docker not available"; exit 0; }

NAME="mldsa-offline-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
fail() { echo "FAIL: OFFLINE: $1"; exit 1; }
inc()  { docker exec "$NAME" sh -c "$1"; }

docker run -d --name "$NAME" ubuntu:24.04 sleep 7200 > /dev/null || fail "cannot start a container"
inc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y clang cmake git make file >/dev/null 2>&1" \
  || fail "cannot install the toolchain"
inc "mkdir -p /src /cache"

# The tree goes in as a TAR STREAM, not a bind mount, for two reasons: this
# checkout may live under a path containing spaces (F13), which libsodium's
# libtool cannot handle, and `docker cp` rejects macOS's com.apple.provenance
# xattr outright -- which is what COPYFILE_DISABLE and the two flags below
# suppress. GNU tar has neither flag and needs neither, so they are added only
# where they mean something.
case "$(uname -s)" in
  Darwin) TARX="--no-mac-metadata --no-xattrs" ;;
  *)      TARX="" ;;
esac
# shellcheck disable=SC2086
(cd "$REPO" && COPYFILE_DISABLE=1 tar -c $TARX \
   --exclude='./build*' --exclude='./.git' --exclude='./crash-*' .) | docker cp - "$NAME:/src"
# shellcheck disable=SC2086
(cd "$CACHE" && COPYFILE_DISABLE=1 tar -c $TARX .) | docker cp - "$NAME:/cache"

docker network disconnect bridge "$NAME" 2>/dev/null || true
inc "timeout 8 getent hosts github.com" > /dev/null 2>&1 \
  && fail "the container is still online, so nothing below would prove anything"
echo "PASS: OFFLINE: the network is disconnected (github.com does not resolve)"

# --- control 2: a cache git will not read ---------------------------------
inc "chown -R 501:501 /cache"
if inc "cd /src && cmake -S . -B bA -DCMAKE_C_COMPILER=clang -DMLDSA_DEPS_CACHE=/cache > /tmp/cA.log 2>&1"; then
    fail "a cache git cannot read was accepted"
fi
inc "grep -q 'not owned by the user' /tmp/cA.log" \
  || { inc "tail -n 20 /tmp/cA.log"; fail "the refusal did not name the ownership as the cause"; }
echo "PASS: OFFLINE: a cache owned by another user is refused, naming its own cause"

# --- 1: the real thing ----------------------------------------------------
inc "chown -R root:root /cache && rm -rf /src/bA"
inc "cd /src && cmake -S . -B b -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release -DMLDSA_DEPS_CACHE=/cache > /tmp/c.log 2>&1" \
  || { inc "tail -n 30 /tmp/c.log"; fail "the offline configure failed"; }
inc "grep -q 'cache holds the pinned commit' /tmp/c.log" || fail "the cache pin was never checked"
inc "grep -q 'liboqs commit verified'        /tmp/c.log" || fail "the populated tree's pin was never checked"
inc "cd /src && cmake --build b -j\$(nproc) --target mldsa_authd_bin > /tmp/b.log 2>&1" \
  || { inc "tail -n 30 /tmp/b.log"; fail "the offline build failed"; }
inc "test -x /src/b/apps/authd/mldsa-authd" || fail "no daemon binary was produced"
echo "PASS: OFFLINE: configured and built with no network, from the cache alone"

# --- control 3: a corrupted archive ---------------------------------------
inc "rm -rf /src/b2 && printf 'x' | dd of=/cache/libsodium-1.0.22.tar.gz bs=1 seek=500 conv=notrunc 2>/dev/null"
if inc "cd /src && cmake -S . -B b2 -DCMAKE_C_COMPILER=clang -DMLDSA_DEPS_CACHE=/cache > /tmp/c2.log 2>&1 && cmake --build b2 --target libsodium_ext > /tmp/b2.log 2>&1"; then
    fail "a corrupted cache was accepted"
fi
inc "grep -qi 'does not match expected' /tmp/b2.log /tmp/c2.log" \
  || fail "the corrupted archive was refused, but not by its hash"
echo "PASS: OFFLINE: one changed byte is refused by URL_HASH"

# --- control 4: the clone moved off the pin -------------------------------
# The cache is a BARE, SHALLOW clone: no work tree to commit in and no HEAD~1
# to step back to. commit-tree builds a commit without needing either.
inc "rm -rf /src/b3 && cd /cache/liboqs.git && t=\$(git rev-parse HEAD^{tree}) && n=\$(git -c user.email=t@example.invalid -c user.name=t commit-tree \$t -p HEAD -m moved) && git update-ref HEAD \$n"
if inc "cd /src && cmake -S . -B b3 -DCMAKE_C_COMPILER=clang -DMLDSA_DEPS_CACHE=/cache > /tmp/c3.log 2>&1"; then
    fail "a cache off the pinned commit was accepted"
fi
inc "grep -q 'pinned commit is' /tmp/c3.log" || fail "the drifted cache was refused, but not by the pin"
inc "test ! -d /src/b3/_deps/liboqs-src" \
  || fail "the drifted cache was refused only AFTER being populated"
echo "PASS: OFFLINE: a drifted cache is refused before anything is populated"

echo "PASS: OFFLINE: all checks"
