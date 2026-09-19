#!/bin/sh
#
# The deployment shape, with a REAL proxy: a browser-shaped client speaks
# WebSocket to Caddy over TCP, and Caddy speaks to the daemon over a Unix
# socket, prepending a PROXY v2 preamble (spec mldsa-authd §7.1, §7.2).
#
# Everything runs inside ONE container, and that is not laziness. The daemon's
# proxy-facing listener is a Unix socket, and a Unix socket cannot be crossed
# between a macOS host and a Linux VM: virtiofs shares the inode, not the
# listening kernel object, so a guest connect() to a host-created socket is
# refused. Caddy on the host is no better -- it is not installed, and installing
# it is a change to the developer's machine. One namespace removes both
# problems and is also how the thing actually runs in production.
#
#   sh tests/caddy_proxy.sh
#
# Needs Docker and network access. It is NOT a CTest: a suite gate that
# silently depends on a container registry is a gate that fails for reasons
# that have nothing to do with the code.
set -eu

IMAGE=ubuntu:24.04
CADDY_VERSION=2.10.2
NAME=mldsa-caddy-$$
REPO=$(cd "$(dirname "$0")/.." && pwd)

skip() { echo "SKIP: CADDY: $1"; exit 0; }
fail() { echo "FAIL: CADDY: $1"; docker logs "$NAME" 2>&1 | tail -20 || true; exit 1; }
inc()  { docker exec "$NAME" sh -c "$1"; }

command -v docker > /dev/null 2>&1 || skip "docker is not installed"
docker info > /dev/null 2>&1 || skip "no docker daemon is reachable"

ARCH=$(docker run --rm "$IMAGE" uname -m 2>/dev/null) || skip "cannot run $IMAGE"
case "$ARCH" in
    aarch64) CADDY_ARCH=arm64 ;;
    x86_64)  CADDY_ARCH=amd64 ;;
    *)       skip "no Caddy build for $ARCH" ;;
esac

cleanup() { docker rm -f "$NAME" > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# The dependency sources -- liboqs's shallow clone and libsodium's tarball --
# are identical between runs and take the better part of an hour to fetch on a
# laptop VM. A named volume makes a re-run minutes rather than an afternoon,
# and it is a DOCKER volume, not a host path, so F13's spaces never come near it.
docker volume create mldsa-authd-deps > /dev/null 2>&1 || true
docker run -d --name "$NAME" -v mldsa-authd-deps:/deps "$IMAGE" sleep 3600 > /dev/null

echo "--- installing the toolchain and Caddy $CADDY_VERSION ($CADDY_ARCH)"
inc "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
     clang cmake git make curl ca-certificates file > /dev/null" || fail "apt-get failed"
inc "curl -fsSL -o /tmp/caddy.tgz \
     https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${CADDY_ARCH}.tar.gz" \
    || fail "could not download Caddy"
# The binary is recorded by digest, not trusted by name: a release asset that
# changed under its tag is exactly the thing a pin exists to notice. This
# prints it rather than asserting it, because the expected value belongs in
# docs/decisions.md next to the run it came from -- a hash hardcoded in a test
# that nobody can regenerate offline is worse than a recorded one.
echo "caddy tarball sha256: $(inc 'sha256sum /tmp/caddy.tgz' | cut -d' ' -f1)"
inc "tar -xzf /tmp/caddy.tgz -C /usr/local/bin caddy && caddy version" || fail "could not unpack Caddy"

echo "--- copying the source tree in"
# COPIED, not bind-mounted: this working copy lives under a path containing
# spaces (audit finding F13), which libtool cannot survive, and the build
# directories are megabytes of host-architecture objects.
inc "mkdir -p /src"
# --no-mac-metadata / --no-xattrs: macOS stamps com.apple.provenance on files,
# and docker cp refuses an archive carrying an xattr the guest filesystem
# cannot set. crash-* are gitignored fuzz replay inputs, not source.
(cd "$REPO" && COPYFILE_DISABLE=1 tar -c --no-mac-metadata --no-xattrs \
     --exclude='./build*' --exclude='./.git' --exclude='./crash-*' .) \
    | docker cp - "$NAME:/src" || fail "could not copy the source tree"

echo "--- building the daemon and the CLIs (this is the slow part)"
inc "mkdir -p /src/b/_deps && [ -d /deps/_deps ] && cp -a /deps/_deps/. /src/b/_deps/ || true"
inc "cd /src && cmake -S . -B b -DCMAKE_C_COMPILER=clang > /tmp/cmake.log 2>&1 && \
     cmake --build b -j\$(nproc) --target mldsa_authd_bin authd_admin_bin authd_client_bin \
     > /tmp/build.log 2>&1" || { inc "tail -30 /tmp/build.log /tmp/cmake.log" || true; fail "the build failed"; }
inc "rm -rf /deps/_deps && cp -a /src/b/_deps /deps/_deps" || true

# ----------------------------------------------------------- caddy validate

# deploy/Caddyfile.example is the file under test, not a copy of it. Only two
# things are substituted, and both are necessarily deployment-specific: the
# site address becomes a bare port, and auto_https is turned off because there
# is no domain to get a certificate for. Every directive that matters --
# reverse_proxy, the Unix upstream, `proxy_protocol v2` -- is used verbatim, so
# an example that drifted from what works would fail this leg.
inc "mkdir -p /run/mldsa-authd"
inc "printf '{\\n\\tadmin off\\n\\tauto_https off\\n}\\n' > /etc/Caddyfile"
inc "sed 's/^authd.example.com {/:8080 {/' /src/deploy/Caddyfile.example >> /etc/Caddyfile"
inc "grep -q '^:8080 {' /etc/Caddyfile && grep -q 'proxy_protocol v2' /etc/Caddyfile" \
    || { inc "cat /etc/Caddyfile"; fail "deploy/Caddyfile.example did not adapt as expected"; }

inc "caddy validate --config /etc/Caddyfile --adapter caddyfile > /tmp/val.log 2>&1" \
    || { inc "cat /tmp/val.log"; fail "caddy validate rejected the configuration this test deploys"; }
echo "PASS: CADDY: caddy validate accepts the reverse_proxy + proxy_protocol v2 configuration"

# The control. V4-2's S5 spike reported "PROXY v2 upstream: NOT supported" and
# was WRONG -- a brace error in its own Caddyfile -- so a validate that passes
# proves nothing until a near-miss is shown to fail. `v9` is deliberately one
# character from the value under test, not a nonsense keyword.
inc "sed 's/proxy_protocol v2/proxy_protocol v9/' /etc/Caddyfile > /etc/Caddyfile.bad"
if inc "caddy validate --config /etc/Caddyfile.bad --adapter caddyfile > /dev/null 2>&1"; then
    fail "caddy validate ACCEPTED proxy_protocol v9, so it discriminates nothing"
fi
echo "PASS: CADDY: caddy validate rejects a near-miss (proxy_protocol v9), so it discriminates"

# ------------------------------------------------------------- the daemon

inc "cd /run/mldsa-authd && /src/b/apps/authd/authd_admin init --dir /run/mldsa-authd \
     --server-id authd --passphrase-file /run/mldsa-authd/pass > /tmp/init.log 2>&1" \
    || { inc "cat /tmp/init.log"; fail "authd_admin init failed"; }

inc "cat > /etc/authd.conf <<'EOF'
store_path = /run/mldsa-authd/store.sqlite3
key_path = /run/mldsa-authd/server.ek
key_passphrase_file = /run/mldsa-authd/pass
server_id = authd
listen_unix = /run/mldsa-authd/p.sock
site_socket = /run/mldsa-authd/s.sock
admin_socket = /run/mldsa-authd/a.sock
site_uids = 0
admin_uids = 0
proxy_protocol = v2
proxy_uids = 0
rate_per_min = 600
rate_burst = 600
EOF"
inc "/src/b/apps/authd/mldsa-authd --config /etc/authd.conf > /tmp/authd.log 2>&1 &
     for i in \$(seq 1 100); do grep -q event=started /tmp/authd.log && exit 0; sleep 0.1; done; exit 1" \
    || { inc "cat /tmp/authd.log"; fail "the daemon did not start"; }

HANDLE=$(inc "/src/b/apps/authd/authd_client keygen --dir /run/dev \
              --passphrase-file /run/mldsa-authd/pass 2>/dev/null") || fail "keygen failed"
inc "/src/b/apps/authd/authd_admin enroll-operator --socket /run/mldsa-authd/a.sock \
     --user alice --handle $HANDLE --pub /run/dev/$HANDLE.pub > /dev/null" \
    || fail "enroll-operator failed"

inc "caddy start --config /etc/Caddyfile --adapter caddyfile > /tmp/caddy.log 2>&1" \
    || { inc "cat /tmp/caddy.log"; fail "caddy would not start"; }
inc "for i in \$(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:8080/ && exit 0; sleep 0.1; done; exit 0"

# ------------------------------------------------------------- the login

CODE=$(inc "/src/b/apps/authd/authd_client login --handle $HANDLE \
        --key /run/dev/$HANDLE.ek --passphrase-file /run/mldsa-authd/pass \
        --server-id authd --server-pub /run/mldsa-authd/server.pub \
        --port 8080 --ws --state s1 2>/tmp/login.err") \
    || { inc "cat /tmp/login.err; tail -20 /tmp/authd.log"; fail "the login through Caddy failed"; }
[ "${#CODE}" -eq 43 ] || fail "the code through Caddy is ${#CODE} characters, expected 43"
echo "PASS: CADDY: a post-quantum login completed through a real Caddy over WebSocket"

# The address the daemon learned is the CLIENT's, stated by Caddy -- not the
# proxy's own, and not absent. Without this the leg would pass on a daemon that
# ignored the preamble entirely.
inc "grep -q 'event=client-address .*src=127.0.0.1' /tmp/authd.log" \
    || { inc "grep client-address /tmp/authd.log || true"; \
         fail "the daemon did not record the client address Caddy stated"; }
echo "PASS: CADDY: the daemon recorded the client address from Caddy's PROXY v2 preamble"

# Req 12 through a real proxy: take the preamble away and the login must stop
# working. This is the check that makes the one above mean something.
# A SECOND Caddy on a second port, rather than reloading or restarting the
# first. The configuration sets `admin off`, so there is no API for `caddy
# reload`, and turning the API on to make a test convenient would mean testing
# a configuration nobody deploys; killing the first needs process tools the
# image does not ship. Two ports is the arrangement with no moving parts.
inc "sed -e '/proxy_protocol v2/d' -e 's/^:8080 {/:8081 {/' /etc/Caddyfile > /etc/Caddyfile.nopp"
inc "grep -q '^:8081 {' /etc/Caddyfile.nopp && ! grep -q proxy_protocol /etc/Caddyfile.nopp" \
    || fail "the no-preamble Caddyfile was not derived as intended"
inc "caddy start --config /etc/Caddyfile.nopp --adapter caddyfile > /tmp/caddy2.log 2>&1" \
    || { inc "cat /tmp/caddy2.log"; fail "the second caddy would not start"; }
if inc "/src/b/apps/authd/authd_client login --handle $HANDLE \
        --key /run/dev/$HANDLE.ek --passphrase-file /run/mldsa-authd/pass \
        --server-id authd --server-pub /run/mldsa-authd/server.pub \
        --port 8081 --ws > /dev/null 2>&1"; then
    fail "a login SUCCEEDED with no PROXY v2 preamble (Req 12 fails open behind a real proxy)"
fi
echo "PASS: CADDY: with proxy_protocol removed the daemon refuses the connection (Req 12)"

inc "grep -c 'event=closed-protocol' /tmp/authd.log > /dev/null" \
    || fail "the daemon logged no protocol refusal for the preamble-less connection"
echo "PASS: CADDY: and it says so in the log"
echo "PASS: CADDY: all checks"
