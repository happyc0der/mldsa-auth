#!/bin/sh
#
# Populate an offline dependency cache for mldsa-auth (V4-11, finding F12).
#
#   sh deploy/fetch-deps.sh /opt/mldsa-deps
#
# Run once on a machine with a network; carry the directory to the build host
# and configure with -DMLDSA_DEPS_CACHE=/opt/mldsa-deps.
#
# Every artefact is VERIFIED AS IT IS WRITTEN, against the same pins
# cmake/Dependencies.cmake enforces -- so a cache produced by this script is
# not a weaker starting point than a fresh fetch, and a cache that was tampered
# with afterwards is still refused at configure time by those same pins.
#
# The pins are read out of cmake/Dependencies.cmake rather than copied here.
# Two files holding the same hash is two files that can disagree, and the one
# that would be wrong is this one.
set -eu

DEST="${1:?usage: fetch-deps.sh <cache-directory>}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
DEPS="$HERE/cmake/Dependencies.cmake"
[ -f "$DEPS" ] || { echo "FAIL: cannot find $DEPS"; exit 1; }

pin() { sed -n "$1" "$DEPS" | head -1; }
OQS_COMMIT=$(pin 's/^set(MLDSA_LIBOQS_COMMIT "\([0-9a-f]*\)").*/\1/p')
OQS_TAG=$(pin 's/^ *GIT_TAG *\([0-9.]*\)$/\1/p')
SODIUM_URL=$(pin 's|^ *"\(https://github.com/jedisct1/libsodium/[^"]*\)")|\1|p')
SODIUM_SHA=$(pin 's/^ *URL_HASH *SHA256=\([0-9a-f]*\)/\1/p')
SQLITE_URL=$(pin 's|^set(_mldsa_sqlite_url "\(https://sqlite.org/[^"]*\)").*|\1|p')
SQLITE_SHA3=$(pin 's/^set(MLDSA_SQLITE_SHA3 \([0-9a-f]*\))/\1/p')

for v in OQS_COMMIT OQS_TAG SODIUM_URL SODIUM_SHA SQLITE_URL SQLITE_SHA3; do
    eval "val=\$$v"
    [ -n "$val" ] || { echo "FAIL: could not read $v from cmake/Dependencies.cmake"; exit 1; }
done

mkdir -p "$DEST"
echo "cache: $DEST"

# --- liboqs: a real clone, so FetchContent can clone FROM it and the
# --- population-time PATCH_COMMAND still runs against the result.
if [ ! -d "$DEST/liboqs.git" ]; then
    echo "--- cloning liboqs $OQS_TAG"
    git clone --bare --depth 1 --branch "$OQS_TAG" \
        https://github.com/open-quantum-safe/liboqs.git "$DEST/liboqs.git.part"
    mv "$DEST/liboqs.git.part" "$DEST/liboqs.git"
fi
GOT=$(git --git-dir="$DEST/liboqs.git" rev-parse HEAD)
[ "$GOT" = "$OQS_COMMIT" ] || {
    echo "FAIL: liboqs $OQS_TAG is $GOT, pinned commit is $OQS_COMMIT"
    echo "      the tag moved, or the clone is not what it claims; refusing to cache it"
    exit 1
}
echo "ok   liboqs $OQS_TAG = $OQS_COMMIT"

sha256_of() {
    if command -v shasum > /dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else sha256sum "$1" | cut -d' ' -f1; fi
}

fetch_verified() { # url, destination, expected, hasher
    url="$1"; out="$2"; want="$3"; hasher="$4"
    if [ ! -f "$out" ]; then
        echo "--- downloading $(basename "$out")"
        curl -fsSL -o "$out.part" "$url"
        mv "$out.part" "$out"
    fi
    got=$($hasher "$out")
    [ "$got" = "$want" ] || {
        echo "FAIL: $(basename "$out") hashes $got, pinned $want"
        echo "      refusing to cache it; delete $out and retry"
        exit 1
    }
    echo "ok   $(basename "$out")"
}

fetch_verified "$SODIUM_URL" "$DEST/libsodium-1.0.22.tar.gz" "$SODIUM_SHA" sha256_of

# sqlite is pinned by SHA3-256, which neither shasum nor sha256sum computes.
# openssl does, and it is on every host that has a TLS proxy.
sha3_of() { openssl dgst -sha3-256 "$1" | sed 's/.*= //'; }
command -v openssl > /dev/null 2>&1 || { echo "FAIL: openssl is needed for sqlite's SHA3-256 pin"; exit 1; }
fetch_verified "$SQLITE_URL" "$DEST/$(basename "$SQLITE_URL")" "$SQLITE_SHA3" sha3_of

echo
echo "Done. Build with:"
echo "  cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \\"
echo "        -DMLDSA_OQS_OPT_TARGET=x86-64-v3 -DMLDSA_DEPS_CACHE=$DEST"
echo
# Finding F72, found by V4-11's own container proof: git refuses to read a
# repository owned by another user (its safe.directory rule), so a cache
# populated as one user and built as another fails -- and, without the
# configure-time probe, fails three layers down inside a generated subbuild
# script. Say it here, where the cache is created, rather than only in the
# runbook: this is the moment the ownership is decided.
echo "NOTE: the cache must belong to whoever BUILDS. If you copy it to another"
echo "      host, or build as a different user, fix the ownership first:"
echo "        chown -R <build-user> $DEST"
echo "      The build refuses an unreadable cache by name rather than guessing."
