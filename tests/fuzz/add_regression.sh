#!/bin/sh
# Admit a (minimized) fuzz artifact as a committed regression input.
#
#   tests/fuzz/add_regression.sh <build-dir> <target> <artifact> <short-name>
#
# The secret scanner (fuzz_keys_replay --scan-secret) is the MANDATORY
# repository admission gate for every target: an input containing an ML-DSA
# secret-key file layout or any 16-byte window of the fixture secret key is
# refused and must stay untracked (then give the root cause a deterministic
# unit test instead). F5 identity-mode inputs are mutation programs by
# construction; replay regenerates the template at runtime.
set -eu

[ $# -eq 4 ] || { echo "usage: $0 <build-dir> <target> <artifact> <short-name>"; exit 2; }
BUILD="$1"; TARGET="$2"; ART="$3"; NAME="$4"
HERE=$(cd "$(dirname "$0")" && pwd)
DEST="$HERE/regressions/$TARGET"
REPLAY="$BUILD/tests/fuzz/fuzz_${TARGET}_replay"
SCANNER="$BUILD/tests/fuzz/fuzz_keys_replay"

[ -d "$DEST" ] || { echo "unknown target '$TARGET'"; exit 2; }
[ -x "$REPLAY" ] && [ -x "$SCANNER" ] || { echo "build the replay drivers first ($BUILD)"; exit 2; }
case "$NAME" in *[!A-Za-z0-9._-]*|"") echo "short-name must be [A-Za-z0-9._-]+"; exit 2;; esac

if ! "$SCANNER" --scan-secret "$ART" > /dev/null 2>&1; then
    "$SCANNER" --scan-secret "$ART" 2>/dev/null | grep VIOLATION || true
    echo "REFUSED: $ART contains secret-key material. Keep it untracked (build dir only) and add a"
    echo "deterministic unit test for the root cause instead."
    exit 1
fi

SUM=$(shasum -a 256 "$ART" | cut -c1-12)
OUT="$DEST/$NAME-$SUM"
cp "$ART" "$OUT"
echo "admitted: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes; secret scan clean)"
echo "reproduce: $REPLAY $OUT"
echo "CTest fuzz_replay_$TARGET now replays it in every build (normal, ASan, UBSan)."
