#!/bin/sh
# No hand-rolled cryptographic primitive (V4-15c, CLAIMS P1/D1).
#
#   sh no_hand_rolled_primitives.sh <repo>
#
# Spec-v2 Req 4.1 and the deployment spec's Req 1 say every primitive comes
# from liboqs or libsodium. The KATs show the wrappers reproduce those
# libraries; nothing looked for code that implements a primitive itself. A
# hash, cipher or lattice scheme written by hand has to carry its defining
# constants -- IVs, round constants, the ChaCha sigma, the NTT modulus -- so
# this scans src/, apps/ and web/client/ for them.
#
# One file is allowed: apps/authd/sha1.c, RFC 6455's accept value and nothing
# else (audit F53). It is also the canary: the SHA-1 IV must be found THERE,
# or the scan is broken and proves nothing.
set -u
REPO="${1:-}"
[ -d "$REPO/src" ] && [ -d "$REPO/apps" ] && [ -d "$REPO/web/client" ] ||
    { echo "FAIL: no src/, apps/ and web/client/ under '$REPO'"; exit 2; }
ALLOWED="apps/authd/sha1.c"

HEX='67452301|efcdab89|98badcfe|10325476|c3d2e1f0|5a827999|6ed9eba1|8f1bbcdc|ca62c1d6'   # SHA-1
HEX="$HEX|6a09e667|bb67ae85|3c6ef372|a54ff53a|510e527f|9b05688c|1f83d9ab|5be0cd19"      # SHA-256 IV
HEX="$HEX|428a2f98|71374491|b5c0fbcf|e9b5dba5|f3bcc908"                                 # SHA-256 K, SHA-512 IV
HEX="$HEX|0000000000008082|800000000000808a|8000000080008000|000000000000808b"          # Keccak RC
HEX="$HEX|61707865|3320646e|79622d32|6b206574"                                          # ChaCha sigma
HEX="$HEX|0ffffffc0fffffff|0ffffffc0ffffffc"                                            # Poly1305 clamp
HEX="$HEX|637c777b"                                                                     # AES S-box head
TEXT='expand 32-byte k|expand 16-byte k|0x63, *0x7c, *0x77, *0x7b'
DEC='121665|121666|3329|8380417|1753|58728449'   # X25519 a24; ML-KEM q; ML-DSA q, root, Montgomery
PATTERN="($HEX)|($TEXT)|(^|[^0-9A-Za-z_])($DEC)([^0-9A-Za-z_]|\$)"

cd "$REPO" || exit 2
hits=$(grep -rniE "$PATTERN" src apps web/client \
           --include='*.c' --include='*.h' --include='*.mjs' --include='*.js' 2>/dev/null)

canary=$(printf '%s\n' "$hits" | grep -c "^$ALLOWED:" || true)
if [ "$canary" -eq 0 ]; then
    echo "FAIL: the SHA-1 constants were not found in $ALLOWED -- the scan is broken, or the file moved"
    exit 1
fi
echo "PASS: the scan finds $ALLOWED's SHA-1 constants ($canary lines) -- the canary"

others=$(printf '%s\n' "$hits" | grep -v "^$ALLOWED:" | grep -v '^$' || true)
if [ -n "$others" ]; then
    printf '%s\n' "$others" | while IFS= read -r l; do
        echo "FAIL: a primitive's defining constant outside $ALLOWED: $(printf '%s' "$l" | cut -c1-160)"
    done
    exit 1
fi
echo "PASS: no primitive's defining constant appears anywhere else in src/, apps/ or web/client/"

# The exception's scope is part of the exception: sha1() is extern (the WS
# test pins it against FIPS 180-1 vectors), so its only production caller must
# be the WebSocket upgrade. F53 said "static-scoped" and "`git grep sha1` only
# finds ws.c"; neither was true (F102) -- this is the check that replaces them.
callers=$(grep -rnE '(^|[^0-9A-Za-z_])sha1[[:space:]]*\(' src apps --include='*.c' 2>/dev/null |
          grep -vE '^apps/authd/sha1\.c:' || true)
if ! printf '%s\n' "$callers" | grep -q '^apps/authd/ws\.c:'; then
    echo "FAIL: ws.c no longer calls sha1() -- the scope check below would be vacuous"
    exit 1
fi
stray=$(printf '%s\n' "$callers" | grep -v '^apps/authd/ws\.c:' | grep -v '^$' || true)
if [ -n "$stray" ]; then
    printf '%s\n' "$stray" | while IFS= read -r l; do
        echo "FAIL: sha1() called outside the WebSocket upgrade: $(printf '%s' "$l" | cut -c1-160)"
    done
    exit 1
fi
echo "PASS: sha1() is called by apps/authd/ws.c and by nothing else in src/ or apps/"
echo "All checks passed"
