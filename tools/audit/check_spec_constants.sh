#!/bin/bash
# V4-3: re-derive every size in docs/mldsa-authd-spec.md from the TREE and
# diff it against what the document says.
#
#   check_spec_constants.sh <repo>
#
# A specification fails by lying, and prose does not compile. This is the
# executable half of V4-3's verification, in the same spirit as V2-1's
# constant checks: numbers come from session.h / transcript.h / mldsa_wrap.h
# and the envelope arithmetic, never from the document being checked.
set -u
REPO="${1:?usage: check_spec_constants.sh <repo>}"
cd "$REPO" || exit 2
SPEC=docs/mldsa-authd-spec.md
[ -f "$SPEC" ] || { echo "FAIL: $SPEC not found"; exit 1; }

hdr() { grep -hoE "#define $1[[:space:]]+[0-9]+" $2 | awk '{print $3}' | head -1; }
PK=$(hdr MLDSA_PUBLIC_KEY_BYTES src/crypto/mldsa_wrap.h)
SK=$(hdr MLDSA_SECRET_KEY_BYTES src/crypto/mldsa_wrap.h)
SIG=$(hdr MLDSA_SIGNATURE_MAX_BYTES src/crypto/mldsa_wrap.h)
IDMAX=$(hdr WIRE_ID_MAX_LEN src/protocol/transcript.h)
HSID=$(hdr WIRE_HANDSHAKE_ID_LEN src/protocol/transcript.h)
OVH=$(hdr SESSION_OVERHEAD_BYTES src/protocol/session.h)
MAGIC=8; DIGEST=32; HANDLE=34

fail=0
check() { # name, derived value, regex-quoted context that must contain it
  if grep -qF "$2" "$SPEC"; then printf '  ok    %-34s %s\n' "$1" "$2"
  else printf '  FAIL  %-34s derived %s, not found in the spec\n' "$1" "$2"; fail=1; fi
}

echo "check_spec_constants: $SPEC"
echo "  (from the tree: pk=$PK sk=$SK sig=$SIG id_max=$IDMAX hsid=$HSID overhead=$OVH)"

# --- record sizing --------------------------------------------------------
rec() { python3 -c "
c=$1; b=$2; inner=c+2; import math
print(((inner+b-1)//b)*b + $OVH)"; }
ROT_BODY=$((1+1+1+HANDLE + PK + 2+SIG + 2+SIG))
ROT_CONTENT=$((ROT_BODY+1))
check "ROTATE body"            "$ROT_BODY"
check "ROTATE content"         "$ROT_CONTENT"
check "AUTHD_MAX_RECORD"       "$(rec 9216 4096)"
check "LOGIN_CODE record @256" "$(rec 43 256)"
check "handle length"          "$HANDLE"
check "WIRE_ID_MAX_LEN"        "$IDMAX"

# --- MLDSASK2 image and the MLDSAEK1 envelope ----------------------------
SK2=$((MAGIC + 1 + PK + SK + DIGEST))          # + id_len
EK_HDR=$((8+1+1+4+8+16+1+24+4))                 # magic..ct_len == the AAD
EK_FILE=$((EK_HDR + SK2 + 16))                  # + id_len, +ABYTES tag
check "MLDSASK2 image (+id_len)" "$SK2"
check "MLDSAEK1 header/AAD"      "$EK_HDR"
check "MLDSAEK1 file (+id_len)"  "$EK_FILE"
check "MLDSAEK1 for a handle"    "$((EK_FILE + HANDLE))"

# --- signature and key sizes quoted in the byte tables -------------------
check "pk_new field"             "$PK"
check "signature bound"          "$SIG"
check "handshake_id in digest"   "$HSID"

echo "  ---"
[ "$fail" -eq 0 ] && echo "OK: every derived size appears in the specification" \
                 || echo "FAIL: the specification disagrees with the tree"
exit $fail
