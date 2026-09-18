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

# --- recovery codes and tickets (V4-9d, spec §10.3) ----------------------
#
# Two different claims are checked here, and only the second could be caught
# by a test:
#
#   1. recovery.h's named constants match the numbers §10.3 states. The text
#     match is scoped to the §10.3 paragraph, because bare digits like "2" and
#     "16" appear all over a specification and a whole-file grep would pass
#     vacuously.
#   2. authd_main.c assigns those NAMED constants to authd_app_t rather than
#     literals of its own. This is the only mechanical check there can be:
#     the fields exist so tests and fuzzing can lower the KDF, so no test can
#     observe what the daemon itself writes into them.

REC=apps/authd/recovery.h
R_OPS=$(hdr RECOVERY_OPS_SPEC $REC)
R_CODES=$(hdr RECOVERY_CODES_MAX $REC)
R_THRESH=$(hdr RECOVERY_LOCK_THRESHOLD $REC)
R_LOCK=$(hdr RECOVERY_LOCK_SECONDS $REC)
R_TTL=$(hdr RECOVERY_TICKET_TTL_S $REC)
R_BYTES=$(hdr BASE32_CODE_BYTES apps/authd/base32.h)
R_CHARS=$(hdr BASE32_CODE_CHARS apps/authd/base32.h)
R_MEM_MIB=$(grep -oE 'RECOVERY_MEM_SPEC[[:space:]]+\(([0-9]+)u \* 1024u \* 1024u\)' $REC | grep -oE '\(([0-9]+)u' | tr -d '(u')

# The §10.3 recovery paragraph only.
SEC=$(awk '/^### 10.3 /{f=1} f{print} /presents to .ENROLL/{if(f) exit}' "$SPEC")
in_sec() { case "$SEC" in *"$2"*) printf '  ok    %-34s %s\n' "$1" "$2";;
                          *) printf '  FAIL  %-34s derived %s, not in §10.3\n' "$1" "$2"; fail=1;; esac; }

in_sec "recovery: max codes"      "1..$R_CODES"
in_sec "recovery: code bytes"     "$R_BYTES random bytes"
in_sec "recovery: code characters" "$R_CHARS base32 characters"
in_sec "recovery: entropy bits"   "$((R_BYTES * 8)) bits"
in_sec "recovery: Argon2id ops"   "ops $R_OPS"
in_sec "recovery: Argon2id memory" "memory $R_MEM_MIB MiB"
in_sec "recovery: ticket lifetime" "$((R_TTL / 60)) minutes"

# libsodium's own names for the same parameters, so a future bump that changes
# what INTERACTIVE means cannot silently change what the daemon uses.
grep -q 'RECOVERY_OPS_SPEC == crypto_pwhash_OPSLIMIT_INTERACTIVE' $REC \
  && printf '  ok    %-34s %s\n' "recovery: ops pinned to libsodium" "static_assert present" \
  || { printf '  FAIL  %-34s %s\n' "recovery: ops pinned to libsodium" "no static_assert"; fail=1; }
grep -q 'RECOVERY_MEM_SPEC == crypto_pwhash_MEMLIMIT_INTERACTIVE' $REC \
  && printf '  ok    %-34s %s\n' "recovery: mem pinned to libsodium" "static_assert present" \
  || { printf '  FAIL  %-34s %s\n' "recovery: mem pinned to libsodium" "no static_assert"; fail=1; }

# The daemon must assign the named constants, never numbers of its own.
for pair in "recovery_ops=RECOVERY_OPS_SPEC" "recovery_mem=RECOVERY_MEM_SPEC" \
            "recovery_lock_threshold=RECOVERY_LOCK_THRESHOLD" \
            "recovery_lock_seconds=RECOVERY_LOCK_SECONDS" \
            "ticket_ttl_s=RECOVERY_TICKET_TTL_S"; do
  f="${pair%%=*}"; c="${pair##*=}"
  if grep -qE "app\.$f[[:space:]]*=[[:space:]]*$c;" apps/authd/authd_main.c; then
    printf '  ok    %-34s %s\n' "daemon assigns $f" "$c"
  else
    printf '  FAIL  %-34s the daemon does not assign %s\n' "daemon assigns $f" "$c"; fail=1
  fi
done

echo "  ---"
[ "$fail" -eq 0 ] && echo "OK: every derived size appears in the specification" \
                 || echo "FAIL: the specification disagrees with the tree"
exit $fail
