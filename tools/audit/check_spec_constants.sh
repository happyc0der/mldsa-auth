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
# F247: a value that could not be DERIVED is a failure, said by name. hdr()
# and its siblings match one spelling of a #define ("NAME <digits>", "(Nu *
# 3600u)"); a define rewritten any other way derived the empty string, and
# every check below then looked for "", " h" or "default ", which every
# document contains. Each derived variable is passed through this before use.
req() { # variable names
  for v in "$@"; do
    eval "x=\${$v-}"
    case "$x" in
      ''|*[!0-9.]*) printf '  FAIL  %-34s could not be derived from the tree (got "%s")\n' "$v" "$x"; fail=1 ;;
    esac
  done
}
check() { # name, derived value, regex-quoted context that must contain it
  if [ -z "$2" ]; then printf '  FAIL  %-34s nothing was derived to look for\n' "$1"; fail=1
  elif grep -qF -- "$2" "$SPEC"; then printf '  ok    %-34s %s\n' "$1" "$2"
  else printf '  FAIL  %-34s derived %s, not found in the spec\n' "$1" "$2"; fail=1; fi
}
req PK SK SIG IDMAX HSID OVH

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
REC_MAX=$(rec 9216 4096); REC_CODE=$(rec 43 256)
req REC_MAX REC_CODE
check "AUTHD_MAX_RECORD"       "$REC_MAX"
check "LOGIN_CODE record @256" "$REC_CODE"
# F247: these two, the envelope header and the handshake id below were looked
# for as bare numbers anywhere in the document, where "34", "64", "67" and
# "16" each occur many times over: any of the four could change in the tree
# and still be "found". Each is now looked for in the phrase that states it.
check "handle length"          "($HANDLE bytes)"
check "WIRE_ID_MAX_LEN"        "\`WIRE_ID_MAX_LEN\` ($IDMAX)"

# --- MLDSASK2 image and the MLDSAEK1 envelope ----------------------------
SK2=$((MAGIC + 1 + PK + SK + DIGEST))          # + id_len
EK_HDR=$((8+1+1+4+8+16+1+24+4))                 # magic..ct_len == the AAD
EK_FILE=$((EK_HDR + SK2 + 16))                  # + id_len, +ABYTES tag
check "MLDSASK2 image (+id_len)" "$SK2"
check "MLDSAEK1 header/AAD"      "Bytes [0, $EK_HDR) are the AEAD's associated data"
check "MLDSAEK1 file (+id_len)"  "$EK_FILE"
check "MLDSAEK1 for a handle"    "$((EK_FILE + HANDLE))"
check "MLDSAEK1 version 2 (+id_len)" "$((EK_FILE + 32))"   # + the store root key (erratum 79)

# --- signature and key sizes quoted in the byte tables -------------------
check "pk_new field"             "$PK"
check "signature bound"          "$SIG"
check "handshake_id in digest"   "handshake_id ($HSID)"

# --- §17's limits table (V4-10c, findings F36/F68) -----------------------
#
# §17 was six rows and the document stated at least ten more limits elsewhere;
# the errata pass completed it. These are the ones with a named constant, so
# they can be derived rather than transcribed -- the rate-limit four are
# operator DEFAULTS rather than protocol constants, which is why the check is
# that §17 quotes the default the code ships, not that the number is fixed.
SEC17=$(awk '/^## 17\. /{f=1} f{print} /^## 18\. /{if(f) exit}' "$SPEC")
in17() { case "$SEC17" in *"$2"*) printf '  ok    %-34s %s\n' "$1" "$2";;
                          *) printf '  FAIL  %-34s derived %s, not in §17\n' "$1" "$2"; fail=1;; esac; }

TOK=apps/authd/tokens.h
hrs() { grep -oE "#define $1[[:space:]]+\(([0-9]+)u \* 3600u\)" $TOK | grep -oE '\(([0-9]+)u' | tr -d '(u'; }
mins() { grep -oE "#define $1[[:space:]]+\(([0-9]+)u \* 60u\)" $TOK | grep -oE '\(([0-9]+)u' | tr -d '(u'; }
T_USER=$(hrs TOKEN_TTL_USER_S); T_OPER=$(hrs TOKEN_TTL_OPERATOR_S)
T_IDLE_USER=$(hrs TOKEN_IDLE_TTL_USER_S); T_IDLE_OPER=$(mins TOKEN_IDLE_TTL_OPERATOR_S)
req T_USER T_OPER T_IDLE_USER T_IDLE_OPER
in17 "token lifetime, user"       "$T_USER h"
in17 "token lifetime, operator"   "$T_OPER h"
in17 "token idle, user"           "$T_IDLE_USER h"
in17 "token idle, operator"       "$T_IDLE_OPER min"

RL=apps/authd/ratelimit.h
RL_MIN=$(hdr RATELIMIT_PER_MIN_DEFAULT $RL); RL_BURST=$(hdr RATELIMIT_BURST_DEFAULT $RL)
RL_GLOBAL=$(hdr RATELIMIT_GLOBAL_PER_SEC_DEF $RL); RL_CONNS=$(hdr RATELIMIT_MAX_CONNS_DEFAULT $RL)
req RL_MIN RL_BURST RL_GLOBAL RL_CONNS
in17 "rate_per_min default"       "\`rate_per_min\` $RL_MIN"
in17 "rate_burst default"         "\`rate_burst\` $RL_BURST"
in17 "rate_global_per_sec default" "default $RL_GLOBAL"
in17 "max_conns_per_addr default" "default $RL_CONNS"

ROT_DAYS=$(grep -oE '#define AUTHD_ROTATION_AGE_DEFAULT[[:space:]]+\(([0-9]+)u' apps/authd/authd_config.h | grep -oE '\(([0-9]+)u' | tr -d '(u')
LINE_MAX=$(hdr AUTHD_LINE_MAX apps/authd/conn_io.h); MAX_CONTENT=$(hdr AUTHD_MAX_CONTENT apps/authd/conn_io.h)
req ROT_DAYS LINE_MAX MAX_CONTENT
in17 "rotation cadence default"   "default $ROT_DAYS days"
in17 "local-socket line limit"    "$LINE_MAX B"
in17 "AUTHD_MAX_CONTENT"          "$MAX_CONTENT B"

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
req R_OPS R_CODES R_THRESH R_LOCK R_TTL R_BYTES R_CHARS R_MEM_MIB

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
            "ticket_ttl_s=RECOVERY_TICKET_TTL_S" \
            "recovery_use_per_sec=RECOVERY_USE_PER_SEC" "recovery_use_burst=RECOVERY_USE_BURST"; do
  f="${pair%%=*}"; c="${pair##*=}"
  if grep -qE "app\.$f[[:space:]]*=[[:space:]]*$c;" apps/authd/authd_main.c; then
    printf '  ok    %-34s %s\n' "daemon assigns $f" "$c"
  else
    printf '  FAIL  %-34s the daemon does not assign %s\n' "daemon assigns $f" "$c"; fail=1
  fi
done

# --- key-at-rest parameters by role, §12 (V4-13a) ---------------------------
# Three roles, three places in the tree: the server's in authd_cli.c (its only
# user), the operator's in cli_common.h (both CLIs), the browser's in
# client_core.h (the core the wasm build compiles). The text match is scoped
# to §12's "Parameters by role" sentence, which names all three -- "ops=3"
# alone appears twice in it, so a whole-file grep would pass on the wrong role.
mib() { grep -hoE "#define $1[[:space:]]+\(([0-9]+)u \* 1024u \* 1024u\)" $2 | grep -oE '\(([0-9]+)u' | head -1 | tr -d '(u'; }
S_OPS=$(hdr KDF_OPS_SERVER apps/authd/authd_cli.c)
O_OPS=$(hdr KDF_OPS_OPERATOR apps/authd/cli_common.h)
CLI_MEM=$(mib KDF_MEM_256MIB apps/authd/cli_common.h)
B_OPS=$(hdr CC_KDF_OPS_BROWSER apps/authd/client_core.h)
B_MEM=$(mib CC_KDF_MEM_BROWSER apps/authd/client_core.h)
req S_OPS O_OPS CLI_MEM B_OPS B_MEM
ROLES=$(grep -A3 -F '**Parameters by role:**' "$SPEC" | tr '\n' ' ' | tr -s ' ')
in_roles() { case "$ROLES" in *"$2"*) printf '  ok    %-34s %s\n' "$1" "$2";;
                              *) printf '  FAIL  %-34s derived %s, not in §12 by role\n' "$1" "$2"; fail=1;; esac; }
in_roles "KDF by role: server"   "server \`ops=$S_OPS, mem=$CLI_MEM MiB\`"
in_roles "KDF by role: operator" "operator \`ops=$O_OPS, mem=$CLI_MEM MiB\`"
in_roles "KDF by role: browser"  "browser \`ops=$B_OPS, mem=$B_MEM MiB\`"

# --- the browser module's compiler, §14 (V4-13b) -----------------------------
# The Emscripten version is pinned in CMakeLists.txt and stated in §14; the
# wasm KAT golden is only a contract for that compiler, so the two must agree.
EMV=$(grep -oE 'set\(MLDSA_EMSCRIPTEN_VERSION "[0-9.]+"\)' CMakeLists.txt | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
req EMV
S14=$(awk '/^## 14\. /{f=1} /^## 15\. /{f=0} f' "$SPEC" | tr '\n' ' ' | tr -s ' ')
case "$S14" in *"Emscripten $EMV"*) printf '  ok    %-34s %s\n' "browser module: Emscripten pin" "$EMV";;
               *) printf '  FAIL  %-34s CMakeLists pins %s, §14 does not say so\n' "browser module: Emscripten pin" "${EMV:-<none>}"; fail=1;; esac
# --- the passphrase policy, §14 (V4-13c) ------------------------------------
# Its numbers live in passphrase.h and the generated list; §14 states them.
PPH=apps/authd/passphrase.h
PP_CP=$(hdr PP_MIN_CODE_POINTS $PPH)
PP_BITS=$(hdr PP_MIN_BITS $PPH)
PP_N=$(grep -oE 'pp_common_count = [0-9]+u' apps/authd/passphrase_common.c | grep -oE '[0-9]+')
req PP_CP PP_BITS PP_N
PP_N_FMT=$(printf "%'d" "$PP_N" 2>/dev/null | tr -d ' '); case "$PP_N_FMT" in *,*) ;; *) PP_N_FMT=$(echo "$PP_N" | sed -E 's/([0-9])([0-9]{3})$/\1,\2/');; esac
in_s14() { case "$S14" in *"$2"*) printf '  ok    %-34s %s\n' "$1" "$2";;
                        *) printf '  FAIL  %-34s derived %s, not in §14\n' "$1" "$2"; fail=1;; esac; }
in_s14 "passphrase: minimum length"   "at least $PP_CP characters"
in_s14 "passphrase: estimate floor"   "at least $PP_BITS bits"
in_s14 "passphrase: common list size" "$PP_N_FMT entries"
# --- the pin's time floor, §7.3 and §17 (V4-67, erratum 53) ------------------
# The value comes from authd_conn.h; the spec states it in µs, bold in §7.3's
# paragraph and in §17's limits table.
FLOOR_NS=$(hdr AUTHD_PIN_FLOOR_NS apps/authd/authd_conn.h)
req FLOOR_NS
[ -n "$FLOOR_NS" ] || FLOOR_NS=0      # already reported; keeps the arithmetic below from aborting the script
FLOOR_US=$((FLOOR_NS / 1000))
S73=$(awk '/^### 7\.3 /{f=1} /^## 8\. /{f=0} f' "$SPEC" | tr '\n' ' ' | tr -s ' ')
case "$S73" in *"**$FLOOR_US µs**"*) printf '  ok    %-34s %s\n' "pin floor: §7.3" "$FLOOR_US µs";;
                *) printf '  FAIL  %-34s derived %s µs, not in §7.3\n' "pin floor: §7.3" "$FLOOR_US"; fail=1;; esac
check "pin floor: §17's table" "| The pin's time floor | $FLOOR_US µs"
echo "  ---"
[ "$fail" -eq 0 ] && echo "OK: every derived size appears in the specification" \
                 || echo "FAIL: the specification disagrees with the tree"
exit $fail
