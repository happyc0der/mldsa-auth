#!/bin/sh
# E2E (Step 6): the real auth_server / auth_client executables, two separate
# processes over loopback TCP.
#
#   demo_e2e.sh <path/to/auth_server> <path/to/auth_client>
#
# Keys, logs and the port file live only in a mktemp -d directory that is
# removed on exit; nothing is written under the repository.
set -eu

SERVER="$1"
CLIENT="$2"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/mldsa-e2e.XXXXXX")
SPID=""

cleanup() {
    if [ -n "$SPID" ]; then kill "$SPID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $1"
    for f in "$TMP/server.log" "$TMP/client.log"; do
        [ -f "$f" ] && { echo "--- $f"; cat "$f"; }
    done
    exit 1
}

"$SERVER" keygen --id e2e-server --dir "$TMP/keys" > /dev/null || fail "server keygen"
"$CLIENT" keygen --id e2e-client --dir "$TMP/keys" > /dev/null || fail "client keygen"
case "$(ls -l "$TMP/keys/e2e-server.sk")" in
    -rw-------*) echo "PASS: E2E: secret key file created with mode 0600" ;;
    *) fail "secret key file mode is not 0600" ;;
esac
for who in e2e-server e2e-client; do
    [ "$(head -c 8 "$TMP/keys/$who.sk")" = "MLDSASK2" ] || fail "$who.sk is not an MLDSASK2 file"
    [ "$(wc -c < "$TMP/keys/$who.sk" | tr -d ' ')" -eq $((6025 + ${#who})) ] || fail "$who.sk size is not 6025 + id_len"
done
echo "PASS: E2E: keygen writes MLDSASK2 secret key files (6025 + id_len bytes)"

"$SERVER" serve --id e2e-server --key "$TMP/keys/e2e-server.sk" \
    --pin "e2e-client=$TMP/keys/e2e-client.pub" \
    --port 0 --port-file "$TMP/port" --once > "$TMP/server.log" 2>&1 &
SPID=$!

i=0
while [ ! -s "$TMP/port" ]; do
    i=$((i + 1))
    [ "$i" -gt 200 ] && fail "server did not publish its port"
    sleep 0.05
done
case "$(ls -l "$TMP/port")" in
    -rw-------*) echo "PASS: E2E: port file published with mode 0600" ;;
    *) fail "port file mode is not 0600" ;;
esac
PORT=$(cat "$TMP/port")

"$CLIENT" connect --id e2e-client --key "$TMP/keys/e2e-client.sk" \
    --peer "e2e-server=$TMP/keys/e2e-server.pub" --port "$PORT" \
    --message "E2E-CANARY-PLAINTEXT-ONE" --message "E2E-CANARY-PLAINTEXT-TWO" \
    > "$TMP/client.log" 2>&1 || fail "client exited nonzero"
echo "PASS: E2E: client exited 0"

if wait "$SPID"; then SPID=""; else SPID=""; fail "server exited nonzero"; fi
echo "PASS: E2E: server exited 0"

[ ! -e "$TMP/port" ] || fail "server did not remove its port file"
echo "PASS: E2E: server removed its port file"

[ "$(grep -c 'authenticated echo verified' "$TMP/client.log")" -eq 2 ] || fail "expected 2 verified echoes"
grep -q 'GOODBYE exchanged' "$TMP/client.log" || fail "client saw no GOODBYE"
grep -q 'GOODBYE exchanged' "$TMP/server.log" || fail "server saw no GOODBYE"
echo "PASS: E2E: two authenticated echoes and GOODBYE on both sides"

if grep -q 'E2E-CANARY' "$TMP/server.log" "$TMP/client.log"; then fail "plaintext canary found in a log"; fi
for who in e2e-server e2e-client; do
    # Secret key starts after magic(8) + id_len(1) + id + public key(1952)
    # (same offset in MLDSASK2; the 32-byte digest follows the secret key).
    off=$((8 + 1 + ${#who} + 1952))
    hex=$(od -An -tx1 -j "$off" -N 16 "$TMP/keys/$who.sk" | tr -d ' \n')
    [ "${#hex}" -eq 32 ] || fail "could not read the $who secret key prefix"
    if grep -qi "$hex" "$TMP/server.log" "$TMP/client.log"; then fail "$who secret key bytes found in a log"; fi
done
echo "PASS: E2E: no plaintext canary and no secret-key bytes in either log"

# --- Second run: asymmetric record padding (V2-7) --------------------------
# The server pads to 4096 and the client not at all, so the client accepts a
# 4121-byte confirmation record while its own records stay unpadded. Neither
# peer is told the other's bucket; this is that property over real sockets.
"$SERVER" serve --id e2e-server --key "$TMP/keys/e2e-server.sk" \
    --pin "e2e-client=$TMP/keys/e2e-client.pub" \
    --port 0 --port-file "$TMP/port2" --once --pad-bucket 4096 \
    > "$TMP/server2.log" 2>&1 &
SPID=$!

i=0
while [ ! -s "$TMP/port2" ]; do
    i=$((i + 1))
    [ "$i" -gt 200 ] && fail "padded server did not publish its port"
    sleep 0.05
done
PORT2=$(cat "$TMP/port2")

"$CLIENT" connect --id e2e-client --key "$TMP/keys/e2e-client.sk" \
    --peer "e2e-server=$TMP/keys/e2e-server.pub" --port "$PORT2" --pad-bucket 1 \
    --message "E2E-CANARY-PADDED-RUN" \
    > "$TMP/client2.log" 2>&1 || fail "padded client exited nonzero"
if wait "$SPID"; then SPID=""; else SPID=""; fail "padded server exited nonzero"; fi
echo "PASS: E2E: padded run (server bucket 4096, client bucket 1) -- both exited 0"

grep -q 'record padding: bucket 4096' "$TMP/server2.log" || fail "server did not apply --pad-bucket 4096"
grep -q 'record padding: bucket 1' "$TMP/client2.log" || fail "client did not apply --pad-bucket 1"
echo "PASS: E2E: each side reports the bucket it was given (the flag reached the session)"

[ "$(grep -c 'authenticated echo verified' "$TMP/client2.log")" -eq 1 ] || fail "padded run: expected 1 echo"
grep -q 'GOODBYE exchanged' "$TMP/client2.log" || fail "padded run: client saw no GOODBYE"
grep -q 'GOODBYE exchanged' "$TMP/server2.log" || fail "padded run: server saw no GOODBYE"
echo "PASS: E2E: padded run completed an authenticated echo and GOODBYE"

if grep -q 'E2E-CANARY' "$TMP/server2.log" "$TMP/client2.log"; then fail "padded run: plaintext canary in a log"; fi
for who in e2e-server e2e-client; do
    off=$((8 + 1 + ${#who} + 1952))
    hex=$(od -An -tx1 -j "$off" -N 16 "$TMP/keys/$who.sk" | tr -d ' \n')
    if grep -qi "$hex" "$TMP/server2.log" "$TMP/client2.log"; then fail "padded run: $who secret key bytes in a log"; fi
done
echo "PASS: E2E: padded run leaked no canary and no secret-key bytes"

# --- Third run: legacy key migration (V2-9) --------------------------------
# A Step 6 MLDSASK1 file is the MLDSASK2 file without its 32-byte digest and
# with the legacy magic. migrate-key converts it to a NEW file; the identity
# survives, so the client's ORIGINAL pinned public key still authenticates.
SK="$TMP/keys/e2e-server.sk"
LEG="$TMP/keys/legacy-server.sk"
MIG="$TMP/keys/migrated-server.sk"
N=$(wc -c < "$SK" | tr -d ' ')
BODY=$((N - 32))
printf 'MLDSASK1' > "$LEG"
dd if="$SK" bs=1 skip=8 count=$((BODY - 8)) >> "$LEG" 2>/dev/null
chmod 600 "$LEG"
[ "$(wc -c < "$LEG" | tr -d ' ')" -eq "$BODY" ] || fail "legacy fixture is not 5993 + id_len bytes"
LEG_BEFORE=$(shasum -a 256 < "$LEG")

"$SERVER" migrate-key --id e2e-server --in "$LEG" --out "$MIG" > "$TMP/migrate.log" 2> "$TMP/migrate.err" \
    || fail "migrate-key exited nonzero"
grep -q 'integrity CANNOT be verified' "$TMP/migrate.err" || fail "migrate-key printed no integrity warning"
grep -q 'no integrity digest' "$TMP/migrate.err" || fail "migrate-key did not say the source has no digest"
echo "PASS: E2E: migrate-key converted a legacy file and warned that its integrity cannot be verified"

[ "$(head -c 8 "$MIG")" = "MLDSASK2" ] || fail "migrated file is not MLDSASK2"
[ "$(wc -c < "$MIG" | tr -d ' ')" -eq "$N" ] || fail "migrated file size is not 6025 + id_len"
case "$(ls -l "$MIG")" in -rw-------*) : ;; *) fail "migrated file mode is not 0600" ;; esac
[ "$(shasum -a 256 < "$LEG")" = "$LEG_BEFORE" ] || fail "migrate-key modified its input"
echo "PASS: E2E: the migrated file is MLDSASK2 (0600, 6025 + id_len) and the source is unmodified"

"$SERVER" migrate-key --id e2e-server --in "$LEG" --out "$MIG" > /dev/null 2>&1 \
    && fail "migrate-key overwrote an existing --out"
"$SERVER" migrate-key --id e2e-client --in "$LEG" --out "$TMP/keys/wrong.sk" > /dev/null 2>&1 \
    && fail "migrate-key accepted the wrong --id"
[ ! -e "$TMP/keys/wrong.sk" ] || fail "a refused migration left an output file"
echo "PASS: E2E: migrate-key refuses to clobber --out and refuses the wrong --id"

# The identity survived: serve with the MIGRATED key, pin the ORIGINAL public key.
"$SERVER" serve --id e2e-server --key "$MIG" \
    --pin "e2e-client=$TMP/keys/e2e-client.pub" \
    --port 0 --port-file "$TMP/port3" --once > "$TMP/server3.log" 2>&1 &
SPID=$!

i=0
while [ ! -s "$TMP/port3" ]; do
    i=$((i + 1))
    [ "$i" -gt 200 ] && fail "migrated-key server did not publish its port"
    sleep 0.05
done
PORT3=$(cat "$TMP/port3")

"$CLIENT" connect --id e2e-client --key "$TMP/keys/e2e-client.sk" \
    --peer "e2e-server=$TMP/keys/e2e-server.pub" --port "$PORT3" \
    --message "E2E-CANARY-MIGRATED-RUN" \
    > "$TMP/client3.log" 2>&1 || fail "client against the migrated key exited nonzero"
if wait "$SPID"; then SPID=""; else SPID=""; fail "migrated-key server exited nonzero"; fi

[ "$(grep -c 'authenticated echo verified' "$TMP/client3.log")" -eq 1 ] || fail "migrated run: expected 1 echo"
grep -q 'GOODBYE exchanged' "$TMP/client3.log" || fail "migrated run: client saw no GOODBYE"
echo "PASS: E2E: the migrated key authenticates against the ORIGINAL pinned public key (identity preserved)"

if grep -q 'E2E-CANARY' "$TMP/server3.log" "$TMP/client3.log"; then fail "migrated run: plaintext canary in a log"; fi
for who in e2e-server e2e-client; do
    off=$((8 + 1 + ${#who} + 1952))
    hex=$(od -An -tx1 -j "$off" -N 16 "$TMP/keys/$who.sk" | tr -d ' \n')
    if grep -qi "$hex" "$TMP/server3.log" "$TMP/client3.log" "$TMP/migrate.log" "$TMP/migrate.err"; then
        fail "migrated run: $who secret key bytes in a log"
    fi
done
echo "PASS: E2E: migrated run leaked no canary and no secret-key bytes"

echo "All checks passed"
