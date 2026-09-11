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
    # Secret key starts after magic(8) + id_len(1) + id + public key(1952).
    off=$((8 + 1 + ${#who} + 1952))
    hex=$(od -An -tx1 -j "$off" -N 16 "$TMP/keys/$who.sk" | tr -d ' \n')
    [ "${#hex}" -eq 32 ] || fail "could not read the $who secret key prefix"
    if grep -qi "$hex" "$TMP/server.log" "$TMP/client.log"; then fail "$who secret key bytes found in a log"; fi
done
echo "PASS: E2E: no plaintext canary and no secret-key bytes in either log"

echo "All checks passed"
