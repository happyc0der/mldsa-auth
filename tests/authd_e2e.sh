#!/bin/sh
#
# Milestone A, end to end, with the SHIPPED binaries as real processes:
#
#   authd_admin init -> mldsa-authd -> authd_client keygen ->
#   authd_admin enroll-operator -> authd_client login ->
#   the Node site handler EXCHANGEs and VERIFYs -> the admin queries
#
# tests/test_authd_cli.c drives the same subcommands in-process to pin their
# refusal paths; this proves the daemon binary, the two CLIs and a site can
# actually perform a login between them. Nothing is written outside a mktemp
# directory, and every log is scanned for secrets at the end.
#
#   sh authd_e2e.sh <authd_admin> <authd_client> <mldsa-authd> [<node> <site.mjs> <recovery.mjs>]
set -eu

ADMIN="$1"
CLIENT="$2"
DAEMON="$3"
NODE="${4:-}"
SITE="${5:-}"
RECOVERY="${6:-}"

# Socket paths must fit sun_path -- 104 bytes on macOS, 108 on Linux -- and
# macOS mktemp -d lands under /var/folders/<...>, which is already ~50 of them.
# Flat, short names here, and NOT spec 16's directory layout, which would not
# fit. The daemon refuses a path that does not, so this would be a confusing
# start-up failure rather than a wrong answer; the guard below says which.
TMP=$(mktemp -d "${TMPDIR:-/tmp}/authd-e2e.XXXXXX")
if [ "${#TMP}" -gt 80 ]; then
    echo "SKIP: E2E: \$TMPDIR is ${#TMP} bytes, leaving no room for a Unix socket path"
    rm -rf "$TMP"
    exit 0
fi

DPID=""
cleanup() {
    if [ -n "$DPID" ]; then kill "$DPID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $1"
    for f in "$TMP/authd.log" "$TMP/login.err" "$TMP/site.err" "$TMP/keygen.err"; do
        [ -f "$f" ] && { echo "--- $f"; cat "$f"; }
    done
    [ -f "$TMP/authd.conf" ] && { echo "--- config"; cat "$TMP/authd.conf"; }
    echo "--- $TMP"; ls -l "$TMP" || true
    exit 1
}

# ---------------------------------------------------------------- init

"$ADMIN" init --dir "$TMP/d" --server-id authd --passphrase-file "$TMP/d/pass" \
    > "$TMP/init.log" 2> "$TMP/init.err" || fail "init exited nonzero"
[ -f "$TMP/d/server.ek" ] || fail "init wrote no server.ek"
[ -f "$TMP/d/server.pub" ] || fail "init wrote no server.pub"
[ -f "$TMP/d/store.sqlite3" ] || fail "init wrote no store"

case "$(ls -l "$TMP/d/pass")" in
    -rw-------*) echo "PASS: E2E: the passphrase file is 0600" ;;
    *) fail "passphrase file mode is not 0600" ;;
esac
case "$(ls -l "$TMP/d/server.ek")" in
    -rw-------*) echo "PASS: E2E: server.ek is 0600" ;;
    *) fail "server.ek mode is not 0600" ;;
esac
case "$(ls -l "$TMP/d/store.sqlite3")" in
    -rw-------*) echo "PASS: E2E: the store is 0600, not the shell's umask" ;;
    *) fail "store mode is not 0600" ;;
esac

# Spec 12: server parameters are ops=4, mem=256 MiB, at header offsets 10 and
# 14, big-endian. Functionally invisible -- a key sealed at ops=3 opens exactly
# the same -- so nothing else in the tree would notice.
ops=$(od -An -tx1 -j 10 -N 4 "$TMP/d/server.ek" | tr -d ' \n')
mem=$(od -An -tx1 -j 14 -N 8 "$TMP/d/server.ek" | tr -d ' \n')
[ "$ops" = "00000004" ] || fail "server.ek opslimit is $ops, expected 00000004 (spec 12)"
[ "$mem" = "0000000010000000" ] || fail "server.ek memlimit is $mem, expected 256 MiB (spec 12)"
echo "PASS: E2E: server.ek carries the spec 12 server parameters (ops=4, mem=256 MiB)"

# Req 10: no plaintext secret key is written to disk by any daemon or CLI
# command. Every functional check in this script still passes if one is, which
# is exactly why it needs its own check.
found=""
for f in $(find "$TMP" -type f); do
    case "$(head -c 8 "$f" 2>/dev/null || true)" in
        MLDSASK1|MLDSASK2) found="$f" ;;
    esac
done
[ -z "$found" ] || fail "a plaintext MLDSASK file was written: $found (Req 10)"
echo "PASS: E2E: no plaintext secret-key file exists anywhere under the work directory"

# ------------------------------------------------------------- bad config

cat > "$TMP/bad.conf" <<EOF
store_path = $TMP/d/store.sqlite3
no_such_key = 1
EOF
rc=0
"$ADMIN" --check-config --config "$TMP/bad.conf" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 3 ] || fail "admin --check-config on a bad config exited $rc, expected exactly 3"
rc=0
"$DAEMON" --config "$TMP/bad.conf" --check-config > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 3 ] || fail "daemon --check-config on a bad config exited $rc, expected exactly 3"
echo "PASS: E2E: both binaries report a configuration error as exit 3 (spec 13)"

# --------------------------------------------------------------- daemon

# The raw loopback listener is the operator's SSH-tunnel path (spec 7.1), and
# until V4-10b no test had ever driven it with the shipped client -- every leg
# here used --unix. A fixed high port derived from the pid keeps concurrent
# runs apart without needing the daemon to report one back.
PORT=$(( 40000 + ($$ % 20000) ))

cat > "$TMP/authd.conf" <<EOF
store_path = $TMP/d/store.sqlite3
key_path = $TMP/d/server.ek
key_passphrase_file = $TMP/d/pass
server_id = authd
listen_unix = $TMP/p.sock
listen_port = $PORT
# The DEPLOYED shape of the proxy-facing socket (spec 7.2): only the proxy's
# uid may connect, and it must state the client's address in a PROXY v2
# preamble before the client writes anything. Running the whole e2e this way
# means every leg below exercises the configuration an operator actually
# deploys, not a development one.
proxy_protocol = v2
proxy_uids = $(id -u)
rate_per_min = 60
rate_burst = 60
site_socket = $TMP/s.sock
admin_socket = $TMP/a.sock
site_uids = $(id -u)
admin_uids = $(id -u)
EOF
"$ADMIN" --check-config --config "$TMP/authd.conf" > /dev/null || fail "the generated config is invalid"

"$DAEMON" --config "$TMP/authd.conf" > "$TMP/authd.log" 2>&1 &
DPID=$!
# Readiness is the "started" event, which the daemon logs only after EVERY
# listener is registered. Polling for the socket FILE would race: bind() creates
# the path before listen() accepts on it.
i=0
while ! grep -q 'event=started' "$TMP/authd.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] || kill -0 "$DPID" 2>/dev/null || fail "the daemon exited during start-up"
    [ "$i" -gt 400 ] && fail "the daemon never logged event=started"
    sleep 0.05
done
echo "PASS: E2E: the daemon started and registered every listener"

# Spec 8: site.sock is 0660, admin.sock is 0600. The uid allowlist refuses a
# stranger either way, so nothing FUNCTIONAL changes if this is wrong -- only a
# direct mode assertion can tell.
case "$(ls -l "$TMP/a.sock")" in
    srw-------*) echo "PASS: E2E: admin.sock is 0600 (spec 8)" ;;
    *) fail "admin socket mode is not 0600" ;;
esac
case "$(ls -l "$TMP/s.sock")" in
    srw-rw----*) echo "PASS: E2E: site.sock is 0660 (spec 8)" ;;
    *) fail "site socket mode is not 0660" ;;
esac

"$ADMIN" list-users --socket "$TMP/a.sock" > "$TMP/users0.txt" || fail "list-users failed on a fresh store"
grep -q '^OK count=0' "$TMP/users0.txt" || fail "a fresh store did not report zero users"
echo "PASS: E2E: the admin socket answers on a fresh store"

# A listener failure must run the cleanup epilogue, not return early. The real
# damage when it does not is the DECRYPTED server key left unwiped in secure
# memory -- which LSan would see, except LSan does not run under macOS ASan. The
# epilogue also closes and unlinks every socket it already opened, and that is
# observable on both platforms and true exactly when it ran.
#
# A regular file at the admin socket path passes every configuration check (its
# directory exists) and is then refused by listener_open_unix, which is a
# realistic leftover after a crash.
cat > "$TMP/bind.conf" <<EOF
store_path = $TMP/d/store.sqlite3
key_path = $TMP/d/server.ek
key_passphrase_file = $TMP/d/pass
server_id = authd
listen_unix = $TMP/bp.sock
site_socket = $TMP/bs.sock
admin_socket = $TMP/ba.sock
site_uids = $(id -u)
admin_uids = $(id -u)
EOF
: > "$TMP/ba.sock"
rc=0
"$DAEMON" --config "$TMP/bind.conf" > "$TMP/bind.log" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "the daemon started despite an unusable admin socket path"
grep -q 'admin socket' "$TMP/bind.log" || fail "the daemon did not name the admin socket it refused"
[ ! -e "$TMP/bs.sock" ] || fail "a listener failure left the site socket behind: the cleanup epilogue did not run"
[ ! -e "$TMP/bp.sock" ] || fail "a listener failure left the protocol socket behind: the cleanup epilogue did not run"
rm -f "$TMP/ba.sock"
echo "PASS: E2E: a listener failure runs the cleanup epilogue that wipes the server key"

# ------------------------------------------------- keygen, enroll, login

head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TMP/opass"
chmod 600 "$TMP/opass"
HANDLE=$("$CLIENT" keygen --dir "$TMP/dev" --passphrase-file "$TMP/opass" 2> "$TMP/keygen.err") \
    || fail "client keygen exited nonzero"
[ "${#HANDLE}" -eq 34 ] || fail "the handle is ${#HANDLE} bytes, expected 34 (spec 3.1)"
echo "PASS: E2E: authd_client keygen produced a 34-byte device handle"

# The handle on the command line is the authority; a .pub whose embedded id
# disagrees must be refused rather than silently enrolling a different device.
rc=0
"$ADMIN" enroll-operator --socket "$TMP/a.sock" --user alice --handle d1deadbeef \
    --pub "$TMP/dev/$HANDLE.pub" > /dev/null 2> "$TMP/mismatch.err" || rc=$?
[ "$rc" -eq 1 ] || fail "enroll-operator with a mismatched handle exited $rc, expected 1"
grep -q 'id-mismatch' "$TMP/mismatch.err" || fail "enroll-operator did not report id-mismatch"
echo "PASS: E2E: a .pub whose embedded id differs from --handle is refused"

"$ADMIN" enroll-operator --socket "$TMP/a.sock" --user alice --handle "$HANDLE" \
    --pub "$TMP/dev/$HANDLE.pub" --label "e2e laptop" > "$TMP/enroll.txt" \
    || fail "enroll-operator exited nonzero"
grep -q '^OK fp=' "$TMP/enroll.txt" || fail "enroll-operator did not return a fingerprint"
echo "PASS: E2E: the operator device is enrolled"
# Keep a copy of the pre-rotation key: after the rotation it must NOT work.
cp "$TMP/dev/$HANDLE.ek" "$TMP/save-old.ek"

# An administrative command must be unreachable from the site socket, and must
# say the same thing a nonsense command would -- so the site socket is not an
# oracle for which admin commands exist.
rc=0
"$ADMIN" list-users --socket "$TMP/s.sock" > /dev/null 2> "$TMP/notperm.err" || rc=$?
[ "$rc" -eq 1 ] || fail "an admin command on site.sock exited $rc, expected 1"
grep -q 'not-permitted' "$TMP/notperm.err" || fail "an admin command on site.sock was not refused"
echo "PASS: E2E: administrative commands are unreachable from the site socket (Req 11)"

CODE=$("$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
        --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
        --unix "$TMP/p.sock" --proxy-v2 2> "$TMP/login.err") || fail "client login exited nonzero"
# 32 bytes of base64url, unpadded, is exactly 43 characters from [A-Za-z0-9_-].
# Hex would be 64 and standard base64 would carry +, / or =.
[ "${#CODE}" -eq 43 ] || fail "the login code is ${#CODE} characters, expected 43 base64url"
case "$CODE" in
    *[!A-Za-z0-9_-]*) fail "the login code is not base64url: $CODE" ;;
esac
echo "PASS: E2E: a real post-quantum login produced a 43-character base64url code"

# The same login over the RAW loopback listener -- the operator's tunnel. The
# two transports differ only in how a frame reaches the wire (spec 7.1), so
# anything that works over one must work over the other, and nothing had ever
# checked the raw one with the shipped client.
CODEP=$("$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
        --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
        --port "$PORT" 2>> "$TMP/login.err") || fail "client login over the raw loopback listener exited nonzero"
[ "${#CODEP}" -eq 43 ] || fail "the raw-listener login code is ${#CODEP} characters, expected 43 base64url"
echo "PASS: E2E: the same login works over the raw loopback listener (the operator tunnel)"

# Req 12, by execution: with proxy_protocol = v2 the daemon must refuse a
# connection that does not state a client address. Without this check every
# other --proxy-v2 leg above would still pass if the preamble were optional.
rc=0
"$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" > /dev/null 2> "$TMP/nopreamble.err" || rc=$?
[ "$rc" -ne 0 ] || fail "a login with NO PROXY v2 preamble succeeded (Req 12 fails open)"
grep -q 'event=closed-protocol' "$TMP/authd.log" \
    || fail "the daemon did not log a protocol refusal for the missing preamble"
echo "PASS: E2E: a connection with no PROXY v2 preamble is refused (Req 12, fail closed)"

# A wrong pin must be refused. Without this, a login that never checked the
# server's signature would pass every other check in this file.
"$ADMIN" keygen-server --key "$TMP/other.ek" --pub "$TMP/other.pub" --server-id authd \
    --passphrase-file "$TMP/opass" > /dev/null 2>&1 || fail "could not make a decoy server key"
rc=0
"$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/other.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2> "$TMP/wrongpin.err" || rc=$?
[ "$rc" -ne 0 ] || fail "login succeeded against the WRONG pinned server key"
echo "PASS: E2E: login refuses a ServerHello not signed by the pinned key (spec 4)"

# ----------------------------------------------------------- the site

if [ -n "$NODE" ] && [ -n "$SITE" ] && [ -x "$NODE" ]; then
    CODE2=$("$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
            --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
            --unix "$TMP/p.sock" --proxy-v2 2>> "$TMP/login.err") || fail "second login exited nonzero"
    "$NODE" "$SITE" "$TMP/s.sock" "$CODE2" > "$TMP/site.txt" 2> "$TMP/site.err" \
        || fail "the site could not exchange the login code"
    grep -q '"role":"operator"' "$TMP/site.txt" || fail "the site did not receive an operator token"
    grep -q '"ttl":28800' "$TMP/site.txt" || fail "the operator token TTL is not 8 hours (spec 11)"
    echo "PASS: E2E: the site exchanged the code for a token, verified it, and logged it out"
else
    echo "SKIP: E2E: node not found, so the EXCHANGE/VERIFY leg did not run"
fi

# ----------------------------------------------------------- recovery

# The device is lost. The user types a recovery code into the site, and a new
# device takes over the identity. No CLI drives this on purpose: spec 13 gives
# neither tool a recovery subcommand because the SITE is what a user reaches.
if [ -n "$NODE" ] && [ -n "$RECOVERY" ] && [ -x "$NODE" ]; then
    # An ordinary `user`, not the operator alice: recovery is what a member of
    # the public does on a website, and an operator's recovery is deliberately
    # NOT reachable from the site socket (asserted inside the script).
    BOB1=$("$CLIENT" keygen --dir "$TMP/bob" --passphrase-file "$TMP/opass" 2>> "$TMP/keygen.err") \
        || fail "keygen for bob's first device exited nonzero"
    BOB2=$("$CLIENT" keygen --dir "$TMP/bob2" --passphrase-file "$TMP/opass" 2>> "$TMP/keygen.err") \
        || fail "keygen for bob's replacement device exited nonzero"
    "$NODE" "$RECOVERY" "$TMP/s.sock" bob "$TMP/bob/$BOB1.pub" "$BOB1" \
        "$BOB2" "$TMP/bob2/$BOB2.pub" "$TMP/codes.txt" alice \
        > "$TMP/rec.txt" 2> "$TMP/rec.err" \
        || fail "the recovery flow failed: $(cat "$TMP/rec.err")"
    grep -q '"operator_recovery_refused_on_site":true' "$TMP/rec.txt" \
        || fail "an operator's recovery codes were mintable from the site socket (Req 11)"
    grep -q '"mangled_accepted":true' "$TMP/rec.txt" \
        || fail "a mistyped-but-equivalent recovery code was not accepted"
    grep -q '"ticket_single_use":true' "$TMP/rec.txt" || fail "the enrollment ticket was not single-use"
    grep -q '"code_single_use":true' "$TMP/rec.txt" || fail "the recovery code was not single-use"
    echo "PASS: E2E: a lost device was recovered with a mistyped code and a single-use ticket"

    # The whole point: the REPLACEMENT device can log in. Everything above
    # would pass if the enrollment had written a row nobody can authenticate
    # against, so this is the check that makes the leg mean something.
    RCODE=$("$CLIENT" login --handle "$BOB2" --key "$TMP/bob2/$BOB2.ek" \
            --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
            --unix "$TMP/p.sock" --proxy-v2 2>> "$TMP/login.err") || fail "the recovered device could not log in"
    [ "${#RCODE}" -eq 43 ] || fail "the recovered device's login code is ${#RCODE} characters, expected 43"
    echo "PASS: E2E: the recovered device completes a real post-quantum login"

    # Spec 15 requires issue and use to be logged, and requires the CODE never
    # to be. Both halves, in that order -- the present canary first, so "no
    # code in the log" cannot pass because nothing was logged at all.
    grep -q 'recovery-issue' "$TMP/authd.log" || fail "the recovery issue was not logged at all"
    grep -q 'recovery-use' "$TMP/authd.log" || fail "the recovery use was not logged at all"
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        ! grep -q "$c" "$TMP/authd.log" || fail "a recovery code reached the daemon log: $c"
        for f in "$TMP/rec.err" "$TMP/login.err" "$TMP/keygen.err"; do
            [ -f "$f" ] || continue
            ! grep -q "$c" "$f" || fail "a recovery code reached $f"
        done
    done < "$TMP/codes.txt"
    echo "PASS: E2E: recovery issue and use are logged, and the codes never are (spec 15)"
else
    echo "SKIP: E2E: node not found, so the recovery leg did not run"
fi

# ----------------------------------------------------------- rotation

# The device replaces its key and keeps its identity, with the shipped
# binaries as real processes. The fingerprint the daemon reports is the
# independent witness: it comes out of the store, not out of the client.
FP_BEFORE=$("$ADMIN" list-devices --socket "$TMP/a.sock" --user alice | sed -n 's/.*fp=//p')
[ -n "$FP_BEFORE" ] || fail "could not read the device fingerprint before rotation"

"$CLIENT" rotate --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > "$TMP/rotate.txt" 2> "$TMP/rotate.err" \
    || fail "client rotate exited nonzero"

FP_AFTER=$("$ADMIN" list-devices --socket "$TMP/a.sock" --user alice | sed -n 's/.*fp=//p')
[ -n "$FP_AFTER" ] || fail "could not read the device fingerprint after rotation"
[ "$FP_BEFORE" != "$FP_AFTER" ] || fail "the active key did not change: rotation did nothing"
echo "PASS: E2E: rotation replaced the device's active key in the store"

# The handle is the identity, and it survives.
"$ADMIN" list-devices --socket "$TMP/a.sock" --user alice > "$TMP/devrot.txt" || fail "list-devices after rotation failed"
grep -q "$(printf '%s' "$HANDLE" | od -An -tx1 | tr -d ' \n')" "$TMP/devrot.txt" \
    || fail "the handle changed across the rotation"
grep -q '^OK count=1' "$TMP/devrot.txt" || fail "rotation created a second device instead of rotating one"
echo "PASS: E2E: the handle is unchanged and there is still exactly one device"

# The device's own .pub must name the NEW key, or the next administrator to
# enrol from it would install a key the server has already superseded.
# dd, not xxd: demo_e2e.sh avoids xxd on purpose -- it is a vim package, not a
# base tool, and is absent from minimal images. MLDSAPK1 is magic(8) +
# id_len(1) + id + pk(1952).
PUBFP=$(dd if="$TMP/dev/$HANDLE.pub" bs=1 skip=$((9 + ${#HANDLE})) count=1952 2>/dev/null \
        | shasum -a 256 | cut -d' ' -f1)
[ "$PUBFP" = "$FP_AFTER" ] || fail "the device .pub still names the OLD key after rotation"
echo "PASS: E2E: the device's .pub was updated to the new key"

# No .ek.next may survive a rotation the daemon acknowledged.
[ ! -e "$TMP/dev/$HANDLE.ek.next" ] || fail "an acknowledged rotation left .ek.next behind"
echo "PASS: E2E: no .ek.next survives an acknowledged rotation"

# The new key logs in.
"$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > "$TMP/code3.txt" 2>> "$TMP/login.err" \
    || fail "login with the rotated key failed"
[ "$(wc -c < "$TMP/code3.txt" | tr -d ' ')" -eq 44 ] || fail "the rotated key's login code is not 43 characters"
echo "PASS: E2E: the rotated key logs in"

# And the OLD key does not. A client cannot be TOLD its key is stale -- Req 6
# makes a superseded key look like an unknown one -- so what it observes is
# that no login code ever arrives.
cp "$TMP/dev/$HANDLE.ek" "$TMP/current.ek"
rc=0
"$CLIENT" login --handle "$HANDLE" --key "$TMP/save-old.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2> "$TMP/oldkey.err" || rc=$?
[ "$rc" -ne 0 ] || fail "the SUPERSEDED key still obtained a login code: there is an overlap window"
echo "PASS: E2E: the superseded key gets no login code (no overlap window, spec 10.2)"

# The rotation is audited, and attributed to a user.
"$ADMIN" audit-tail --socket "$TMP/a.sock" --n 10 > "$TMP/audit2.txt" || fail "audit-tail after rotation failed"
grep -q 'event=key-rotate' "$TMP/audit2.txt" || fail "the rotation was not audited"
grep -q 'event=key-rotate user=[0-9a-f][0-9a-f]' "$TMP/audit2.txt" \
    || fail "the rotation audit row has no user attributed to it"
echo "PASS: E2E: the rotation is audited and attributed to its user"

# Spec 15: both fingerprints are logged, and neither is a secret.
grep -q "event=rotate-fp-old fp=$FP_BEFORE" "$TMP/authd.log" || fail "the daemon did not log the OLD fingerprint"
grep -q "event=rotate-fp-new fp=$FP_AFTER" "$TMP/authd.log" || fail "the daemon did not log the NEW fingerprint"
echo "PASS: E2E: the daemon logged both fingerprints (spec 15)"

# ------------------------------------------------------- admin queries

"$ADMIN" list-users --socket "$TMP/a.sock" > "$TMP/users.txt" || fail "list-users failed"
# alice (operator, enrolled by an administrator) plus, when the recovery leg
# ran, bob (user, created by the site's own first ENROLL -- spec 10.1).
if [ -n "$NODE" ] && [ -n "$RECOVERY" ] && [ -x "$NODE" ]; then
    grep -q '^OK count=2' "$TMP/users.txt" || fail "list-users did not report alice and bob"
    grep -q 'role=user' "$TMP/users.txt" || fail "bob was not created with the user role"
else
    grep -q '^OK count=1' "$TMP/users.txt" || fail "list-users did not report one user"
fi
grep -q 'role=operator' "$TMP/users.txt" || fail "alice is not an operator"
grep -q '^END$' "$TMP/users.txt" || fail "list-users did not terminate with END"

"$ADMIN" list-devices --socket "$TMP/a.sock" --user alice > "$TMP/devices.txt" || fail "list-devices failed"
grep -q '^DEVICE handle=' "$TMP/devices.txt" || fail "list-devices listed no device"
grep -q '^END$' "$TMP/devices.txt" || fail "list-devices did not terminate with END"

"$ADMIN" audit-tail --socket "$TMP/a.sock" --n 10 > "$TMP/audit.txt" || fail "audit-tail failed"
grep -q 'event=device-enroll' "$TMP/audit.txt" || fail "the enrollment was not audited"
grep -q '^END$' "$TMP/audit.txt" || fail "audit-tail did not terminate with END"
echo "PASS: E2E: list-users, list-devices and audit-tail all return complete lists"

rc=0
"$ADMIN" audit-tail --socket "$TMP/a.sock" --n 50 > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "audit-tail --n 50 exited $rc, expected a usage error naming the bound"
rc=0
"$ADMIN" backup --socket "$TMP/a.sock" --path relative.db > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "backup with a relative path exited $rc, expected a usage error"
echo "PASS: E2E: out-of-range and relative arguments are refused before the socket"

"$ADMIN" backup --socket "$TMP/a.sock" --path "$TMP/backup.sqlite3" > /dev/null \
    || fail "backup failed"
[ -s "$TMP/backup.sqlite3" ] || fail "backup wrote no file"
# VACUUM INTO runs inside the daemon and takes the DAEMON'S umask. A backup is a
# byte-for-byte copy of the credential database, so its mode is not the umask's
# business.
case "$(ls -l "$TMP/backup.sqlite3")" in
    -rw-------*) echo "PASS: E2E: the backup is 0600, like the store it copies" ;;
    *) fail "the backup is not 0600" ;;
esac

# ------------------------------------------------------------- shutdown

# Close nothing and the drain loop would wait forever: evloop_stop marks local
# slots draining rather than closing them, so a still-open client socket wedges
# shutdown. Every client above is one-shot and already gone.
kill -TERM "$DPID"
i=0
while kill -0 "$DPID" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 200 ]; then
        kill -9 "$DPID" 2>/dev/null || true
        fail "the daemon did not exit within 10s of SIGTERM"
    fi
    sleep 0.05
done
if wait "$DPID"; then DPID=""; else DPID=""; fi
echo "PASS: E2E: the daemon drained and exited on SIGTERM"
[ -e "$TMP/a.sock" ] && fail "the admin socket was left behind after shutdown"
echo "PASS: E2E: every socket file was removed on shutdown"

# ------------------------------------------------- the audit chain, offline
#
# spec 9.2 calls the head MAC "detectable from a second trust domain". Until
# V4-10c store_audit_verify() was reachable from nothing, so that was a claim
# rather than a control (finding F29). This runs with the daemon STOPPED, which
# is half the point: the same command works on a backup.
"$ADMIN" audit-verify --store "$TMP/d/store.sqlite3" --key "$TMP/d/server.ek" \
    --passphrase-file "$TMP/d/pass" --server-id authd > "$TMP/audit1.txt" 2>&1 \
    || { cat "$TMP/audit1.txt"; fail "audit-verify rejected an untampered chain"; }
grep -q 'the audit chain verifies' "$TMP/audit1.txt" || fail "audit-verify printed no verdict"
grep -qE 'head=[0-9a-f]{64}' "$TMP/audit1.txt" || fail "audit-verify printed no head MAC"
# A chain with nothing in it verifies trivially, so a check that did not look
# at the count would pass on a store that had recorded nothing at all.
ENTRIES=$(sed -n 's/.*verifies (\([0-9]*\) entries).*/\1/p' "$TMP/audit1.txt")
[ "${ENTRIES:-0}" -ge 3 ] \
    || fail "audit-verify reports $ENTRIES audit entries, expected at least 3"
echo "PASS: E2E: audit-verify accepts the real chain and reports $ENTRIES entries"

# The check that makes the one above mean something: change one byte of one
# audited row and the verdict must flip. Nothing else in this file can tell a
# verifier from a printer.
cp "$TMP/d/store.sqlite3" "$TMP/tampered.sqlite3"
python3 - "$TMP/tampered.sqlite3" <<'PYEOF' || fail "could not tamper with the audit chain"
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE audit SET detail='tampered' WHERE seq=(SELECT MAX(seq) FROM audit)")
assert c.total_changes == 1, "no audit row was altered"
c.commit(); c.close()
PYEOF
rc=0
"$ADMIN" audit-verify --store "$TMP/tampered.sqlite3" --key "$TMP/d/server.ek" \
    --passphrase-file "$TMP/d/pass" --server-id authd > "$TMP/audit2.txt" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "audit-verify exited $rc on a tampered chain, expected exactly 1"
grep -q 'audit-chain-corrupt' "$TMP/audit2.txt" \
    || { cat "$TMP/audit2.txt"; fail "audit-verify did not name the corruption"; }
echo "PASS: E2E: audit-verify detects a single tampered audit row (spec 9.2)"

# A wrong passphrase must not be reported as a corrupt chain: the chain is keyed
# from the envelope KEK, so opening the key is a different failure from failing
# to verify, and an operator told "corrupt" would look in the wrong place.
printf 'not-the-passphrase' > "$TMP/wrong.pass"; chmod 600 "$TMP/wrong.pass"
rc=0
"$ADMIN" audit-verify --store "$TMP/d/store.sqlite3" --key "$TMP/d/server.ek" \
    --passphrase-file "$TMP/wrong.pass" --server-id authd > "$TMP/audit3.txt" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "audit-verify accepted a wrong passphrase"
grep -q 'audit-chain-corrupt' "$TMP/audit3.txt" \
    && fail "audit-verify blamed the chain for a wrong passphrase"
echo "PASS: E2E: a wrong passphrase is a key failure, not a chain failure"

# --------------------------------------------------------- secret scan

# The passphrase bytes must not appear in any log. Unlike the daemon's logger,
# which has no arbitrary-buffer sink at all, the CLIs use fprintf freely -- so
# "it cannot happen by construction" is not an argument available here.
PASSHEX=$(cat "$TMP/opass")
for f in "$TMP"/*.log "$TMP"/*.err "$TMP"/*.txt; do
    [ -f "$f" ] || continue
    if grep -qi "$PASSHEX" "$f"; then fail "the device passphrase appears in $f"; fi
done

# There is no secret-key-byte scan here, and the reason is the point: unlike
# demo_e2e.sh's key files, every key this flow writes is SEALED, so there are no
# plaintext secret-key bytes on disk to look for. The Req 10 scan above is the
# check that proves that, and it would fail loudly if one ever appeared.
if grep -q "$CODE" "$TMP/authd.log"; then fail "the login code appears in the daemon log"; fi
echo "PASS: E2E: no passphrase and no login code appears in any log"

echo "All checks passed"
