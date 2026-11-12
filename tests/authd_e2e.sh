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
UPID=""
SUPID=""
RESTPID=""
RU=""
cleanup() {
    if [ -n "$DPID" ]; then kill "$DPID" 2>/dev/null || true; fi
    if [ -n "$UPID" ]; then kill "$UPID" 2>/dev/null || true; fi
    # A check that fails while one of these is up used to leave it running
    # (three such daemons were found hours after a campaign, V4-127). Their
    # variables are not cleared when a leg ends, so only a process that is
    # still this shell's child is signalled.
    for p in "$SUPID" "$RESTPID"; do
        [ -n "$p" ] || continue
        [ "$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')" = "$$" ] && kill "$p" 2>/dev/null
    done
    rm -rf "$TMP"
    if [ -n "$RU" ]; then rm -rf "$RU"; fi
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

# ------------------------------------------- the config an operator copies
#
# deploy/authd.conf.example is what a deployment starts from, so its KEYS and
# VALUES are checked here. Only the paths are rewritten into $TMP -- those are
# deployment-specific by nature; everything else is exactly the file as
# shipped, which is the part that can rot when a key is renamed or a bound
# changes.
EX="$(cd "$(dirname "$0")/.." && pwd)/deploy/authd.conf.example"
if [ -f "$EX" ]; then
    mkdir -p "$TMP/ex"
    : > "$TMP/ex/server.ek"; : > "$TMP/ex/pass"
    sed -e "s|/var/lib/mldsa-authd|$TMP/ex|g" \
        -e "s|^key_passphrase_file = .*|key_passphrase_file = $TMP/ex/pass|" \
        -e "s|/run/mldsa-authd|$TMP|g" \
        -e "s|^site_uids = .*|site_uids = $(id -u)|" \
        -e "s|^admin_uids = .*|admin_uids = $(id -u)|" \
        -e "s|^proxy_uids = .*|proxy_uids = $(id -u)|" \
        -e "s|^listen_port = .*|listen_port = 0|" "$EX" > "$TMP/ex.conf"
    "$DAEMON" --config "$TMP/ex.conf" --check-config > "$TMP/ex.out" 2>&1 \
        || { cat "$TMP/ex.out"; fail "deploy/authd.conf.example does not pass --check-config"; }
    # F63: the file an operator copies must turn the rate limiter ON. A
    # default-shaped example would leave a deployment with a proxy-facing
    # listener, no client address and no complaint.
    grep -q 'proxy_protocol=v2' "$TMP/ex.out" \
        || { cat "$TMP/ex.out"; fail "the example config does not enable proxy_protocol=v2"; }
    echo "PASS: E2E: deploy/authd.conf.example validates and enables the rate limiter"
else
    fail "deploy/authd.conf.example is missing"
fi

# --------------------------------------------------------------- daemon

# The raw loopback listener is the operator's SSH-tunnel path (spec 7.1), and
# until V4-10b no test had ever driven it with the shipped client -- every leg
# here used --unix. A port derived from the pid keeps concurrent runs apart
# without needing the daemon to report one back.
#
# BELOW every ephemeral range (audit finding F84): the kernel hands out
# outgoing-connection ports from 32768-60999 on Linux and 49152-65535 on
# macOS, and a listener picked from inside that range can find its port
# already taken by some unrelated connection -- a start-up failure that looks
# like a flake. This was 40000 + pid % 20000, squarely inside Linux's range,
# and the one unexplained authd_e2e failure (nightly 36007850109, 1.24 s in:
# start-up) fits it. 20000-29999 is outside both.
PORT=$(( 20000 + ($$ % 10000) ))

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
# F199 (V4-111): this store was made by `init`, so the daemon did not make it.
if grep -q 'store-created\|created a new, empty store' "$TMP/authd.log"; then
    fail "the daemon said it created a store that init had already made (F199)"
fi

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

# F130: a second daemon started on the SAME configuration while this one runs
# -- an operator debugging by hand, an overlapping restart -- fails, because its
# TCP port is taken. Its start-up cleanup used to unlink every Unix socket path
# in the configuration, opened or not, so the running daemon lost all three
# sockets and stayed up, unreachable, logging nothing.
rc=0
"$DAEMON" --config "$TMP/authd.conf" > "$TMP/second.log" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "a second daemon started on a configuration already in use"
for sk in p.sock s.sock a.sock; do
    [ -S "$TMP/$sk" ] || fail "a second daemon's failed start removed the running daemon's $sk (F130)"
done
"$ADMIN" list-users --socket "$TMP/a.sock" > /dev/null \
    || fail "the running daemon is unreachable after a second daemon failed to start (F130)"
echo "PASS: E2E: a second daemon on the same configuration fails and leaves the running one reachable"

# F204: the leg above is saved by the TCP port -- the second daemon fails at
# that bind before it reaches a Unix socket. With listen_port left at 0, which
# deploy/authd.conf.example offers, nothing failed: the second daemon unlinked
# the first one's three sockets, bound its own and started. The first stayed
# up and unreachable, and stopping the second removed the paths altogether.
cat > "$TMP/u.conf" <<EOF
store_path = $TMP/d/store.sqlite3
key_path = $TMP/d/server.ek
key_passphrase_file = $TMP/d/pass
server_id = authd
listen_unix = $TMP/up.sock
site_socket = $TMP/us.sock
admin_socket = $TMP/ua.sock
site_uids = $(id -u)
admin_uids = $(id -u)
EOF
wait_started() {    # <pid> <log>: 0 once the log has event=started, 1 if the process ended first
    i=0
    while ! grep -q 'event=started' "$2" 2>/dev/null; do
        i=$((i + 1))
        kill -0 "$1" 2>/dev/null || return 1
        [ "$i" -gt 400 ] && return 1
        sleep 0.05
    done
    return 0
}
"$DAEMON" --config "$TMP/u.conf" > "$TMP/u1.log" 2>&1 &
UPID=$!
wait_started "$UPID" "$TMP/u1.log" || fail "a daemon with no TCP listener did not start"
"$ADMIN" list-users --socket "$TMP/ua.sock" > /dev/null || fail "the Unix-only daemon's admin socket does not answer"
ino_before=$(ls -i "$TMP/ua.sock" | awk '{print $1}')
"$DAEMON" --config "$TMP/u.conf" > "$TMP/u2.log" 2>&1 &
U2=$!
if wait_started "$U2" "$TMP/u2.log"; then
    kill "$U2" 2>/dev/null || true
    wait "$U2" 2>/dev/null || true
    fail "a second daemon started on a Unix-only configuration already in use (F204)"
fi
rc=0
wait "$U2" || rc=$?
[ "$rc" -ne 0 ] || fail "a second daemon on a Unix-only configuration exited zero (F204)"
grep -q 'in-use' "$TMP/u2.log" || fail "the second daemon did not say the socket is in use (F204)"
for sk in up.sock us.sock ua.sock; do
    [ -S "$TMP/$sk" ] || fail "a second daemon removed the running daemon's $sk (F204)"
done
[ "$(ls -i "$TMP/ua.sock" | awk '{print $1}')" = "$ino_before" ] \
    || fail "the running daemon's admin socket was replaced by a second daemon (F204)"
"$ADMIN" list-users --socket "$TMP/ua.sock" > /dev/null \
    || fail "the running daemon is unreachable after a second daemon tried its sockets (F204)"
kill -0 "$UPID" 2>/dev/null || fail "the running daemon died when a second one tried its sockets (F204)"
echo "PASS: E2E: a second daemon on a Unix-only configuration is refused, and the running one still answers (F204)"

# The canary for that refusal: a daemon that was KILLED leaves its sockets
# behind with nothing listening, and those must still be replaced.
kill -9 "$UPID" 2>/dev/null || true
wait "$UPID" 2>/dev/null || true
[ -S "$TMP/ua.sock" ] || fail "a killed daemon left no socket behind: the canary has nothing to replace"
"$DAEMON" --config "$TMP/u.conf" > "$TMP/u3.log" 2>&1 &
UPID=$!
wait_started "$UPID" "$TMP/u3.log" || fail "a daemon did not start over the sockets a killed one left behind"
"$ADMIN" list-users --socket "$TMP/ua.sock" > /dev/null \
    || fail "the daemon that replaced a killed one's sockets does not answer"
kill "$UPID" 2>/dev/null || true
wait "$UPID" 2>/dev/null || true
UPID=""
echo "PASS: E2E: sockets left by a killed daemon are replaced -- the canary"

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
printf 'not a socket\n' > "$TMP/ba.sock"
rc=0
"$DAEMON" --config "$TMP/bind.conf" > "$TMP/bind.log" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || fail "the daemon started despite an unusable admin socket path"
grep -q 'admin socket' "$TMP/bind.log" || fail "the daemon did not name the admin socket it refused"
[ ! -e "$TMP/bs.sock" ] || fail "a listener failure left the site socket behind: the cleanup epilogue did not run"
[ ! -e "$TMP/bp.sock" ] || fail "a listener failure left the protocol socket behind: the cleanup epilogue did not run"
# F130: ...and the file it refused to bind over is NOT the daemon's to delete.
[ "$(cat "$TMP/ba.sock" 2>/dev/null)" = "not a socket" ] \
    || fail "the daemon deleted the file at the admin socket path that it refused to bind over (F130)"
rm -f "$TMP/ba.sock"
echo "PASS: E2E: a listener failure runs the cleanup epilogue that wipes the server key"

# V4-51: the daemon refuses to START on a file it cannot trust, and says why.
# V4-44's coverage found its passphrase, key and store refusals had run only
# through --check-config or not at all. Each case damages ONE copy of the
# server's files; the daemon must exit nonzero, name the file and the status,
# and leave no socket behind. The undamaged copies start (the canary).
mkdir "$TMP/su" && cp "$TMP/d/server.ek" "$TMP/su/server.ek" && cp "$TMP/d/pass" "$TMP/su/pass" \
    && chmod 0600 "$TMP/su/server.ek" "$TMP/su/pass" || fail "could not copy the server's files for the start-up leg"
su_conf() {
    cat > "$TMP/su.conf" <<EOF
store_path = $1
key_path = $2
key_passphrase_file = $3
server_id = authd
listen_unix = $TMP/su-p.sock
site_socket = $TMP/su-s.sock
admin_socket = $TMP/su-a.sock
site_uids = $(id -u)
admin_uids = $(id -u)
EOF
}
su_refused() {
    # In the background, with a deadline: a daemon that wrongly STARTS would
    # otherwise run forever, and a campaign would see a timeout, not a check.
    "$DAEMON" --config "$TMP/su.conf" > "$TMP/su.log" 2>&1 &
    supid=$!
    i=0
    while kill -0 "$supid" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 400 ]; then
            kill -TERM "$supid" 2>/dev/null; wait "$supid" 2>/dev/null || true
            fail "the daemon started with $2, and was still running 20 s later"
        fi
        sleep 0.05
    done
    rc=0
    wait "$supid" || rc=$?
    [ "$rc" -ne 0 ] || fail "the daemon started with $2"
    # F126 (V4-61): spec §13 -- 3 for a file the configuration names that
    # cannot be used as configured, 1 for an operation that failed.
    [ -z "${3:-}" ] || [ "$rc" -eq "$3" ] || fail "the daemon refused $2 with exit code $rc, expected $3 (spec §13, F126)"
    grep -qF "$1" "$TMP/su.log" || fail "the daemon refused $2 without saying '$1': $(cat "$TMP/su.log")"
    for s in su-p su-s su-a; do [ ! -e "$TMP/$s.sock" ] || fail "refusing $2 left $s.sock behind"; done
}
chmod 0644 "$TMP/su/pass"
su_conf "$TMP/su/store.sqlite3" "$TMP/su/server.ek" "$TMP/su/pass"
su_refused "passphrase file $TMP/su/pass: unsafe-permissions" "a group-readable passphrase file" 3
chmod 0600 "$TMP/su/pass"; chmod 0644 "$TMP/su/server.ek"
su_refused "$TMP/su/server.ek: unsafe-permissions" "a group-readable server key" 3
chmod 0600 "$TMP/su/server.ek"
printf 'not the passphrase\n' > "$TMP/su/wrongpass" && chmod 0600 "$TMP/su/wrongpass"
su_conf "$TMP/su/store.sqlite3" "$TMP/su/server.ek" "$TMP/su/wrongpass"
su_refused "$TMP/su/server.ek: decryption-failed" "the wrong passphrase" 3
printf 'this file is not a database, whatever its name says\n' > "$TMP/su/garbage.sqlite3"
su_conf "$TMP/su/garbage.sqlite3" "$TMP/su/server.ek" "$TMP/su/pass"
su_refused "$TMP/su/garbage.sqlite3: database-error" "a store file that is not a database" 1
su_conf "$TMP/su/store.sqlite3" "$TMP/su/server.ek" "$TMP/su/pass"
su_umask=$(umask); umask 022   # F200: the store this start creates must not take this
"$DAEMON" --config "$TMP/su.conf" > "$TMP/su-ok.log" 2>&1 &
SUPID=$!
umask "$su_umask"
i=0
while ! grep -q 'event=started' "$TMP/su-ok.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] || kill -0 "$SUPID" 2>/dev/null || fail "the undamaged copies did not start (the canary): $(cat "$TMP/su-ok.log")"
    [ "$i" -gt 400 ] && fail "the undamaged copies never logged event=started (the canary)"
    sleep 0.05
done
kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
# F199, F200 (V4-111): nothing was at $TMP/su/store.sqlite3, so that start
# CREATED the store -- the supported first start after keygen-server, and also
# what a mistyped store_path does. The daemon must say so, on stderr and as a
# warn event, and the file must be 0600 although that start's umask was 022.
# The next start finds the store there and says neither.
grep -qF "$TMP/su/store.sqlite3: created a new, empty store (no store was there)" "$TMP/su-ok.log" \
    || fail "a daemon that created its store did not say so on stderr (F199): $(cat "$TMP/su-ok.log")"
grep -q '^warn event=store-created$' "$TMP/su-ok.log" \
    || fail "a daemon that created its store did not log event=store-created at warn (F199): $(cat "$TMP/su-ok.log")"
[ "$(sed -n '/event=store-created/=' "$TMP/su-ok.log" | head -1)" -lt "$(sed -n '/event=started/=' "$TMP/su-ok.log" | head -1)" ] \
    || fail "event=store-created was not logged before event=started (F199)"
sumode=$(ls -l "$TMP/su/store.sqlite3" | cut -c1-10)
[ "$sumode" = "-rw-------" ] || fail "the store the daemon created is $sumode, not -rw------- (F200)"
"$DAEMON" --config "$TMP/su.conf" > "$TMP/su-ok2.log" 2>&1 &
SUPID=$!
i=0
while ! grep -q 'event=started' "$TMP/su-ok2.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] || kill -0 "$SUPID" 2>/dev/null || fail "the second start on the created store failed: $(cat "$TMP/su-ok2.log")"
    [ "$i" -gt 400 ] && fail "the second start on the created store never logged event=started"
    sleep 0.05
done
kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
if grep -q 'store-created\|created a new, empty store' "$TMP/su-ok2.log"; then
    fail "the second start on the same store said it created it again (F199)"
fi
# V4-113: the line the runbook's step 9 and the rehearsal read. A daemon whose
# RLIMIT_MEMLOCK is below what its slots need must log memlock-limit at WARN,
# in exactly the form `warn event=memlock-limit need=<bytes>`, and say why on
# stderr; the unit tests pin the level function, and until now nothing pinned
# that the daemon's start uses it (the rehearsal's pattern was blind from
# V4-99 to V4-111, F201). Staged with a 1 MiB soft limit, which the default
# 256 slots (10485760 B) do not fit. A platform that will not lower the limit
# is a SKIP, said aloud.
if (ulimit -S -l 1024) 2>/dev/null; then
    (ulimit -S -l 1024; exec "$DAEMON" --config "$TMP/su.conf") > "$TMP/su-ml.log" 2>&1 &
    SUPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/su-ml.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] || kill -0 "$SUPID" 2>/dev/null || fail "the daemon did not start under a 1 MiB memlock limit: $(cat "$TMP/su-ml.log")"
        [ "$i" -gt 400 ] && fail "the daemon under a 1 MiB memlock limit never logged event=started"
        sleep 0.05
    done
    kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
    grep -q '^warn event=memlock-limit need=10485760$' "$TMP/su-ml.log" \
        || fail "a daemon whose memlock limit is short did not log 'warn event=memlock-limit need=10485760': $(cat "$TMP/su-ml.log")"
    grep -q 'RLIMIT_MEMLOCK is 1048576 bytes but 256 slots need 10485760' "$TMP/su-ml.log" \
        || fail "a daemon whose memlock limit is short did not say so on stderr, with both numbers: $(cat "$TMP/su-ml.log")"
    echo "PASS: E2E: under a 1 MiB memlock limit the daemon starts, logs 'warn event=memlock-limit need=10485760' and names both numbers on stderr"
else
    echo "SKIP: E2E: this platform will not lower RLIMIT_MEMLOCK; the memlock-limit WARN line is not staged"
fi
# F205 (V4-120): the same for open files. Every slot is a descriptor; with too
# few the daemon stops accepting on every socket and used to say nothing. The
# default 256 + 8 slots need 296. Under a SOFT limit of 64 the daemon raises
# its own limit and the line is INFO; under a HARD limit of 64 it cannot, and
# must log `warn event=fd-limit need=296` and name the numbers on stderr.
start_limited() {    # <log>: waits for started, then stops the daemon
    i=0
    while ! grep -q 'event=started' "$1" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] || kill -0 "$SUPID" 2>/dev/null || fail "the daemon did not start under a 64-descriptor limit: $(cat "$1")"
        [ "$i" -gt 400 ] && fail "the daemon under a 64-descriptor limit never logged event=started"
        sleep 0.05
    done
    kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
}
if (ulimit -S -n 64) 2>/dev/null; then
    (ulimit -S -n 64; exec "$DAEMON" --config "$TMP/su.conf") > "$TMP/su-fs.log" 2>&1 &
    SUPID=$!
    start_limited "$TMP/su-fs.log"
    grep -q '^info event=fd-limit need=296$' "$TMP/su-fs.log" \
        || fail "a daemon that could raise its own descriptor limit did not log 'info event=fd-limit need=296' (F205): $(cat "$TMP/su-fs.log")"
    if grep -q 'RLIMIT_NOFILE' "$TMP/su-fs.log"; then
        fail "a daemon that could raise its own descriptor limit complained about it (F205)"
    fi
    (ulimit -S -n 64; ulimit -H -n 64; exec "$DAEMON" --config "$TMP/su.conf") > "$TMP/su-fh.log" 2>&1 &
    SUPID=$!
    start_limited "$TMP/su-fh.log"
    grep -q '^warn event=fd-limit need=296$' "$TMP/su-fh.log" \
        || fail "a daemon whose descriptor limit is short did not log 'warn event=fd-limit need=296' (F205): $(cat "$TMP/su-fh.log")"
    grep -q 'RLIMIT_NOFILE is 64 but max_slots = 256 and max_local_slots = 8 need 296 open files' "$TMP/su-fh.log" \
        || fail "a daemon whose descriptor limit is short did not say so on stderr, with the numbers (F205): $(cat "$TMP/su-fh.log")"
    echo "PASS: E2E: under a soft limit of 64 descriptors the daemon raises it and logs fd-limit at info; under a hard limit of 64 it logs 'warn event=fd-limit need=296' and names the numbers on stderr (F205)"
    # F207 (V4-123): what a short HARD limit does once connections arrive.
    # The daemon used to accept until accept() failed, and then the admin
    # socket was as dead as the rest: the operator could not ask it anything.
    # It must instead hold back enough descriptors for its own sockets: with
    # 64, that is 64 - 8 local - 32 = 24 connections, refused beyond that by
    # the slot table, and the admin socket answers throughout.
    (ulimit -S -n 64; ulimit -H -n 64; exec "$DAEMON" --config "$TMP/su.conf") > "$TMP/su-fc.log" 2>&1 &
    SUPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/su-fc.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && fail "the daemon for the descriptor-cap leg never logged event=started: $(cat "$TMP/su-fc.log")"
        sleep 0.05
    done
    python3 - "$TMP/su-p.sock" "$TMP/su-fc.held" <<'PYEOF' &
import socket, sys, time
held = []
for _ in range(70):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        c.connect(sys.argv[1])
        held.append(c)
    except OSError:
        pass
    time.sleep(0.01)
time.sleep(0.5)
open(sys.argv[2], "w").write("%d\n" % len(held))
time.sleep(600)
PYEOF
    HOLDPID=$!
    i=0
    while [ ! -s "$TMP/su-fc.held" ]; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && { kill "$HOLDPID" "$SUPID" 2>/dev/null; fail "the 70 held connections for the descriptor-cap leg were never opened"; }
        sleep 0.05
    done
    rc=0
    "$ADMIN" list-users --socket "$TMP/su-a.sock" > /dev/null 2> "$TMP/su-fc.err" || rc=$?
    kill "$HOLDPID" 2>/dev/null; wait "$HOLDPID" 2>/dev/null || true
    kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
    [ "$rc" -eq 0 ] \
        || fail "with 64 descriptors and 70 connections held, the admin socket did not answer (F207): $(cat "$TMP/su-fc.err")"
    if grep -q 'event=accept-failed' "$TMP/su-fc.log"; then
        fail "with 64 descriptors and 70 connections held, the daemon ran out of descriptors instead of refusing at its cap (F207)"
    fi
    [ "$(grep -c '^info event=accepted ' "$TMP/su-fc.log")" -eq 24 ] \
        || fail "with 64 descriptors the daemon did not accept exactly 24 connections (F207): $(grep -c '^info event=accepted ' "$TMP/su-fc.log")"
    grep -q '^warn event=accept-refused-no-slot$' "$TMP/su-fc.log" \
        || fail "connections beyond the descriptor cap were not refused with accept-refused-no-slot (F207)"
    grep -q 'at most 24 connections' "$TMP/su-fc.log" \
        || fail "a daemon whose descriptor limit is short did not say how many connections it will hold (F207): $(cat "$TMP/su-fc.log")"
    echo "PASS: E2E: under a hard limit of 64 descriptors and 70 held connections the daemon holds 24, refuses the rest with accept-refused-no-slot, never fails an accept(), and its admin socket answers (F207)"
else
    echo "SKIP: E2E: this platform will not lower RLIMIT_NOFILE; the fd-limit lines are not staged"
fi
# F206 (V4-121): SIGHUP. Its default action kills the process with no drain,
# and systemd counts death by SIGHUP as a clean exit, so Restart=on-failure
# leaves the service down. The daemon has no reload; it must say so and stay.
"$DAEMON" --config "$TMP/su.conf" > "$TMP/su-hup.log" 2>&1 &
SUPID=$!
i=0
while ! grep -q 'event=started' "$TMP/su-hup.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] && fail "the daemon for the SIGHUP leg never logged event=started: $(cat "$TMP/su-hup.log")"
    sleep 0.05
done
kill -HUP "$SUPID"
i=0
while kill -0 "$SUPID" 2>/dev/null && ! grep -q 'event=sighup-ignored' "$TMP/su-hup.log"; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && break
    sleep 0.05
done
kill -0 "$SUPID" 2>/dev/null || fail "a daemon sent SIGHUP died (F206): $(cat "$TMP/su-hup.log")"
grep -q '^warn event=sighup-ignored$' "$TMP/su-hup.log" \
    || fail "a daemon sent SIGHUP did not log 'warn event=sighup-ignored' (F206): $(cat "$TMP/su-hup.log")"
# The loop turns at least once a second; a flag that is never cleared would
# log on every turn.
sleep 1.3
[ "$(grep -c '^warn event=sighup-ignored$' "$TMP/su-hup.log")" -eq 1 ] \
    || fail "one SIGHUP was logged more than once (F206): $(cat "$TMP/su-hup.log")"
kill -HUP "$SUPID"
i=0
while [ "$(grep -c '^warn event=sighup-ignored$' "$TMP/su-hup.log")" -lt 2 ]; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && fail "a second SIGHUP was not logged like the first (F206): $(cat "$TMP/su-hup.log")"
    sleep 0.05
done
kill -TERM "$SUPID"; wait "$SUPID" 2>/dev/null || true
grep -q '^info event=stopped accepted=' "$TMP/su-hup.log" \
    || fail "after a SIGHUP, SIGTERM no longer drains and stops the daemon -- the canary (F206): $(cat "$TMP/su-hup.log")"
echo "PASS: E2E: SIGHUP does not stop the daemon; each one is logged as 'warn event=sighup-ignored', and SIGTERM still drains and stops it (F206)"
# F219 (V4-137): a stop while the site is being answered. A handler queues
# its reply and the loop writes it on its next turn; the stop waited for the
# protocol connections alone, so a SIGTERM that landed during a handler ended
# the loop with the reply unsent. RECOVERY-USE for a user nobody enrolled
# costs one Argon2id computation (F143), which is the window: the request is
# sent, the signal follows 20 ms later, and the reply must still arrive.
#
# An attempt whose reply was already there before the signal proves nothing
# and is repeated ("void"); so is one whose signal beat the daemon to the
# request, which the daemon never served ("unserved": no Argon2id, so it
# answers EOF well inside the computation's time).
f219_got=""
f219_seen=""
for f219_try in 1 2 3 4 5 6 7 8; do
    "$DAEMON" --config "$TMP/su.conf" > "$TMP/su-dr.log" 2>&1 &
    SUPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/su-dr.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && fail "the daemon for the drain leg never logged event=started: $(cat "$TMP/su-dr.log")"
        sleep 0.05
    done
    python3 - "$TMP/su-a.sock" "$SUPID" > "$TMP/su-dr.txt" <<'PYEOF' || fail "the drain leg's client failed: $(cat "$TMP/su-dr.txt")"
import os, signal, socket, sys, time
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(sys.argv[1])
# A cheap request first: once it is answered the connection is being served.
c.sendall(b"PING\n")
buf = b""
while not buf.endswith(b"\n"):
    d = c.recv(256)
    if not d:
        print("noping"); sys.exit(0)
    buf += d
c.sendall(b"RECOVERY-USE user=6e6f626f6479 code=0000000000000000\n")
time.sleep(0.02)
c.setblocking(False)
try:
    early = c.recv(256)
except BlockingIOError:
    early = None
t0 = time.monotonic()
os.kill(int(sys.argv[2]), signal.SIGTERM)
if early is not None:
    print("void"); sys.exit(0)
c.setblocking(True)
c.settimeout(30)
got = b""
while not got.endswith(b"\n"):
    d = c.recv(256)
    if not d:
        break
    got += d
ms = int((time.monotonic() - t0) * 1000)
if got == b"ERR code=invalid\n":
    print("reply")
elif got == b"":
    print("lost %d" % ms)
else:
    print("other %r" % got)
PYEOF
    rc=0
    wait "$SUPID" || rc=$?
    [ "$rc" -eq 0 ] || fail "a daemon stopped while it was answering the site exited $rc, not 0 (F219): $(cat "$TMP/su-dr.log")"
    f219_got="$(cat "$TMP/su-dr.txt")"
    f219_seen="$f219_seen [$f219_got]"
    case "$f219_got" in
        reply) break ;;
        void|lost*) ;;
        *) fail "the drain leg's request was answered '$f219_got', not 'ERR code=invalid' (F219)" ;;
    esac
done
[ "$f219_got" = reply ] \
    || fail "a daemon stopped while it was answering the site never delivered the reply it had computed (F219); attempts:$f219_seen"
grep -q '^info event=draining$' "$TMP/su-dr.log" && grep -q '^info event=stopped accepted=' "$TMP/su-dr.log" \
    || fail "the daemon of the drain leg did not log draining and stopped (F219): $(cat "$TMP/su-dr.log")"
echo "PASS: E2E: a daemon sent SIGTERM while it is answering the site writes the reply before it stops (F219)"
# F208 (V4-124): a loop that fails. The daemon logged error event=loop-failed
# and then exited 0, which systemd reads as a clean stop: Restart=on-failure
# left the service down. Linux's prlimit can stage it from outside -- poll()
# refuses more descriptors than RLIMIT_NOFILE allows, so lowering a running
# daemon's limit to 1 fails its next poll() -- and nothing portable can, so
# the leg is skipped elsewhere.
#
# The leak check is off for this one daemon. In an ASan build LeakSanitizer
# runs at exit and must open /proc/<pid>/task; under a limit of 1 it cannot,
# calls that a fatal error and exits 1 itself -- whatever main() returned. The
# leg then passed with the defect in place (campaign v99's LF1 survived in
# the first nightly). Every other daemon in this script keeps the leak check.
if [ "$(uname -s)" = Linux ] && command -v prlimit > /dev/null 2>&1; then
    ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0" \
        "$DAEMON" --config "$TMP/su.conf" > "$TMP/su-lf.log" 2>&1 &
    SUPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/su-lf.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && fail "the daemon for the loop-failed leg never logged event=started: $(cat "$TMP/su-lf.log")"
        sleep 0.05
    done
    prlimit --pid "$SUPID" --nofile=1:1 \
        || fail "prlimit could not lower the running daemon's RLIMIT_NOFILE"
    i=0
    while kill -0 "$SUPID" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 100 ] && { kill -KILL "$SUPID"; fail "a daemon whose poll() cannot succeed was still running after 5 s (F208): $(cat "$TMP/su-lf.log")"; }
        sleep 0.05
    done
    rc=0
    wait "$SUPID" || rc=$?
    grep -q '^error event=loop-failed$' "$TMP/su-lf.log" \
        || fail "a daemon whose poll() failed did not log 'error event=loop-failed' (F208): $(cat "$TMP/su-lf.log")"
    [ "$rc" -eq 1 ] \
        || fail "a daemon whose loop failed exited $rc, not 1: systemd would count that a clean stop and not restart it (F208)"
    grep -q '^info event=stopped accepted=' "$TMP/su-lf.log" \
        || fail "a daemon whose loop failed did not log its stopped lines (F208): $(cat "$TMP/su-lf.log")"
    grep -q 'Sanitizer' "$TMP/su-lf.log" \
        && fail "a sanitizer, not the daemon, ended the loop-failed leg, so its exit status proves nothing (F208): $(cat "$TMP/su-lf.log")"
    for s in su-p.sock su-a.sock; do
        [ ! -e "$TMP/$s" ] || fail "a daemon whose loop failed left $s behind (F208)"
    done
    # The canary: the same daemon, stopped by SIGTERM, exits 0.
    "$DAEMON" --config "$TMP/su.conf" > "$TMP/su-lf2.log" 2>&1 &
    SUPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/su-lf2.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && fail "the daemon for the loop-failed canary never logged event=started: $(cat "$TMP/su-lf2.log")"
        sleep 0.05
    done
    kill -TERM "$SUPID"
    rc=0
    wait "$SUPID" || rc=$?
    [ "$rc" -eq 0 ] || fail "a daemon stopped by SIGTERM exited $rc, not 0 -- the canary (F208)"
    grep -q 'event=loop-failed' "$TMP/su-lf2.log" \
        && fail "a daemon stopped by SIGTERM logged loop-failed -- the canary (F208)"
    echo "PASS: E2E: a daemon whose poll() fails logs 'error event=loop-failed', closes its sockets and exits 1, and one stopped by SIGTERM exits 0 (F208)"
else
    echo "SKIP: E2E: no Linux prlimit here, so a failing poll() is not staged (F208)"
fi
# F209 (V4-126): the watchdog. A daemon that hangs -- a loop that never
# returns to poll() -- stayed "active" under systemd for ever, and nobody
# could log in. The unit now sets WatchdogSec=, and the daemon must ping:
# WATCHDOG=1 to $NOTIFY_SOCKET at a quarter of $WATCHDOG_USEC. A datagram
# socket stands in for systemd's and stamps what arrives.
python3 - "$TMP/wd.sock" "$TMP/wd.got" <<'PYEOF' &
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
s.settimeout(60)
with open(sys.argv[2], "a", buffering=1) as f:
    while True:
        try:
            m = s.recv(256)
        except socket.timeout:
            break
        f.write("%d %s\n" % (int(time.monotonic() * 1000), m.decode("ascii", "replace")))
        if m == b"QUIT":
            break
PYEOF
WDPY=$!
i=0
while [ ! -S "$TMP/wd.sock" ]; do
    i=$((i + 1)); [ "$i" -gt 200 ] && fail "the stand-in notify socket never appeared"
    sleep 0.05
done
# 1.2 s: a ping every 300 ms, and a loop that must wake that often for it.
NOTIFY_SOCKET="$TMP/wd.sock" WATCHDOG_USEC=1200000 \
    "$DAEMON" --config "$TMP/su.conf" > "$TMP/su-wd.log" 2>&1 &
SUPID=$!
i=0
while [ "$(grep -c ' WATCHDOG=1$' "$TMP/wd.got" 2>/dev/null || true)" -lt 4 ]; do
    i=$((i + 1))
    if [ "$i" -gt 300 ]; then
        kill -TERM "$SUPID" 2>/dev/null || true
        fail "a daemon given WATCHDOG_USEC sent $(grep -c ' WATCHDOG=1$' "$TMP/wd.got" 2>/dev/null || true) WATCHDOG=1 in 15 s, not 4: systemd would kill it as hung, or it has no watchdog (F209): $(cat "$TMP/wd.got" 2>/dev/null)"
    fi
    sleep 0.05
done
kill -TERM "$SUPID"
if wait "$SUPID"; then rc=0; else rc=$?; fi
SUPID=""
[ "$rc" -eq 0 ] || fail "the watchdog daemon exited $rc on SIGTERM"
[ "$(sed -n 1p "$TMP/wd.got" | cut -d' ' -f2)" = "READY=1" ] \
    || fail "the first thing a watchdog daemon told systemd was not READY=1 (F209): $(cat "$TMP/wd.got")"
T1=$(grep ' WATCHDOG=1$' "$TMP/wd.got" | sed -n 1p | cut -d' ' -f1)
T4=$(grep ' WATCHDOG=1$' "$TMP/wd.got" | sed -n 4p | cut -d' ' -f1)
[ $((T4 - T1)) -lt 2000 ] \
    || fail "an idle daemon's four pings for a 1.2 s watchdog spanned $((T4 - T1)) ms, not under 2000: its loop does not wake for them (F209)"
# The canary: the same daemon with no WATCHDOG_USEC says READY=1 and no more.
: > "$TMP/wd.got"
NOTIFY_SOCKET="$TMP/wd.sock" "$DAEMON" --config "$TMP/su.conf" > "$TMP/su-wd2.log" 2>&1 &
SUPID=$!
i=0
while ! grep -q ' READY=1$' "$TMP/wd.got" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 400 ] && fail "the canary daemon never said READY=1: $(cat "$TMP/su-wd2.log")"
    sleep 0.05
done
sleep 2.5
kill -TERM "$SUPID"
if wait "$SUPID"; then :; fi
SUPID=""
[ "$(grep -c ' WATCHDOG=1$' "$TMP/wd.got" || true)" -eq 0 ] \
    || fail "a daemon with no WATCHDOG_USEC pinged a watchdog nobody set -- the canary (F209): $(cat "$TMP/wd.got")"
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.sendto(b"QUIT", sys.argv[1])' "$TMP/wd.sock"
wait "$WDPY" 2>/dev/null || true
rm -f "$TMP/wd.sock"
echo "PASS: E2E: a daemon given WATCHDOG_USEC says READY=1 and then WATCHDOG=1 at a quarter of it, waking for each; one given none sends none (F209)"
echo "PASS: E2E: a daemon that finds no store at store_path creates one and says so -- on stderr and as warn event=store-created, before started -- and creates it 0600 under a umask of 022; the next start on it says neither (F199, F200)"
echo "PASS: E2E: the daemon refuses to start on a group-readable passphrase file or server key, the wrong passphrase, or a store that is not a database -- naming the file and the status each time, with exit code 3 for the first three and 1 for the store, and leaving no socket; the undamaged copies start"

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

    # V4-36 (CLAIMS D5): the REAL daemon's clock. Every expiry -- a login
    # code's 60 s, a token's TTL -- is now_unix plus a constant, and every C
    # test sets now_unix itself, so nothing had watched authd_main advance it.
    # A daemon whose loop stopped updating it would issue codes that never
    # expire, and every other check would pass. `issued` in an EXCHANGE reply
    # is that clock: a second exchange, 2 s of wall time later, must say so,
    # and both must agree with this shell's clock.
    ISSUED1=$(sed -n 's/.*"issued":\([0-9]*\).*/\1/p' "$TMP/site.txt")
    T1=$(date +%s)
    sleep 2
    CODE3=$("$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
            --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
            --unix "$TMP/p.sock" --proxy-v2 2>> "$TMP/login.err") || fail "third login exited nonzero"
    "$NODE" "$SITE" "$TMP/s.sock" "$CODE3" > "$TMP/site3.txt" 2>> "$TMP/site.err" \
        || fail "the site could not exchange the third login code"
    ISSUED2=$(sed -n 's/.*"issued":\([0-9]*\).*/\1/p' "$TMP/site3.txt")
    T2=$(date +%s)
    [ -n "$ISSUED1" ] && [ -n "$ISSUED2" ] || fail "an EXCHANGE reply carried no issued time"
    [ $((ISSUED2 - ISSUED1)) -ge 2 ] \
        || fail "the daemon's clock did not advance: a code exchanged 2 s later was issued at $ISSUED2, the first at $ISSUED1 (D5)"
    d1=$((ISSUED1 - T1)); d2=$((ISSUED2 - T2))
    [ "${d1#-}" -le 5 ] && [ "${d2#-}" -le 5 ] \
        || fail "the daemon's clock is not the wall clock: issued $ISSUED1 and $ISSUED2 against this shell's $T1 and $T2 (D5)"
    echo "PASS: E2E: the daemon's clock advances with the wall clock -- two exchanges $((ISSUED2 - ISSUED1)) s apart, each within 5 s of this shell (D5)"
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
        ! grep -qF -- "$c" "$TMP/authd.log" || fail "a recovery code reached the daemon log: $c"
        for f in "$TMP/rec.err" "$TMP/login.err" "$TMP/keygen.err"; do
            [ -f "$f" ] || continue
            ! grep -qF -- "$c" "$f" || fail "a recovery code reached $f"
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

# ------------------------------------- rotation recovery, characterised
#
# client_resolve_key's .ek / .ek.next recovery (spec 10.2) had NO end-to-end
# test: this script only checked that no .next survived an acknowledged
# rotation. These three legs pin what the shipped client does TODAY, before
# V4-13a moves it onto a shared core -- so the refactor cannot change it
# unseen. They assert observed behaviour, not intended behaviour.
#
# State here: .ek holds the LIVE (rotated) key, save-old.ek the SUPERSEDED one.
hash_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
EK="$TMP/dev/$HANDLE.ek"
NEXT="$TMP/dev/$HANDLE.ek.next"
LIVE_HASH=$(hash_of "$EK")
OLD_HASH=$(hash_of "$TMP/save-old.ek")

# 1. USE_EK: .ek is live and .ek.next was never committed. Login must succeed
#    on .ek, say so, and -- by design, "login should not delete files" --
#    leave .ek.next where it is.
cp "$TMP/save-old.ek" "$NEXT"; chmod 600 "$NEXT"
"$CLIENT" login --handle "$HANDLE" --key "$EK" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > "$TMP/rec1.txt" 2> "$TMP/rec1.err" \
    || { cat "$TMP/rec1.err"; fail "recovery USE_EK: login with a stale .ek.next present exited nonzero"; }
[ "$(wc -c < "$TMP/rec1.txt" | tr -d ' ')" -eq 44 ] || fail "recovery USE_EK: no 43-character login code"
grep -q "is still the live key" "$TMP/rec1.err" || fail "recovery USE_EK: did not report .ek as the live key"
grep -q "was never committed" "$TMP/rec1.err" || fail "recovery USE_EK: did not report .ek.next as never committed"
[ -e "$NEXT" ] || fail "recovery USE_EK: login DELETED .ek.next -- login must not delete files"
[ "$(hash_of "$EK")" = "$LIVE_HASH" ] || fail "recovery USE_EK: login changed .ek"
echo "PASS: E2E: recovery USE_EK -- a stale .ek.next is reported and left alone; .ek logs in"
rm -f "$NEXT"

# 2. REFUSE: neither file authenticates. Deleting either would be guessing
#    with the only copies of an identity, so NOTHING may be touched.
cp "$TMP/save-old.ek" "$EK"; chmod 600 "$EK"
cp "$TMP/save-old.ek" "$NEXT"; chmod 600 "$NEXT"
rc=0
"$CLIENT" login --handle "$HANDLE" --key "$EK" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2> "$TMP/rec2.err" || rc=$?
# The files FIRST: that nothing was deleted or changed is the property; the
# message saying so is only a report of it. fail() stops at the first
# failure, so this order decides which check a defect is caught by.
[ -e "$EK" ] && [ -e "$NEXT" ] || fail "recovery REFUSE: a key file was deleted when neither authenticated"
[ "$(hash_of "$EK")" = "$OLD_HASH" ] && [ "$(hash_of "$NEXT")" = "$OLD_HASH" ] \
    || fail "recovery REFUSE: a key file was modified when neither authenticated"
[ "$rc" -ne 0 ] || fail "recovery REFUSE: login succeeded although neither key is live"
grep -q "NOTHING has been deleted" "$TMP/rec2.err" || fail "recovery REFUSE: did not say that nothing was deleted"
echo "PASS: E2E: recovery REFUSE -- neither key live, both files untouched"

# 3. PROMOTE_NEXT: the server committed and the rename was interrupted --
#    .ek is stale, .ek.next is live. Login must finish the rename.
cp "$TMP/current.ek" "$NEXT"; chmod 600 "$NEXT"
"$CLIENT" login --handle "$HANDLE" --key "$EK" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > "$TMP/rec3.txt" 2> "$TMP/rec3.err" \
    || { cat "$TMP/rec3.err"; fail "recovery PROMOTE: login with a committed .ek.next exited nonzero"; }
[ "$(wc -c < "$TMP/rec3.txt" | tr -d ' ')" -eq 44 ] || fail "recovery PROMOTE: no 43-character login code"
grep -q "completed the interrupted rotation" "$TMP/rec3.err" || fail "recovery PROMOTE: did not report completing the rotation"
[ ! -e "$NEXT" ] || fail "recovery PROMOTE: .ek.next survived its own promotion"
[ "$(hash_of "$EK")" = "$LIVE_HASH" ] || fail "recovery PROMOTE: .ek does not hold the live key after promotion"
echo "PASS: E2E: recovery PROMOTE -- an interrupted rotation is completed by the next login"

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

# ------------------------------------------ revocation, end to end (V4-15a)
#
# Req 9 through the shipped binaries. Until V4-15a nothing in this script
# revoked anything (CLAIMS D9): a user disabled with the operator's own tool,
# and a device revoked the way a site revokes one, must each refuse the NEXT
# login -- and re-enabling must restore it, so the refusal is the status and
# not a broken identity. dave is an identity of his own, placed after the
# counts above so they are untouched.
DAVE=$("$CLIENT" keygen --dir "$TMP/dave" --passphrase-file "$TMP/opass" 2>> "$TMP/keygen.err") \
    || fail "keygen for dave exited nonzero"
"$ADMIN" enroll-operator --socket "$TMP/a.sock" --user dave --handle "$DAVE" \
    --pub "$TMP/dave/$DAVE.pub" > /dev/null || fail "enroll-operator dave failed"
dave_login() {
    "$CLIENT" login --handle "$DAVE" --key "$TMP/dave/$DAVE.ek" \
        --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
        --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2>> "$TMP/login.err"
}
dave_login || fail "dave could not log in before any revocation (the canary)"
"$ADMIN" disable-user --socket "$TMP/a.sock" --user dave --reason "e2e" > /dev/null \
    || fail "disable-user dave failed"
grep -q 'event=user-disabled' "$TMP/authd.log" || fail "the daemon did not log the user-disabled event"
rc=0; dave_login || rc=$?
[ "$rc" -ne 0 ] || fail "a DISABLED user still obtained a login code (Req 9)"
"$ADMIN" enable-user --socket "$TMP/a.sock" --user dave > /dev/null || fail "enable-user dave failed"
dave_login || fail "re-enabled, dave still cannot log in: the refusal was not the user's status"
echo "PASS: E2E: a disabled user is refused, and the same identity logs in again once re-enabled"
if [ -n "$NODE" ] && [ -n "$SITE" ] && [ -x "$NODE" ]; then
    # dave is an operator, and since V4-82 (F171) an operator's device is
    # revoked from admin.sock only: site.sock must refuse it, and admin.sock
    # then revokes it the same way.
    rc=0; "$NODE" "$SITE" "$TMP/s.sock" --revoke "$DAVE" > /dev/null 2> "$TMP/site-op.err" || rc=$?
    [ "$rc" -ne 0 ] && grep -q 'not-permitted' "$TMP/site-op.err" \
        || fail "site.sock revoked an OPERATOR's device (F171)"
    dave_login || fail "a refused revocation still revoked dave's device"
    echo "PASS: E2E: site.sock may not revoke an operator's device (F171)"
    "$NODE" "$SITE" "$TMP/a.sock" --revoke "$DAVE" > /dev/null 2>> "$TMP/site.err" \
        || fail "REVOKE-DEVICE over admin.sock failed"
    rc=0; dave_login || rc=$?
    [ "$rc" -ne 0 ] || fail "a REVOKED device still obtained a login code (Req 9)"
    echo "PASS: E2E: a device revoked over admin.sock is refused at its next login"
else
    echo "SKIP: E2E: node not found, so the REVOKE-DEVICE leg did not run"
fi

# RECOVERY-USE with revoke=all (V4-22a, CLAIMS D9): the stolen-device recovery,
# spent the way a site spends it. Until V4-22a it ran in-process only. bob has
# two devices -- the first, which the revoke=none recovery above left active,
# and the one it enrolled -- and an unspent second code. Both devices log in
# first, so the refusals after cannot be a key or a passphrase gone wrong.
if [ -n "$NODE" ] && [ -n "$SITE" ] && [ -n "$RECOVERY" ] && [ -x "$NODE" ]; then
    bob_login() {   # <handle> <key directory>
        "$CLIENT" login --handle "$1" --key "$TMP/$2/$1.ek" \
            --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
            --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2>> "$TMP/login.err"
    }
    bob_login "$BOB1" bob || fail "bob's first device could not log in before revoke=all (the canary: revoke=none left it active)"
    bob_login "$BOB2" bob2 || fail "bob's recovered device could not log in before revoke=all (the canary)"
    "$NODE" "$SITE" "$TMP/s.sock" --recover-all bob "$(sed -n 2p "$TMP/codes.txt")" \
        > "$TMP/recall.txt" 2>> "$TMP/site.err" || fail "RECOVERY-USE revoke=all over site.sock failed"
    grep -q '"recovered_all":"bob"' "$TMP/recall.txt" || fail "RECOVERY-USE revoke=all did not report its user"
    rc=0; bob_login "$BOB1" bob || rc=$?
    [ "$rc" -ne 0 ] || fail "after RECOVERY-USE revoke=all, bob's first device still obtained a login code (Req 9)"
    rc=0; bob_login "$BOB2" bob2 || rc=$?
    [ "$rc" -ne 0 ] || fail "after RECOVERY-USE revoke=all, bob's recovered device still obtained a login code (Req 9)"
    ! grep -qF -- "$(sed -n 2p "$TMP/codes.txt")" "$TMP/authd.log" || fail "the second recovery code reached the daemon log"
    echo "PASS: E2E: RECOVERY-USE with revoke=all over site.sock refuses every device of the user at its next login"
else
    echo "SKIP: E2E: node not found, so the revoke=all leg did not run"
fi

# ------------------------------------------------------------- shutdown

# V4-127 (F210): a site holds a token across the restart below. It exchanges a
# login code now, closes its connection, and asks again once the daemon is
# back. The reference site ended a session whenever the daemon could not be
# asked; what makes that wrong is that the token is still good afterwards,
# and this is where that is measured.
RESTPID=""
if [ -n "$NODE" ] && [ -n "$SITE" ] && [ -x "$NODE" ]; then
    CODEH=$("$CLIENT" login --handle "$HANDLE" --key "$TMP/dev/$HANDLE.ek" \
            --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
            --unix "$TMP/p.sock" --proxy-v2 2>> "$TMP/login.err") || fail "the login before the restart exited nonzero"
    "$NODE" "$SITE" "$TMP/s.sock" --hold "$CODEH" "$TMP" > "$TMP/hold.txt" 2> "$TMP/hold.err" &
    RESTPID=$!
    i=0
    while [ ! -e "$TMP/hold.ready" ]; do
        i=$((i + 1))
        [ "$i" -gt 400 ] || kill -0 "$RESTPID" 2>/dev/null || { cat "$TMP/hold.err"; fail "the site holding a token exited before the restart"; }
        [ "$i" -gt 400 ] && fail "the site never exchanged the code it was to hold across the restart"
        sleep 0.05
    done
fi

# Close nothing and the drain loop would wait forever: evloop_stop marks local
# slots draining rather than closing them, so a still-open client socket wedges
# shutdown. Every client above is one-shot and already gone; the site
# holding a token closed its connection before it wrote hold.ready.
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

if [ -n "$RESTPID" ]; then
    # The daemon is down: the site's request fails with no answer from it.
    : > "$TMP/hold.down"
    i=0
    while [ ! -e "$TMP/hold.down.seen" ]; do
        i=$((i + 1))
        [ "$i" -gt 400 ] && { cat "$TMP/hold.err"; fail "the site holding a token never tried the stopped daemon"; }
        sleep 0.05
    done
    "$DAEMON" --config "$TMP/authd.conf" > "$TMP/authd2.log" 2>&1 &
    DPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/authd2.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] || kill -0 "$DPID" 2>/dev/null || { cat "$TMP/authd2.log"; fail "the daemon exited when started again on its own store"; }
        [ "$i" -gt 400 ] && fail "the restarted daemon never logged event=started"
        sleep 0.05
    done
    : > "$TMP/hold.up"
    rc=0; wait "$RESTPID" || rc=$?
    RESTPID=""
    [ "$rc" -eq 0 ] || { cat "$TMP/hold.err"; fail "a token issued before the daemon restarted was refused after it: every restart would log every user out (F210)"; }
    grep -q '"held":"alice"' "$TMP/hold.txt" || fail "the token verified after the restart is not alice's: $(cat "$TMP/hold.txt")"
    grep -q '"while_down":"E[A-Z]*"' "$TMP/hold.txt" \
        || fail "with the daemon stopped the site's request did not fail as a socket error: $(cat "$TMP/hold.txt")"
    echo "PASS: E2E: a token issued before a daemon restart verifies after it; while the daemon was down the site got $(sed -n 's/.*"while_down":"\([A-Z]*\)".*/\1/p' "$TMP/hold.txt"), not a refusal (F210)"
    kill -TERM "$DPID"
    i=0
    while kill -0 "$DPID" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 200 ]; then
            kill -9 "$DPID" 2>/dev/null || true
            fail "the restarted daemon did not exit within 10s of SIGTERM"
        fi
        sleep 0.05
    done
    if wait "$DPID"; then DPID=""; else DPID=""; fi
else
    echo "SKIP: E2E: node not found, so the token-across-a-restart leg did not run"
fi

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

# ------------------------------------------ the log privacy switches (V4-13d)
#
# The shipped daemon with log_identities = hashed and log_client_ip = prefix
# (spec §15, finding F14), on the same store. test_authd_localapi proves the
# logger and the store agree in-process; only this can prove authd_main
# applies the config it parsed, and that `authd_admin pseudonym` -- the
# operator's one way back from a pseudonymous journal -- prints what the
# daemon wrote.
sed '/^listen_port/d' "$TMP/authd.conf" > "$TMP/priv.conf"
printf 'log_identities = hashed\nlog_client_ip = prefix\n' >> "$TMP/priv.conf"
"$ADMIN" --check-config --config "$TMP/priv.conf" > "$TMP/privcheck.txt" \
    || fail "the privacy config is invalid"
grep -q 'log_identities=hashed log_client_ip=prefix' "$TMP/privcheck.txt" \
    || { cat "$TMP/privcheck.txt"; fail "--check-config does not report the privacy modes"; }
"$DAEMON" --config "$TMP/priv.conf" > "$TMP/priv.log" 2>&1 &
DPID=$!
i=0
while ! grep -q 'event=started' "$TMP/priv.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] || kill -0 "$DPID" 2>/dev/null || fail "the privacy daemon exited during start-up"
    [ "$i" -gt 400 ] && fail "the privacy daemon never logged event=started"
    sleep 0.05
done
CAROL=$("$CLIENT" keygen --dir "$TMP/carol" --passphrase-file "$TMP/opass" 2>> "$TMP/keygen.err") \
    || fail "keygen for carol exited nonzero"
"$ADMIN" enroll-operator --socket "$TMP/a.sock" --user carol --handle "$CAROL" \
    --pub "$TMP/carol/$CAROL.pub" > /dev/null || fail "enroll-operator carol failed"
"$CLIENT" login --handle "$CAROL" --key "$TMP/carol/$CAROL.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2>> "$TMP/login.err" \
    || fail "login through the privacy daemon failed"
kill -TERM "$DPID"
i=0
while kill -0 "$DPID" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 200 ] && fail "the privacy daemon did not exit on SIGTERM"
    sleep 0.05
done
wait "$DPID" 2>/dev/null || true
DPID=""

IDH=$("$ADMIN" pseudonym --store "$TMP/d/store.sqlite3" --key "$TMP/d/server.ek" \
        --passphrase-file "$TMP/d/pass" --server-id authd --id "$CAROL") \
    || fail "authd_admin pseudonym exited nonzero"
case "$IDH" in
    idh=[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) fail "authd_admin pseudonym printed '$IDH', expected idh= and 16 hex characters" ;;
esac
# canaries first: the lines exist, so the absences below mean something
grep -q 'event=client-hello' "$TMP/priv.log" && grep -q 'event=login-code-issued' "$TMP/priv.log" \
    || { cat "$TMP/priv.log"; fail "the privacy daemon logged no login"; }
N=$(grep -c -- "$IDH" "$TMP/priv.log" || true)
[ "$N" -ge 3 ] || { cat "$TMP/priv.log"; fail "carol's pseudonym is on $N lines, expected enroll, client-hello and login-code-issued"; }
echo "PASS: E2E: log_identities = hashed -- authd_admin pseudonym finds carol's $N lines"
grep -q -- "$CAROL" "$TMP/priv.log" && fail "carol's handle appears in the hashed journal"
grep -q ' id=' "$TMP/priv.log" && fail "a line in the hashed journal carries id="
echo "PASS: E2E: carol's handle appears nowhere in the hashed journal"
grep -q 'src=127.0.0.0/24 ' "$TMP/priv.log" || fail "log_client_ip = prefix did not log the /24"
grep -q '127\.0\.0\.1' "$TMP/priv.log" && fail "the client's full address appears in the prefix journal"
echo "PASS: E2E: log_client_ip = prefix -- the journal keeps 127.0.0.0/24 and not the address"
# The authoritative record is untouched: the store's audit chain still names
# carol's device, which is why hashing the journal loses no evidence.
"$ADMIN" audit-verify --store "$TMP/d/store.sqlite3" --key "$TMP/d/server.ek" \
    --passphrase-file "$TMP/d/pass" --server-id authd > /dev/null 2>&1 \
    || fail "audit-verify failed after the privacy daemon ran"
python3 - "$TMP/d/store.sqlite3" "$CAROL" <<'PYEOF' || fail "the audit table does not name carol's device"
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
n = c.execute("SELECT COUNT(*) FROM audit WHERE handle = ?", (sys.argv[2].encode(),)).fetchone()[0]
sys.exit(0 if n >= 1 else 1)
PYEOF
echo "PASS: E2E: the audit chain still records carol's real handle and verifies"

# -------------------------------------- peer credentials at accept (V4-15a)
#
# Req 11 through authd_main's own wiring, which no in-process test runs: the
# harness builds its listeners itself. A daemon whose site_uids and admin_uids
# name a uid that is NOT this process's must refuse it on both sockets at
# accept -- before a byte of any command is read -- and go on serving the
# proxy-facing socket, whose list does name it. test_authd_ws proves the
# listener refuses; only this proves main hands each socket its OWN list
# (CLAIMS D11). The refusal is counted in the daemon's journal, one
# listener-peer-rejected per socket: a reply, even an error, would mean served.
FOREIGN=$(( $(id -u) + 1 ))
sed -e '/^listen_port/d' -e "s/^site_uids = .*/site_uids = $FOREIGN/" \
    -e "s/^admin_uids = .*/admin_uids = $FOREIGN/" "$TMP/authd.conf" > "$TMP/foreign.conf"
grep -q "^site_uids = $FOREIGN\$" "$TMP/foreign.conf" && grep -q "^admin_uids = $FOREIGN\$" "$TMP/foreign.conf" \
    || fail "the foreign-uid config was not derived"
"$DAEMON" --config "$TMP/foreign.conf" > "$TMP/foreign.log" 2>&1 &
DPID=$!
i=0
while ! grep -q 'event=started' "$TMP/foreign.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 400 ] || kill -0 "$DPID" 2>/dev/null || fail "the foreign-uid daemon exited during start-up"
    [ "$i" -gt 400 ] && fail "the foreign-uid daemon never logged event=started"
    sleep 0.05
done
# Waits for the journal to count one more refusal than $1; the daemon logs it
# after closing the socket, so the client can be gone first.
refused_after() {
    j=0
    while [ "$(grep -c 'event=listener-peer-rejected' "$TMP/foreign.log" || true)" -le "$1" ]; do
        j=$((j + 1)); [ "$j" -gt 100 ] && return 1
        sleep 0.05
    done
    return 0
}
n0=$(grep -c 'event=listener-peer-rejected' "$TMP/foreign.log" || true)
"$ADMIN" list-users --socket "$TMP/a.sock" > "$TMP/foreign-admin.txt" 2>&1 \
    && fail "admin.sock SERVED a uid outside admin_uids (Req 11)"
refused_after "$n0" || fail "admin.sock did not refuse a uid outside admin_uids at accept (Req 11)"
n1=$(grep -c 'event=listener-peer-rejected' "$TMP/foreign.log" || true)
"$ADMIN" list-users --socket "$TMP/s.sock" > "$TMP/foreign-site.txt" 2>&1 || true
refused_after "$n1" || fail "site.sock did not refuse a uid outside site_uids at accept (Req 11)"
kill -0 "$DPID" 2>/dev/null || fail "the foreign-uid daemon died refusing a peer"
"$CLIENT" login --handle "$CAROL" --key "$TMP/carol/$CAROL.ek" \
    --passphrase-file "$TMP/opass" --server-id authd --server-pub "$TMP/d/server.pub" \
    --unix "$TMP/p.sock" --proxy-v2 > /dev/null 2>> "$TMP/login.err" \
    || fail "the foreign-uid daemon did not serve the proxy socket its list allows (the canary)"
echo "PASS: E2E: site.sock and admin.sock refuse a uid outside their own lists at accept; the proxy socket still serves"
kill -TERM "$DPID"
i=0
while kill -0 "$DPID" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 200 ] && fail "the foreign-uid daemon did not exit on SIGTERM"
    sleep 0.05
done
wait "$DPID" 2>/dev/null || true
DPID=""

# ------------------------------------------ a real second user (V4-22b)
#
# The leg above cannot tell WHOSE uid the listener compares: the client and the
# daemon are one user, so a check that read the daemon's own uid instead of the
# peer's would pass it, and pass every other test too (CLAIMS D11). Here a
# genuinely different user connects: nobody, holding the daemon's group, which
# is spec 8's shape for the site's own user. It needs Linux's setpriv and either
# root or passwordless sudo -- CI's Linux runners and a root container both --
# and is skipped elsewhere; the leg above still runs everywhere.
#
# Two barriers stand in front of each socket, and this tells them apart. File
# permission comes first: $TMP is 0700, admin.sock 0600, so the sockets live in
# their own 0711 directory and admin.sock is opened to everyone here -- the peer
# check must hold by itself. The peer check comes second, at accept, and is what
# the journal counts. A client stopped by file permission says cannot-connect
# and is never counted; one refused at accept got through connect() and is.
AS=""
RU_OK=1
if [ "$(uname -s)" != Linux ] || ! command -v setpriv > /dev/null 2>&1 || ! id -u nobody > /dev/null 2>&1; then
    RU_OK=0
elif [ "$(id -u)" -ne 0 ]; then
    if sudo -n true 2> /dev/null; then AS="sudo -n"; else RU_OK=0; fi
fi
if [ "$RU_OK" -eq 1 ]; then
    NB_UID=$(id -u nobody); NB_GID=$(id -g nobody); D_GID=$(id -g)
    [ "$NB_UID" -ne "$(id -u)" ] || fail "nobody is this process's own uid"
    RU=$(mktemp -d "${TMPDIR:-/tmp}/authd-ru.XXXXXX") && chmod 0711 "$RU" || fail "could not make the real-user socket directory"
    cp "$ADMIN" "$RU/authd_admin" && chmod 0755 "$RU/authd_admin" || fail "could not copy authd_admin for nobody"
    # $AS is "sudo -n" or nothing: word splitting is the point.
    # shellcheck disable=SC2086
    as_nobody()       { $AS setpriv --reuid="$NB_UID" --regid="$NB_GID" --groups="$D_GID" -- "$@"; }
    # shellcheck disable=SC2086
    as_nobody_alone() { $AS setpriv --reuid="$NB_UID" --regid="$NB_GID" --clear-groups -- "$@"; }
    sed -e '/^listen_port/d' -e "s|^listen_unix = .*|listen_unix = $RU/p.sock|" \
        -e "s|^site_socket = .*|site_socket = $RU/s.sock|" -e "s|^admin_socket = .*|admin_socket = $RU/a.sock|" \
        -e "s/^site_uids = .*/site_uids = $NB_UID/" "$TMP/authd.conf" > "$TMP/realuser.conf"
    grep -q "^site_uids = $NB_UID\$" "$TMP/realuser.conf" && grep -q "^admin_uids = $(id -u)\$" "$TMP/realuser.conf" \
        && grep -q "^proxy_uids = $(id -u)\$" "$TMP/realuser.conf" && grep -q "^site_socket = $RU/s.sock\$" "$TMP/realuser.conf" \
        || fail "the real-user config was not derived"
    "$DAEMON" --config "$TMP/realuser.conf" > "$TMP/realuser.log" 2>&1 &
    DPID=$!
    i=0
    while ! grep -q 'event=started' "$TMP/realuser.log" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt 400 ] || kill -0 "$DPID" 2>/dev/null || fail "the real-user daemon exited during start-up"
        [ "$i" -gt 400 ] && fail "the real-user daemon never logged event=started"
        sleep 0.05
    done
    chmod 0666 "$RU/a.sock" || fail "could not open admin.sock's file mode for the leg"
    rej() { grep -c 'event=listener-peer-rejected' "$TMP/realuser.log" || true; }
    rej_after() {
        j=0
        while [ "$(rej)" -le "$1" ]; do j=$((j + 1)); [ "$j" -gt 100 ] && return 1; sleep 0.05; done
        return 0
    }
    # The canary: site.sock's list names nobody, so nobody is SERVED -- the
    # daemon answers (an admin command on site.sock is refused by the command
    # table, which is an answer), and no rejection is counted.
    n=$(rej)
    as_nobody "$RU/authd_admin" list-users --socket "$RU/s.sock" > "$TMP/ru-site.txt" 2>&1 || true
    grep -q "refused: " "$TMP/ru-site.txt" \
        || fail "nobody, whom site_uids names, was not served on site.sock (the canary): $(cat "$TMP/ru-site.txt")"
    [ "$(rej)" -eq "$n" ] || fail "nobody's served connection to site.sock was counted as a peer rejection"
    # admin.sock: the file mode lets nobody connect, so only the peer check can
    # refuse it -- and nobody is not in admin_uids.
    n=$(rej)
    as_nobody "$RU/authd_admin" list-users --socket "$RU/a.sock" > "$TMP/ru-admin.txt" 2>&1 \
        && fail "admin.sock SERVED nobody, a real user outside admin_uids (Req 11)"
    grep -q "cannot-connect" "$TMP/ru-admin.txt" && fail "nobody's connect() to admin.sock failed: file permission, not the peer check"
    rej_after "$n" || fail "admin.sock did not refuse nobody at accept (Req 11)"
    # p.sock: 0660, and nobody holds the daemon's group, so again only the peer
    # check stands between them -- proxy_uids does not name nobody.
    n=$(rej)
    as_nobody "$RU/authd_admin" list-users --socket "$RU/p.sock" > "$TMP/ru-proxy.txt" 2>&1 \
        && fail "the proxy socket SERVED nobody, a real user outside proxy_uids (Req 11)"
    grep -q "cannot-connect" "$TMP/ru-proxy.txt" && fail "nobody's connect() to the proxy socket failed: file permission, not the peer check"
    rej_after "$n" || fail "the proxy socket did not refuse nobody at accept (Req 11)"
    # The control: without the daemon's group, nobody is stopped by site.sock's
    # 0660 at connect() and the daemon never sees it -- so the two refusals
    # above were the peer check, not a file permission counted by mistake.
    n=$(rej)
    as_nobody_alone "$RU/authd_admin" list-users --socket "$RU/s.sock" > "$TMP/ru-perm.txt" 2>&1 \
        && fail "nobody without the daemon's group reached site.sock"
    grep -q "cannot-connect" "$TMP/ru-perm.txt" || fail "nobody without the daemon's group was not stopped at connect(): $(cat "$TMP/ru-perm.txt")"
    sleep 0.3
    [ "$(rej)" -eq "$n" ] || fail "a connect() refused by file permission was counted as a peer rejection"
    kill -0 "$DPID" 2>/dev/null || fail "the real-user daemon died refusing a peer"
    echo "PASS: E2E: a real second user (nobody, uid $NB_UID) is served where its uid is listed and refused at accept where it is not; without the group it never reaches the check"
    # V4-42 (audit F122, spec 12): a device key owned by another user is
    # refused even when its mode is right. Such a file is unreadable to anyone
    # but its owner and root, so root runs the client: with mode 0600 passing
    # the custody check's other half, the owner comparison is the only barrier.
    # The canary is a root-owned copy, which root may open: the refusal is
    # about whose file it is, not about root. Root needs a passphrase file of
    # its own too: the client holds that file to the same custody rule, and
    # CI's first run of this leg stopped there, at not-owned-by-this-user.
    mkdir "$RU/ck" && cp "$TMP/dev/$HANDLE.ek" "$RU/ck/foreign.ek" && chmod 0600 "$RU/ck/foreign.ek" \
        || fail "could not copy the device key for the custody leg"
    # shellcheck disable=SC2086
    $AS install -m 0600 "$TMP/opass" "$RU/ck/opass" || fail "could not make root's own passphrase file"
    # shellcheck disable=SC2086
    $AS chown "$NB_UID" "$RU/ck/foreign.ek" || fail "could not hand the key copy to nobody"
    [ "$(stat -c %u:%a "$RU/ck/foreign.ek")" = "$NB_UID:600" ] || fail "the foreign key copy is not nobody's, mode 0600"
    # shellcheck disable=SC2086
    $AS "$CLIENT" login --handle "$HANDLE" --key "$RU/ck/foreign.ek" --passphrase-file "$RU/ck/opass" \
        --server-id authd --server-pub "$TMP/d/server.pub" --unix "$TMP/p.sock" --proxy-v2 \
        > /dev/null 2> "$TMP/ck-foreign.err" && fail "the client opened a device key owned by another user (spec 12)"
    grep -q 'unsafe-permissions' "$TMP/ck-foreign.err" \
        || fail "a device key owned by another user was refused for another reason: $(cat "$TMP/ck-foreign.err")"
    # shellcheck disable=SC2086
    $AS install -m 0600 "$TMP/dev/$HANDLE.ek" "$RU/ck/own.ek" || fail "could not make root's own key copy"
    # shellcheck disable=SC2086
    $AS "$CLIENT" login --handle "$HANDLE" --key "$RU/ck/own.ek" --passphrase-file "$RU/ck/opass" \
        --server-id authd --server-pub "$TMP/d/server.pub" --unix "$TMP/p.sock" --proxy-v2 \
        > /dev/null 2> "$TMP/ck-own.err" || true
    grep -q 'unsafe-permissions' "$TMP/ck-own.err" && fail "root's own 0600 key copy was refused as unsafe-permissions (the canary)"
    echo "PASS: E2E: a device key owned by another user is refused as unsafe-permissions though its mode is 0600; the owner's own copy is not (spec 12)"
    # V4-48: the passphrase file is held to the same rule (authd_secret.c's
    # owner check), and CI's first run of the leg above hit it by accident.
    # A 0600 copy that nobody owns must be refused before any key is opened;
    # root's own copy, used above, is the canary.
    cp "$TMP/opass" "$RU/ck/foreign.pass" && chmod 0600 "$RU/ck/foreign.pass" \
        || fail "could not copy the passphrase file for the custody leg"
    # shellcheck disable=SC2086
    $AS chown "$NB_UID" "$RU/ck/foreign.pass" || fail "could not hand the passphrase copy to nobody"
    # shellcheck disable=SC2086
    $AS "$CLIENT" login --handle "$HANDLE" --key "$RU/ck/own.ek" --passphrase-file "$RU/ck/foreign.pass" \
        --server-id authd --server-pub "$TMP/d/server.pub" --unix "$TMP/p.sock" --proxy-v2 \
        > /dev/null 2> "$TMP/ck-pass.err" && fail "the client used a passphrase file owned by another user (spec 12)"
    grep -q 'not-owned-by-this-user' "$TMP/ck-pass.err" \
        || fail "a passphrase file owned by another user was refused for another reason: $(cat "$TMP/ck-pass.err")"
    grep -q 'not-owned-by-this-user' "$TMP/ck-own.err" \
        && fail "root's own passphrase copy was refused as not-owned-by-this-user (the canary)"
    echo "PASS: E2E: a passphrase file owned by another user is refused as not-owned-by-this-user; the owner's own copy is not"
    kill -TERM "$DPID"
    i=0
    while kill -0 "$DPID" 2>/dev/null; do
        i=$((i + 1)); [ "$i" -gt 200 ] && fail "the real-user daemon did not exit on SIGTERM"
        sleep 0.05
    done
    wait "$DPID" 2>/dev/null || true
    DPID=""
else
    echo "SKIP: E2E: no setpriv, nobody, root or passwordless sudo here, so the real-second-user leg did not run"
fi

# ------------------------------------------------ sanitizer reports (F94)
#
# The daemons this script starts write to their own logs, which ctest never
# sees. Under a UBSan build UB now aborts the process (V4-14c), which some leg
# would notice -- but a report in a log nobody reads is how F94 went unseen,
# so every log this run wrote is searched for one, ASan's included.
for f in "$TMP"/*.log "$TMP"/*.err; do
    [ -f "$f" ] || continue
    if grep -qE 'runtime error:|ERROR: AddressSanitizer|ERROR: LeakSanitizer' "$f"; then
        fail "a sanitizer report is in $f"
    fi
done
echo "PASS: E2E: no sanitizer report in any daemon or client log"

# --------------------------------------------------------- secret scan

# The passphrase bytes must not appear in any log. Unlike the daemon's logger,
# which has no arbitrary-buffer sink at all, the CLIs use fprintf freely -- so
# "it cannot happen by construction" is not an argument available here.
PASSHEX=$(cat "$TMP/opass")
for f in "$TMP"/*.log "$TMP"/*.err "$TMP"/*.txt; do
    [ -f "$f" ] || continue
    if grep -qi "$PASSHEX" "$f"; then fail "the device passphrase appears in $f"; fi
done

# No secret-key BYTES are scanned for here: every key this flow writes is
# sealed, and this script holds no plaintext key to look for. The header scan
# (after init, and again at the very end) finds a file that BEGINS with
# MLDSASK; key bytes anywhere else are looked for by test_authd_cli, which
# opens each sealed key in-process and scans for windows of it (V4-15c).
# -F -- : the code is base64url, and one in 64 begins with '-', which grep
# read as OPTIONS (audit finding F89). "-V..." printed grep's version and
# exited 0 -- a false FAIL; most other option strings exited 2, and the check
# passed without searching anything. -F because a code is a string, not a
# pattern.
if grep -qF -- "$CODE" "$TMP/authd.log"; then fail "the login code appears in the daemon log"; fi
echo "PASS: E2E: no passphrase and no login code appears in any log"

# ------------------------------------------ Req 10, after every key operation
#
# The header scan at the top runs once, right after init -- before keygen,
# rotation, recovery and the carol and dave legs had written anything, so it
# covered none of them (CLAIMS D10). The same scan, now that all of them have.
found=""
for f in $(find "$TMP" -type f); do
    case "$(head -c 8 "$f" 2>/dev/null || true)" in
        MLDSASK1|MLDSASK2) found="$f" ;;
    esac
done
[ -z "$found" ] || fail "a plaintext MLDSASK file was written: $found (Req 10)"
echo "PASS: E2E: after every key operation, still no plaintext secret-key file anywhere under the work directory"

echo "All checks passed"
