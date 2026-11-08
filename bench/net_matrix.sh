#!/bin/bash
# The network matrix (V4-71): demo logins over emulated links.
#
#   bench/net_matrix.sh <build-dir> [logins-per-profile] [out-dir]     Linux only
#
# Runs itself again inside an unprivileged user and network namespace
# (`unshare -rn`), where a real kernel netem qdisc goes on the namespace's own
# loopback. Nothing outside the namespace is touched: no root, no change to the
# host's network. netem applies to each direction, so a profile's RTT is twice
# its delay.
#
# For each profile it starts a fresh demo auth_server -- the demo ledger admits
# 16 handshakes per 30 s (audit F1), so one server reused across profiles
# refuses logins for that reason and not the link's -- then times N logins
# (`auth_client connect`, one echo, GOODBYE) from process start to exit.
#
# A profile whose emulation did not take is a FAILURE, not a row: the measured
# ping RTT must be within 25% (or 0.35 ms) of twice the profile's delay. Without
# that check a qdisc that silently failed to attach would publish loopback
# numbers under a satellite's name.
#
# Exit: 0 all profiles measured; 1 a profile failed its RTT check or a login
# failed; 2 usage; 77 this host cannot run it (no unshare, tc or netem).
set -u

BUILD="${1:-}"
N="${2:-15}"
OUT="${3:-$PWD/net-matrix}"
[ -n "$BUILD" ] || { echo "usage: $0 <build-dir> [logins-per-profile] [out-dir]"; exit 2; }
BUILD=$(cd "$BUILD" 2>/dev/null && pwd) || { echo "build directory not found: $1"; exit 2; }
for b in apps/auth_server apps/auth_client; do
    [ -x "$BUILD/$b" ] || { echo "$BUILD/$b not built"; exit 2; }
done

# name|netem arguments|delay in ms, each direction
PROFILES='none||0
lan|delay 0.25ms|0.25
broadband|delay 10ms 1ms|10
continental|delay 40ms 4ms|40
intercontinental|delay 75ms 5ms|75
4g|delay 25ms 8ms loss 0.5% rate 20mbit|25
3g|delay 100ms 20ms loss 1% rate 1mbit|100
2g|delay 150ms 30ms loss 2% rate 200kbit|150
satellite|delay 300ms 10ms loss 0.5% rate 5mbit|300
lossy5|delay 10ms loss 5%|10
lossy10|delay 10ms loss 10%|10
lossy20|delay 25ms loss 20%|25'

if [ "${NET_MATRIX_INNER:-}" != 1 ]; then
    [ "$(uname -s)" = Linux ] || { echo "SKIP: Linux only (netem)"; exit 77; }
    command -v unshare >/dev/null && command -v tc >/dev/null && command -v ping >/dev/null ||
        { echo "SKIP: needs unshare, tc and ping"; exit 77; }
    unshare -rn true 2>/dev/null || { echo "SKIP: unprivileged user namespaces are not available here"; exit 77; }
    mkdir -p "$OUT"
    NET_MATRIX_INNER=1 exec unshare -rn bash "$0" "$BUILD" "$N" "$OUT"
fi

# ---- inside the namespace ------------------------------------------------
ip link set lo up
tc qdisc add dev lo root netem delay 1ms 2>/dev/null && tc qdisc del dev lo root ||
    { echo "SKIP: the kernel has no netem qdisc"; exit 77; }
K="$OUT/keys"; rm -rf "$K"; mkdir -p "$K"
"$BUILD/apps/auth_server" keygen --id srv --dir "$K" >/dev/null &&
"$BUILD/apps/auth_client" keygen --id cli --dir "$K" >/dev/null || { echo "FAIL: keygen"; exit 1; }

CSV="$OUT/logins.csv"
echo "profile,i,ms,exit" > "$CSV"
rc=0
printf '%-17s %9s %9s %5s %10s %10s %10s\n' profile "rtt ms" "want ms" ok median p90 max
while IFS='|' read -r name args delay; do
    tc qdisc del dev lo root 2>/dev/null
    if [ -n "$args" ]; then
        # shellcheck disable=SC2086  # netem's arguments are words
        tc qdisc add dev lo root netem $args || { echo "FAIL: $name: tc refused [$args]"; rc=1; continue; }
    fi
    rtt=$(ping -c 5 -q 127.0.0.1 2>/dev/null | sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
    want=$(awk -v d="$delay" 'BEGIN { printf "%.2f", 2 * d }')
    if ! awk -v r="${rtt:-x}" -v w="$want" 'BEGIN { if (r == "x") exit 1; t = w * 0.25; if (t < 0.35) t = 0.35;
                                                   d = r - w; if (d < 0) d = -d; exit (d <= t) ? 0 : 1 }'; then
        echo "FAIL: $name: measured RTT ${rtt:-none} ms, the profile emulates $want ms -- the emulation did not take"
        rc=1
        continue
    fi
    rm -f "$OUT/port"
    "$BUILD/apps/auth_server" serve --id srv --key "$K/srv.sk" --pin "cli=$K/cli.pub" \
        --port-file "$OUT/port" >> "$OUT/server.log" 2>&1 &
    spid=$!
    for _ in $(seq 50); do [ -s "$OUT/port" ] && break; sleep 0.1; done
    port=$(cat "$OUT/port" 2>/dev/null) || { echo "FAIL: $name: the server did not start"; rc=1; kill "$spid"; continue; }
    for i in $(seq "$N"); do
        t0=$(date +%s%N)
        "$BUILD/apps/auth_client" connect --id cli --key "$K/cli.sk" --peer "srv=$K/srv.pub" \
            --port "$port" --message hello >/dev/null 2>>"$OUT/client.err"
        e=$?
        t1=$(date +%s%N)
        echo "$name,$i,$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", (b - a) / 1e6 }'),$e" >> "$CSV"
    done
    kill "$spid"; wait "$spid" 2>/dev/null
    awk -F, -v p="$name" -v r="$rtt" -v w="$want" '
        $1 == p { n++; if ($4 == 0) { ok++; v[ok] = $3 } }
        END {
            for (i = 1; i <= ok; i++) for (j = i + 1; j <= ok; j++) if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
            med = (ok % 2) ? v[(ok + 1) / 2] : (v[ok / 2] + v[ok / 2 + 1]) / 2
            printf "%-17s %9.2f %9.2f %2d/%-2d %10.1f %10.1f %10.1f\n", p, r, w, ok, n, med, v[int(0.9 * (ok - 1)) + 1], v[ok]
            exit (ok == n) ? 0 : 1
        }' "$CSV" || { echo "FAIL: $name: a login failed (see $OUT/client.err)"; rc=1; }
done <<< "$PROFILES"
tc qdisc del dev lo root 2>/dev/null
echo "raw: $CSV"
exit "$rc"
