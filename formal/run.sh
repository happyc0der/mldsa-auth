#!/bin/bash
# V4-4: prove the base model, and prove every proof can fail.
#   formal/run.sh [path-to-proverif]
# Exits 0 only if every base property is true, every resilience run is true,
# and every deliberately-broken control makes its target property FALSE.
set -u
cd "$(dirname "$0")" || exit 2
PV="${1:-proverif}"; command -v "$PV" >/dev/null || { echo "FAIL: proverif not found ($PV)"; exit 2; }
if command -v timeout >/dev/null; then TO="timeout 600"; elif command -v gtimeout >/dev/null; then TO="gtimeout 600"; else TO=""; echo "  (no timeout: queries run unbounded)"; fi
python3 gen_controls.py >/dev/null || { echo "FAIL: control generation"; exit 1; }
mkdir -p out; fail=0
res() { $TO "$PV" -in pitype "$1" 2>&1 | grep -E "^RESULT"; }
expect() { # label, file, "substring => is true|false", ...
  local label="$1" file="$2"; shift 2
  local r; r=$(res "$file"); local ok=1 want
  for want in "$@"; do grep -qF "$want" <<<"$r" || { ok=0; MISS="$want"; }; done
  if [ $ok -eq 1 ]; then printf '  ok    %s\n' "$label"
  else printf '  FAIL  %-14s missing: %s\n' "$label" "$MISS"; sed 's/^/          /' <<<"$r"; fail=1; fi
}
echo "formal/run.sh: $($PV -help 2>&1 | head -1)"
echo "-- base: all properties hold --"
expect base authd.pv \
  "inj-event(respEstablished(a,b,s,nb,k)) ==> inj-event(initEstablished(a,b,s,nb,k)) is true" \
  "inj-event(initEstablished(a,b,s,nb,k)) ==> inj-event(respSentServerHello(a,b,s,nb)) is true" \
  "inj-event(initConfirmed(a,b,s,nb,k)) ==> inj-event(respEstablished(a,b,s,nb,k)) is true" \
  "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true" \
  "event(codeIssued(d,st_1,cd)) && attacker(cd)) is true" \
  "event(siteLoggedIn(d,st_1)) ==> event(loginStart(d,st_1)) is true" \
  "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h)) is true"
echo "-- resilience: one KEX half or the record key leaks, guarantee holds --"
expect leak_kem controls/leak_kem.pv "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true"
expect leak_dh  controls/leak_dh.pv  "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true"
expect leak_c2s controls/leak_c2s.pv "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h)) is true"
# A control succeeds when its target query is no longer PROVABLE: the base
# proves it "is true", the broken variant yields "is false" or "cannot be
# proved". Either way the guarantee is gone, which is what the control shows.
broken() { # label, file, query-substring
  local label="$1" file="$2" q="$3"
  local line; line=$($TO "$PV" -in pitype "$file" 2>&1 | grep -E "^RESULT" | grep -F "$q" | grep -v "even event" | head -1)
  if [ -z "$line" ]; then printf '  FAIL  %-16s query not found\n' "$label"; fail=1
  elif grep -q "is true\." <<<"$line"; then printf '  FAIL  %-16s still proves: %s\n' "$label" "$line"; fail=1
  else printf '  ok    %-16s no longer provable (%s)\n' "$label" "$(grep -oE 'is false|cannot be proved' <<<"$line")"; fi
}
echo "-- controls: each MUST make its target property unprovable --"
broken ctl_sigb        controls/sigb.pv       "inj-event(initEstablished(a,b,s,nb,k)) ==> inj-event(respSentServerHello(a,b,s,nb))"
broken ctl_kdf_nodh    controls/kdf_nodh.pv   "event(initEstablished(a,b,s,nb,k)) && attacker(k))"
broken ctl_kdf_nokem   controls/kdf_nokem.pv  "event(initEstablished(a,b,s,nb,k)) && attacker(k))"
broken ctl_rot_hsid    controls/rot_hsid.pv   "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h))"
broken ctl_rot_sigold  controls/rot_sigold.pv "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h))"
echo "---"
[ $fail -eq 0 ] && echo "OK: base proves, resilience holds, every control fails -- the proofs are not vacuous" || echo "FAIL"
exit $fail
