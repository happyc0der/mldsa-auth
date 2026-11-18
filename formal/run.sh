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
# V4-265 (F405): every result the base model gives is one of the thirteen named
# below. `expect` looks for the results it names; a query added to authd.pv
# and answered "false" or "cannot be proved" was looked for by nobody, and
# this script still printed OK.
BASE_RESULTS=13
n=$(res authd.pv | grep -vc "even event")
if [ "$n" -ne "$BASE_RESULTS" ]; then
  printf '  FAIL  the base model gives %s results; this script names %s\n' "$n" "$BASE_RESULTS"; fail=1
else printf '  ok    the base model gives %s results, each named below\n' "$n"; fi
echo "-- base: all properties hold --"
expect base authd.pv \
  "inj-event(respEstablished(a,b,s,nb,k)) ==> inj-event(initEstablished(a,b,s,nb,k)) is true" \
  "inj-event(initEstablished(a,b,s,nb,k)) ==> inj-event(respSentServerHello(a,b,s,nb)) is true" \
  "inj-event(initConfirmed(a,b,s,nb,k)) ==> inj-event(respEstablished(a,b,s,nb,k)) is true" \
  "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true" \
  "event(codeIssued(d,st_1,cd)) && attacker(cd)) is true" \
  "event(siteLoggedIn(d,st_1,cd)) ==> event(loginStart(d,st_1)) is true" \
  "event(siteLoggedIn(d,st_1,cd)) ==> event(codeIssued(d,st_1,cd)) is true" \
  "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h)) is true"
# V4-204 (F281): the events the properties speak of can OCCUR. "not event(X)
# is false" is ProVerif exhibiting a run that reaches X. Until V4-204 the
# site's login could not occur at all, and the state query above was true of
# a protocol that never logged anyone in. A site login is reached only
# through the daemon establishing, the code being issued and the initiator
# confirming it, so this one run covers the whole login path.
echo "-- reachability: the honest protocol runs --"
expect reachable authd.pv \
  "not event(siteLoggedIn(d,st_1,cd)) is false" \
  "not event(codeIssued(d,st_1,cd)) is false" \
  "not event(initEstablished(a,b,s,nb,k)) is false" \
  "not event(respEstablished(a,b,s,nb,k)) is false" \
  "not event(rotated(d,po,pn,h)) is false"
echo "-- resilience: one KEX half or the record key leaks, guarantee holds --"
expect leak_kem controls/leak_kem.pv "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true"
expect leak_dh  controls/leak_dh.pv  "event(initEstablished(a,b,s,nb,k)) && attacker(k)) is true"
expect leak_c2s controls/leak_c2s.pv "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h)) is true"
# A control succeeds when its target query is FALSE: ProVerif exhibits the
# attack. Until V4-265 "cannot be proved" was accepted too, which three
# controls gave (F406): that says ProVerif found a derivation and could not
# turn it into a run, which is weaker evidence than a run. Every control
# now gives a run, and anything else fails.
broken() { # label, file, query-substring
  local label="$1" file="$2" q="$3"
  local line; line=$($TO "$PV" -in pitype "$file" 2>&1 | grep -E "^RESULT" | grep -F "$q" | grep -v "even event" | head -1)
  if [ -z "$line" ]; then printf '  FAIL  %-16s query not found\n' "$label"; fail=1
  elif grep -q "is true\." <<<"$line"; then printf '  FAIL  %-16s still proves: %s\n' "$label" "$line"; fail=1
  elif ! grep -q "is false\." <<<"$line"; then printf '  FAIL  %-16s no attack exhibited: %s\n' "$label" "$line"; fail=1
  else printf '  ok    %-16s no longer provable (is false)\n' "$label"; fi
}
echo "-- controls: each MUST make its target property unprovable --"
broken ctl_sigb        controls/sigb.pv       "inj-event(initEstablished(a,b,s,nb,k)) ==> inj-event(respSentServerHello(a,b,s,nb))"
broken ctl_peerid      controls/peerid.pv     "inj-event(initEstablished(a,b,s,nb,k)) ==> inj-event(respSentServerHello(a,b,s,nb))"
broken ctl_kdf_nodh    controls/kdf_nodh.pv   "event(initEstablished(a,b,s,nb,k)) && attacker(k))"
broken ctl_kdf_nokem   controls/kdf_nokem.pv  "event(initEstablished(a,b,s,nb,k)) && attacker(k))"
broken ctl_siga        controls/siga.pv       "inj-event(respEstablished(a,b,s,nb,k)) ==> inj-event(initEstablished(a,b,s,nb,k))"
broken ctl_conf        controls/conf.pv       "inj-event(initConfirmed(a,b,s,nb,k)) ==> inj-event(respEstablished(a,b,s,nb,k))"
broken ctl_codeplain   controls/codeplain.pv  "event(codeIssued(d,st_1,cd)) && attacker(cd))"
# V4-297 (F506): without the state comparison, a code issued under the
# attacker's state (a ClientHello relayed into a connection the attacker
# opened) lands in the page's own session -- the code accepted is not the one
# issued under that state. The session control is the login-CSRF itself.
broken ctl_state       controls/state.pv      "event(siteLoggedIn(d,st_1,cd)) ==> event(codeIssued(d,st_1,cd))"
broken ctl_session     controls/session.pv    "event(siteLoggedIn(d,st_1,cd)) ==> event(loginStart(d,st_1))"
broken ctl_code        controls/code.pv       "event(siteLoggedIn(d,st_1,cd)) ==> event(codeIssued(d,st_1,cd))"
broken ctl_rot_hsid    controls/rot_hsid.pv   "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h))"
broken ctl_rot_sigold  controls/rot_sigold.pv "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h))"
echo "---"
[ $fail -eq 0 ] && echo "OK: base proves, resilience holds, every control fails -- the proofs are not vacuous" || echo "FAIL"
exit $fail
