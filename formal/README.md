# formal/ — a ProVerif model of the mldsa-authd handshake, login and rotation

`authd.pv` models, in the symbolic (Dolev–Yao) setting, the spec-v2 handshake
(§6.3) together with the two things `docs/mldsa-authd-spec.md` adds on top of
it: the login-code exchange (§6.2) and key rotation (§6.3). Each construct
carries a comment citing the specification line it mirrors.

## What it proves (base model)

- **Injective mutual agreement**: the daemon agrees with the device on
  `(A, B, session_id, nonce_B, key)`; the device agrees with the daemon on
  `(A, B, session_id, nonce_B)` when it accepts the ServerHello, and on the key
  only through key confirmation, when it decrypts the daemon's first record
  (V4-297: this sentence said both directions agreed on the key, F509).
- **Session-key secrecy.**
- **Login-code secrecy**, and that a site login under a `state` was begun by
  that device with that `state` -- with the attacker able to open connections
  of its own to the daemon, under a `state` of its choosing, as anyone can
  (spec 7.1: the proxy forwards an upgrade with no `Origin`), and to post a
  code and a session of its choosing to the site. What protects the device
  is that its page posts its code inside its own session. Until V4-297 only
  the page ever opened a connection, and the property held because nobody
  else could (audit F506).
- **The code the site accepts is the code the daemon issued** to that device
  under that `state` (V4-265). The site's event carries the code, and anyone
  may post a code of their choosing to the site as well as the page that
  holds the real one. Before V4-265 only that page could post, and the
  site's comparison of the two codes could be deleted from the model with
  every result unchanged (audit F404).
- **That it runs** (V4-204): ProVerif exhibits a run that reaches the site's
  login, which passes through the daemon establishing the session, issuing
  the code, and the device confirming it. Until V4-204 the site's login could
  not occur in the model at all, and the `state` property above was true of
  a protocol that logged nobody in (audit F281).
- **Rotation binding**: a committed rotation was requested in that session;
  and (V4-265) ProVerif exhibits a run in which a rotation is committed.

## Why the controls exist

A proof that cannot fail proves nothing. `gen_controls.py` derives fifteen
variants from `authd.pv` by exact string replacement, each asserting the edit
changed the file:

- **resilience** (must still prove): leak the ML-KEM secret, or the X25519
  secret, or the record key — the relevant guarantee still holds. The first
  two are the hybrid claim, checked rather than asserted: either KEX half
  surviving is enough.
- **controls** (must become unprovable): sign only `ClientHello` (mutual
  agreement breaks); drop the initiator's check that the responder it
  reached is the one it dialed (mutual agreement breaks: the model has two
  pinned servers and resolves `sig_B`'s key by the id received, as the code
  does — V4-75, F147); ablate one half of the KDF while leaking the other (the
  key becomes recoverable — so both halves are load-bearing); drop
  `handshake_id` from the rotation digest, or skip the outgoing-key signature,
  while leaking the record key (rotation is no longer bound to its session).
  Since V4-204 the other four properties have one each: the daemon skips
  `sig_A` (it no longer authenticates the device); the device takes the
  daemon's first record without decrypting it (key confirmation breaks); the
  login code is also sent in the clear (it is no longer secret). Since
  V4-265: the site does not compare the code it is given with the code that
  was issued (any posted value logs the device in). Since V4-297: the site
  does not compare the `state` (a code issued under the attacker's `state`, a
  ClientHello relayed into the attacker's own connection, is accepted in the
  page's session: the code accepted is not the code issued under that
  `state`); and the site takes the session from the request apart from the
  code, as this model did before (a login lands in the attacker's session:
  the login-CSRF itself).

  Every query has a control. Not every check in the model has one (V4-297,
  F507): deleted one at a time, these leave every result unchanged --
  the session-id echo and the ClientAuth `handshake_id` (each covered by the
  signatures too), the responder's and ROTATE's `=A` on the claimed id, the
  distinct rotation labels and `pk_old` in the rotation digest (each needs a
  second enrolled device to matter, which the model does not have), the
  ROTATE op tag, the single-use of a login code (no query is injective,
  below), and the incoming key's signature (Limits). Removing `ClientHello`
  from `sig_B` and unbinding `state` from its ClientHello are caught, but
  only by the `sigb` control's anchor and by the reachability check.

The base *proves* each property "true"; a control must make the same query
**"false"**, which is ProVerif exhibiting the attack. `run.sh` requires
"is true" for the base and resilience runs and "is false" for every control,
and it counts the base model's results, thirteen, so that a query nobody
named cannot be answered "false" unnoticed (V4-265, audit F405).

Until V4-265 three controls, the two for rotation and the one for the login
code, answered "cannot be proved", and `run.sh` accepted that. The cause was
not, as this page said, that injective agreement under a leaked key is hard
for ProVerif. The model sent on its two private channels with sequential
outputs, so everything after such a send waited for a receiver; ProVerif
proves with that abstracted away and then could not rebuild a run that goes
past one. The sends are now in parallel with what follows them, which is
what sending is, and all eleven controls give a run (audit F406). V4-297
made the page's own send on its connection asynchronous for the same
reason, and all twelve do.

## Limits

What the model leaves out, so that nothing is read into it:

- **One honest device, no dishonest enrolled one.** The daemon's process is
  given the device's id and key; the code resolves a key by the handle
  claimed, and answers an unknown handle with a decoy. Misbinding between
  two enrolled devices is not analysed. The identities are in both
  signatures' transcripts and in the KDF, which is the usual defence; the
  model does not show it.
- **No long-term key is ever given to the attacker.** Forward secrecy and
  key-compromise impersonation are not modelled, so nothing here supports
  or contradicts what the protocol specification says of forward secrecy, and
  it makes no statement about key-compromise impersonation.
- **The page's own connection carries its `state` on a channel the
  attacker cannot write** -- the WebSocket URL, under the site's TLS -- but
  since V4-297 the attacker opens connections of its own with any `state`.
  Only the WebSocket path is modelled: the raw listener binds the empty
  state, and `EXCHANGE` accepts one, so P4 is a property of the browser
  path. The CLI hands its code to the site by a person's paste, not by the
  page's post, and is not modelled (F511).
- **A login code is used once and expires in 60 s: not modelled.** No query
  is injective (an injective P4b cannot be proved even of the base), and the
  model has no time. Single use and expiry rest on the tests and mutations
  claim D5 names (V4-297, F508).
- **Records are bare encryption.** No sequence numbers, no associated data,
  no BYE, no `ROTATE_ACK`; a completed rotation does not change the key the
  daemon expects next. Replay protection and "the old key is refused
  afterwards" rest on tests, not on this model.
- **The incoming key's signature has no control.** Spec Req 8 wants a
  rotation signed by the outgoing key and by the incoming one. The model
  checks both, and the rotation query would hold without the second: the
  outgoing key's signature already covers the new public key, and the one
  honest device always holds the new secret key. Showing what `sig_new`
  buys needs a dishonest enrolled device, which this model does not have
  (the first limit above). The check itself is pinned in the code by tests
  and by mutations `v49c W3` and `v126 RO1`.
- **Secrecy and agreement name the client-to-server key.** The other
  direction's key has the same inputs and protects the login code, whose
  secrecy is its own query.
- **Not modelled at all** (V4-297, F510): recovery, enrollment, revocation
  and tokens; ROTATE's `flags` (the code's digest includes them, the
  model's does not); ClientAuth's re-check that the key is still active
  (V4-79); and the uniform responder flow -- the decoy and its timing floor
  are about what an observer can tell, which a symbolic model cannot say.

## Running it

ProVerif's opam package pulls in GTK; build the CLI from source instead:

```
opam switch create . 5.1.1        # or any OCaml >= 4.14 + ocamlfind
curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && (cd proverif2.05 && ./build)   # exits 2 on the
                                                              # GUI half; the CLI builds
formal/run.sh proverif2.05/proverif
```

`run.sh` exits 0 only if the base and resilience runs prove and every control
fails. It is what the `formal` nightly job runs.
