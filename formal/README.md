# formal/ — a ProVerif model of the mldsa-authd handshake, login and rotation

`authd.pv` models, in the symbolic (Dolev–Yao) setting, the spec-v2 handshake
(§6.3) together with the two things `docs/mldsa-authd-spec.md` adds on top of
it: the login-code exchange (§6.2) and key rotation (§6.3). Each construct
carries a comment citing the specification line it mirrors.

## What it proves (base model)

- **Injective mutual agreement** on `(A, B, session_id, nonce_B, key)`, both
  directions, plus key confirmation when the initiator decrypts the daemon's
  first record.
- **Session-key secrecy.**
- **Login-code secrecy**, and that a site login under a `state` was begun by
  that device with that `state`.
- **That it runs** (V4-204): ProVerif exhibits a run that reaches the site's
  login, which passes through the daemon establishing the session, issuing
  the code, and the device confirming it. Until V4-204 the site's login could
  not occur in the model at all, and the `state` property above was true of
  a protocol that logged nobody in (audit F281).
- **Rotation binding**: a committed rotation was requested in that session.

## Why the controls exist

A proof that cannot fail proves nothing. `gen_controls.py` derives thirteen
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
  login code is also sent in the clear (it is no longer secret); the site
  does not compare the `state` (a login can land in a session that never
  began it). Every query now has a control.

The base *proves* each property "true"; a control makes the same query "false"
or "cannot be proved". Either regression means the guarantee is gone, which is
what the control demonstrates — so `run.sh` accepts anything but "is true" for
a control, and requires "is true" for the base and resilience runs. Two
rotation controls land on "cannot be proved" rather than "false": injective
agreement with a leaked key is a hard case for ProVerif's resolution (the
P5′ risk V4-4 named), and the honest reading is that the check under test is
exactly what moved the property from provable to unprovable. The login-code
control lands there too.

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
  or contradicts the protocol specification's statement about them.
- **`state` reaches the daemon on a channel the attacker cannot write.**
  It travels in the WebSocket URL, under the site's TLS. The property is
  about a web attacker who chooses which session a code is presented in
  (login-CSRF), not one who rewrites the page's own connection.
- **Records are bare encryption.** No sequence numbers, no associated data,
  no BYE, no `ROTATE_ACK`; a completed rotation does not change the key the
  daemon expects next. Replay protection and "the old key is refused
  afterwards" rest on tests, not on this model.
- **A completed rotation is not exhibited.** ProVerif proves that a rotation
  the daemon commits was requested in that session, and its two controls
  bite; asked to exhibit a run that reaches a committed rotation, it
  answers "cannot be proved" either way. That the honest rotation completes
  is shown by the tests.
- **Secrecy and agreement name the client-to-server key.** The other
  direction's key has the same inputs and protects the login code, whose
  secrecy is its own query.

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
