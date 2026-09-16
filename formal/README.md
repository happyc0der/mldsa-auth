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
- **Rotation binding**: a committed rotation was requested in that session.

## Why the controls exist

A proof that cannot fail proves nothing. `gen_controls.py` derives eight
variants from `authd.pv` by exact string replacement, each asserting the edit
changed the file:

- **resilience** (must still prove): leak the ML-KEM secret, or the X25519
  secret, or the record key — the relevant guarantee still holds. The first
  two are the hybrid claim, checked rather than asserted: either KEX half
  surviving is enough.
- **controls** (must become unprovable): sign only `ClientHello` (mutual
  agreement breaks); ablate one half of the KDF while leaking the other (the
  key becomes recoverable — so both halves are load-bearing); drop
  `handshake_id` from the rotation digest, or skip the outgoing-key signature,
  while leaking the record key (rotation is no longer bound to its session).

The base *proves* each property "true"; a control makes the same query "false"
or "cannot be proved". Either regression means the guarantee is gone, which is
what the control demonstrates — so `run.sh` accepts anything but "is true" for
a control, and requires "is true" for the base and resilience runs. Two
rotation controls land on "cannot be proved" rather than "false": injective
agreement with a leaked key is a hard case for ProVerif's resolution (the
P5′ risk V4-4 named), and the honest reading is that the check under test is
exactly what moved the property from provable to unprovable.

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
