#!/usr/bin/env python3
# V4-4: derive each deliberately-broken model from formal/authd.pv by an EXACT
# string replacement, asserting the edit changed the file. A control that is
# identical to the base proves nothing, so every edit must bite.
import pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
base = (HERE / "authd.pv").read_text()
out = HERE / "controls"; out.mkdir(exist_ok=True)

def make(name, *edits):
    s = base
    for old, new in edits:
        assert s.count(old) >= 1, f"{name}: anchor absent: {old!r}"
        s = s.replace(old, new)
    assert s != base, f"{name}: no change"
    (out / f"{name}.pv").write_text(s); print(f"  {name}")

# sig_B must cover the responder's own fields (spec-v2 6.3.2). Drop shu -> the
# responder's contributions are unauthenticated at message 2; mutual agreement
# must break.
make("sigb",
     ("hash((serverauth, ch, shu))", "hash((serverauth, ch))"))

# The hybrid KDF must use BOTH secrets. Two ablations, each with the OTHER
# secret handed to the attacker, so the key must become recoverable.
make("kdf_nodh",
     ("(* LEAK:kem *)", "out(c, ssk);"),
     ("kdf(ssx,", "kdf(zeroG,"))
make("kdf_nokem",
     ("(* LEAK:dh *)", "out(c, ssx);"),
     ("kdf(ssx, ssk,", "kdf(ssx, zerokem,"))

# Rotation must be bound to its session (handshake_id in the digest) and need
# the outgoing key's signature. Both controls also leak the record key, so the
# only thing standing between the attacker and a forged rotation is the check
# under test.
make("rot_hsid",
     ("(* LEAK:c2s *)", "out(c, kc2s);"),
     ("let mrot = (hsid, A,", "let mrot = (A,"))
make("rot_sigold",
     ("(* LEAK:c2s *)", "out(c, kc2s);"),
     ("let mo = checksign(sigOld, pkA) in", "let mo = hash((rotold, mrot)) in"))

# Resilience (these must still PROVE): leak one KEX half, key stays secret.
make("leak_kem", ("(* LEAK:kem *)", "out(c, ssk);"))
make("leak_dh",  ("(* LEAK:dh *)",  "out(c, ssx);"))
# Rotation stays bound even if every record key leaks (must still PROVE).
make("leak_c2s", ("(* LEAK:c2s *)", "out(c, kc2s);"))
