# For an external reviewer

This directory is the packet for an outside review of **mldsa-auth**: a
post-quantum mutual-authentication protocol and the daemon that deploys it as
a website's login system. It was written, specified, tested and audited by a
single author working with an AI coding agent. **That is the main reason it
needs you.** Everything here that was checked by a machine says so; everything
that rests on reading says that too.

## What the system is

- **The protocol** ([spec-v2](../ml-dsa-auth-protocol-spec-v2.md)). The two
  sides authenticate mutually with **ML-DSA-65** over a signed transcript.
  They agree a key with a **hybrid X25519 + ML-KEM-768** exchange, HKDF-SHA256
  over both shared secrets, then run **ChaCha20-Poly1305** records with strict
  sequencing and verified padding. It is C11 over liboqs and libsodium, with
  no primitive of its own (`src/`).
- **The daemon** ([deployment spec](../mldsa-authd-spec.md), `apps/authd/`).
  `mldsa-authd` terminates the handshake and issues a short-lived, single-use
  **login code**, which the site exchanges for a token over a local socket.
  Around that sit enrollment, **key rotation** proven by both keys, revocation,
  recovery codes, and an audit log chained by MAC. Its store is SQLite, and
  its keys are sealed at rest under Argon2id.
- **The clients.** A CLI, and a **browser client**: the same C client core
  compiled to WebAssembly, with a thin JavaScript transport, IndexedDB storage
  and no cryptography in JavaScript (`web/`).
- **A symbolic model** ([`formal/`](../../formal/README.md)). ProVerif proves
  agreement, key secrecy, login-code secrecy and rotation binding, and has
  controls that must make each proof fail.

## In and out of scope

**In:** the protocol and its implementation (`src/`), the daemon, CLIs and
client core (`apps/`), the browser client (`web/`), the formal model, and the
deployment artifacts (`deploy/`).

**Out:** the internals of liboqs, libsodium and SQLite (their pinned versions
are checked against published advisories in [ADVISORIES.md](ADVISORIES.md));
the operator's host and its root; the TLS proxy; and the site's own account
system, which decides who may enroll.

## The documents, in reading order

1. **[CLAIMS.md](CLAIMS.md): start here.** Every security requirement of
   both specifications, mapped to the tests, mutations, fuzz oracles and
   proofs that pin it, and to what that evidence does **not** establish. A
   gate (`tools/audit/check_claim_map.py`, in CI) fails if anything the map
   cites stops existing.
2. [The threat model](../v4/threat-model.md) and [the audit
   register](../v4/audit.md). 105 findings (F1–F107), with severity, evidence and
   disposition. The open ones are listed below.
3. The two specifications. The deployment spec's §20 lists 45 errata, each
   citing the finding that forced it.
4. [REPRODUCE.md](REPRODUCE.md): how to re-run every result, and where CI
   and the nightly run them on Linux.
5. [The decision log](../decisions.md), when you want to know why something is
   the way it is. It records failures as carefully as results.

## What "verified" means here

- **Tests** are named checks, not exit codes. The suite is 49 tests with the
  browser client, run under ASan and UBSan on Linux and macOS in CI.
- **Mutations**: 275 committed defects in 31 campaigns, each of which must be
  caught *by a named check*. The nightly runs all of them. Since V4-14a a
  mutation the compiler refuses no longer counts as caught unless the
  compiler is the check; that change found two properties no test had been
  checking.
- **Fuzzing**: twelve libFuzzer targets whose oracles are properties or
  independent models, not crash detectors, run for 600 s each nightly.
- **The formal model**: symbolic, so it proves the protocol's logic, not the
  code's.
- **Gates that check the documents**: the spec's constants and vocabularies,
  every mutation anchor, and this packet's claim map, all checked against the
  tree.

## What is open, and where to look hardest

Building this packet found seven findings. The three medium ones were fixed
before it was frozen (V4-14c): **F92** (an omitted uid allowlist turned off
Req 11's check), **F93** (recovery with `revoke=all` spanned several
transactions, against Req 14) and **F94** (the UBSan build did not stop on
undefined behaviour). Each fix has a test shown able to fail, and the audit
register says how. Still open:

| Finding | Severity | In one line |
|---|---|---|
| F91 | Info | An advisory affects liboqs 0.16.0 in LMS/HSS, which this build does not compile. **Mitigated in V4-14d**: the fix is in 0.17.0, which is not yet released, and a CTest now fails if the linked archive ever holds LMS, HSS or XMSS code |

The other four were closed in V4-14d. **F95** and **F96** were wording:
Req 3 now states its one exception (secret hashes are found by SQLite
equality on a 256-bit hash; spec erratum 43), and Req 5 says the
`handshake_id` is *recorded* with a login code, not bound to it (erratum 44).
**F90**: ten mutations were credited without a named check. Every kill now
names one, and the runner and CI refuse a mutation that does not.

**Since the tag** (V4-15a, on `main`): eight of the claim map's "not
established" gaps in the daemon were closed with checks, each shown able to
fail by campaign v58 -- an expired login code at EXCHANGE, plaintext scans of
the store, `sig_old` alone, live sessions under DISABLE-USER and
`revoke=all`, the uid allowlists through `main`'s own wiring, and faults
injected into revoke, disable and enroll. Building them found three more
findings, all closed: **F97** (three Req 7 refusal paths logged nothing),
**F98** (four documents said such a refusal is *audited*; erratum 45 says
*logged*, the journal being Req 7's log) and **F99** (the fault-hook gate the
map cites ran nowhere; it is a CTest now).

V4-15b then took the protocol's gaps: replay of an older record and a gap
wider than one, the ledger's two untested CONSUMED checks, every padding byte,
two fields dropped from what is signed (caught by the hand-built peers), and
ServerHello lengths across every decoy case. The constant-time inventory
became a gate (`tests/constant_time_sites.sh`), so the `sodium_memcmp` to
`memcmp` swap two earlier campaigns declined is now killed by name (campaign
v59). Two stale references were corrected (**F100**, **F101**).

V4-15c took the artifact side: a gate that no hand-rolled primitive's
constants appear outside the one sanctioned SHA-1, and that only the WebSocket
upgrade calls it; the MLDSAEK1 envelope opened by §12 and raw libsodium alone,
in both directions; the build flags checked where they are attributable (the
compile commands, and the project's own archives); keys at rest scanned by
content after every key operation, migrate-key included; and the journal
scanned for key material, session keys, shared secrets, signatures and nonces
(campaign v60). Four descriptions were corrected: F53's account of the SHA-1
(**F102**), a runbook path (**F103**), a hardening gate's canary that cannot
fail for this project's code (**F104**), and three statements of the nightly's
total left at 238 by the two steps before (**F106**). **F105** was
left open (Info): the repository's secret scanner counted a window that is
mostly public key as a secret one. It failed closed; the new scans, which first
copied its rule and so failed on one fresh key in 256, no longer did.

V4-16 closed F105. The scanner now keeps only windows made wholly of secret
bytes (3906 of 4017), the rule the V4-15c scans use. Its controls cover both
sides of each of the rule's three boundaries and F105's own case, a public-key
file whose byte after `rho` is the fixture's `K[0]`; campaign v61 shows V2-8's
rule, restored with its own arithmetic, caught by those controls alone, and
V2-8's campaign was re-anchored with the same kills.

V4-17 named the Linux runner image: every Linux job runs on `ubuntu-26.04`,
moved there only after CI and the full nightly matched the last 24.04 runs
test for test and mutation for mutation, rather than on GitHub's schedule.
**F107** corrected the README's test counts.

The register also carries older items that were accepted with a stated
rationale, such as F18's plain `memcmp` sites and F41's fingerprint sink.

**Questions I would most like an outside answer to:**

1. **The hybrid KDF and transcript binding** (spec-v2 §6.3): is
   `HKDF(ss_x || ss_k, session_id, info)` with the transcript digest in
   `info` a sound combiner here, and does the signed transcript cover
   everything it must?
2. **Rotation** (deployment §6.3, §10.2): two signatures, by the outgoing and
   the incoming key, over a digest carrying the session's `handshake_id`. Is
   possession of both keys established, and is a captured ROTATE useless
   elsewhere?
3. **The login code's binding to the browser's `state`** (§7.1, §14): does it
   stop login-CSRF, given that the code rides a same-origin POST?
4. **The decoy flow** (§7.3): an unknown or revoked identity gets a real,
   signed ServerHello and fails at ClientAuth. Is the uniformity real, and is
   what the tests compare (outcomes, not bytes or timing) enough?
5. **The key envelope** (§12): Argon2id and XChaCha20-Poly1305 with the header
   as associated data. Are the parameters and the construction sound?
6. **The browser trust chain** (§14): the module is compiled from the C core
   with a pinned Emscripten, checked against a native known-answer golden, and
   served under a strict CSP. What remains trusted that should not be?
7. **The findings above**, and the three fixed in V4-14c: are the fixes
   whole?

## Frozen at

The annotated tag `v2.1.0-review.1` froze this packet: read it at that tag to
review exactly what was frozen. On `main` the packet moves with the tree --
V4-15a's changes above are there and not in the tag -- until a later tag
freezes it again.
