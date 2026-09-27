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
   register](../v4/audit.md). 94 findings (F1–F96), with severity, evidence and
   disposition. The open ones are listed below.
3. The two specifications. The deployment spec's §20 lists 40 errata, each
   citing the finding that forced it.
4. [REPRODUCE.md](REPRODUCE.md): how to re-run every result, and where CI
   and the nightly run them on Linux.
5. [The decision log](../decisions.md), when you want to know why something is
   the way it is. It records failures as carefully as results.

## What "verified" means here

- **Tests** are named checks, not exit codes. The suite is 43 tests with the
  browser client, run under ASan and UBSan on Linux and macOS in CI.
- **Mutations**: 233 committed defects in 26 campaigns, each of which must be
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

Found while building this packet, and **not fixed in it**:

| Finding | Severity | In one line |
|---|---|---|
| **F92** | Med | Omitting `site_uids` or `proxy_uids` turns off the peer-credential check (Req 11) and the config calls itself valid |
| **F93** | Med | Recovery with `revoke=all` spans several transactions (against Req 14) |
| **F94** | Med | The UBSan build does not stop on undefined behaviour, so that gate cannot fail on UB |
| F95 | Low | Req 3 names secret hashes as compared in constant time; the store finds them by SQLite equality |
| F90 | Low | Nine mutations are killed without a named check |
| F96 | Info | "Bound to `handshake_id`" means "recorded with" |
| F91 | Info | An advisory affects liboqs 0.16.0 in LMS/HSS, which this build does not compile |

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
7. **The findings above.** Particularly whether F92 and F93 should block a
   public deployment.

## Frozen at

The annotated tag `v2.1.0-review.1`, on `main`. Everything in this directory
refers to the tree at that tag.
