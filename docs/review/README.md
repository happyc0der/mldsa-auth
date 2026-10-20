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
   register](../v4/audit.md). 117 findings (F1–F119), with severity, evidence and
   disposition. The open ones are listed below.
3. The two specifications. The deployment spec's §20 lists 46 errata, each
   citing the finding that forced it.
4. [REPRODUCE.md](REPRODUCE.md): how to re-run every result, and where CI
   and the nightly run them on Linux.
5. [The decision log](../decisions.md), when you want to know why something is
   the way it is. It records failures as carefully as results.

## What "verified" means here

- **Tests** are named checks, not exit codes. The suite is 52 tests with the
  browser client, run under ASan and UBSan on Linux and macOS in CI.
- **Mutations**: 305 committed defects in 40 campaigns, each of which must be
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

V4-20 closed two older daemon findings. **F45**: an audit row is stamped with
the clock of the transaction it records, not a second read of the wall clock.
**F48**: a byte-identical re-enrollment is idempotent only for the handle's own
user; anyone else gets `pk-in-use` (erratum 46). F48 was wider than recorded,
since the store's own check reached via=recovery as well. Campaign v62 kills
both halves of each fix. **F108** corrected the README's campaign count.

V4-21 closed **F41**. A fingerprint is now a type that only a public key
produces, so the logging API's one byte sink no longer accepts a bare 32-byte
secret: that call is a compile error, pinned by the CTest `log_fp_type`. The
three mutations that leak a secret through it now need an explicit cast, and
the journal scans still kill them; campaign v63 shows the new gate can fail.

V4-22a took the claim map's next test-level gaps, each check shown able to
fail by campaign v64. Each of the following now has a check of its own:
- the active-key lookup's KEY clause (the mirror of V4-15a's device clause);
- RECOVERY-USE with `revoke=all` through the shipped daemon and the site's own
  library;
- `sig_old` by the incoming key and by a key enrolled nowhere, each over the
  right digest;
- the store scans in upper-case hex and both base64 alphabets, run over a
  backup as well;
- every padding byte of the inners of every padding bucket, 10,907 cases.

It also corrected three sentences that had gone stale: D13 still said the
logging sink accepts any 32-byte secret (**F109**), and this page's own counts
of findings and errata had missed V4-20's additions to both (**F110**).
liboqs 0.17.0, which F91's bump waits for, is still unreleased.

V4-22b took two gaps that needed an environment rather than a unit test. The
real-Caddy leg is now a CI job, with its container image and the Caddy
tarball pinned by digest: until then the tarball's digest was printed, never
checked, and only the arm64 one had ever been recorded while CI runs amd64.
And a real second user now connects to the daemon's sockets. Every earlier
test ran the client as the daemon's own user, so a peer check that compared
the daemon's OWN uid instead of the peer's passed all of them; campaign v65
shows the new leg killing exactly that. **F111** records a stale comment found
on the way, left open.

V4-22c closed the last of them. Every write of every mutation in the store is
now failed in turn, on a test-only hook under the same gate as the old one.
That is 23 operations, from one write to twelve. After each fault, the
database another connection sees must be exactly as it was, and the same
handle must then complete the call. Before V4-22c, eight hand-placed fault
points covered one write each. Campaign v66 shows the sweep catching two
defects nothing else did:
- an early commit in recovery-code replacement;
- a missing rollback in token issue.

**F112** recorded that a failed COMMIT was never rolled back. It rested on
reading, because COMMIT was out of the hook's reach.

V4-23 closed F112. `tx_commit` now rolls back whenever COMMIT fails, so
every mutation's commit is covered and no caller changed. A second test-only
hook fails the COMMIT of each of the 18 mutations that run a transaction, and
leaves the transaction open, as SQLite does on `SQLITE_BUSY`. The old helper
failed all 18: the write lock stayed held against a second store, and the
same handle could not begin again. Campaign v67 shows the new checks catching
F112 restored, and a COMMIT made around the helper on Req 7's refusal path.
Real I/O failures at COMMIT, injected once by hand through a failing VFS,
were already rolled back by SQLite itself; the path F112 needs is as narrow
as its row said. F111 was left open.

V4-24a closed **F111** and took two more of the map's gaps:
- F111's refusal of an unlisted socket mode is a check now, and its header
  names it correctly.
- P11's "no branch on the decapsulated bytes" had rested on reading. The
  test now chooses ciphertexts whose implicit-rejection secret takes every
  value of its first byte, a zero at each position, and two leading zeros,
  and needs the initiator to complete, keyed by exactly that secret.
- D13's journal scan now covers every raw frame and every decrypted payload
  of the connection. Building it found **F113**: the map said the scan
  covered every signature, and the ROTATE's two were never looked for.

Campaign v68 shows each new check catching a defect V4-23's suite let
through. **F114**, found on the way, records that six tests' scratch
directories, named for their PID, can fail a later run in a tree reused
across crashing runs; it is open. F91 is the only other open finding.

V4-24b took two gates:
- **P8:** F94's fix had been pinned by nothing, and campaigns cannot mutate
  CMake. `build_flags` now checks each tree's sanitizer flags against its
  intent. A new CTest, `ubsan_aborts`, needs a planted signed overflow to
  stop the process: what the compiler did, not only what it was told. Four
  hand controls showed both failing.
- **P2:** every heap secret's allocation site, 35 of them, is pinned to
  libsodium's guarded memory (`secure_mem_sites`). Campaign v69 shows a key
  moved to `malloc` caught by name.

Two findings were fixed in V4-24b:
- **F115:** five local-API error returns left a decoded secret on the stack,
  among them a valid login code. Fixed, with the evidence stated as reading:
  no check can read a dead stack frame.
- **F116:** the documented test counts and the README's test table had
  drifted. Corrected.

V4-24c took D10's last gap. Rotation's files had been looked at only by the
e2e's header scan, which reads a file's first eight bytes; a raw secret key
carries no magic. `test_authd_cli` now runs the CLI's own rotate and login
against the in-process daemon and searches every file for every key the
device held: after an acknowledged rotation, after the login that completes
an interrupted one, and after a rotation from a superseded key. Account
recovery makes no key of its own -- the replacement device's is an ordinary
keygen -- so the map now says so. Campaign v70 shows each scan catching a
raw key the V4-24b suite let through. Two findings were fixed on the way:
- **F117:** D4's store and backup scans looked for the first of three
  recovery codes only. All three are looked for now.
- **F118:** a rotation that failed after sealing its new key left the new
  public key's temp file in the device's directory. It is removed on every
  return now.

V4-25 recorded the first measurements of the browser client on a phone (spec
§14, erratum 47): a Xiaomi 12 Pro in Chrome and Edge keeps Argon2id far inside
its 2 s budget, over Wi-Fi and over mobile data. It also found **F119**, open:
Safari on a Mac runs the client about 21× slower than Edge on the same machine,
and every iPhone browser shares Safari's engine.

V4-26 found F119's cause, and it was the measurement, not the client. Safari
runs a page from a non-secure origin -- plain http on any name but `localhost`
-- without its JIT, and the timing tool served such an origin. On a secure
origin Safari runs the client at Edge's speed (spec §14, erratum 48). Every
timing row now records whether its page was a secure context, and
`phone_timing_tool` runs the real tool through both kinds of origin to pin
that. Safari on a non-local HTTPS origin, which is what a deployment is, and
any iPhone are still unmeasured.

V4-27 took D10 into the browser. The key never leaves the wasm module except
sealed, but nothing had looked at what Chromium actually writes to disk.
`browser_e2e` now opens every envelope its store held, natively, with the
test's passphrase. It then scans both profiles, about 15 MB each, for the
key's secret windows and for the passphrase. It trusts a clean result only
after the same scan finds, whole, a canary written into IndexedDB and the key
itself planted in the clear. Nothing was found.

V4-29 closed a gap in D13 that its own limits named. With `log_ids = full`,
the logger prints an identifier as an escaped `id=` field: printable bytes as
themselves, everything else as dots. A secret passed where an identifier
belongs would print about a third of its bytes that way, and no hex or base64
search sees it. Every journal scan now matches the `id=` fields against each
secret's escaped image, in one shared header. Campaign v71 passes five
secrets where identifiers belong: the login code, a nonce, a signature, a
token and a ticket. Each passed V4-28's scans and is caught by name now.

V4-30 did the same for D4's enrollment ticket. The ticket was scanned only
when it was issued, and no mutation had ever leaked it. A ticket kept as the
new device's label when ENROLL spends it, with enrollment still working,
passed every check. The store and a backup are now scanned after the spend
too, and campaign v72 shows both scans catching a leak by name.

V4-31 fixed the test fixtures' leak: they were always stopped before their
deadline, the only point where they cleaned up, so every run left a test
store behind (411 of them). V4-32 moved one of D9's checks out of process.
The wasm client in Node holds live sessions for two devices against the
real daemon process. After the site revokes one, that device's WebSocket
closes and the other's stays open. V4-33 did the same for DISABLE-USER and
RECOVERY-USE with `revoke=all`.

The register also carries older items that were accepted with a stated
rationale, such as F18's plain `memcmp` sites. F41's fingerprint sink was one
until V4-21: it takes a type of its own now, so a bare secret no longer compiles
into the journal.

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
