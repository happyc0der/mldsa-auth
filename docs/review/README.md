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
   register](../v4/audit.md). 137 findings (F0–F137), with severity, evidence and
   disposition; no F16 was ever assigned. The open ones are listed below.
3. The two specifications. The deployment spec's §20 lists 54 errata, each
   citing the finding that forced it.
4. [REPRODUCE.md](REPRODUCE.md): how to re-run every result, and where CI
   and the nightly run them on Linux.
5. [The decision log](../decisions.md), when you want to know why something is
   the way it is. It records failures as carefully as results.

## What "verified" means here

- **Tests** are named checks, not exit codes. The suite is 58 tests with the
  browser client, run under ASan and UBSan on Linux and macOS in CI.
- **Mutations**: 384 committed defects in 57 campaigns, each of which must be
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
| F91 | Info | Two advisories affect liboqs 0.16.0 in LMS/HSS, which this build does not compile (the second, GHSA-xv6c-h66p-6mfq, found in V4-38). **Mitigated in V4-14d**: both fixes are in 0.17.0, which is not yet released, and a CTest now fails if the linked archive ever holds LMS, HSS or XMSS code |

Three rows older than the packet also stay open, by their own account (this
page said only F91 until V4-38, F120):

| Finding | Severity | In one line |
|---|---|---|
| F5 | Med | Coverage had been measured once, before the daemon existed. Since V4-40 `apps/authd/` has a figure ([coverage.md](../v4/coverage.md)), and the security checks it found untested (F122) are all covered, the last (`REVOKE-TOKENS handle=`) in V4-60. The wasm build is not measured |
| F15 | Info | v1's x86_64 performance target was never measured on x86_64, and v1's code is gone, so it cannot be |
| F17 | Med | Req 4.9 (no secret-dependent control flow) is partly pinned: since V4-15b a gate fails if a constant-time comparison site stops using one, but nothing measures timing. Req 4.8, its other half, closed in V4-11. Since V4-65 one path is measured, §7.3's decoy flow (`bench_decoy`), and it found F135 |

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
across crashing runs; it is open. F91 is the only other finding open since
the packet was built (three older rows also stay open; see the table above).

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

V4-28 closed **F114**. The seven tests that named a scratch directory after
their pid make it with `mkdtemp` now, and a CTest, `scratch_dirs`, fails if
a pid is formatted into a name again. That left F91 the only finding open
since the packet was built.

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

V4-34 put the hand-control method into a tested tool, after a throwaway
script's stale library archive produced two false survivals. It also
gated the mutation counts the READMEs state; three had drifted. V4-35
closed D10's last CLI gap: a rotation whose reply is refused, or lost after
the daemon committed, now gets the same disk scan as every other rotation.

V4-36 watched the real daemon's clock. Every expiry is the daemon's clock
plus a constant, and every C test sets that clock itself, so a daemon whose
clock stopped would have passed everything. `authd_e2e` now has two codes
exchanged 2 s apart report issued times 2 s apart. Using the hand-control
tool here found two flaws in it, both fixed. It could not name a binary whose
file name differs from its target. It also compared whole-file hashes,
which change on every link here, so it now compares the code.

V4-37 made the event-loop tests wait for what they expect, not for a fixed
number of turns: a wait that never ends is a failed check by name. Under
load they had never flaked here, so it is insurance. V4-38 re-ran
[REPRODUCE.md](REPRODUCE.md) word for word in a fresh clone. Every command
worked, but that page and this one had stale counts (**F120**). The counts
that can be read from the tree are gated now. A second liboqs advisory in
LMS, which is not compiled, joined F91.

V4-39 took P10's backend check into every native tree. The CTest
`backend_symbols` needs each executable to link the one intended
ML-DSA/ML-KEM family. It is shown failing on three real builds: each
aarch64 backend turned off, and liboqs's runtime dispatch. In CI it failed
exactly the Linux jobs when the x86_64 ML-KEM backend was forced off. That
checked a claim ci.yml had only asserted: `generic` on the macOS runners
keeps the aarch64 backends.

V4-40 measured the daemon's coverage for the first time (F5;
[coverage.md](../v4/coverage.md)). Forked test children had never been
counted, and are now. Three findings are open from it:
- **F121:** three functions nothing calls, one of them a wrapper whose
  sentinel would skip the peer-credential check.
- **F122:** five security checks no test drives to their refusal, among
  them key-file custody and the CLI's WebSocket frame bounds.
- **F123:** `REVOKE-TOKENS user= handle=` ignores `user=`. Its scope is the
  owner's decision.

V4-41 removed F121's dead code and gated the test counts. The CTest
`doc_test_counts` needs the README's count for each tree's configuration to
equal what ctest registers there, and this page's and REPRODUCE.md's counts to
repeat the README's. On its first run it found this page still saying 55 tests
where V4-39 had made it 56 (**F124**).

V4-42 took F122's first item, key-file custody. A key file that anyone but its
owner can read or write is refused, and so is one another user owns. Neither
refusal had ever run until V4-42. Campaign v75 shows each half caught: the mode
half everywhere, the owner half by `authd_e2e`'s privileged leg on Linux.

V4-43 took the second item, the CLI client's WebSocket frame reader, which
parses what a server sends. Each of its refusals is now driven from a byte
array, among them the bound of a frame against the caller's buffer, with
guard bytes after it. Campaign v76 removes each refusal in turn and is caught
by name, or by ASan for the control frame read onto the stack.

V4-44 gated the two gates' inventory counts in prose (25 constant-time sites,
35 secure-memory sites) and re-measured coverage. V4-45 took F122's fourth
item. A store whose `meta` holds a malformed or later schema version, or a
store id or decoy key of the wrong length, is refused at open; campaign v77
shows each check caught.

V4-46 took the fifth item, on the daemon's record path. A ROTATE with the
drop-tokens flag now has a test while the device holds tokens: they go,
another device's stay, and the journal says how many. A BYE of the wrong
length is refused. The oversized-record check cannot be reached, because the
frame cap equals the record cap, and the register says so instead of
claiming a test. Campaign v78 shows each check caught. F122's last item,
`REVOKE-TOKENS handle=`, waits on the owner's decision on F123.

V4-47 fixed a false failure seen three times on a loaded macOS runner:
`test_net`'s T12 needs a signal storm to interrupt the network code, and the
signalling process was sometimes not scheduled in time (**F125**). An attempt
in which no call was interrupted is now retried, up to five times, rather
than counted as a failure. A real failure is still immediate.

V4-48 held the passphrase file to the key file's custody, in tests: a
symlink, a directory, a loose mode, an empty or oversized file and another
user's file are each refused with their own status. Campaign v79 shows
each check caught, the owner half on Linux.

V4-49 took the listener's socket paths. A path too long for `sun_path` is
refused, not truncated, and a file or a planted symlink at the path is
refused and left alone. A stale socket is still replaced, and an allowlist
longer than its bound is refused. Campaign v80 shows each check caught,
including the `stat`-for-`lstat` slip that would follow a symlink.

V4-50 re-checked that the test fixtures clean up after themselves (they do)
and removed the leak's old leftovers. F5's row now says plainly that only
`REVOKE-TOKENS handle=` and the unmeasured wasm build keep it open.

V4-51 drove the shipped daemon's start-up refusals. It refuses to start on
a group-readable passphrase file or server key, on the wrong passphrase, and
on a store file that is not a database. Each time it names the file and the
status and leaves no socket behind. With any of those refusals removed,
campaign v81 shows the daemon starting anyway, and caught. Writing the tests
found three diagnostics that disagree with each other (**F126**, the owner's
call): exit codes, status names, and a misleading "audit-chain-corrupt".

V4-52 drove the local-API client against a daemon that misbehaves: a reply
too large for the buffer, one cut off before its end, no reply at all, and a
request over the line cap. Each is refused with its own status, and nothing
is written past the buffer. Campaign v82 shows each check caught.

V4-53 lists the mutations that only the privileged Linux leg can kill, in
`tools/mutations/linux_only_kills.txt`. Off Linux, a listed survivor is
scored as expected rather than as a failure, so a local campaign can end
clean. On Linux the list changes nothing, and the nightly must still kill
every one. The anchors gate refuses a list entry that names no mutation.

V4-54 drove the event loop against peers that pipeline and peers that never
read, and found **F127** (Low). A frame sent right behind another was served
only when the peer sent something more, and pipelined bytes behind a nearly
full buffer closed the connection. Both are fixed. A peer that never reads now
provably stops being served, holds one unsent reply at most, and is closed at
its deadline; when it reads, every reply arrives byte for byte. Campaign v83
shows each of those checks caught.

V4-55 fixed a campaign, not the daemon (**F128**). The V4-50..53 control
nightly found v82's LC1 red on Linux. Its mutant over-read the client's line
buffer, and ASan caught that before the named check could. LC1 is now the
line cap applied one byte late, and the test sends a request exactly one
byte over the cap and one exactly at it. A new LC6, the cap one byte early,
is caught by the second.

V4-56 found **F129** (Low, macOS only). A peer that vanished with a reply
still unsent kept its slot, and the loop spun until the slot's deadline: macOS
reports that socket as a hang-up alone. A hang-up with a reply pending is now
a write attempt, so a peer that has gone is closed at once, and one that only
half-closed still gets its reply. CI with the fix reverted failed on the three
macOS jobs and passed on Linux.

V4-57 fixed **F130** (Medium), found by the defensive review. A daemon that
failed to start deleted socket paths it had never created: a file it had
just refused to bind over, and, when started a second time on a running
daemon's configuration, that daemon's three live sockets. The running
daemon then stayed up but could not be reached. It now removes only what it
holds, and both cases are tested end to end.

V4-58 fixed **F131** and **F132** (both Medium) in the reference site. It now
issues a new session id at a login, a signup and a recovery, names its cookie
`__Host-sid` behind TLS, and bounds its session table. Erratum 49 states these
obligations in spec §14, and the runbook's rules for writing your own site
now include them.

V4-59 closed **F133** (Low), the residue of F24: a store backup had the
umask's mode until the copy finished. The backup file is now created 0600
before a byte is copied, and removed if the backup fails. A test-only observer
reads the mode between the copy and the chmod, and campaign v84 shows each
part caught.

V4-60 fixed **F123** (Low): `REVOKE-TOKENS user= handle=` now revokes only
that user's tokens on that handle, and a handle belonging to another user
revokes nothing (`OK count=0`). Erratum 50 says so in §8. With it, F122's
last untested check is covered, and F122 is closed.

V4-61 fixed **F126**: the daemon's start-up diagnostics now agree. A file the
configuration names that cannot be used exits 3, whichever file it is
(erratum 51). The passphrase reader names its permissions refusal
`unsafe-permissions`, like the key-file reader. A damaged store value is
`store-corrupt`; `audit-chain-corrupt` now means only the audit chain.

V4-62, the owner's decision: on the reference site, new recovery codes need a
login, not only a session. The account page logs in again with the device
key and passphrase and sends that login's code, and the site mints the codes
only if the code is the session's own user's. Erratum 52 and the runbook's
seventh site rule say so.

V4-63 fixed **F134** (Info), a false failure: `browser_e2e`'s teardown could
wait for ever on a browser that had closed its DevTools socket or died, and
V4-61's CI ran it into the 600 s limit with every check passed. Every wait in
the teardown is bounded now, and a killed browser is closed in milliseconds.

V4-65 measured the decoy flow's timing for the first time (`bench_decoy`),
and found **F135** (Low, open). An enrolled handle's ServerHello comes about
half a microsecond later than a decoy's. It showed only at 100,000 round trips
a class over loopback, and the cause is the store lookup: a hit does more
work than a miss. Revoked and unknown handles do not differ. A prober can
learn only whether a handle it already holds is active, since handles cannot
be guessed. The remedy is the owner's call.

V4-66 fixed **F136** (Med): one malformed request ended the reference
site's process. A route's error escaped the request handler, and so did an
upgrade target the URL parser refuses. Both are now answered or closed, and
the site keeps serving. `site_sessions` runs the site in a child process to
show it.

V4-67 fixed **F135** with the owner's choice of remedy, a time floor. The
pin's lookup does not return until 50 µs after it began, whichever key it
pinned, and at 100,000 round trips a class the difference no longer shows.
It only waits, so nothing pinned or sent changes. A lookup slower than the
floor is not hidden; about 1 in 10,000 here.

V4-68 fixed **F137** (Med), found answering the owner's question whether the
system is secure end to end. The threat model said an attacker inside TLS
could not impersonate the site. That is true for the CLI, and not for a
browser, whose page code arrives over that TLS on every visit. And the
browser client stored its server pin but logged in with whatever key the
page offered. It now uses the pin and refuses a page offering another, and
the threat model, spec §14 (erratum 54) and the runbook say what a browser
still trusts TLS for.

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
   what the tests compare (outcomes, not bytes or timing) enough? A
   benchmark first measured the timing in V4-65: an enrolled handle was about
   half a microsecond slower (F135). Since V4-67 a 50 µs floor on the lookup
   hides it end to end. Is a floor the right remedy?
5. **The key envelope** (§12): Argon2id and XChaCha20-Poly1305 with the header
   as associated data. Are the parameters and the construction sound?
6. **The browser trust chain** (§14): the module is compiled from the C core
   with a pinned Emscripten, checked against a native known-answer golden, and
   served under a strict CSP. What remains trusted that should not be? Since
   V4-68 the answer the project gives is TLS, for the page's own code (F137).
7. **The findings above**, and the three fixed in V4-14c: are the fixes
   whole?

## Frozen at

The annotated tag `v2.1.0-review.1` froze this packet: read it at that tag to
review exactly what was frozen. On `main` the packet moves with the tree --
V4-15a's changes above are there and not in the tag -- until a later tag
freezes it again.
