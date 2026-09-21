# Protocol Decisions (v1.0.0 and v2.0.0 released; V3 assurance work on `main`)

This is a running log of decisions made while implementing
[ml-dsa-auth-protocol-spec.md](ml-dsa-auth-protocol-spec.md), for
anything the spec left underspecified or that required resolving an
ambiguity. The spec itself (Section 6.3 onward) is the normative source for
wire format and protocol behavior; this file explains *why* those choices
were made and points at where each was decided.

## Key exchange: X25519 only in v1

Section 10's `[DECISION NEEDED]` is resolved: v1 uses classical X25519 for
key exchange. Hybrid X25519 + ML-KEM-768 is deferred to a v2 milestone.
Rationale: ML-DSA-65 already resolves the more time-critical threat
(active identity/downgrade attacks); the "harvest now, decrypt later"
threat hybrid KEX defends against targets long-lived confidentiality, not
per-session ephemeral secrets, and is less urgent than shipping a smaller,
fully-hardened v1 first. See Section 10 and this session's Step 1 planning
notes for the full tradeoff writeup (complexity/performance/dependency
surface).

## liboqs: ML-DSA-65 only

`liboqs` is built with `-DOQS_MINIMAL_BUILD=SIG_ml_dsa_65` — no other
signature algorithm and no KEM algorithm is compiled in, keeping the
built library's algorithm surface (and thus attack surface) to exactly
what v1 uses. Confirmed via symbol inspection of the built static library
(only `OQS_SIG_ml_dsa_65_*` symbols present). *Extended by V2-2: v2 also
builds `KEM_ml_kem_768` for the hybrid key exchange — see "V2-2 —
dependency configuration" below.*

## Dependencies are pinned, not floated

Per spec Section 3. `liboqs` is fetched via CMake `FetchContent` at
`GIT_TAG 0.16.0`; `libsodium` is fetched as a release *distribution
tarball* (not a raw git checkout) at version `1.0.22`, pinned by
`URL_HASH` (SHA-256 of the tarball itself — stronger than a commit pin
alone, since it's byte-exact). See
[../cmake/Dependencies.cmake](../cmake/Dependencies.cmake) for the exact
resolved commit SHAs recorded for both, for audit purposes.

## `handshake_id`: a 16-byte truncated SHA-256 transcript identifier

`ClientAuth` carries `handshake_id`, the first 16 bytes of
`SHA-256("mldsa-auth/v1/handshake-id" || 0x00 || encode(ClientHello) ||
encode(ServerHello))` — a deterministic value derived from the full
pre-`ClientAuth` transcript, used by the responder to look up which
pending handshake a given `ClientAuth` belongs to. It is **not** an
authentication mechanism: it's a lookup hint only. The responder always
recomputes it from its own stored transcript and still verifies `sig_A`
against that transcript before accepting anything — a forged or
mismatched `handshake_id` can only cause a lookup miss, never a forged
acceptance. An earlier draft used a raw, caller-supplied
`ClientAuth.session_id` field instead; that was rejected specifically
because it would have been an unauthenticated routing value with no
cryptographic relationship to the handshake it claimed to identify. See
[ml-dsa-auth-protocol-spec.md](ml-dsa-auth-protocol-spec.md)
Section 6.3.3 for the normative definition.

## Network framing and cross-message acceptance: deferred to Step 4

Step 3 (wire format) implements structural serialization only:
deterministic encode/decode for `ClientHello`/`ServerHello`/`ClientAuth`,
with strict per-field bounds checking and full-buffer consumption. It
does **not** implement: actual socket/transport framing, comparing
`ServerHello.session_id_echo` or `ClientAuth.handshake_id` against
anything, reconstructing transcripts from stored state, verifying
signatures against a live peer identity, or any session lifecycle
(pending-handshake expiry, single-use/replay enforcement). All of that is
Step 4 (`handshake_ctx`, Section 8) and later steps' responsibility — a
structurally well-formed message can still be semantically wrong, and
Step 3's decoders have no way to know that. See spec Section 6.3.5 for
the explicit division of responsibility.

---

## Step 4 — handshake state machine

### KDF info encoding corrected: length-prefixed and injective

The key schedule's HKDF `info` was previously specified — and implemented
in the Step 2 `kex_derive_session_key` — as plain concatenation of a fixed
label, `A_id`, `B_id` and a direction byte. That is **not injective**:
`A="ab", B="c"` and `A="a", B="bc"` produced identical bytes. The same
function also accepted zero-length identities and arbitrary direction
bytes, and had **no test coverage** (the Step 2 RFC 5869 KAT exercises only
the underlying HKDF primitive). Step 4 was its first caller, so no key was
ever derived through the old encoding.

Replaced by spec §6.3.7: `"mldsa-auth/v1/kdf" || 0x00 || len(A) || A ||
len(B) || B || direction`, built only by `kex_build_kdf_info()`, which
rejects ids outside 1..64 and any direction other than `0x43`/`0x53`.
Both identities are also bound into the signed transcripts, which
constrained practical exploitation — but a KDF's context input has to be
unambiguous on its own. This is a breaking change to the normative key
schedule, acceptable only because nothing had used the old one.

### Direction bytes and identity roles fixed

`0x43` ('C') for initiator→responder, `0x53` ('S') for
responder→initiator. `A_id` is always the initiator and `B_id` always the
responder, whichever side computes. `kex.h` is the single source of truth
(`KEX_DIR_*`); `handshake.h` aliases them.

### The initiator binds the responder's identity

The initiator rejects a ServerHello whose `B_id` is not the peer it
dialed, before any key lookup. Otherwise a different identity that is
*also* pinned, and signs correctly with its own key, would pass every
other check.

### Traffic keys only once each role's mutual-auth obligations are met

The initiator authenticates B at `verify_server_hello` but has not yet
authenticated itself, so it derives no traffic keys there. It runs X25519
once as a *validation probe* (to reject a low-order peer key before it
signs anything) and discards the result immediately; `finish()` recomputes
the shared secret and derives keys. The initiator context has no
shared-secret field at all. The responder derives keys into temporary
buffers only after `sig_A` verifies, then commits them only after the
single-use commit succeeds.

### The initiator's `ESTABLISHED` is optimistic

A 3-message handshake gives the initiator no signal that the responder
accepted `ClientAuth`. The state is kept (rather than adding a role-specific
`KEYS_READY_UNCONFIRMED`), and the distinction is made machine-checkable
instead: `handshake_is_peer_confirmed()` is false for an initiator and true
for a responder in `ESTABLISHED`. Irreversible actions must be gated on
that predicate, never on the state. Confirmation arrives with the first
authenticated session-layer message (Step 5).

### Pending-handshake store is a digest-only ledger

The responder computes `TH_client_auth` and `handshake_id` once, from the
exact ClientHello and ServerHello wire bytes, when it creates the
ServerHello, and stores only those digests (~56 B/entry instead of ~3.6 KB
of message bytes). The ledger cannot route a ClientAuth or complete a
handshake; everything needed to finish lives in the responder context that
created the ServerHello, and in Step 4 the ClientAuth must be delivered to
that same context. `handshake_id`-to-context routing is deferred to
transport integration.

### Bounded signature-failure tolerance (N = 3), not replay tolerance

`handshake_id` is derivable by any passive observer, so if a single forged
ClientAuth consumed the entry, one injected message could deterministically
kill an honest handshake. Instead a `sig_A` failure is counted and the
entry kept (retryable) until three failures, then tombstoned. A failure
never establishes a session, never yields keys, and never extends the
entry's deadline. A *successful* ClientAuth is single-use immediately.
Malformed messages and `handshake_id` mismatches are rejected before the
ledger is consulted, so they cannot burn another handshake's budget.

### Local failures never spend an authenticated handshake's entry

After a valid `sig_A`, the responder performs X25519 and the KDF into
temporaries *before* committing, so a local failure cancels the orphaned
entry (reclaiming capacity) instead of consuming it. If the commit itself
fails, the store's own expiry/terminal semantics decide the ledger state
and the handshake code makes no second transition.

### Duplicate ClientHello is accepted — an availability trade-off

The same ClientHello delivered twice produces two independent pending
entries with distinct `handshake_id`s. No `session_id` deduplication is
done, because ClientHello is unsigned: rejecting a repeated `session_id`
would let an off-path attacker deny service by pre-claiming an honest
client's. This is bounded by capacity and TTL only; transport-level rate
limiting is the deferred mitigation.

### Concurrency is a documented boundary

v1 contexts, keystore and pending store are not thread-safe, and "atomic"
means logically indivisible under caller serialization (spec §6.3.6). No
locking was added. A server integration must confine a store and its
responder contexts to one thread, or make lookup, expiry check,
signature-result handling and the commit one critical section.

### Security Req 4.7 — "rejected and logged"

A differing key for a pinned identity is rejected with the distinct status
`KEYSTORE_ERR_KEY_MISMATCH` and never replaces the pin. The library has no
logging facility in v1, so emitting the log record is the caller's job;
the distinct status is the hook for it.

---

## Step 5 — session layer

### Records carry a type byte (`0x04`)

The earlier §6.4 sketch had records as sequence number plus ciphertext.
Adding `record_type` puts records in the same message-type namespace as the
handshake (`0x01`–`0x03`). A handshake message handed to the record parser
is therefore rejected on its first byte, and later record types (close,
alert) need no version bump. The type is covered by the AD. Cost: one byte
per record.

### Exact nonce and AD

The nonce is four zero bytes followed by the big-endian `seq`; the earlier
"zero-padded to 12 bytes" did not say which side. The 47-byte AD is the
label `"mldsa-auth/v1/record"`, `0x00`, `handshake_id`, the direction byte,
and the header (type and `seq`).

`handshake_id` was chosen over `session_id` because it is a hash of both
authenticated messages, whereas the initiator chooses `session_id`. The
direction byte is defense in depth: keys are already per direction, so it
only matters if a future bug ever made both directions share a key.

A test builds the nonce and AD from literal bytes. It is the only check
that catches a *symmetric* layout bug, where both peers would still
interoperate.

### `handshake_id` is retained in ESTABLISHED

Both `finish()` functions used to zero `handshake_id`. It is public
(`ClientAuth` carries it in the clear), so keeping it costs nothing. The
handshake gained additive accessors: `handshake_get_role()`,
`handshake_get_handshake_id()` (ESTABLISHED only), and
`handshake_default_clock_ms()`, the shared fail-closed clock.

### Contiguous sequence numbers; every receive failure is terminal

A record must carry exactly the next expected `seq`. The earlier text
("≤ last accepted rejected") would have let an attacker delete records
silently. v1 transport is reliable and in-order, so a gap can only mean
deletion or a bug.

Any receive failure ends the session, following TLS rather than
DTLS-style drop-and-continue:
- anyone able to inject into the stream can already reset it, so terminal
  failure gives attackers nothing new;
- each key sees at most one failed verification;
- `seq` is checked before any AEAD work, so replayed junk costs the
  receiver no cryptography.

### Exactly-once key handoff

`session_init_from_handshake()` copies the keys and then wipes the
handshake context, as its last step and only on success. Two sessions
seeded from one handshake would both send `seq 0` under the same key,
which is catastrophic nonce reuse for ChaCha20-Poly1305. The API makes
that impossible, not merely documented.

### Initiator confirmation

The first successfully opened responder record confirms the initiator,
and nothing else does. The responder commits its keys only after verifying
`sig_A`, so a valid `s2c` record proves it accepted the handshake. The
responder should send an empty record immediately; the Step 6 apps do this.

### Two-tier limits

The spec's 2³² records / 1 h are the *rekey trigger*. Hard limits of
2³³ records / 65 min fail closed if the application ignores the trigger.

These are conservative policy values, not a derived AEAD bound. Nonce
uniqueness is necessary but not sufficient; aggregate data per key, record
size and forgery bounds also matter. They must be revisited if the
maximum plaintext, the AEAD, the transport, or the rekey policy changes.

Limits can only be tightened at init, which is how tests reach the
thresholds without test hooks.

### Session lifecycle

Session objects must be zero-initialized, and init works only on an EMPTY
object. Anything else (a live, failed or expired session that still owns a
key block) is refused with nothing touched, so a key block is never
overwritten or leaked. Wipe is idempotent.

### Zero allocation: two portable gates

`sodium_malloc` allocates with `mmap` on this platform, so malloc-level
hooks cannot see secure allocations. The proof is therefore:

1. **Gate 1:** a counting `secure_mem` implementation substituted at link
   time (the library is a static archive). It proves one allocation at
   init, zero in the steady state, and one free at wipe.
2. **Gate 2:** a CMake structural scan of `session.c`, with built-in
   negative controls, for ordinary-heap freedom.

macOS's `malloc_logger` is only an optional, off-by-default diagnostic.
It is not a stable public API, and no claim rests on it.

---

## Step 6 — reference TCP transport

### Framing: 4-byte length prefix, no frame-type byte

The payload's first byte is already the message type (`0x01`–`0x04`), and
each state expects exactly one type, which the library decoders and
`session_open` enforce. A second type byte would only duplicate it. The
length is unauthenticated on purpose: a wrong length changes the payload
boundaries, and then decoding or the AEAD fails, which is terminal.

### Per-state maximums, checked on the header

Every state reads with its own bound: 146, 3 457 or 3 328 bytes for the
handshake messages, exactly 25 for the confirmation, and up to 65 561 in
the session phase. An oversize or zero length is rejected after the 4
header bytes, so a peer cannot make the reader wait for or buffer a
payload it will refuse. Frames use fixed, caller-owned buffers; nothing is
allocated per frame.

### A failed ClientAuth closes the TCP connection

This is transport policy only. The library's retryable signature failure
(N = 3) is unchanged and remains right for transports where a forged
message can arrive alongside the genuine one. On a single TCP stream a
second ClientAuth is not meaningful, and an attacker who can inject into
the stream can already reset it. The server wipes the context, which
cancels the pending entry, so no ledger capacity is left held.

### Loopback only

The reference server binds `127.0.0.1` and offers no option to bind
anything else. A non-loopback listener would need rate limiting, a
concurrency model and operational hardening that are outside v1.

### Authenticated close in the demo application protocol

MSG, ECHO and GOODBYE travel inside records, so Step 5's record layer
needs no new record type. GOODBYE lets both sides tell an orderly close
from truncation; a bare EOF is always reported as a failure.

### Demo key files

The key files are a documented demo format, not production key
management. Keys are generated by `keygen` into a directory the user names
(by convention the git-ignored `demo-data/`) with `O_EXCL`, and the secret
key file is created 0600.

Loading refuses:
- symlinks;
- secret key files that are group- or world-accessible or owned by someone
  else;
- a wrong size or magic;
- an id mismatch;
- a public key that fails a sign/verify self-test against the secret key.

Trust is explicit: `--pin ID=FILE`, with the id checked against the file.
Tests never write keys under the repository.

*Step 7.1 replaced the secret-key file format with `MLDSASK2` (integrity
digest, atomic publish); see the Step 7.1 section below.*

### Tests use processes, not threads

`tests/test_net.c` forks a server child, an optional frame-aware proxy
child that injects faults, and raw peers. Processes keep every
context and store confined without any locking, and preserve the "no
pthread in `src/` or `tests/`" property. The parent kills any child that
fails to report in time, so no test can hang. SIGPIPE is deliberately not
ignored in the test, so an unprotected write would fail the run.

The approved plan put an `alarm()` watchdog in each child. Parent-side
kill-on-timeout is used instead, because `alarm()` shares `ITIMER_REAL`
with the EINTR storm test's `setitimer`.

### Two corrections to the plan, found while implementing

- **T10 and session keys.** The plan said T10 would search the logs for
  the session keys "read white-box before the wipe". The sessions are
  local to the demo functions, so exposing their keys to a test would need
  a secret-revealing hook in the application. T10 instead asserts that
  every log is printable text with no run of 16 or more hex digits. That
  rules out any key, session key, nonce or signature appearing raw or
  hex-encoded. It also runs explicit window searches for both secret keys,
  both signatures and the plaintext canary.
- **T2 timeouts.** T2's fragmentation run needs about 2.8 s, because
  roughly 7 KB of handshake crosses the proxy one byte at a time. It
  therefore uses a 15 s handshake timeout instead of the 2 s test default.

---

## Step 7 — fuzzing and adversarial robustness

### Toolchain: Homebrew LLVM, in a separate build directory only

Apple Clang ships no libFuzzer runtime (`libclang_rt.fuzzer_osx.a`), so
`-fsanitize=fuzzer` compiles but cannot link. Coverage-guided fuzzing uses
Homebrew's keg-only LLVM (clang 23.1.1), which is not on `PATH`, and only in
`build-fuzz` (`-DMLDSA_FUZZ=ON`). The normal, ASan and UBSan builds keep
Apple Clang.

`MLDSA_FUZZ=ON` checks that `-fsanitize=fuzzer` compiles and links, and
refuses to configure otherwise. Where libFuzzer isn't built, the CTest
`fuzz_libfuzzer` test reports *Skipped*, never passed.

### One harness, two drivers

Each target is linked twice:
- with libFuzzer, as `fuzz_<t>`;
- with a portable driver, as `fuzz_<t>_replay`. This one is built in every
  configuration and runs in CTest: the empty input, seeds, committed
  regressions, and a fixed-seed mutation smoke.

The replay smoke is a fallback, not coverage-guided, and says so in its
output.

### Deterministic RNG, test only

The fuzz binaries install a fixed-key ChaCha20 stream through the public
hooks `randombytes_set_implementation` and
`OQS_randombytes_custom_algorithm`. Keys, nonces, signatures and
`handshake_id` are then identical on every run, so seeds stay valid,
crashes reproduce exactly, and oracles compare against genuine bytes
regenerated at runtime.

The hooks appear only under `tests/fuzz/`, and each binary prints a
test-only banner. Nothing in `src/` or `apps/` changed.

### Oracles are reference models, not "didn't crash"

Each harness predicts the correct outcome independently and aborts on any
disagreement:
- **F1:** canonical round trip and full consumption. Transcript digests are
  compared with `crypto_hash_sha256` built from literal labels. There is
  deliberately no pairwise digest-inequality check, because equal SHA-256
  outputs would be a collision, not a bug.
- **F2 and F3:** exact status, state, ledger and key behavior.
- **F4:** a reference stream parser. A rejected length must consume exactly
  the 4 header bytes.
- **F5:** a structural file model (since Step 7.1 it also recomputes the
  secret-key file's integrity digest).

"OK only for the genuine bytes" (F2, F3) rests on ML-DSA and AEAD
unforgeability. A violation would mean a parser non-canonicality, a
verification bypass, or a cryptographic break.

Two white-box fixture steps are used:
- **F3** clones a freshly initialized `session_t`; the clone is checked
  against the real session at start-up.
- **F4** wraps a socketpair end in a `net_conn_t`.

### Secret policy and identity-mode programs

No ML-DSA secret key bytes, including the deterministic fixture keys, are
committed anywhere:
- **Seeds** are generated at runtime into ignored build directories.
- **Identity-mode inputs are mutation programs.** `fuzz_keys` applies them
  to a template it regenerates in memory from the fixed RNG, so a stored
  input never contains the key.
- **Admission gate:** `fuzz_keys_replay --scan-secret` checks every file
  for a secret-key file layout, or any 16-byte window of the fixture secret
  key. It runs in CTest (`fuzz_no_committed_secrets`) and in
  `add_regression.sh`, for every target.

### Corrections to the plan found while implementing

- **F5 identity oracle.** The plan's "OK iff the key regions equal the
  template" is unsound: mutating secret-key fields that do not affect
  validity (the signing seed K, for example) legitimately still loads. The
  oracle is now:
  - the unmodified template must load;
  - OK means exactly the file's key bytes were loaded;
  - structural failures match the model exactly.
- **Template length.** The identity template is 5 998 bytes
  (8 + 1 + 5 + 1952 + 4032), not 6 002 as the plan said. (Since Step 7.1
  the template is the 6 030-byte `MLDSASK2` file.)

### RESOLVED in Step 7.1: the demo loader accepted a corrupted t0 component

Found by the `fuzz_keys` smoke on its first run, and committed as
`tests/fuzz/regressions/keys/t0-corruption-accepted-*`, a 9-byte
instruction program (renamed `t0-corruption-original-*` in Step 7.1).

`demo_keys_load_identity` checks consistency with a single sign/verify.
Three bytes overwritten in the secret key's t0 component (offset 2642)
behave as follows:

| Measurement (20 keys × 200 messages) | Result |
|---|---|
| Keys that passed the loader's self-test | 15 of 20 (75%) |
| Signatures that then failed to verify | 1 284 of 4 000 (32%) |

t0 only feeds the signing hint, so a damaged t0 breaks some signatures and
not others. This is fail-closed, because peers reject the bad signatures,
but the corruption goes undetected and shows up as intermittent handshake
failures.

The fix belonged in `apps/demo_keys.c`, outside Step 7 scope, so it was
deferred; Step 7 recorded the finding and relaxed the F5 oracle to the
loader's documented contract. **Resolved in Step 7.1** by an integrity
digest over every stored field of the secret-key file (next section).

---

## Step 7.1 — demo secret-key integrity

Scope: the demo/reference secret-key file only (`apps/demo_keys.{c,h}`),
plus its tests, fuzz harness and docs. No change to `src/`, the handshake,
session, wire format, transport, KDF or AEAD, and none to the protocol spec,
which never specifies the demo key format.

### Format `MLDSASK2`

| Offset | Field | Bytes |
|---|---|---|
| 0 | magic `"MLDSASK2"` | 8 |
| 8 | `id_len` (1..64) | 1 |
| 9 | `id` | `id_len` |
| 9 + id_len | public key | 1952 |
| 1961 + id_len | secret key | 4032 |
| 5993 + id_len | digest | 32 |

```
digest = SHA-256( "mldsa-auth/v1/demo-key-integrity" || 0x00
                  || id_len || id || public_key || secret_key )
file size = 8 + 1 + id_len + 1952 + 4032 + 32 = 6025 + id_len   (6026 .. 6089)
```

- **Label length.** The label is 32 ASCII bytes, hashed **without** its
  terminating NUL. The code never hard-codes the number: it uses
  `sizeof(DEMO_KEY_INTEGRITY_LABEL) - 1`. The hash input is therefore
  6018 + id_len bytes. (The approval message said 33 bytes and
  6019 + id_len; measured with `wc -c`, `od -c` and Python, the literal is
  32 bytes, and 33 is `sizeof`, which counts the NUL.)
- **Independent checks.** T14 and the `fuzz_keys` model each compute the
  digest with their own copy of the label and their own length rule, so a
  label, length or NUL slip made symmetrically by keygen and the loader is
  still caught (mutations K2, K2b, K4).
- **Offsets.** The secret key sits at the same offset as in `MLDSASK1`, so
  existing offset logic (the E2E log scan) is unchanged. The magic itself is
  compared exactly, not hashed; the label already binds the version.

### Load order (first failure wins)

1. `O_NOFOLLOW` open; regular file, else IO; owner and `mode & 077`, else
   PERMISSIONS.
2. `9 <= size <= 6089`, else FORMAT. This admits every legacy size, so a
   legacy file reaches the next check.
3. Magic `MLDSASK1` → **`UNSUPPORTED_VERSION`**; anything but `MLDSASK2`
   → FORMAT.
4. `id_len` in 1..64 and size exactly `6025 + id_len`, else FORMAT
   (truncated, extended or digest-stripped files).
5. Read; the secret key goes straight into `secure_mem`.
6. Recompute the digest (streaming SHA-256, the secret read in place) and
   compare all 32 bytes with **`sodium_memcmp`** (constant time). Mismatch
   → **`INTEGRITY`**. Hash state and both digests are wiped on every path.
7. Id → ID_MISMATCH. The id is checked after integrity, so a corrupted id
   reports INTEGRITY.
8. The sign/verify self-test stays as defense in depth against a buggy
   *writer* pairing mismatched keys (KEY_MISMATCH). It is no longer relied
   on to detect corruption.

On any failure `*kp` holds nothing: NULL secret key, zeroed public key. The
two new statuses are appended to `demo_keys_status_t`, so existing values
are stable.

### Keygen: atomic, no-clobber, 0600

Both images are built first; the secret image lives in one `secure_mem`
buffer. Each is written to a hidden temp file in the same directory
(`.<id>.sk.tmp.<pid>`, `O_CREAT|O_EXCL|O_NOFOLLOW`, final mode), fsync'ed,
and published with `link()`, which fails rather than overwrite. The secret
key is published first; a failed public-key link unlinks it again. Temps are
always removed and the directory is fsync'ed. A reader never sees a partial
`.sk`, and an existing identity is never overwritten. A crash between write
and link can leave a hidden 0600 temp file: a demo-only limitation.

### What the digest protects, and what it does not

It is **unkeyed**. It detects accidental corruption, truncation and
mis-assembly deterministically at load time. It is not an authenticity
mechanism: anyone able to write the 0600 file can recompute it, or simply
replace the key. Production key storage remains out of scope (spec §9).

### Legacy files and the public-key format

- **`MLDSASK1` is rejected, not migrated.** A migration would have to trust
  an unverifiable legacy file, which is exactly the input this step stops
  accepting, and demo keys are cheap to regenerate. The status message says
  "regenerate it with keygen". *(V2-9 adds an opt-in `migrate-key` command
  for the one case where regenerating is not free — an identity whose public
  key peers have already pinned. The reasoning here is unchanged: the
  loaders still refuse legacy files, and migration is a separate, explicit
  act that prints what it cannot verify. See § V2-9.)*
- **`MLDSAPK1` is unchanged.** Public files hold no secret, trust comes from
  out-of-band pinning, and a corrupted pinned key fails deterministically:
  every signature from that peer is rejected. The intermittent failure mode
  is specific to secret keys.

### Evidence

- **Before and after**, same probe (keygen → `70 3c 8d` at file offset
  4608, i.e. secret-key offset 2642 → load, 20 fresh keys): the Step 7
  loader accepted 11 of 20; the Step 7.1 loader accepts 0 of 20
  (`integrity-check-failed`).
- **T14** writes the recorded corruption into 5 fresh keys and requires
  INTEGRITY for all of them.
- **Fuzz regressions.** `t0-corruption-original-*` (renamed) and the new
  `t0-corruption-rejected-*` both replay as `integrity-check-failed`, and the
  F5 model predicts that status by recomputing the digest.

### OPEN issue: the secret scanner's 16-byte window rule also matches public-key prefixes

**RESOLVED in V2-8** — see § *V2-8 — fuzz-scanner precision*. The measurement
below (153 violations from the generated public-mode seeds) is now 0, with the
secret-key rules unchanged. The rest of this section is left as written,
because it is the record of how the limitation was found and why it was
allowed to stand for four steps.

Not a Step 7.1 regression — the rule dates from Step 7 — but it was measured
while verifying this step, so it is recorded here.

`fuzz_keys_replay --scan-secret` rejects any file containing a 16-byte window
of the fixture **secret** key. An ML-DSA-65 secret key begins with `rho`,
which is also the first 32 bytes of the public key, so every file holding the
fixture public key matches 17 of those windows. Measured: the 9 generated
public-mode seeds produce 153 violations.

- **No effect today.** Seeds live only in ignored build directories, and no
  committed file contains the fixture public key: the scan over every tracked
  file reports 0 violations.
- **The limitation.** A minimized F5 *public-mode* artifact would be refused
  by `add_regression.sh`, even though a public key is not secret. That is a
  scanner **precision** problem: it over-rejects.
- **Not a reason to weaken secret-key scanning.** The window rule is what
  makes the admission gate conservative, and a public-key false positive
  costs one untracked artifact plus a deterministic unit test, which the
  crash workflow already requires.
- **Deferred** to a future narrow task: for example, excluding windows that
  fall inside the `rho` prefix shared with the public key, or matching the
  secret key only from offset 32 onward, with a test proving that a real
  secret-key file is still refused.

---

## Step 8 — benchmarking

Scope: a new `bench/` tree, its CMake wiring, one CTest smoke, and
`bench/results.md`. No change to `src/`, `apps/`, the protocol, the spec or
the dependency configuration — the benches only call the same public APIs
the tests use.

### Headline: 0.372 ms against a 15 ms target

The full mutual handshake, measured in process, has a median of 0.372 ms on
an Apple M4 Pro — about 40x inside spec §5.1's budget. Two signatures and
two verifications are 81% of that; parsing, encoding and transcript hashing
together are under 2%. **This is a signature-bound protocol.** Record-layer
throughput is 722 MiB/s at 64 KiB and 4.19 M records/s at 64 B. Full tables,
including the loopback transport cost, are in `bench/results.md`.

### The platform does not match the spec's wording

§5.1 targets "a modern x86_64 core"; the only machine available is arm64.
`bench/results.md` states plainly that these are real measurements on a
different architecture and therefore not a literal verification of Req 5.1.
The spec is left unchanged: editing a requirement to match the hardware that
happened to be available would be the wrong direction of fit.

### Measurement decisions

- **The clock is chosen, not assumed.** macOS `CLOCK_MONOTONIC` reports
  whole microseconds, which would have quantized every unbatched row (ML-DSA
  verify measured in 1 us steps). The harness measures each candidate at
  startup and takes the finest: `CLOCK_MONOTONIC_RAW`, 41 ns here. The
  chosen clock and its measured resolution print with every result.
- **Two timing shapes.** Stateless operations are batch-timed, with the
  batch size calibrated so one batch lasts ~20 us; stateful ones (handshake
  phases, `session_open`) rebuild state in a prepare step outside the timed
  region. Every row reports its batch size, so a reader can see which is
  which.
- **Performance cores.** On Apple Silicon an unhinted thread can be
  scheduled on an efficiency core, which would produce numbers unrelated to
  the code. The bench requests `QOS_CLASS_USER_INTERACTIVE` and reports the
  class actually granted.
- **The executing backend is checked, not inferred.** The harness calls the
  same `OQS_CPU_has_extension` predicate liboqs branches on internally, so
  the reported backend cannot drift from the one that ran.
- **The loopback bench fixes its socket buffers up front.** It drives both
  ends from one process in strict request/response order, which is only safe
  while every message fits the socket buffer. Both ends are set to 256 KiB
  (the `tests/fuzz/fuzz_frame.c` pattern), the granted size is read back with
  `getsockopt`, and the bench aborts at startup unless it exceeds the largest
  handshake message by 4x. There is deliberately no runtime fallback and no
  forked variant: the control flow is guaranteed by construction.

### Req 3 (build-time backend selection): measured, deviation kept

`OQS_DIST_BUILD=ON` means liboqs compiles both the reference and aarch64
ML-DSA backends and picks between them with a CPU-feature branch per
sign/verify call — where Req 3 asks for build-time selection with no runtime
branching. A comparison build (`OQS_DIST_BUILD=OFF`,
`OQS_OPT_TARGET=native`) was benchmarked against the default.

The difference is 0.6-3.0%, smaller than the 7-8% run-to-run spread of the
ML-DSA rows themselves: **not distinguishable from noise**. Both builds run
the same NEON backend, and the branch is one feature test against tens of
microseconds of lattice arithmetic. Changing the default is therefore not
justified on performance grounds, and a `native` non-dist build would tie
binaries to the build machine's CPU. The deviation stands, now with a
measurement behind the decision rather than an assumption.

### Benchmarks run in CI, but only as a smoke test

`bench_smoke` runs every bench binary with `--smoke` (tiny iteration counts)
in the normal, ASan and UBSan builds, so bench code cannot rot or drift out
of the API. It asserts correctness only — handshakes complete, sealed records
open, no zero medians — never a performance threshold, since sanitizer builds
are several times slower.

### The default build type is Debug, and that matters

liboqs is built inside this CMake project, so a default build compiles
ML-DSA unoptimized: signing is 5.8x slower, the handshake 4.0x. libsodium is
an ExternalProject with its own Autotools defaults, so it stays optimized in
every configuration — meaning a Debug bench run pairs slow signatures with
normal-speed AEAD and misleads twice over. `bench/run_bench.sh` and both
READMEs say to benchmark Release builds only; the default is deliberately
left as Debug, since it is the right default for development.

### Harness-sanity mutations (M1-M4)

Steps 4-7 validated tests by making them fail. A benchmark has no pass/fail,
so the analogue is: a deliberate change must move a reported number in a
predicted direction. Injecting 1 ms into the timed sign callback moved the
sign median by +1.28 ms and left verify unchanged (M1); the same delay inside
`handshake_responder_create_server_hello` moved both that phase (+1.28 ms)
and the end-to-end handshake (+1.30 ms) (M2); sealing half the bytes a row
claims produced an implausible 1.84x MiB/s (M3); removing warmup widened p99
while the median held (M4).

**A correction found while running these.** M2 first injected its delay into
the bench's own phase wrapper, which moved the phase row but not the
end-to-end row — correctly, since the end-to-end path calls the library
function directly rather than the wrapper. The mutation was wrong, not the
harness: it now patches the shared library function, where both paths must
see it. M4's effect is real but small and noisy (p99 widened by 3% in one
run, 70% in another), because warmup matters least for a batch-timed AEAD
row.

---

## Step 9 — documentation

Scope: `README.md` rewritten as the repository's front door, plus this
section. No code, test, build-system or spec change.

### The spec is not edited, and the README carries the gap

Spec §5.1 targets "a modern x86_64 core" and §9's limitations list predates
Steps 4-8, so it does not mention traffic analysis, the routing gap, rate
limiting or thread safety. Both could have been "fixed" by editing the spec.
Neither was.

The spec is the brief this project was built against; editing a requirement
after measuring on different hardware would be fitting the target to the
result, and back-filling §9 would erase the evidence that those limitations
were discovered while implementing rather than anticipated. The README states
the full, current picture and says plainly where it differs from the spec --
the measurement platform, and the Req 3 backend deviation. A reader comparing
the two documents can see exactly what changed and when.

### Limitations and deferred work are separate lists

"What this does not protect against" and "deferred work" answer different
questions, so the README keeps them apart. The first is a **security scope**
statement: what an attacker can still do to someone who deploys this
correctly -- no CA, harvest-now-decrypt-later, traffic analysis, DoS, thread
safety, demo key storage. The second is an **engineering backlog**: routing,
scanner precision, key migration, pin hardening, padding, hybrid KEX.

The two overlap (padding appears in both, as a leak and as a deferred
feature), but merging them would bury a security caveat in a to-do list. A
reader deciding whether the protocol is safe for their threat model reads the
first; a reader deciding what to build next reads the second.

### Every documented command was executed

Documentation rots by asserting things that stopped being true. Rather than
proofreading, every fenced command in the README was extracted and run
verbatim, in order, against freshly deleted build directories -- configure,
build, ctest, the sanitizer build, both fuzz modes, the benchmark build and
run, and the three-step demo -- and the test count, dependency versions and
performance figures were compared against `ctest -N`,
`cmake/Dependencies.cmake` and `bench/results.md` rather than memory.

That immediately found one defect: the benchmark section told the reader to
run `bench/run_bench.sh build-bench 3` without ever showing how `build-bench`
is created. The command block is now self-contained.

### Citations are section names, not line numbers

The README cites `docs/decisions.md` by section heading rather than by line
number. Line numbers in a cross-file citation are wrong as soon as anything is
inserted above them -- this file grew by ~100 lines in Step 8 alone -- whereas
headings survive edits and can be verified mechanically. Each cited heading
was checked to exist verbatim.

---

## v2 — roadmap decisions

These four decisions were taken before any v2 code was written. The
technical design they govern is in
[ml-dsa-auth-protocol-spec-v2.md](ml-dsa-auth-protocol-spec-v2.md).

### Compatibility: clean break, no negotiation

v2 peers speak only v2. Every domain label moves from `mldsa-auth/v1/` to
`mldsa-auth/v2/`, and the ClientHello/ServerHello layouts grow by the ML-KEM
encapsulation key and ciphertext, so a v1 message fails a v2 decoder on
length and full consumption alone -- and a v2 message fails a v1 decoder the
same way. There is no version field.

The alternative, a version byte with negotiation, was rejected: it would
create a downgrade surface that then has to be authenticated and tested, and
it would double the handshake state machine's surface, all to serve mixed
fleets that do not exist. Trust here is explicit pinning, so there is no
discovery step in which a version could be negotiated away; peers are
upgraded together by whoever pinned them.

### v1 maintenance life: frozen at `v1.0.0` (upgrade-or-fork)

**This repository does not maintain a patchable v1 branch.** When v2's
wire-format, key-schedule and handshake functions replace v1's, the v1
functions are deleted from `src/` rather than kept behind a build flag or on
a maintenance branch.

Reasoning:

- v1 is documented as not production-ready (no CA or revocation,
  loopback-only reference server, unencrypted demo keys, single-threaded),
  so there is no deployed base a patch branch would serve.
- The break is at the wire level, so a v1 security fix would still force
  both peers to upgrade. A v1 patch would buy nothing that upgrading to v2
  does not.
- Every change in this project carries a fixed verification cost -- fresh
  ASan and UBSan builds, fuzz budgets, a mutation campaign. Maintaining a
  second protocol track would double that cost indefinitely, and nobody has
  committed to paying it.
- Keeping dead cryptographic code compiled-but-unused is its own hazard: it
  invites accidental use and has to be tested to stay trustworthy.

Anyone who needs a patched v1 can branch from the `v1.0.0` tag -- git makes
that trivial, and the tag is immutable -- but no such branch is promised
here. This is stated in three places a reader might look: this section, the
README status line, and spec-v2 §2.1, so it is never discoverable only as a
code-deletion rationale.

### Specification versioning: a new v2 document, v1 frozen

v2 is specified in a new file, `docs/ml-dsa-auth-protocol-spec-v2.md`, and
`docs/ml-dsa-auth-protocol-spec.md` is never edited again.

Editing the v1 document in place would have left every v1 tag pointing at a
specification that no longer describes the code at that tag -- including
`v1.0.0`, which is a published release. A complete second document costs
some duplication, and that is the price of keeping each released version
self-describing. It also preserves the project's standing rule that the
brief is not rewritten after the fact (Step 8 and Step 9 both declined to
edit it).

### Scope of v2

**In:** hybrid X25519 + ML-KEM-768 key exchange (the spec's one deferred
decision); record padding (the other item v1 deferred to "a future protocol
version"); and four narrow backlog items -- fuzz-scanner precision, pinning
liboqs by commit SHA, build-time backend selection (Security Req 3), and
`MLDSASK1` -> `MLDSASK2` key migration.

**Out, and recorded as such:** multi-connection handshake routing, transport
rate limiting, thread safety, CA/revocation, group sessions, and production
key storage. These remain integrator obligations or later work, listed in
spec-v2 §9 and the README.

The AEAD rekey and expiry limits are *reviewed* by v2 rather than changed:
v1 required a revisit if the maximum plaintext, the AEAD, the transport or
the rekey policy changed. Padding moves the *content* bound to 65 534 bytes
but leaves the AEAD plaintext bound at 65 536, and nothing else changed, so
the v1 values carry over. That review is recorded in spec-v2 §6.4.5.

---

## V2-2 — dependency configuration

Build configuration only: ML-KEM-768 enabled, the liboqs pin moved from a
mutable tag to an enforced commit, and the algorithm backend chosen at
compile time (Security Req 4.10). No `src/`, `apps/`, `tests/` or bench
source changed.

### ML-KEM-768 enabled, and nothing else

`OQS_MINIMAL_BUILD` becomes `"SIG_ml_dsa_65;KEM_ml_kem_768"` — liboqs's
`filter_algs` takes a `;`-separated list. Symbol inspection of the built
archive confirms the surface is exactly two algorithms: the only
algorithm-specific exports are `OQS_SIG_ml_dsa_65*` and
`OQS_KEM_ml_kem_768*`, alongside liboqs's generic `OQS_SIG_*`/`OQS_KEM_*`
dispatch entry points. No other signature or KEM family is compiled in.

### The pin is the commit; the tag is only the fetch hint

v1 fetched liboqs at `GIT_TAG 0.16.0` and recorded the resolved commit in a
comment, which pins nothing: a git tag is mutable, so an upstream re-point
would silently change what this project builds. The v1 README listed this as
deferred work.

The obvious fix — setting `GIT_TAG` to the commit SHA — does not work here.
CMake 4.4.3's `ExternalProject.cmake` states: *"If `GIT_SHALLOW` is enabled
then `GIT_TAG` works only with branch names and tags. A commit hash is not
allowed."* Turning the shallow clone off would pull liboqs's full history
into every build directory; the shallow `.git` is already ~160 MB.

So the tag remains the *fetch mechanism* and the commit is *verified*, by
`cmake/VerifyLiboqsCommit.cmake`, in two places:

1. **At population**, as the `PATCH_COMMAND`. This runs before liboqs's own
   `CMakeLists.txt` is ever processed, so a re-pointed or replaced tag never
   reaches configuration. A wrong pin aborts with both hashes named
   (verified: the mismatch fires and liboqs's CMake output never appears).
2. **At every configure**, re-running the same script after
   `FetchContent_MakeAvailable`. This is the only guard on the path where
   the first one cannot run: `-DFETCHCONTENT_SOURCE_DIR_LIBOQS=<dir>`, the
   documented CMake override that points the build at a local source tree
   and skips download, update and patch entirely. Verified with a
   substituted source at a different commit: check 2 fires, and the patch
   step never runs.

**A finding worth recording**: local tampering with an already-populated
`_deps/liboqs-src` is *self-healing*, not a durable attack. ExternalProject's
update step re-checks out the tag on every configure, so a commit added by
hand is silently reverted before either check runs. The realistic vectors
are therefore (a) upstream re-pointing the tag — caught by check 1 on a
fresh fetch and by check 2 after an update moves HEAD — and (b) a
substituted source directory — caught by check 2. The first negative control
written for this step simulated the self-healing case and passed vacuously;
it was replaced by the source-substitution test above, which does not.

A CMake trap, recorded so the next editor does not repeat it: **CMake's
regex engine has no bounded-repetition operator**, so `MATCHES
"^[0-9a-f]{40}$"` matches `{40}` literally and rejects every valid SHA. The
script validates the length with `string(LENGTH)` instead. This was caught
by the very first fresh configure.

### Backend selection at build time: linked, not merely compiled

Security Req 4.10 (spec-v2 §3) asks for the optimized backend to be chosen
at build time with no runtime branching in hot paths. v1 shipped
`OQS_DIST_BUILD=ON`, liboqs's default, which compiles every backend and
dispatches through `OQS_CPU_has_extension()` on each call. v2 sets
`OQS_DIST_BUILD=OFF`.

The precise claim matters. liboqs compiles its portable-C object library
unconditionally — `if(OQS_ENABLE_SIG_ml_dsa_65) add_library(ml_dsa_65_ref …)`
— so those objects are in `liboqs.a` either way. What `OQS_DIST_BUILD=OFF`
changes is the dispatch in `sig_ml_dsa_65.c` / `kem_ml_kem_768.c` from a
runtime `if` to a compile-time `#if`, after which nothing references the
portable-C entry points and the linker never pulls them into a binary. So
the conformance statement is **"one backend is linked"**, and the
verification measures executables, not the archive: every Mach-O executable
in the build tree, discovered dynamically, carries the NEON symbols and zero
`PQCP_MLDSA_NATIVE_MLDSA65_C_*` symbols (15 of 17 executables link the
algorithm at all; the check fails if that count is zero, so it cannot pass
vacuously).

`MLDSA_OQS_OPT_TARGET` (top-level `CMakeLists.txt`) selects the target and
defaults to **`auto`**. Step 8 used `native`, which liboqs accepts only by
falling through to its "pass the string to the compiler as a CPU name"
branch; `auto` is the documented value that means "tune for this machine"
(`-mcpu=native` on Apple arm64, `-march=native` on x86_64). `generic` is the
portable baseline (`-march=armv8-a+crypto`, `-march=x86-64`).

**`auto` is not portable**: the binary may use instructions absent on an
older CPU of the same family. Anything distributed must be built with
`generic`, which on x86_64 gives up liboqs's AVX2 backends. Both paths are
tested (a full `generic` build passes the suite), and an unrecognised CPU
name fails loudly at compile time rather than silently degrading.

This change is made for **requirement conformance, not speed**. Step 8
measured the runtime-dispatch branch at 0.6–3.0%, inside run-to-run noise;
nobody should read this as a performance optimization.

---

## V2-3 — ML-KEM-768 wrapper

`src/crypto/mlkem_wrap.{c,h}`, the post-quantum half of v2's hybrid key
exchange. Purely additive: no existing behaviour changes, and no protocol
code calls the KEM yet (that is V2-5).

### The same shape as `mldsa_wrap`

Identical conventions, so the two wrappers read alike: sizes as macros,
`_Static_assert`ed against liboqs's `OQS_KEM_ml_kem_768_length_*` **and**
cross-checked at run time against the `OQS_KEM` object's reported lengths;
the secret (here FIPS 203's *decapsulation key*) in `secure_mem`, the
public *encapsulation key* inline; `*_free` wipes, frees, NULLs and is
idempotent. Status is tested as `!= OQS_SUCCESS`, never `== OQS_ERROR`,
because liboqs casts mlkem-native's `int` return straight to `OQS_STATUS`
— a negative internal code that is not exactly `OQS_ERROR` would otherwise
read as success.

### "Decapsulation never fails" is true of the ciphertext only

The roadmap said ML-KEM decapsulation never fails. Reading mlkem-native's
`kem.c` shows that is precise about the *ciphertext* and wrong about the
keys, because mlkem-native implements FIPS 203's input validation:

| Input | Behaviour | Test |
|---|---|---|
| Tampered **ciphertext** | Implicit rejection: decaps returns success with a pseudorandom secret | `mlkem768_implicit_rejection` |
| Malformed **encapsulation key** | Encaps FAILS (§7.2 modulus check, `mlk_kem_check_pk`) | `mlkem768_input_validation` |
| Corrupted **decapsulation key** | Decaps FAILS (§7.3 hash check, `mlk_kem_check_sk`) | `mlkem768_input_validation` |

Keypair generation performs no pairwise-consistency test
(`MLK_CONFIG_KEYGEN_PCT` is not defined in liboqs's config), so a caller
cannot rely on keygen to self-check.

All three are pinned by tests, so a future liboqs that stops validating is
caught here rather than in a handshake. Spec-v2 Security Req 4.11 needs no
change — it speaks only of the ciphertext — but the wrapper header now
documents all three, because "never fails" is the kind of half-truth that
leads a caller to skip a return-value check.

On any failure the wrapper zeroes its output buffers, so a caller can never
mistake a partial result or an implicit-rejection secret for a usable key.

### The KAT runs through the wrapper, not around it

`test_vectors` reproduces liboqs's own single-vector KEM KAT record
(`count / seed / pk / sk / ct / ss`, no trailing blank line) by driving the
NIST-KAT DRBG through **`mlkem_wrap`'s own functions**, then compares
SHA-256(record) against `"ML-KEM-768"."single"` read live from liboqs's
vendored `tests/KATs/kem/kats.json`. Testing liboqs directly would prove
only that liboqs works; routing the KAT through the wrapper proves the
wrapper does not corrupt, truncate or mis-order anything on the way. No
expected value is written into this repository.

### Mutations

Six temporary defects, each required to make a *named* check fail:

| # | Defect | Observed |
|---|---|---|
| K1 | encaps returns success without writing `ct`/`ss` | 4 named failures, first the KAT record hash |
| K2 | decaps ignores liboqs's status | corrupted-dk check fails |
| K3 | encaps ignores liboqs's status | malformed-ek check fails |
| K4 | free does not clear the encapsulation key | free-contract check fails |
| K4b | free leaves the pointer dangling | **SegFault** on the idempotent free — libsodium's guard pages catch the double free before any check prints |
| K5 | one `ct` byte altered in the hashed record only | KAT hash fails — proves the hash covers every field and the test is not comparing against itself |

### The mutation runner, and a bug class rediscovered

The V2-3 campaign was first run through a **one-off runner**: it deleted
four artifact paths by name (`mlkem_wrap.c.o`, `test_vectors.c.o`,
`libmldsa_core.a`, `test_vectors`) and fingerprinted two of them. What
happened next is worth recording in order, because the final state alone
hides the lesson.

**1. K5 exposed a dirty restore.** K5 mutates the *test* file rather than
the wrapper. The first runner's delete list did not include
`test_vectors.c.o`, so after the mutated source was restored byte-exactly,
make's one-second timestamp granularity saw no reason to recompile it: the
stale, still-mutated object was linked into the "clean" rebuild, and the
post-mutation clean-suite check ran against mutated code. It reported
`RESTORED-NOT-CLEAN` and `CLEAN-SUITE=FAIL` — the run caught itself, but
only because K5 happened to mutate a file the list had missed.

**2. Root cause: enumeration, not the missing entry.** This is the same bug
class as the Step 4 harness, independently rediscovered. That harness took
four iterations to get right, and the scratch summaries show the identical
symptom: v1 reported `restored-suite-FAIL(BAD)` on 2 of 4 mutations, v2 on
**all four** ("source restored, cmp identical | restored-objects=clean |
CLEAN-SUITE=FAIL"), and only v4 — which added a `mutant-in-binary` text-hash
fingerprint — came back clean. Both runners named their artifacts, so both
were one forgotten path away from silently testing stale code. Adding the
missing entry would have fixed this instance and left the class intact.

**3. The fix is discovery, not a longer list.** The runner used from here on
is generalized and step-agnostic:

- snapshots **every** `.c`/`.h` under `src/`, `apps/`, `tests/`, `bench/`
  (49 files today) rather than a per-step subset;
- before each rebuild deletes **every** object, archive and Mach-O
  executable found under the build directory, with `_deps/` pruned so the
  vendored liboqs and libsodium are never rebuilt;
- fingerprints **all** of them together (41 objects + 15 executables today),
  so "mutant-in-binaries" and "restored=clean" cover artifacts nobody
  thought to list;
- refuses to start if a `MUTATION` marker is already present, and reports
  any source file a mutation *adds*;
- takes the mutation ids, the test to run and the expected failure text from
  an external spec file, so nothing step-specific lives in the runner.

The marker guard exists because of a second flaw in the same session: a run
that died mid-mutation left its defect in the tree, and the next run
snapshotted *that* as its baseline, reporting "clean suite fails" at
preflight. The affected file was new and therefore untracked, so
`git checkout` could not rescue it — a mutation campaign on unstaged new
files has no safety net but its own snapshot.

**4. Re-run, same results.** The complete V2-3 campaign (K1–K5 and K4b) was
re-run through the generalized runner and produced identical outcomes: all
six killed, every restore clean, no residue. The fix closed the
artifact-enumeration gap without changing any verdict.

**Cost, accepted deliberately.** Deleting every artifact means a full
project rebuild per mutation — about 18 builds for a six-mutation campaign,
several minutes of wall time. The vendored dependencies are pruned, so the
expensive part is never repeated. That cost buys the guarantee that a
"clean suite" result was produced by clean code, which is the entire point
of the exercise.

**Mutation runners were session tooling at the time of V2-3** — like every
prior step's, they lived in the scratchpad and were not committed. V2-4 and
V2-5 reuse this generalized runner unchanged, supplying only their own
mutation script and spec file.

*Superseded after V2-4:* because the runner is genuinely step-agnostic, it
is now committed as `tools/run_mutations_v2.sh`. The **per-step** mutation
scripts and spec files are still not repository content — they encode one
step's defects and have no life beyond it.

## V2-4 — wire format v2 and the hybrid key schedule

### One step where two key schedules coexist, deliberately

The wire format changes in place: `client_hello_t` gains `mlkem_ek`,
`server_hello_t` gains `mlkem_ct`, the four `*_MAX_ENCODED_LEN` macros
follow, and the three transcript labels move to `mldsa-auth/v2/`. The key
schedule could not change in place, because `protocol/handshake.c` still
calls the v1 derivation and V2-5, not V2-4, rewrites it. So V2-4 **adds**
`kex_build_kdf_info_v2()` and `kex_derive_session_key_v2()` beside the v1
pair rather than replacing it.

The consequence is stated plainly rather than glossed: between V2-4 and
V2-5, `main` emits v2-layout messages whose ML-KEM fields are **all zero**
(`handshake.c` zeroes every message struct before filling it) and still
derives keys with the X25519-only schedule. That intermediate state is an
implementation checkpoint, **never a protocol version** — it is not
tagged as one, not specified, and not interoperable with anything. V2-5
deletes `KEX_KDF_LABEL`, `KEX_KDF_INFO_MAX_LEN`, both v1 functions, their
tests (T23–T28) and their benchmark rows; `kex.h` says so at the
declaration, so nobody adds a caller in the meantime.

The `_v2` suffix is permanent. It names the key schedule the way the label
inside it does, so V2-5's deletion removes code without renaming anything.

### Every constant is proven equal, never restated by hand

`WIRE_MLKEM_EK_LEN`/`WIRE_MLKEM_CT_LEN` restate the KEM's sizes the way
`WIRE_X25519_PUB_LEN` restates `KEX_PUBLIC_KEY_BYTES`, keeping
`transcript.h` free of crypto-layer includes. The equality is not left to
review: `transcript.c` includes `mlkem_wrap.h` and static-asserts both
against `MLKEM_PUBLIC_KEY_BYTES`/`MLKEM_CIPHERTEXT_BYTES`, and asserts the
four message maxima against the literals in spec-v2 §6.3.1 (1330 / 1234 /
4545 / 3328). `kex.c` asserts the v2 info bounds (55 / 181) against the
layout arithmetic and against `KEX_KDF_INFO_MAX_LEN + 32`.

A scratch program compiled against the real headers printed all of them,
including liboqs's own `OQS_KEM_ml_kem_768_length_*`, and every value
matched the spec tables and the v1→v2 deltas (1330 = 146 + 1184,
4545 = 3457 + 1088, 181 = 149 + 32).

### The vectors are computed outside this codebase, and that is the point

A hybrid combiner that drops `ss_k`, swaps the two secrets, or omits the
transcript digest is **symmetric**: both peers compute the same wrong key,
every handshake succeeds, and every round-trip test passes while the
post-quantum protection is silently gone. Interop proves nothing about it.
RFC 5869's vectors do not help either — they test `kex_hkdf_sha256`, which
is not where this bug lives.

So `test_handshake.c` D3 pins literal inputs to literal expected keys,
generated by a hand-written RFC 5869 implementation in Python's
`hmac`/`hashlib` — no libsodium, no code from this repository. The
generator is quoted verbatim in the test's comment, and verification
re-ran it and diffed its output against the arrays in the source. Both
directions matched:

```
c2s 791e53d2cbd70f63276304f909a68834d5de496135a99083f7858aeda5d91c5a
s2c ddb64a76f485bd11387a129574f7b425d9f6686b936b9e6b086af0de69d715af
```

### A test that would have accepted a v1 label

`test_transcript_hashes` built its expected digests by passing the
`TRANSCRIPT_LABEL_*` **macros** to its hand-rolled hasher. That test
therefore agreed with whatever the header contained: had the labels been
left at `mldsa-auth/v1/`, it would have passed. Only `fuzz_wire`, which
spells its labels as literals, would have noticed.

The three calls now use literal strings — the same discipline
`hand_kdf_info()` already applied to the KDF label. Mutation M5 exists to
keep it that way.

### Two silent fuzz-coverage losses, fixed generally

Growing a message by 1088–1184 bytes broke two size assumptions that would
have failed quietly:

- `fuzz_wire`'s `fuzz_target_max_len` was 4096, below the 4545-byte v2
  `ServerHello`. Raised to 8192, with `run_fuzz.sh`'s `-max_len` to match.
- `fuzz_handshake`'s seed scratch buffers were fixed 4096-byte arrays, so
  `encode_server_hello` would have failed and the `s1-wrong-echo` and
  `s1-zero-ephemeral` seeds would have vanished behind their `if`. They
  are now sized from `SERVER_HELLO_MAX_ENCODED_LEN`.

The underlying defect was in the replay driver, not in either target: it
**truncated** any seed longer than `fuzz_target_max_len`
(`len = (s->len <= cap) ? s->len : cap`), so a stale limit shrank the
corpus instead of reporting anything. A seed the target cannot accept is a
harness defect, so the driver now fails, naming the seed and both sizes.
Proved by negative control: with the limit put back to 4096, the driver
refuses with `seed "server-hello" is 4484 bytes, over the target maximum
of 4096` instead of quietly truncating.

### Mutations M1–M8, including two that did not behave as predicted

| # | Defect | Outcome |
|---|---|---|
| M1 | IKM = `ss_x` twice (`ss_k` dropped) | killed — D3, D4 (4 named checks) |
| M2 | IKM = `ss_k ‖ ss_x` (order swapped) | killed — D3, D2 (3) |
| M3 | transcript digest omitted from the info | killed — D1, D3 (6) |
| M4 | v2 builder uses the v1 label | killed — D1, D3 (4) |
| M5 | `TRANSCRIPT_LABEL_SERVER_AUTH` left at `/v1/` | killed — the literal-label check (1) |
| M6 | `decode_client_hello` length check omits `ek` | **survived the plain build; killed by ASan** |
| M7 | `ek` before `ephemeral_pub` in encoder *and* decoder | killed — W3 offsets (1) |
| M8 | `CLIENT_HELLO_MAX_ENCODED_LEN` left at the v1 formula | **killed at compile time** |

**M6 is the interesting one.** Dropping `WIRE_MLKEM_EK_LEN` from the
decoder's remaining-length check does *not* let a v1 `ClientHello` through:
the trailing full-consumption check (`off != len`) still rejects it, so W5
and every functional oracle pass. What the mutation actually introduces is
a **1184-byte out-of-bounds read** performed before that rejection. ASan
caught it immediately — `heap-buffer-overflow ... READ of size 1184` in
`decode_client_hello` (`transcript.c:248`), reported from the Step 3
truncation sweep, whose exact-size heap buffers exist for precisely this
reason. Recorded as it happened: the functional suite is not sufficient
for this class of defect, and the sanitizer run is not optional.

**M8 is caught earlier than planned.** The mutation was predicted to fail
check W1; instead the tree does not compile, because `transcript.c`'s new
static assert fires: `static assertion failed due to requirement
'(1U + 1U + 64U + 32U + 16U + 32U) == 1330U'`. A defect that cannot be
built is a stronger result than one caught at run time, so the assert
stays and the prediction is corrected rather than the assert weakened.

### The sanitizer builds were wrong, and a mutation exposed it

M6's first run reported "survived" under what was supposed to be an ASan
build. It was not one: the trees had been configured with
`-DMLDSA_SANITIZE=address`, and this project's options are `ENABLE_ASAN` /
`ENABLE_UBSAN`. CMake accepted the unknown variable silently, so both
"sanitizer" trees were plain Debug builds with no instrumentation, and the
sanitizer verification they produced was worthless. Rebuilt with the
correct options — confirmed by `otool -L` showing
`libclang_rt.asan_osx_dynamic.dylib` linked and by `__ubsan` symbols in the
UBSan binary — both trees pass 15/15 with zero reports, and M6 is killed.
The lesson is the step's own discipline turned inward: a verification tool
must itself be verified, and here the mutation campaign is what did it.

A second self-inflicted incident reinforced the runner's design. M8 was
demonstrated by hand (apply, build, restore) because the runner treats a
build failure as fatal; the failed build left stale objects behind, and the
next suite run reported 12 failures against byte-exactly restored sources.
Deleting every project object, archive and executable and rebuilding
restored 15/15. This is the same artifact-enumeration hazard the V2-3
narrative describes — avoided by the runner, walked straight into as soon
as a mutation was driven manually.

### Scope deviation, reported not hidden

The declared file list allowed two *check-name* edits in
`tests/test_net.c`. A third edit was required: `CH_PAYLOAD` is that file's
own hand-computed `ClientHello` size, used to predict exact byte counts on
the wire, and it needed `WIRE_MLKEM_EK_LEN`. Without it, four T5/T8/T9
checks failed. It is the same class as the check names — stale v1
arithmetic in the test's independent model — but it was not in the
approved list, so it is recorded here rather than absorbed silently.

## Process hardening after V2-4 (standing rules)

V2-4 produced two verification failures that had nothing to do with the code
under test: a mutation that could not compile aborted the campaign and had
to be driven by hand, and two "sanitizer" builds turned out to carry no
instrumentation at all. Both are closed here as standing rules, mechanically
enforced rather than remembered.

### A mutation that does not compile is KILLED, automatically

The mutation runner previously treated a mutated tree that fails to build as
a fatal error: it printed `FATAL mutated tree does not build`, abandoned the
campaign, and left the remaining mutations unrun. That is backwards. A
defect caught by the **compiler** — a static assert, a type error — is
caught earlier and more cheaply than any test could manage; it is the
strongest possible outcome, not a reason to stop.

The runner now records such a mutation as `KILLED(compile)` and continues.
Two guards keep that honest:

- **The failure must be attributable.** The first compiler error must name a
  file in the project's own source region (`src/`, `apps/`, `tests/`,
  `bench/`) with a line and column. A build that fails for an unrelated
  reason — a broken toolchain, a full disk, a vendored dependency — is
  reported as `SURVIVED(BAD: unattributable build failure)`, never
  laundered into a kill. The error line is saved to `<ID>.killreason`.
- **The epilogue is shared.** Restore, forced rebuild, full clean-suite run,
  residue grep and the printed row now come from one `finish_mutation`
  function used by every verdict, so no path can skip the bookkeeping.

That last point is the real fix. The reason V2-4's M8 had to be driven
manually is that the runner bailed before its restore/rebuild step; the
manual run then left stale objects behind, and a byte-exactly restored tree
reported 12 failures. The same hazard produced a stale `fuzz_wire_replay`
after a negative control was run by hand. **Corollary, now a rule: no
temporary edit to a source file is made outside the runner.** If an
experiment genuinely needs one, it ends with every project object, archive
and executable deleted and the tree rebuilt — the same `forced_build` the
runner performs — before any result is reported.

Verified by re-running the full V2-4 campaign unattended: M8 reports
`compile-fail | KILLED(compile)` with its static-assert error recorded, all
eight mutations run to completion, and the tree ends with every artifact
identical to the clean fingerprints.

### A sanitizer build is not trusted until its instrumentation is proven linked

V2-4's first ASan and UBSan trees were configured with
`-DMLDSA_SANITIZE=address`. This project's options are **`ENABLE_ASAN`** and
**`ENABLE_UBSAN`**. CMake accepts an unknown `-D` variable silently — it
appears in the cache as `MLDSA_SANITIZE:UNINITIALIZED=address` and changes
nothing — so both trees were plain Debug builds. They compiled, they passed
15/15, and the "0 sanitizer reports" they produced meant nothing. No line of
build or test output said so. Only the linked binary did.

**Standing rule: every fresh ASan/UBSan build is verified before its results
are reported.** The check is mechanical
(`tools/check_sanitizer_link.sh`) and has two parts, because either alone
can be fooled:

1. **The option is genuinely ON** — `ENABLE_ASAN:BOOL=ON` /
   `ENABLE_UBSAN:BOOL=ON` in `CMakeCache.txt`. This is what catches a
   mistyped `-D` flag, which otherwise leaves the real option at its `OFF`
   default.
2. **Every project executable carries the instrumentation** — for ASan,
   `otool -L` shows `libclang_rt.asan_osx_dynamic.dylib` (or `nm -u` shows
   `__asan_` imports); for UBSan, `nm` finds `__ubsan` symbols. Binaries are
   **discovered**, never enumerated, and an empty result is a failure, not a
   pass — the same rule the Req 4.10 symbol check follows. CMake's own
   compiler-probe binaries under `CMakeFiles/` are excluded by path: they
   are built during configure, before project flags exist.

Controls, all executed: both V2-4 sanitizer trees pass with 15/15
executables instrumented; the plain `build` tree is refused; a tree
reconstructed with the original `-DMLDSA_SANITIZE=address` mistake is
refused, with the offending cache line printed; and the ASan tree checked
as UBSan is refused, so the two kinds cannot be confused for each other.

**Why this rule and not "be careful":** the failure was silent in every
output a human would look at, and it was found only because mutation M6
reported "survived" under a build that should have caught it. A verification
tool that cannot itself be verified is not evidence. From V2-5 onward the
link check runs immediately after each sanitizer build, and its result is
quoted in the step's exit report alongside the test counts.

### A suite result is not trusted until the build is proven current (added after V2-9)

The third standing rule, and the one the first two could not cover.

**What happened.** V2-9's `build-ubsan` was freshly configured (CMake ran full
compiler detection, so the directory was genuinely empty), fully built, and
genuinely instrumented — of sources as they stood twelve minutes before a late
edit to `tests/fuzz/fuzz_keys.c`. Nothing rebuilt it, and **`ctest` never
compiles**: it runs whatever binaries exist. So the gate exercised stale
binaries and reported 15/15, and that number went into an exit report.

**Why the existing rules could not catch it.** `check_sanitizer_link.sh`
passed, correctly — the binaries really were instrumented. It proves
*instrumentation*, never *currency*. And rebuilding had only ever happened as
a **side effect** of other work: a mutation campaign's `forced_build`, the
README pass's `rm -rf build build-fuzz build-asan build-bench`. `build-ubsan`
is absent from that `rm` list, which is the entire reason ASan escaped and
UBSan did not. Currency was an accident of unrelated activity, not a gate.

**The rule.** *Every suite result quoted in an exit report must be preceded,
in the same invocation, by `tools/check_build_current.sh` on that build
directory* — same command, so the pairing is visible in the transcript rather
than asserted afterwards:

```sh
tools/check_build_current.sh build-asan && ctest --test-dir build-asan --output-on-failure
```

The `&&` matters: on a stale tree the check rebuilds, fails, and the suite
does not run at all, so a stale number cannot be produced in the first place.

**Why a no-op rebuild rather than mtimes.** The script fingerprints every
project object and executable, rebuilds, and requires every fingerprint to be
unchanged. A stale object cannot survive a rebuild byte-identical, whereas
`touch` and `git checkout` forge mtimes freely and say nothing about content.
This is sound here because the build is already known deterministic — the
mutation runner asserts it in every campaign preflight and has never fired —
and the check re-proves it on each run. Objects are hashed whole; executables
by their `__text` section, because a relink can move `LC_UUID` without
changing any code.

**Certified by demonstration, not assertion.** The decisive control reproduces
the V2-9 mistake exactly: break a literal in `test_session.c` that the suite
checks, run `ctest` on ASan without rebuilding — **`100% tests passed out of
15`** — then run the currency check — **`FAIL: build-asan was STALE`**, naming
`test_session.c.o` and `test_session` — then re-run the suite: **`93% tests
passed, 1 tests failed`**. The first number and the third describe the same
source tree. Only one of them is true.

Two further controls pin the design. A comment appended at the end of a file
changes the object and **not** the executable's text, so an executables-only
check would miss it — which is why objects are fingerprinted (mutation Z1).
And forcing a source's mtime to 2027 makes the build recompile — the object's
mtime moves, its hash does not — and the check still reports OK, so it
certifies content rather than timestamps (mutation Z4). Mutations Z2 (skip the
rebuild) and Z3 (treat an empty artifact set as success) are killed by the
same controls.

## V2-5 — the hybrid handshake

The state machine now implements spec-v2 §6.3: the initiator generates a
per-handshake ML-KEM-768 keypair and sends `ek`, the responder encapsulates
when it creates `ServerHello` and retains `ss_kem`, the initiator
decapsulates at `finish`, and both derive from `(ss_x, ss_kem,
TH_client_auth)`. V2-4's debt is paid here too: `KEX_KDF_LABEL`,
`KEX_KDF_INFO_MAX_LEN`, `kex_build_kdf_info` and `kex_derive_session_key`
are deleted, exactly as `kex.h` promised they would be.

### Where a malformed encapsulation key fails, and why it fails there

Encapsulation is the *first* place a bad `ek` can be detected: the wire
decoder validates length only (§6.3.5), and `accept_client_hello` does
structure and identity. So `create_server_hello` returns
`HANDSHAKE_ERR_KEX` — terminal, nothing written to the output buffer,
nothing inserted into the ledger.

It runs **before** `sig_B`, which is a deliberate ordering choice: a peer
that sends a malformed key should not be able to make the responder spend
an ML-DSA signature (~65 µs) first. `HANDSHAKE_ERR_KEX` now covers both
halves of the hybrid, and its comment says so rather than leaving "X25519
failure" to be read as exhaustive.

The responder does **not** keep a copy of `ek`. It re-decodes
`ctx->ch_bytes` — the exact bytes it accepted — at the moment it
encapsulates. That avoids 1 184 bytes in every responder context, and it
keeps the "use the exact wire bytes, never a re-serialized struct" rule
that the transcript code already follows.

### Where the initiator decapsulates, and why not earlier

At `finish`, as the spec requires. The context therefore holds the received
`mlkem_ct` (public, 1 088 bytes) from `verify_server_hello` until then.

There is no decapsulation "probe" mirroring the X25519 low-order probe,
because there is nothing to probe for: decapsulation cannot fail on a
tampered ciphertext (Security Req 4.11) — it succeeds and returns a
different secret. A probe would prove only that the local `dk` is intact.
A nonzero return from `mlkem_decaps` at `finish` therefore means a missing
or corrupted decapsulation key, which is a local defect, and is reported as
`HANDSHAKE_ERR_INTERNAL` rather than `KEX`.

### A retryable failure must KEEP ss_kem

`verify_client_auth` has three retryable outcomes — malformed, wrong
`handshake_id`, and a `sig_A` failure below the limit — after which the
handshake is still live and the ledger entry still ACTIVE. Wiping `ss_kem`
there would make the *next* ClientAuth fail with no way to recover, because
the secret exists only from the encapsulation that produced the ciphertext
already sent. So the retryable paths deliberately leave it alone, and only
the terminal paths (through `fail_ctx`) and the success path wipe it. This
is the one place where "wipe secrets as early as possible" is wrong, so it
is stated in `handshake.h`, asserted in H6, and mutated by N8.

One consequence worth recording: `TH_client_auth` is now a KDF input as
well as the signed message, so its `sodium_memzero` moved from immediately
after `sig_A` verification to after key derivation. A mutation that leaves
the old wipe in place (N2) derives from a zeroed digest — and because only
the responder does that, the two sides disagree and T1 catches it.

### Manual-peer oracles: why real-vs-real proves nothing here

A combiner bug — dropping `ss_k`, swapping the two secrets, omitting the
transcript digest — is **symmetric**. Both peers compute the same wrong key
and every interop assertion in the suite still passes. The v1 tests, which
run a real initiator against a real responder, are structurally blind to
it.

H1 and H2 fix that by playing one side **by hand**: the test generates the
keypairs, encapsulates or decapsulates itself, and therefore *holds* the
KEM secret. It then predicts the traffic keys with `expected_keys()`, built
from the literal spec-v2 §6.3.7 layout over `kex_hkdf_sha256` —
independent of `kex_derive_session_key_v2` and of `handshake.c` — and
requires the real side's keys to equal them byte for byte. N1 (both secrets
= `ss_x`) and N6 (decapsulation ignored) are killed by these and by nothing
else in the suite.

### The tampered-ciphertext test is white-box, deliberately

Spec-v2 §6.3 promises that a tampered `ct` "surfaces as the initiator's
first record failing to authenticate". Asserting that end-to-end is
awkward, because `ct` is *signed*: altering it on the wire produces
`HANDSHAKE_ERR_SIGNATURE` long before any key exists (H4 proves exactly
that). The only way to reach implicit rejection with two genuine contexts
is to alter the ciphertext the initiator has **already accepted**, so
`test_session.c`'s S27 flips one byte of `h.ini.peer_mlkem_ct` — a public
field — and then runs both sides normally. Both reach ESTABLISHED, the keys
differ, and the first record fails `SESSION_ERR_AUTH` in each direction, so
the initiator is never confirmed. The test says in its own comment that it
reaches into the context and why; the precedent is the existing tests that
read `eph.private_key` and `keys_committed`.

H3 covers the same property black-box, from the other side: the *test*
plays the responder, tampers with the ciphertext **before** signing, and
checks the initiator's key matches neither the encapsulator's key nor the
all-zero-`ss_k` key — the second half of which is what proves decapsulation
actually ran.

### The fuzz harness models FIPS 203's modulus check itself

`fuzz_handshake` S0 now drives `create_server_hello` and predicts its
result from an *independent* implementation of FIPS 203 §7.2: every 12-bit
coefficient of the encapsulation key's first 1 152 bytes must be < 3329.
Neither liboqs nor this project's wrapper is taken on trust — a
disagreement aborts. Seeds pin the boundary at 3328 (must pass) and 3329
(must fail), plus an all-`0xFF` key. Every scenario also asserts the wipe
rule, including the retryable exception above.

### Mutations

Run against the **fresh ASan tree**, because several of these are
wipe/leak-class defects a plain build cannot see (the V2-4 standing rule).

| # | Defect | Killed by |
|---|---|---|
| N1 | both KDF secrets = `ss_x` (symmetric: T1 still passes) | H1, H2 |
| N2 | responder derives with the digest already zeroed | T1, H2 |
| N3 | `fail_ctx` does not free `ss_kem` | H5, H6 |
| N4 | `finish` does not free `dk` | T21, H1 |
| N5 | encapsulation status ignored | H5 |
| N6 | decapsulation ignored (`ss_k` left zero) | T1, H1 |
| N7 | keys committed before `consume_success` | **survived — equivalent mutant, see below** |
| N8 | `ss_kem` freed on a retryable `sig_A` failure | H6 |

Seven of eight were killed. **N7 survived, and the reason is worth
recording rather than papering over.** It swaps the commit of the traffic
keys with `consume_success`, which is exactly the ordering the code
documents as load-bearing. But the only way out of that function after the
commit point is `goto fail_no_cancel` → `fail_ctx()`, and `fail_ctx()`
wipes `session_keys` and clears `keys_committed`. So the reordered version
produces **no difference observable through the public API**: T22 still sees
no key, the same status, the same ledger state. It is an equivalent mutant,
not a hole in the suite — no test can distinguish it without a white-box
hook into the middle of a single call, and adding one would test the
implementation's internal sequencing rather than any property of the
protocol.

The ordering stays as written. What N7 actually demonstrates is that the
commit ordering is **defence in depth**: correctness here does not *depend*
on it, because `fail_ctx()` is a reliable backstop on every post-commit
failure path. That is a stronger position than the ordering alone, and it
is now known rather than assumed. (Same shape as V2-4's M6, where a
mutation survived the plain suite and ASan caught it — here nothing catches
it, because there is nothing to catch.)

## V2-6 — record padding

Records now carry a padded inner plaintext (`content_len(2, BE) || content ||
0x00…` rounded up to a sender-chosen bucket), the receiver enforces the three
rules of spec-v2 §6.4.1, and `mldsa-auth/v2/record` replaces the last `/v1/`
label in `src/`. With this step the v2 protocol is complete; V2-7 is
integration and measurement.

### The empty record stopped being 25 bytes, and that reached into `apps/`

This is the part of the change that is not in `session.c`. With padding the
smallest record is **27** bytes (a 2-byte inner) and the default-bucket
confirmation is **281**, so four files outside the session layer became wrong
the moment `session.c` changed: `apps/frame.h`'s `FRAME_CONFIRM_LEN` and
`FRAME_MIN_RECORD`, `apps/frame.c`'s assert on them, `apps/demo_app.{h,c}`'s
message bound and confirmation receive, `tests/test_net.c`'s `CONFIRM_FRAME`
and raw-initiator receive, and `tests/fuzz/fuzz_frame.c`'s state-3 bounds.

`FRAME_CONFIRM_LEN` became a **range**, `FRAME_CONFIRM_MIN`/`FRAME_CONFIRM_MAX`
(27..4121): the client cannot know the responder's bucket, exactly as
spec-v2 §6.5.1 says. The check that the confirmation is *empty* did not
weaken — it was already on the decrypted content (`pt_len != 0 →
APP_PROTOCOL`), which is where padding cannot confuse it.

One consequence was not anticipated in the plan and is worth recording:
`session_open` decrypts the **inner** into the caller's buffer before it can
parse it, so a confirmation buffer must be sized for the largest padded
inner, not for the (empty) content. Two `uint8_t pt[1]` buffers in
`test_net.c` were exactly that mistake, and all three of its failures traced
to it.

### `pad_bucket` is validated, not defaulted

It joins `session_limits_t` and must be exactly one of
`{1, 16, 64, 256, 1024, 4096}`. **Zero is rejected**, not silently read as
"use the default" — the same fail-closed rule the other limits follow, and it
means a caller that zero-initializes a `session_limits_t` and forgets the
bucket gets an error instead of a surprise policy. S13 covers all six valid
values and six invalid ones (0, 2, 32, 255, 8192, 65536).

### The inner is built and encrypted in place, on evidence

`session_seal` assembles the inner directly in the caller's output buffer at
`out + 9` and encrypts it from there — no scratch buffer, so the
zero-allocation gates hold unchanged. That is sound because libsodium's IETF
ChaCha20-Poly1305 encrypts with
`crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, npub, 1U, k)`, a same-index
keystream XOR, and writes the tag only afterwards; decryption verifies the
tag over `c` **before** `crypto_stream_chacha20_ietf_xor_ic(m, c, …)` writes
`m`. Both directions are therefore safe with `c == m`. This was read out of
the vendored source rather than assumed from the API contract, which says
nothing about overlap.

`session_open` decrypts the inner into `pt_out`, validates it, `memmove`s the
content to offset 0 and **wipes the tail** — otherwise the length prefix and
the padding would stay in the caller's buffer, which is both a hygiene defect
and a way for an application to read bytes it did not send.

### The state check moved ahead of the capacity check

Required capacity now depends on the pad bucket, and a non-ACTIVE session has
no meaningful one (an EMPTY session's limits are all zero). Checking capacity
first made `session_seal` on a dead session report `INVALID_ARG` instead of
`UNEXPECTED_STATE`, which is the wrong answer and broke nine `check_dead`
assertions. State is now checked first; capacity and overlap still come
before the expiry check and the sequence reservation, so API misuse still
terminates nothing and consumes no `seq`.

A related test-only correction: `session_limits_t` now has trailing padding
after its `uint32_t`, so S17's `memcmp` against the defaults was comparing
uninitialized padding bytes. It compares field by field.

### Fuzzing the receiver's rules required sealing inners

The padding rules sit **behind** the AEAD: a random record fails
authentication long before its inner is parsed, so no amount of fuzzing raw
records reaches them. `fuzz_session` gained an **inner mode** (selector bit
5) in which the chunk *is* the inner plaintext and the harness seals it
itself — with its own literal `/v2/record` label, nonce and AD — under the
receiver's key at the expected sequence number. Every input is then authentic
by construction and the oracle predicts from the inner bytes alone.

Writing that oracle produced one honest correction: the first version
asserted that *every* `MALFORMED` zeroes the caller's buffer. That is false
for a record rejected on **length or type**, which never touches the buffer
at all. The assertion now applies to failures that happen after decryption —
`AUTH` and the two inner-format rejections.

### AEAD limit review (the review v1 deferred to this step)

v1 required the rekey and expiry limits to be revisited if the maximum
plaintext, the AEAD, the transport or the rekey policy changed. **v2 changes
none of them.** The AEAD plaintext bound is still 65 536 bytes — padding
moved the *content* bound to 65 534, not the record bound; the AEAD is
unchanged; the transport is unchanged; rekeying is still a full handshake
(now including a fresh ML-KEM keypair). **The v1 limits therefore carry over
unchanged**: 2³²/2³³ records per direction and 3 600 000/3 900 000 ms.

Padding does raise the *average* bytes per record, which moves the
aggregate-data figure toward the bound for small messages. At the hard limit
one key still protects at most 2³³ records of at most 2¹⁶ bytes — 2⁴⁹ bytes
per direction — and forgery exposure is still capped at one failed
verification per key by the terminal-failure policy. The headroom is large
enough that no change is warranted. This paragraph is the record of that
decision.

### Mutations

Run against the fresh ASan tree (Q2 and Q7 are memory-hygiene class).

| # | Defect | Killed by |
|---|---|---|
| Q1 | receiver skips the zero-padding check | P4(b), P4(c) |
| Q2 | receiver skips the `content_len` bound | **ASan abort** in P4(a) — see below |
| Q3 | receiver requires the inner to match its own bucket | P3 (3 checks) |
| Q4 | `content_len` written little-endian | S1, S2(a) (8 checks) — not P1, see below |
| Q5 | seal leaves the padding region unwritten | **compile failure** — see below |
| Q6 | minimum record left at 25 | P4(f), S9 (3 checks) |
| Q7 | open does not wipe the tail after the move | P5 |
| Q8 | `limits_valid` accepts any bucket | S13 (3 checks) |
| Q9 | label left at `/v1/record` | S2(a) and 8 others (literal `'v','2'`) |

All nine were killed, but **three died differently than predicted**, and the
differences are the interesting part.

**Q2 is caught as a memory fault, not a failed assertion.** Dropping the
`content_len` bound leaves `pad_len = body - 2 - content_len` to underflow —
these are `size_t` — so the padding scan is handed a length near `SIZE_MAX`.
ASan reports `BUS ... in sodium_is_zero` from `session_open`, called from
P4(a), and the process dies before printing anything. The test does reach the
defect; there is simply no FAIL line to match. This is exactly the
memory-hygiene class the plan predicted for Q2, and it is why the campaign
runs against the sanitizer tree. It also shows the bound check is not
redundant with the padding check: without it there is no length to scan.

**Q4 never reaches P1.** A little-endian `content_len` breaks the ordinary
round trip first: S1 fails at every payload size, S2(a) fails, and then
S2(c)'s fixture calls `fatal()` and exits — so the P-series never runs. Eight
named checks fail before that point, which is a kill; the prediction that P1
would be the one to catch it was simply wrong about ordering.

**Q5 does not compile.** Removing the `memset` that writes the padding leaves
`used` unused, and the project builds with `-Wall -Wextra -Werror`. The
runner's V2-4 hardening credits that as `KILLED(compile)` automatically —
the strongest outcome, and the first time that path has fired for a
non-assert mutation.

## V2-7 — integration and measurement

Nothing in this step changes a byte on the wire: `src/protocol/session.c` is
byte-identical throughout, and the two zero-allocation gates are quoted in the
exit report to prove that rather than assert it. What changes is everything
around the protocol — the pad bucket becomes a configurable policy instead of
a hardcoded default, the demo exercises a padded path over real sockets, the
fuzz dictionaries stop naming v1 sizes, `bench/results.md` is re-measured on
v2, and the README stops describing confidentiality as classical. The step
also carries the directed `pt_cap` deliverable.

### `--pad-bucket` belongs on both binaries, not only the client

The roadmap said `auth_client --pad-bucket`. That would have left the
interesting path untested: the **confirmation record is the server's**, and
its size is exactly what exercises V2-6's new `FRAME_CONFIRM_MIN..MAX`
receive range. A client-only flag can never produce a 4121-byte confirmation,
so the range would have stayed a compile-time constant nothing on the wire
ever reached. Both binaries take the flag; each controls only what that peer
sends; nothing is negotiated, and the demo's second end-to-end run uses
*asymmetric* buckets (server 4096, client 1) precisely so the
receiver-knows-nothing-about-the-sender's-bucket property is what is being
tested.

### `demo_config_t.pad_bucket == 0` means "use the library default"

Every caller of `demo_config_t` `memset`s it to zero — `make_cfg()` in
`test_net.c`, `cmd_connect`, `cmd_serve` — so a zero field must not become an
invalid-limits error. `demo_app.c` translates instead: `limits_for()` returns
`NULL` when the bucket is 0 (library defaults), and a `session_limits_t` built
from `session_default_limits()` with that bucket otherwise.

This is a **demo-layer convention and nothing more**. It does not weaken
`session.h`, where V2-6 decided 0 is an invalid bucket and `limits_valid()`
still rejects it; the demo layer never passes 0 down. `config_valid()` rejects
a *nonzero* bucket that is not one of the six, so a value like 32 fails at
configuration rather than at `session_init_from_handshake`. Two mutations
(R2, R3) exist because both halves of that translation are silent when wrong:
passing a literal 0 down breaks every default connection, and accepting any
nonzero bucket moves a CLI error into the session layer.

### Dictionaries carry sizes, not labels

The roadmap sketch said the dictionaries "get v2 labels". Following that would
have been cargo cult. **No fuzzed input contains a domain-separation label**:
labels live in the AEAD associated data and in the transcript hashes, neither
of which is attacker-supplied, so a `"mldsa-auth/v2/record"` token could never
help libFuzzer construct a more interesting input — it would only add a string
that never appears in any byte the target reads.

What the dictionaries actually carry is **lengths**, and those were stale v1
values: `len_146`, `len_3457`, `len_25`, `chunk_ch_87`, `chunk_sh_3396`. Those
are now the v2 message maxima (1330/1331, 4545/4546), the v2 record bounds
(26/27, 281, 4121/4122) and the v2 transcript chunk sizes (1271, 4484), plus
`eklen_1184`/`ctlen_1088` for the ML-KEM fields and four big-endian
`content_len` tokens (`0000`, `0001`, `003e`, `fffe`) that V2-6's inner mode
made fuzzable input for the first time. `keys.dict` is untouched.

The dictionaries get **no mutation campaign**, and the reason is worth
stating: a dictionary has no oracle. Removing a token does not make any test
fail — it makes coverage arrive more slowly, which no assertion can observe.
Claiming a kill there would be theatre.

### The one way to size `pt_cap` wrong

Directed deliverable, approved 2026-09-13. `session_open`'s contract now
states the rule in `session.h`, with `SESSION_OPEN_CAP_FOR(max_record_len)`
as the arithmetic and both standard values spelled out — 65536 for the
session phase, 4096 for the confirmation phase.

The rule is: **size `pt_cap` from the largest record you are willing to
accept, never from the content length you expect.** The sender picks the pad
bucket; the receiver neither controls nor learns it in advance, so an "empty"
message is not a small record — at bucket 4096 it is 4121 bytes on the wire.

The contract comment cites the real mistake rather than a hypothetical one:
in V2-6 `tests/test_net.c` opened the empty confirmation record into
`uint8_t pt[1]`, which was correct under v1's fixed 25-byte confirmation and
became an `INVALID_ARG` the moment records could be padded. All three of that
file's failures traced to those two buffers. `test_net.c` now sizes them
`SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX)`, so the file that made the mistake
demonstrates the rule, and `test_session.c`'s P7 makes it executable: the same
record opens under a rule-sized cap and fails `INVALID_ARG` — non-terminally,
with the session still ACTIVE and no sequence number consumed — under a
content-sized one.

### The v1 column is recorded history, not a measurement

`bench/results.md`'s v1 → v2 table is the one place in this project where a
number is reported that **cannot be reproduced from this tree**: V2-4 and
V2-5 deleted v1's key schedule, wire format and handshake from `main`, so
there is no v1 to run. The v1 column is therefore the recorded V2-2 figures —
same machine, same liboqs configuration, same method, measured 2026-09-12 —
and the table says so above the table, not in a footnote someone can miss.
Every v2 figure in that section is the median of three run medians from
`build-bench/bench-results/run-{1,2,3}.csv` of the run performed during this
step, and the section names those files, because the failure mode of a step
whose deliverable is numbers in a document is a stale or mis-transcribed
figure that no test catches.

### What padding costs, stated plainly

Measured, both buckets, same payloads: a 64-byte seal+open round trip costs
605 ns unpadded and 1.29 µs at the default bucket 256 — **2.1×** — while at
64 KiB the two columns agree within noise, because the content already fills
the inner and there is nothing to pad. `session_open` pays more than
`session_seal` (+505 ns against +179 ns) because it additionally scans the
padding for nonzero bytes and wipes the tail.

That is the trade the bucket exists to let an integrator make, and it is
recorded here so the default is a choice rather than an accident: ~500 ns per
small record against an observer learning message length only to within 256
bytes. An application dominated by small records should measure bucket 1
before accepting the default.

### A dry run outside the runner destroyed work, and the rule that forbids it

Recorded because the standing rule it violates already existed, and because
the exit report would otherwise be the only place this appears.

Before launching the R1-R6 campaign I checked that each mutation's
search string still matched, by applying it and then reverting with
`git checkout -- apps/demo_app.c src/protocol/session.h tests/test_net.c`.
Those three files held **uncommitted V2-7 work**, so the revert discarded it:
`SESSION_OPEN_CAP_FOR` and the `pt_cap` contract block, the `--pad-bucket`
wiring in `demo_app.c`, and T17 in `test_net.c`. All three were reconstructed
by hand and re-verified (full suite green, T17's eight checks passing), and
every gate that had already run against the lost text was re-run against the
reconstructed text rather than carried over — a build whose sources no longer
exist proves nothing about the sources that do.

The V2-4 standing rule says it plainly: **no temporary source edit is made
outside the runner.** The runner snapshots every source file before it
touches one, restores byte-exactly, verifies the restore with `cmp`, and
rebuilds — precisely so an edit cannot outlive its purpose. A "quick check"
that bypasses it gives up all of that. The dry run was not necessary either:
the runner's own `mutate.py` contract already fails loudly when a search
string does not match exactly once, so the campaign itself is the check.

The follow-on rule, now used for the rest of this step: when a scratch copy
of a working file is needed, it goes to the scratch directory and comes back
with `cp`. `git checkout --` is never a restore mechanism for a dirty tree,
because git cannot restore what it has never been told about.

### Mutations

Run through `tools/run_mutations_v2.sh` against the fresh ASan tree
(`build-asan`, `tools/check_sanitizer_link.sh` passing), each killed by a
named check:

| # | Defect | Killed by |
|---|---|---|
| R1 | `limits_for()` ignores `cfg->pad_bucket` and always passes NULL | T17 (2 checks: the 4121-byte confirmation, the bucket-1 byte count) |
| R2 | the 0-means-default translation removed, so a literal 0 reaches `session_init_from_handshake` | T1 and 19 more (20) — every default connection |
| R3 | `config_valid()` degraded to a range check, admitting 32 | T17's invalid-bucket check |
| R4 | `SESSION_OPEN_CAP_FOR` subtracts `SESSION_HEADER_BYTES`, not the overhead | P7 (2 checks) |
| R5 | the client's confirmation reader keeps a single-size expectation (`FRAME_CONFIRM_MIN` as its maximum) | T17 and 14 more (15) |
| R6 | `test_net`'s confirmation buffer sized from the content again — the V2-6 regression | T8(a) and 2 more (3) |

Two things are worth recording beyond the verdicts.

**R2 and R5 are loud, and that is the point.** Twenty and fifteen named
checks respectively — because both defects break *every* connection, not
only the padded ones. A wiring bug in the demo layer cannot hide in a corner
of the test matrix; it takes the happy path down with it. R1, R3, R4 and R6
are the narrow ones, and each is caught by the check written for it.

**R3 needed a second run, for a reason that belongs in the runner's
history.** Its expected-failure string began with `--pad-bucket`, and the
runner passes those strings to `grep -qF "$w"` without a `--` guard, so grep
read it as an option and errored. The first campaign therefore printed
`SURVIVED(BAD)` while `R3.test` contained exactly the FAIL line the spec
asked for. Requeued with the leading dashes trimmed, it reported
`KILLED(1 named)`. The harness was wrong, not the mutation — but the
distinction is only visible because the runner keeps every per-mutation log,
so the verdict could be checked against the evidence instead of being
believed.

## V2-8 — fuzz-scanner precision

The repository admission gate refused files it had no reason to refuse. A
minimized *public-mode* `fuzz_keys` artifact — a file whose entire content is
public data — could not be committed as a regression, because the scanner's
16-byte window rule matched the fixture public key. Measured before this
step: the nine generated public-mode seeds produced **153 violations**, 17
each. Measured after, with every secret-key rule unchanged: **0**.

### What is actually secret in an ML-DSA-65 secret key

The layout comes from the code that packs it — liboqs's mldsa-native
`mld_pack_sk_rho_key_tr_s2()` / `mld_unpack_sk()` and `params.h` — not from a
reading of FIPS 204:

| region | offsets | secret? | why |
|---|---|---|---|
| `rho` | [0, 32) | **no** | it *is* `pk[0..32)` |
| `K` | [32, 64) | yes | the signing seed |
| `tr` | [64, 128) | **no** | `SHAKE256(pk, 64)` (`sign.c:371`) |
| `s1` | [128, 768) | yes | 5 x 128 |
| `s2` | [768, 1536) | yes | 6 x 128 |
| `t0` | [1536, 4032) | yes | 6 x 416 |

Two regions totalling 96 bytes are recoverable by anyone holding the public
key. Everything else is key material.

### The kept set is "holds a secret byte", not "lies in a secret region"

A window is excluded only when it lies **entirely** inside `rho` or entirely
inside `tr`: 17 windows at offsets 0..16, and 49 at 64..112. That leaves
4017 - 66 = **3951** of the original 4017.

The alternative reading — keep only windows fully inside a secret region —
would have kept 3906 and dropped the 45 that straddle a boundary. Those 45
each contain secret bytes (the window at offset 17 is `rho[17..32) || K[0]`),
so dropping them would have weakened the gate to no purpose. They also cannot
produce a public-key false positive: in the public key the byte following
`rho` is `t1[0]`, not `K[0]`, so a match would require the two to coincide.
The result is zero public-key false positives *and* full coverage of every
secret byte — the choice was not a trade-off once the question was asked
precisely.

### The exclusions are proven at run time, and failure stops the gate

Before any exclusion is applied, the scanner checks two identities against
the regenerated fixture: `sk[0..32) == pk[0..32)`, and
`SHAKE256(pk, 64) == sk[64..128)`. If either fails it prints `SCANNER ABORT`
and refuses to scan — it does not fall back to the old, wider rule, and it
does not proceed with a narrower one.

That direction is deliberate. The exclusions are only sound while the packing
is what this code believes it is; a liboqs that repacked the secret key would
make "offsets 0..32 are public" a false statement about real key bytes. A
gate that quietly kept running would be worse than one that goes red, because
its silence is exactly what everyone relies on. The check costs one SHAKE256
per scan.

`OQS_SHA3_shake256` is declared in `<oqs/sha3.h>` — `<oqs/oqs.h>` includes
only `sha3_ops.h`, which names the function in a comment but does not declare
it, so the first build failed with an implicit-declaration error. It needs no
`OQS_init()`: the SHA3 callbacks are statically initialised
(`sha3.c:9`), and `OQS_init()` is a no-op unless `OQS_DIST_BUILD` is set,
which V2-2 turned off.

### The scanner proves its own rules before it admits anything

Sixteen controls (C1-C7) run inside the existing `fuzz_no_committed_secrets`
gate, on in-memory buffers, before a single file is read; any failure refuses
the whole scan. This is the `session_no_alloc_scan` pattern: a checker whose
negative controls are part of the check, so it cannot pass by doing nothing.

C1 and C2 are the load-bearing ones — a real `MLDSASK2` file and a legacy
`MLDSASK1` file must still be caught by **both** rules, with exactly 3951
window hits. That literal is what makes an off-by-one at either boundary die:
3950 or 3952 fails the control. C5 then names *which* boundary, by scanning
the single window either side of each. C3 is the step's purpose, executable:
the three public-key seed files, clean. C6 keeps one window from each of `K`,
`s1` and `t0` under test, so a future "optimisation" that narrowed the kept
set further would fail immediately.

No new CTest was added; the suite stays at 15. The controls run in every
configuration the gate runs in, which includes both sanitizer builds.

### Why the gate's own output changed shape

The summary line now reads `N file(s) scanned, V violation(s) (L layout,
W window), T token-only file(s)`. The two rules have different meanings — one
says "this is a key file", the other "this contains key bytes" — and a report
that sums them cannot distinguish a scanner that lost a rule from one that
found nothing. Every control asserts the two counts separately for the same
reason.

### Mutations

Ten mutations through `tools/run_mutations_v2.sh` against the fresh ASan
tree, test `fuzz_no_committed_secrets`. All killed; every restore verified
clean with a passing suite and zero residue.

| # | Defect | Killed by |
|---|---|---|
| X1 | the exclusion is disabled: every window kept | the in-loop bound assert (abort) — see below |
| X2 | the layout rule never fires | C1, C2 |
| X3 | the window rule never fires (empty table) | C1, C6.1 and 5 more (7) |
| X4 | `rho` exclusion off by one, arithmetic unchanged | the kept-window count assert (abort) |
| X5 | `tr` exclusion off by one, arithmetic unchanged | the kept-window count assert (abort) |
| X6 | the derivability proof compares `tr` at the wrong offset | `SCANNER ABORT`, before any control runs |
| X7 | test-side: C3 expects the pre-V2-8 count of 17 | C3.1 and 2 more (3) |
| X8 | exclusion disabled **and** the arithmetic updated to match | C1, C3.1-C3.3 and 6 more (10) |
| X9 | `rho` boundary slips **and** the arithmetic is corrected to match | **C5.2 alone** |
| X10 | `tr` boundary slips **and** the arithmetic is corrected to match | **C5.4 alone** |

**X1 found a real sharp edge, and the fix is in this commit.** Disabling the
exclusion makes the fill loop produce 4017 windows for a table sized 3951,
and the equality assertion that was supposed to catch a miscount ran *after*
the loop — so the first campaign reported an ASan heap-buffer-overflow at the
table write rather than a named failure. The table is sized from a
compile-time constant and the predicate is a pure function of the offsets, so
correct code never reaches it; but a checker whose failure mode is heap
corruption is the wrong failure mode for a checker. The loop now bound-checks
*before* each write (`w < SCAN_KEPT_WINDOWS`), and the after-loop equality
assert catches the other direction. The mutation was retained exactly as
written, and now dies by name.

**X1, X4 and X5 die before the controls, which is why X8, X9 and X10 exist.**
Each of the first three changes how many windows are kept, so a count
assertion fires before a single control runs — a kill, but one that proves
the *arithmetic* is guarded, not that the controls work. X8, X9 and X10 make
the same three defects while updating the constants to agree, so execution
reaches the controls. X9 and X10 are then killed by **one control each**,
C5.2 and C5.4 — the single window either side of the boundary. That is the
whole case for writing C5: with the arithmetic self-consistent, nothing else
in the suite can tell a 32-byte exclusion from a 33-byte one.

**X6 never reaches the controls either, by design.** A broken derivability
proof must stop the gate before it decides anything, so its expected failure
text is empty ("must fail somehow") and the evidence is the `SCANNER ABORT`
line in its log.

## V2-9 — legacy key migration

Step 7.1 refused to migrate `MLDSASK1` files, on the grounds that migration
means trusting a file with no integrity digest. That reasoning is intact, and
the loaders still refuse legacy files. What it omitted is the one case where
"just regenerate it" has a real cost: **an identity whose public key peers
have already pinned.** Regenerating means redistributing pins out of band —
the one operation this trust model makes expensive. `migrate-key` preserves
the identity, and makes the thing Step 7.1 was protecting against explicit
instead of silent.

### The command states what it cannot do, every time

A legacy file offers exactly one integrity signal: the sign/verify self-test.
Step 7 measured that test **accepting a key with a corrupted `t0` component
in 11 of 20 cases** — the finding that motivated the digest in the first
place. So the migration prints, on stderr, on every success:

> the digest in the new file certifies these key bytes **as they are now**,
> not as keygen originally wrote them

with the 11-of-20 figure and the advice to regenerate and re-pin if the
identity matters. This is the honest framing: migration converts a *format*,
it does not recover *provenance*.

That is asserted, not merely claimed. T14.2 writes the recorded `t0`
corruption into five freshly generated legacy files and requires every
outcome to be either `KEY_MISMATCH` with no output, or a migrated file
carrying a **correct, independently recomputed digest** over the corrupted
bytes.

**Writing that check found something the plan had wrong.** The first version
required each migrated file to *load* afterwards, and it failed: ML-DSA
signing is randomized, so the sign/verify self-test is **probabilistic** —
the same corrupted key can pass it during migration and fail it moments later
in the loader. (That is also why Step 7's figure was 11 of 20 rather than
all-or-nothing.) Three consecutive runs of the corrected check measured 1/5,
0/5 and 2/5 refused at migration, and of those migrated, 2 of 4, 4 of 5 and
2 of 3 re-loaded — all passing.

So the guarantee migration can offer is narrower than "the migrated file
works", and the check now states the narrow one: the output is a correct
`MLDSASK2` file **for the bytes it was given**, its load status is `OK` or
`KEY_MISMATCH` (never `INTEGRITY`, never `FORMAT`), and the counts are
printed rather than asserted. A migrated file that fails to load is not a
migration bug — it is the self-test doing its job on the second roll.

### In-place migration is impossible by construction

The output goes through the same publish path as `keygen`: a temp file
created `O_EXCL` 0600, fsync'ed, then `link()`ed to its final name, which
fails with `EEXIST` rather than clobbering. Passing the same path for `--in`
and `--out` therefore fails with `EXISTS` — not because a check forbids it,
but because the only way to create the output is one that cannot overwrite.
The input is opened read-only and is never modified or deleted; T14.2 hashes
it before and after the entire block and requires the digests to match, and
the CLI tells the user to delete it themselves once the new file is verified.

### `--id` is required

Every loader in this project checks the id inside a file against an id the
caller names. Migration must not be the one path that trusts a file's own
label — a mistyped `--in` should not silently produce a correctly-formatted
file for the wrong identity. The id is compared after the layout checks and
before the self-test, so the statuses mean the same thing they mean in
`demo_keys_load_identity`.

### A new status rather than an overloaded one

An `MLDSASK2` input is not a malformed file; it is a user pointing the
command at the wrong thing. `DEMO_KEYS_ERR_NOT_LEGACY` ("already MLDSASK2:
nothing to migrate") says which mistake was made. Overloading `FORMAT` would
have been cheaper and less useful.

### Loose permissions are refused, not laundered

`migrate-key` applies the loader's custody rules to its input: no symlink, a
regular file, owned by the caller, no group or other access. A migration that
accepted a world-readable secret and produced a tidy 0600 file would be
laundering, not converting.

### The fuzzer found the same thing, independently

The 600-second `fuzz_keys` run on the new mode **crashed** — on the harness's
own oracle, not on `demo_keys.c`. The migrate-mode assertion required a
migrated file to load, and a mutation program that flips one bit in the key
region produced a file that migration accepted and the loader then refused.

It is the same phenomenon T14.2 had already surfaced, reached from the other
direction and with a 12-byte input: the self-test is randomized, so "migration
succeeded" does not imply "the result loads". Two independent oracles, written
days apart in different styles, disagreed with the same wrong assumption — and
both were wrong in the same direction, which is the useful signal. The harness
now asserts what is actually guaranteed: the output carries the input's keys
under a correct digest (checked byte for byte, deterministic), and its load
status is `OK`, `KEY_MISMATCH` or `CRYPTO` — **never** `INTEGRITY` or
`FORMAT`, which would mean migration wrote a file disagreeing with its own
digest or layout. The artifact replays clean against the corrected oracle.

The artifact itself is *not* committed as a regression. The documented crash
workflow says to admit one, but `tests/fuzz/regressions/` is outside V2-9's
declared file scope, and quietly widening a scope to file a trophy is the
wrong trade. The property it found is pinned twice over without it — by
T14.2's deterministic digest check and by the migrate-mode seeds.

### The new parser is fuzzed

Every file parser in this project has a fuzz mode with an independent model,
and the legacy reader is not the first exception. `fuzz_keys` gains a migrate
mode on selector bit 3, reusing the identity-mode template and mutation
grammar unchanged: the same programs that fuzz the loader now also fuzz the
migration. Its model is written separately from `model_secret` (there is no
digest to predict), and every input additionally asserts that the source is
byte-identical afterwards and that an output exists **only** on success —
carrying the input's own keys under a digest the harness recomputes with its
own copy of the label.

### Mutations

Nine mutations through `tools/run_mutations_v2.sh` against the fresh ASan
tree; every restore verified clean with a passing suite and zero residue.

| # | Defect | Killed by |
|---|---|---|
| Y1 | migration ignores the self-test's verdict | T14.2 pk-flip and s1-flip (2) |
| Y2 | the migrated digest omits the id from its body | T14.2 digest-vs-independent and 3 more (4) |
| Y3 | an `MLDSASK2` input is treated as legacy | T14.2 NOT_LEGACY |
| Y4 | migration does not check the caller's `--id` | T14.2 ID_MISMATCH and 5 more (6) |
| Y5 | the output is written with `O_TRUNC` instead of `O_EXCL` + `link()` | T14.2 no-clobber and 5 more (6) |
| Y6 | the exact legacy-size check is dropped | T14.2 truncated/extended/id_len and 3 more (4) |
| Y7 | the CLI prints no integrity warning | `demo_e2e`'s stderr grep |
| Y8 | a failed `link()` leaves the 0600 temp file behind | see below |
| Y9 | test-side: the fuzz model predicts OK for a short legacy file | `fuzz_replay_keys` (abort) |

**Y8 survived the first campaign, and it was right to.** The temp file was
being unlinked in *two* places: inline on the success path, and in the
epilogue for failures. The test checks for leftovers after a **successful**
migration, so disabling the epilogue changed nothing it could see — and the
failure path that needs the epilogue (a `write_new_file` I/O error, or a
`link()` losing a race against a file appearing between the `lstat` and the
`link`) cannot be forced by a portable test.

Rather than write a test for an unreachable branch or wave the mutation
through as equivalent, the code now has **one** cleanup site: the epilogue
unlinks the temp file on every exit, success included. That is simpler — it
matches `demo_keys_generate_files`, which already cleans up its temporaries
unconditionally — and it means the line is exercised by every successful
migration in the suite, so Y8 is now killed by the check that was written for
it. A cleanup path only reachable by accident is a cleanup path nobody has
tested.

## V2-10 — build currency, final review, release

The last step. It exists because of something V2-9's tagging review turned
up: a build directory can be complete, correctly configured, genuinely
instrumented — and *stale*. `ctest` never compiles. The tool and the rule that
close that gap are recorded above under **Process hardening after V2-4**
(*A suite result is not trusted until the build is proven current*); this
section records what the release itself rests on.

### Build currency before V2-10 is unverifiable, and the release does not rest on it

For **V2-4, V2-5, V2-6 and V2-8** there is no way to establish, after the
fact, whether the suite results those steps quoted came from binaries built
from the sources they committed. The only evidence that could settle it is the
binaries themselves, and those build directories have been overwritten many
times since. No amount of reasoning about timestamps or commit order
substitutes for it: a stale tree and a current tree produce identical-looking
`ctest` output, which is the whole reason the currency rule now exists.

That gap is stated once, here, and not litigated further. **V2-7 and V2-9 are
excluded from it** — both had a forced full re-run recorded at the time, V2-7
after the file-loss incident and V2-9 after the fuzz-oracle correction, so
their quoted results are known to describe the sources they shipped.

What the release rests on instead is **V2-10's end-to-end re-run against the
release tree**: every suite, every mutation, every scan, each paired in the
same invocation with a currency proof. A release verified whole does not
inherit doubt from the order in which its parts were built.

### The retrospective run found a mutation that had been silently dead

Re-running all 56 mutations was justified on the argument that a stale
mutation is indistinguishable from a passing one. It was: **X3 no longer
applied.** Its anchor — the assertion message `"kept-window count disagrees
with the layout arithmetic"` — does not exist in the codebase. It was reworded
while fixing X1's table overrun *during V2-8*, and X3 was never re-run
afterwards, so V2-8's "X1–X10 all killed" carried an X3 verdict from code that
no longer existed by the time that step was committed. Re-targeted to the
current source, X3 is killed by scanner controls C1, C2 and C5.2 —
`KILLED(7 named)`.

The lesson is narrower than "mutations rot": a mutation's search string is
part of the test, and editing the code it targets silently disarms it. The
runner's exactly-once contract reports this loudly (`FATAL apply: expected
exactly 1 occurrence, found 0`) — but only when the campaign is actually
re-run.

**N7 survived, and should have.** V2-5 recorded it as an equivalent mutant;
it behaves the same way now. Consistency with a documented result, not a
regression.

### Provenance: dependencies came from a local cache, declared

The retrospective run happened while GitHub was unreachable, so every fresh
configure failed. Rather than wait, the run sourced liboqs and libsodium from
a **local, pin-verified cache**: liboqs at `5a1a854b0dc9…` (checked equal to
the pinned commit before use) and the libsodium tarball at
`adbdd8f16149…` (checked equal to `URL_HASH`). Both pins stayed enforced
end to end, though the liboqs pin was enforced through **one** of its two
points rather than both: `FETCHCONTENT_SOURCE_DIR_LIBOQS` bypasses the
population-time `PATCH_COMMAND` by CMake's design, while the configure-time
re-check ran on every tree and logged `liboqs commit verified` each time.

This is a real limitation of that run, not a footnote: it cannot show that a
clean checkout can still fetch and build from nothing. A complete
fresh-network configure was therefore run separately before the tag, and it
closed exactly that gap.

### The clean-checkout fetch, and the README pass (2026-09-14)

Once GitHub was reachable again, both outstanding items ran against the
release tree, in that order — the fetch first, because the driver rule is
never to delete a working tree before proving a fresh configure succeeds.

**A genuine fetch from nothing.** No `FETCHCONTENT_SOURCE_DIR`, no seeded
tarball, an empty directory: `cmake -S . -B <fresh>` fetched liboqs and
libsodium over the network, configured, built, and passed 15/15 with its
currency proven. The checkout landed on `5a1a854b0dc9…` — the pinned commit —
and this run exercised the **population-time `PATCH_COMMAND`** enforcement
point that the local-cache run had to bypass, so both of the pin's
enforcement points are now known to fire. Independently, `git ls-remote`
confirmed upstream tag `0.16.0` still resolves to that same commit, which is
the property the tag-plus-SHA design exists to detect if it ever changes.

**Gate 7, the README verbatim pass: all 18 blocks exit 0**, against fresh
build directories that fetched their own dependencies (`liboqs commit
verified` appears once per configured tree). That covers both `ctest` runs
(15/15 each), the 5-target smoke and 5-target 600-second local fuzz (10 runs,
**0 crashes, 0 artifacts**), a 3-repetition bench (0.445 / 0.455 / 0.449 ms
against the 15 ms target), both demo blocks, and the `migrate-key` block with
its integrity warning asserted by text.

With this, nothing in the release rests on the offline cache: every claim in
the V2-10 record has been reproduced from a clean checkout.

### The review pass: three of four analyses were invalid on the first attempt

Worth recording because each first attempt produced a *clean-looking* result
that would have been wrong to report.

- **clang-tidy** reported 31 `clang-diagnostic-error`s: the analysis tree had
  been configured but never built, so libsodium's headers did not exist yet,
  and Homebrew clang needed `-isysroot`. Fixed: 0 compile errors, 33 TUs.
- **scan-build** reported `0 bugs found` — vacuously. Passing
  `-DCMAKE_C_COMPILER` **overrode the analyzer's compiler interposition**, so
  all 41 project objects were compiled by the real clang and analysed by
  nothing. With the flag dropped, the cache shows `ccc-analyzer` and the
  objects are genuinely analysed.
- **`-Weverything`** collected almost nothing: the per-target `-Werror` is
  appended after `CMAKE_C_FLAGS`, so `-Wno-error` never applied and every
  translation unit aborted at the error limit. Driving clang per-TU from
  `compile_commands.json` with `-Werror` stripped covers all 33 units without
  editing the build files.

**No defects were found.** scan-build's single report (uninitialized `th` at
`test_handshake.c:1197`) is a cross-TU false positive: all five callers guard
`th` behind a successful `transcript_hash_client_auth`, which the analyzer
cannot see into. clang-tidy's correctness-flavoured hits are all deliberate
project idioms — the macro-vs-literal cross-checks (`T14_FILE(5)` *is* 6030,
confirmed numerically), the `/* secrets SWAPPED */` sensitivity case, and
`(v << 8) | in[i]`, which is `uint8_t` promoting to `int` and casting
straight back. `-Wswitch-default` is excluded on evidence rather than
convenience: `frame.c`'s switch handles every `net_status_t` enumerator, so
adding `default:` would disable `-Wswitch`'s protection against a future one.

## V3-1 — the verification gates run on Linux too

`src/` and `apps/` were already portable — no `__APPLE__`, no Mach headers.
The *harness* was not: all three `tools/` scripts and `add_regression.sh`
depended on `otool`, `shasum`, Mach-O detection and BSD `mktemp -t`. Since
V3's whole point is CI, and CI's value is a second platform, porting the
gates comes before writing any workflow: a CI job that cannot run the
standing rules is theatre.

Each script now detects the platform with `uname`, names the mechanism it
used in its own output, and keeps the shim duplicated rather than sourced —
`tools/` is deliberately not an installable unit.

### What the port found

Three defects surfaced that ten steps of macOS-only verification could not.

**libm.** `bench_common.c` calls `sqrt()`; macOS folds libm into libSystem,
Linux does not. One line in `bench/CMakeLists.txt`.

**LeakSanitizer.** LSan runs by default under ASan on Linux and **does not
exist on macOS**, so "fresh ASan, 0 reports" had never once exercised leak
detection. All five `fuzz_replay_*` tests leaked their seed/regression corpus.
Fixed in `da65211` with a single atexit teardown; nothing in `src/` or `apps/`
leaked.

**gcc `-Wformat-truncation`.** 17 temp-path `snprintf` calls that clang never
analysed made the tree unbuildable under gcc with the project's own `-Werror`.
Fixed in `b98bf8a` by checking the return values, not by suppressing the
warning. The project now builds clean under gcc 13 and clang 18 on Linux and
Apple clang 21 on macOS.

### And two defects in the gate itself

The W-series mutations were aimed at the shims and found real weaknesses in
`check_build_current.sh`:

- **W1**: the empty-set guard fired only when objects *and* executables were
  zero, so a broken `is_exe()` reported `41 object(s), 0 executable(s) … OK` —
  passing while checking nothing but objects. V2-10's N3 control only ever
  tested the both-zero case. Now **both** counts must be non-zero.
- **W4**: forcing the wrong platform branch left `textdump` silently empty, so
  every executable fingerprint compared equal and the gate passed vacuously.
  The text tool is now probed against a real binary before any comparison.

Both were found by mutating the tool rather than the code it checks, which is
the same discipline applied one level up.

### gcc compile-kill attribution, demonstrated

The runner credits `KILLED(compile)` only when the first compiler error names
a project source file with `line:col`. That regex was written against clang
and the claim that "gcc's format matches" was an assertion — untestable on the
dev machine, where `gcc` is an Apple clang alias. Under real GNU gcc 13.3.0,
with the compiler identity asserted first, both paths attribute correctly:

```
W5a  compile-fail  KILLED(compile)   /work/src/protocol/session.c:18:1: error: static assertion failed: "record AD label is 20 bytes"
W5b  compile-fail  KILLED(compile)   /work/src/protocol/session.c:253:9: error: unused variable 'w5b_unused_probe' [-Werror=unused-variable]
```

Both carry `path:line:col: error:`, so no regex widening was needed. Had they
not, the fix was specified in advance: make the column optional while still
requiring a project path, then re-verify on both compilers.

## V3-2 — a publishable environment block on Linux

`print_environment()` emitted the `os` line via `uname` but wrapped the `cpu`
line in `#if defined(__APPLE__)`. On Linux that did not fail to build — it
silently omitted CPU identification altogether, which is why V3-1 never saw
it. The consequence is a publishing defect rather than a build defect:
**"0.450 ms" with no chip named is not a result**, and V3-5 is about to
publish x86_64 numbers to close the spec §5.1 deviation carried since Step 8.

### Four facts, not one

The Linux branch reports the CPU model and online core count, and two things
macOS has no analogue for:

- **cpu scaling** — the cpufreq governor and `intel_pstate/no_turbo`. A
  `powersave` governor can halve throughput, so a Linux timing without it is
  uninterpretable.
- **virtualization** — the DMI vendor. CI runners are shared VMs; a reader
  must be able to tell that from bare metal before trusting a median.

Cores are a plain online count: macOS reports a performance/efficiency split
and Linux has no universal equivalent, so none is invented.

### Unknown values say why, and name their source

Anything unreadable prints `unknown (<why>)`, never nothing and never a
guess — an absent line cannot be told apart from a platform with nothing to
say, while an explicit unknown can be falsified. The reason names the field
and the file (`unknown (no model name in /proc/cpuinfo)`), so a reader can
check the claim rather than trust it.

That path is not hypothetical: **arm64 Linux has no `model name` field in
/proc/cpuinfo at all**, so the degraded branch is the one that runs on the
container this step was verified in. The x86_64 path that V3-5 will take
therefore stays unproven until it runs on a real x86_64 runner — stated here
as a known gap, with the oracle written so a wrong value there fails loudly.

### The oracle lives in bench_smoke

The environment block is the only part of a published measurement that is
prose rather than a number, so it had no oracle at all. `run_smoke.cmake`
already captured each binary's output, so the assertions went there rather
than into a new test, and the suite stays at 15: every required key present,
no empty values, no bare `unknown` without a reason, and on Linux the `cpu`
value must either contain the `model name` CMake reads independently from
/proc/cpuinfo or declare itself unknown.

### What the mutations found in the oracle

- **V1** exposed a **prefix collision**: the key regex allowed one space, so
  the line `cpu scaling ...` satisfied the requirement for `cpu` and a deleted
  `cpu` line passed unnoticed. Values are column-aligned, so requiring two
  spaces after the key disambiguates — a longer key sharing the prefix is
  followed by exactly one.
- **V2** twice returned a *void* verdict before a real one. Rebuilding only
  the changed `.o` left a stale `libmldsa_bench.a`, so the mutation never
  reached the binary; printing the binary's own `cpu` line proved it still
  showed the genuine value. The full forced build that
  `tools/run_mutations_v2.sh` performs — objects **and** archives **and**
  executables — is not belt-and-braces; a partial one silently reports
  survivals that never happened.

V1, V2, V3 and V5 are all killed by the oracle; V4 (altering the macOS
wording) is killed by the byte-identical diff of the macOS block, which is the
regression guard for every figure already published in `bench/results.md`.

## V3-3 — every gate on every push, Linux and macOS

Until this step every gate in the project's history had been run by hand, by
one agent, on one arm64 laptop. `.github/workflows/ci.yml` now runs the full
per-push set on every push to `main` and on every pull request: eight jobs —
`ubuntu-latest` × clang × {debug, asan, ubsan}, `ubuntu-latest` × gcc × debug,
`macos-latest` × clang × {debug, asan, ubsan}, and a Linux-only job for the
fuzz smoke run and the repository secret scan.

### Bring-up happened on a branch, and the branch found six things

A workflow file cannot be verified locally; GitHub running it is the first
honest test. So it was developed on a throwaway `ci-bringup` branch and merged
only after going green there — six iterations, then four negative controls.
The first run was 3 pass / 5 fail, and every failure was a real finding:

1. **The V3-2 oracle compared a regex against itself.** `run_smoke.cmake`
   checked the `cpu` line against `/proc/cpuinfo` with `MATCHES`. The string
   `Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz` does not match itself as a
   pattern (`(R)` is a capture group), so the check passed on the two AMD
   runners and failed on the Intel one: **its verdict was decided by which
   machine GitHub handed out.** It is now literal `string(FIND)`. Proven with
   the exact string rather than by waiting for another Intel runner: in the
   Linux container with `/proc/cpuinfo` bind-mounted to that model name, the
   real line passes and V3-2's mutation V2 (a constant cpu string) still fails.
2. **`qsort(NULL, 0, …)`** in `tests/fuzz/fuzz_replay_main.c` when the
   regressions directory is empty. glibc declares `qsort __nonnull((1, 4))`;
   macOS headers do not, so only Linux UBSan diagnoses it. Four targets failed
   at once. Guarded with `if (n > 0)`.
3. **The macOS runner cannot compile liboqs with the project's default
   target.** `MLDSA_OQS_OPT_TARGET=auto` is `-mcpu=native`; on `macos-26-arm64`
   that enables **no** ARM crypto extensions (the record-runner step probes it:
   `__ARM_FEATURE_{AES,CRYPTO,SHA2}` are all defined on the M4 Pro, none on the
   runner), so `sha2_armv8.c` fails with *always_inline function
   'vsha256hq_u32' requires target feature 'sha2'*. The macOS jobs pin
   `generic` (`-march=armv8-a+crypto`, the documented portable target, which
   still selects the AARCH64 backends). Stated plainly: **the macOS ticks
   verify the portable target; only the development machine verifies
   `auto`.** Linux keeps `auto`.
4. **Caching a `-march=native` build across a heterogeneous fleet is
   unsound, and the reason for caching was wrong.** The plan assumed ~8 min of
   dependency build per job and called a cache mandatory. Measured on this
   workflow: Configure 12 s + Build 23 s cold, against 0 s + 11 s warm — a
   ~24 s saving. Against that, GitHub's Linux fleet is mixed (EPYC 9V74, EPYC
   7763, Xeon 8370C and 8573C were all seen in one afternoon), and the second
   run restored an EPYC-built tree onto another CPU: **13 of 15 tests died
   with SIGILL.** Keying the cache on the CPU model would have fixed it at the
   cost of most of the hit rate, for a saving already too small to matter. There
   is no cache; every job builds its dependencies from the pinned sources on the
   machine that runs them. This also removes the poisoned-cache threat surface
   rather than merely mitigating it. If a future step makes the per-job build
   expensive, the numbers above are the ones to beat.
5. **Three budgets in `tests/test_net.c` were tuned to this laptop.** T2 pushes
   ~12 000 bytes through the proxy one at a time with a sleep per byte; what
   that costs is the host's sleep granularity: 3.2 s here, over 18 s on the
   macOS runner. Its handshake bound (15 s), then its per-frame idle budget
   (2 s), then the proxy's own lifetime (`CHILD_WAIT_MS − 2 s = 18 s`, the
   suspiciously constant 18.2 s the logs kept showing) each failed in turn.
   All three are liveness guards nothing asserts on; the handshake bound is now
   the ceiling the design allows (the server refuses a handshake timeout above
   its pending store's TTL), the idle budget is per-scenario, and
   `CHILD_WAIT_MS` has headroom over the slowest platform the project runs on.
6. **T12 was a race, and the macOS runner lost it one time in three.** The
   EINTR test stormed SIGALRM with `setitimer(500 µs)` in each peer and
   required at least one observed retry. Across seven macOS executions the
   alarms delivered were 19, 10, 4, 3, 3, 1, 0 — it failed the two where at most
   one landed. This laptop delivers 6. The property is sound; the mechanism
   depended on the host's timer resolution, which a VM does not honour. The
   alarms now come from a dedicated process that signals both peers as fast as
   it is scheduled for exactly as long as the scenario runs: 89–608 alarms and
   38–289 retries per side over ten consecutive local runs.

   A redesign that accidentally became vacuous would be worse than the flake it
   replaced, so the new mechanism was mutation-tested (fresh ASan tree,
   `tools/run_mutations_v2.sh`): **S1**, every EINTR still retried but none
   counted → KILLED (`288 alarms in the client`, `retries: client 0, server 0`,
   T12 FAIL); **S2b**, EINTR no longer retried in the poll wait → KILLED (the
   connection fails). S1 shows the assertion still fires; S2b shows the storm
   really interrupts blocking calls — if it did not, making EINTR fatal would
   have changed nothing. (S2's first form was KILLED(compile) on
   `-Wunused-parameter`, an artefact of the mutation's own shape; it was
   requeued with the parameter kept in use, the V2-7 R3 precedent.)

One finding was **not** fixed here. In the macOS VM the environment block
prints `Apple M1 (Virtual) (3 performance + -1 efficiency cores)`:
`sysctl_long()` returns −1 when `hw.perflevel1.logicalcpu` does not exist, and
the `cpu` line prints that sentinel raw. That is exactly the class V3-2's
*unknown says why* rule exists for — but the macOS block's wording is the
byte-identical regression guard for every figure already published, so it is
recorded here and proposed for V3-5, which owns the bench reporting changes.

### The standing rules are enforced by construction

Every suite job runs `tools/check_build_current.sh "$BUILD_DIR" && ctest
--test-dir "$BUILD_DIR"` as **one step**, so a stale tree cannot produce a
number; the sanitizer jobs run `tools/check_sanitizer_link.sh` before the
suite. The rules no longer depend on anyone remembering them. Actions are
pinned by commit SHA, `permissions: contents: read`, no secrets, superseded
runs are cancelled, every job has a timeout.

### The negative controls — CI can go red for the right reason

A green workflow proves nothing until it has been shown to fail. Each control
was pushed alone against the green baseline (`5412ac2`) and reverted
byte-exactly (`git diff 5412ac2` empty afterwards):

| # | Deliberate break | Result |
|---|---|---|
| C1 | `test_session.c`: `l == 27u` → `28u` | all 7 suite jobs red on `FAIL: v2-6 P6: empty content at bucket 1 -> a 27-byte record` by name; the fuzz job green, correctly — it runs only `-L fuzz` |
| C2 | `session.c`: an unused local | all 8 jobs red at **Build**: `session.c:253:9: error: unused variable 'control_c2_unused'` — clang `[-Werror,-Wunused-variable]`, gcc `[-Werror=unused-variable]` |
| C3 | `bench_common.c`: `#if 0` around the Linux `cpu` line | the 4 Linux suite jobs red on `bench_smoke: … environment block has no 'cpu' line` (V3-2's oracle); macOS green (the line is under `__linux__`); fuzz green (no `fuzz` label) |
| C4 | `cmake/Dependencies.cmake`: last nibble of the pinned liboqs SHA | all 8 jobs red at **Configure**, in liboqs's *patch step* — `VerifyLiboqsCommit.cmake`, before liboqs's own CMake runs: `liboqs commit pin MISMATCH: checked out …183 / pinned …184` |

C4 changed shape. The plan's version ("pin the cache key to a constant, then
change a pin") tested that a stale cache could not be measured; with no cache
that threat is gone, and the control became V2-2's N1 run on every job: the
pin is enforced at population time, on both platforms, in CI.

### Cost, measured

Green run [34930946282](https://github.com/happyc0der/mldsa-auth/actions/runs/34930946282),
no cache, wall clock per job (Configure / Build / rule 3 + suite):

| job | total | configure | build | suite |
|---|---|---|---|---|
| ubuntu · gcc · debug | 63 s | 14 | 23 | 21 |
| ubuntu · clang · debug | 69 s | 15 | 29 | 22 |
| ubuntu · clang · asan | 86 s | 15 | 35 | 25 |
| ubuntu · clang · ubsan | 86 s | 15 | 36 | 26 |
| macos · clang · debug | 95 s | 15 | 46 | 25 |
| macos · clang · asan | 126 s | 16 | 55 | 43 |
| macos · clang · ubsan | 219 s | 22 | 119 | 58 |
| fuzz smoke + secret scan | 318 s | 69 (configure+build) | — | 182 (`-L fuzz`), 61 (smoke) |

The jobs run in parallel, so a push is green or red in about five minutes.
The 56-mutation suite (4–6 h) and the 600 s fuzz budgets belong to a
scheduled workflow (V3-4), not to a push — a policy with the numbers attached,
not an omission.

## V3-4 — the deep gates run nightly, and the campaigns are finally in the repository

`.github/workflows/nightly.yml` runs, at 03:17 UTC and on demand, the two
gates V3-3 deliberately left off the push: the mutation suite (one job per
campaign, fresh Linux ASan tree) and the 600 s fuzz budgets (one job per
target, crash artifacts uploaded for 30 days).

### The finding that reshaped the step

**The mutation campaigns were not in the repository.** `git ls-files` tracked
`tools/run_mutations_v2.sh` and nothing else; the seven `mutate_v2*.py`
scripts and their spec files lived in one agent's scratch directory. Every
"56 mutations re-run" claim in this document — V2-10's included — rested on
files nobody but that agent could see or run. They are now `tools/mutations/`,
one script and one spec per step, consolidated to the expectation strings
that killed in each step's exit report, and `tools/README.md` carries the
rule: **a step's campaign is committed with the step.** Dry-run on
`main@62aa7b5`: all 58 anchors apply (56 + V3-3's S1/S2b), none rotted.

### What the first run on a machine this agent does not control found

Six campaigns green, all five fuzz targets `crashes=0` after 600 s — and two
campaigns red. Both were **consolidation defects in the committed specs**, not
findings about the tree, and each reproduced a recorded verdict exactly:

- **M6** (`decode_client_hello` accepts a v1-length message) is killed on an
  ASan tree by a `heap-buffer-overflow in __asan_memcpy` that aborts
  `test_handshake` before W5 ever prints. V2-4 recorded that as the ASan form
  of its spec (`M6|^test_handshake$|`, "must fail somehow"); the consolidation
  took the plain-suite form instead, so the runner reported
  `SURVIVED(BAD: [W5 text])` — mutant in the binaries, test failed, named text
  absent. Restored to the recorded form; it now reads `KILLED(0 named)`.
- **N7** (keys committed before `consume_success`) survived — as it did in
  V2-5 and V2-10, where it is recorded as an **equivalent mutant**:
  `fail_ctx()` wipes the keys on every post-commit failure path, so no
  public-API test can distinguish the reordering. Linux reproduced the record
  precisely. A documented survivor cannot be a pass criterion, so it is not in
  the nightly's spec; the reason sits beside the campaigns in
  `tools/README.md`, not only here. **57 must-kill**, one documented
  equivalent.

The second run: 13/13 green, 57 KILLED, every campaign ending in
`final: all sources restored; all artifacts identical to clean fingerprints`,
fuzz runs after 600 s of 40.8 M (wire), 1.23 M (handshake), 127.6 M
(session), 16.4 M (frame) and 0.90 M (keys), all `crashes=0 artifacts=0`.

### The negative controls — the nightly can go red for the right reason

Baseline `05bcdcc`; each control a tree differing from it by exactly one
file (checked before every push), reverted byte-exactly afterwards.

| # | Deliberate break | Result |
|---|---|---|
| D1 | `spec_v26.txt`: Q1's expectation replaced by text no check prints | only `mutations · v26` red: `Q1 SURVIVED(BAD: [this text is printed by no check (CONTROL D1)])`, tree restored, exit 1 — a rotted expectation is loud, the X3 lesson enforced by the runner |
| D2a | Q1's defect applied to `session.c` *with* its `/* MUTATION */` marker left in (my sed missed it) | every campaign red at the snapshot step: `FATAL: refusing to snapshot -- MUTATION marker already present in: src/protocol/session.c` — the residue guard refuses a tree that already carries a marker. Not the planned control, so it does not stand in for it; reported as what it proved |
| D2b | the same defect, marker removed | every campaign red at `FATAL: clean suite fails`; every fuzz job red before its 600 s run, at `fuzz_libfuzzer_smoke_session`: `ORACLE FAILURE [session] … session_open status disagrees` — V2-6's authenticated-inner model caught the real defect on its own |
| D3 | `fuzz_wire.c`: `abort()` on a first byte of `0x42` | red on **all 13 jobs**: `fuzz · wire` at the smoke step (`libFuzzer: deadly signal`), and every campaign at `FATAL: clean suite fails` because `fuzz_replay_wire` shares the harness. The 7-byte crash input beginning `42` was uploaded (`fuzz-wire`, 277 bytes) and downloaded — a crash found on a runner is kept, not lost with it |

One thing the controls exposed about GitHub itself: a concurrency group keeps
**one** pending run, whatever `cancel-in-progress` says. Four back-to-back
pushes produced one running, one pending and two *cancelled* runs; D2 and D3
were re-run on their own SHAs (`gh run rerun`), one at a time. Controls on
this workflow are pushed one per completed run.

### Cost, measured

Run 2, no cache, `ubuntu-latest`: campaigns 154–460 s each (v33 → v28), fuzz
jobs 810–832 s each; the whole nightly completes in about **20 minutes** of
wall clock on 13 parallel jobs. The plan's 4–6 h estimate was the *serial*
laptop figure; nothing here runs serially. The 300/30-minute timeouts stand
with an order of magnitude of headroom.

### Choices recorded

Linux only (the stricter tree — LSan runs there — and macOS runners are the
slow ones; reversible by a matrix row). V2-2's config controls stay out (N1
already runs per push as V3-3's C4). Separate workflow and badge from the push
gate; the README says, beside the badge, that GitHub disables a scheduled
workflow after 60 days without a commit — a badge that stopped is not a badge
that passes.

## V3-5 — the first x86_64 measurements, and the backend claim proven there

### The step's own premise was wrong, and checking it was the first finding

The V3 roadmap said *"spec-v2 §5.1 targets 'a modern x86_64 core' and has
never been measured on one … carried as a recorded deviation since Step 8"*.
Both halves needed checking against the documents rather than the memory of
them:

- **v1** §5.1 does say it, and that deviation is real and recorded twice
  above. But v1 is frozen at `v1.0.0` and its code was **deleted from `main`
  in V2-4/V2-5**. Closing it would mean benchmarking a protocol this
  repository no longer implements. **V3-5 does not close it**; it stays open,
  and `bench/results.md` says so where a reader looking for the numbers will
  find it.
- **spec-v2** §5.1 was rewritten in V2-1 and now reads *"< 15 ms per
  handshake **on the measurement platform** … the reference measurement
  platform is an Apple M4 Pro (arm64)"*. **There is no open x86_64 deviation
  in v2.** The step could not close what was not open, and does not claim to.

What was genuinely missing was more interesting than the bookkeeping: the
x86_64 *backend* claim had never been executed, and the tool that checks it
was not in the repository.

### The backend claim, proven in the binary on the architecture it was written for

`mldsa_backend()`/`mlkem_backend()` return `"AVX2-optimized (x86_64)"` from an
`#if defined(OQS_ENABLE_*_x86_64)` branch that had never been **compiled**,
let alone checked against what the linker actually pulled in. Every symbol
check in this project's history was arm64 — and V3-3 had just proved that
untested branches in this very file rot silently.

`tools/check_backend_symbols.sh` is now **in the repository** (it was
scratch-only and arm64-only — the same finding as V3-4's about the mutation
campaigns: an unversioned tool makes an unverifiable claim), knows the
`PQCP_*_{C,AARCH64,X86_64}_*` families taken from the pinned liboqs source,
and carries three vacuous-pass guards. On the first x86_64 run it found the
AVX2 families in all 15 executables and zero portable-C symbols.

`bench.yml` then adds the step that matters: **the binary's own environment
block must name the family the symbol check just found in that binary.** A
block that lies about what it measured invalidates every number beneath it,
and this is what makes that unpublishable.

### A shared VM is not a benchmark platform, and every figure says so

`ubuntu-latest` runners are 4-vCPU slices of Azure hosts. Five different CPUs
appeared during this one step (EPYC 7763, EPYC 9V74, Xeon Platinum 8370C,
Xeon 8573C, Xeon 6973P-C), and the two measured differ by **24%** on the same
build. So: figures are published **per CPU model, never averaged**, as an
upper bound on latency and a lower bound on throughput, with the environment
block naming the chip, the governor and the hypervisor beside them.

The decision made in advance was that if run-to-run spread exceeded ±20%, no
headline figure would be published at all — only the spread. It did not: the
spread is ±0.7–2.0%, *narrower* than the M4 Pro's ±2.5% for the same
measurement, because ML-DSA's rejection sampling dominates the variance and
the VM adds less than that. Two EPYC 7763 runs on different machines agreed
to 0.7%, so the VM penalty here is systematic rather than noisy.

The claim that survives: **15–19× inside §5.1's target on x86_64 as well**,
with margin enough that no bare-metal correction changes it.

### What the controls found — including a defect in the workflow itself

| # | break | result |
|---|---|---|
| E1 | `-DMLDSA_OQS_OPT_TARGET=generic` on x86_64 (V2-2's N3 path: `-march=x86-64`, no AVX2) | 15 `FAIL … portable-C backend symbol(s) linked`, `linking a backend: 0` — the check detects the real regression on an architecture it had never run on |
| E2 | U1: the x86_64 branch names the aarch64 family | agreement check red, naming both sides: `ml-dsa backend disagrees with the linked symbols (x86_64): … NEON-optimized (aarch64)`, while `ml-kem backend` stayed `ok` — U1 mutates only one of the two |
| E3 | the symbol check pointed at a bare configure | `FAIL: no executable linked an ML-DSA/ML-KEM backend at all` — the second guard, since CMake's own probe binaries mean the first never fires |

**E1 also exposed a defect in `bench.yml`.** The step ran
`check_backend_symbols.sh … | tee symbols.log`, so `tee` decided its exit
status: the step printed 15 `FAIL` lines **under a green tick**, and only the
agreement check downstream turned the run red. Fixed with `set -o pipefail`
and re-run **with E1 still applied**, so the fix was proven at the step that
had been lying rather than by a subsequent green.

### U2 survived first, and that was the useful part

The campaign is `tools/mutations/{mutate,spec}_v35` (V3-4's rule: a step's
campaign ships with the step). U3 (the macOS `cpu` line dropped) was killed
immediately. **U2 — the absent-sysctl sentinel printed raw, the exact defect
V3-3 found — SURVIVED**, because on any Apple Silicon Mac both perflevel keys
exist, so the degraded branch never runs; and on Linux the code does not
compile at all. It was unkillable everywhere the campaigns run, while still
broken in production.

The fix was not to accept it but to make the path reachable: `print_environment()`
now probes `core_count()` with a name that cannot resolve and requires the
`unknown (<why>)` form via `BENCH_REQUIRE`. U2 is killed on re-run. This is
the shape of an honest mutation result — a survivor that exposes a gap in the
*oracle* rather than a property of the code. (Contrast N7, which survives
because it is genuinely equivalent.)

`spec_v35.txt` lists only U2 and U3: U1's branch does not compile on arm64,
so it is applied by hand during `bench.yml` bring-up, where the agreement
check kills it.

### The macOS sentinel, fixed with the published figures' guard intact

V3-3 observed `Apple M1 (Virtual) (3 performance + -1 efficiency cores)` on
GitHub's macOS runner: `sysctl_long()` returns −1 for an absent key and the
raw sentinel reached the block. `core_count()` now renders it as
`unknown (no hw.perflevel1.logicalcpu)`, and `bench_smoke`'s oracle rejects
any value containing a negative number token (anchored so `clang-2100.1.1.101`
and `-O3` do not match). **The M4 Pro line is byte-identical** — proven by the
same before/after diff V3-2 used — so every figure already published keeps its
regression guard; only the degraded path changed.

### Follow-up: T12's storm needed to be *running*, not merely forked

The per-push run of the commit that landed V3-5 went red on one macOS job:
`T12 ... (EINTR retries: client 0, server 0; 1 alarms in the client)` — the
mechanism V3-3 had redesigned, failing 1 macOS job in 15 since.

One alarm in a whole scenario means the storm process barely got a timeslice.
Forking is not starting: on a loaded 3-vCPU runner a new process can wait tens
of milliseconds to be scheduled, and T12's scenario finishes inside that
window. **V3-3 removed this test's dependence on the host's timer granularity
and replaced it with a dependence on fork-to-first-run latency** — a smaller
race, and still a race.

`run_scenario()` now waits, bounded by `OPS_MS`, until the parent has actually
*received* an alarm before the scenario begins: the property the test needs,
asserted rather than assumed. The server child is still blocked in
`net_accept()` at that point, so it too does all of its work under the storm.
A storm that never starts now fails T12 loudly with 0 alarms instead of
passing or hanging. Locally the floor rose from 38 EINTR retries per side to
167 over twelve consecutive runs, and S1/S2b were re-run against the changed
mechanism — both still KILLED, so it detects a real regression as before.

### Cost, measured

One dispatch: 237 s total — 56 s configure+build, 169 s for 5 repetitions,
the checks under 3 s. The 45-minute timeout stands as a ceiling with an order
of magnitude of headroom.

## V3-6 — closing the milestone without a version number

### The release the roadmap planned would have misrepresented the code

V3 was scoped as *assurance and CI, shipping as v2.1.0*. Checked before
acting: `git diff b71a06a HEAD -- src apps cmake CMakeLists.txt` is **empty**.
Every line V3 changed is in `tools/` (23 files), `tests/` (4), `bench/` (4),
`.github/` (3) and documentation. **Anyone building from a `v2.1.0` tag would
get bit-for-bit what `v2.0.0` already gives them.**

Semver MINOR advertises added backwards-compatible functionality; there is
none in the artifact. PATCH advertises fixes to it; there are none either —
the fixes were to tests, tools and CI. `CMakeLists.txt` declares no `VERSION`,
so nothing in the build depends on the number; it lives only in tags and prose.

There is a defensible reading in which the version tracks *the repository as a
distributed artifact*, and a bump for "added continuous verification" would be
fair. But v1.0.0 → v2.0.0 was a **protocol** break: the number has so far meant
the implementation, and changing what it means silently, in the release that
claims to be about trustworthiness, is exactly the wrong place to do it.

**Decision: no version bump and no GitHub Release.** The five annotated
`v3-step*` tags already record the work, and the badges, `.github/`,
`tools/mutations/` and this log make it visible to anyone deciding whether to
trust the code. The README's status paragraph says plainly that the library is
byte-identical to `v2.0.0` and that the verification was *automated rather than
changed*. A version number that advertises a change to the code is a claim, and
this project does not make claims it cannot show.

### A campaign that was committed and never ran

`tools/mutations/` held **59 mutations across 9 specs**; `nightly.yml`'s matrix
listed **8**. `v35` was absent — correctly, since U2 and U3 anchor inside
`bench_common.c`'s `#if defined(__APPLE__)` branch and cannot be applied on
Linux at all. But the omission was never written down, which left three
published counts wrong (README ×3 and `tools/README.md` ×1 all said 57), one
claim outright false (*"nightly.yml runs every campaign"*), and **U2 — a defect
that only ever appeared on a macOS VM — re-verified nowhere automatically**.

V3-4 excluded macOS from the nightly and recorded that as *"reversible by
adding a matrix row"*. This is that row: one `macos-latest` job for the one
macOS-only campaign, ~2 minutes. The exclusion narrows rather than reverses —
the eight architecture-independent campaigns still run on the stricter Linux
ASan tree.

### The counts are now derived, not remembered

Every mechanically checkable claim in `README.md` and `tools/README.md` is
re-derived from the tree by a scratch audit — test count from `ctest -N`,
campaign and mutation counts from `tools/mutations/spec_*.txt`, the workflow
table from the YAML matrices, and every relative link resolved from its own
file's directory — and diffed against what the documents say. It found all four
stale counts above. It also found a defect in **itself** on the first run
(links resolved from the repository root, so correct `../docs/…` links in
`tools/README.md` were reported broken); the tool was fixed before its verdict
was believed, which is the same rule the gates themselves follow.

One check in it is worth keeping beyond this step: **every committed campaign
must appear in some nightly matrix**. That is the invariant whose violation
started this section.

## V4-1 — auditing v1–v3 against a deployment, and what that found

v3 closed with a verified reference implementation whose own README says
"Not production-ready". v4 asks a different question of the same code: what
stands between it and being one website's login system? This step answers it
with evidence rather than opinion — `docs/v4/audit.md` (findings register,
coverage, spec-conformance matrix, disposition of all 31 recorded debt items)
and `docs/v4/threat-model.md` (assets, adversaries, trust boundaries, and what
the post-quantum layer adds over TLS+passwords — and does not).

No code was touched. Fixes are owned by later steps, per the rule that an
audit reports rather than repairs.

### The finding that justified the whole step

**The project does not build in Release with gcc on Linux** —
`-Werror=unused-result` on two `symlink()` calls in `tests/test_net.c`.
Measured, not inferred: `Release + gcc FAILS`, `Release + clang BUILDS`, and a
three-line probe confirms gcc does **not** honour a `(void)` cast on
`warn_unused_result` while clang does.

It survived three milestones of verification because every axis that would
have caught it is covered *separately*: CI builds Linux in Debug, ASan and
UBSan (never Release); the only Release build is `bench.yml`, with clang; and
`_FORTIFY_SOURCE=2` is defined only when not sanitizing and only takes effect
at `-O2`. **The one configuration a deployment would actually use — Linux,
Release, gcc — had never been built.** The matrix was wide but had a hole
exactly where production lives.

### Coverage, measured for the first time

87.77% regions / 97.19% lines / **77.29% branches** across `src/` and `apps/`.
Not adopted as a gate — the mutation campaigns are the gate — but an uncovered
branch is one no mutation could ever be killed in, so it maps the blind spots.
The shape is the interesting part: the **protocol core is the best-covered
code** (`session.c` 95.99% branches, `keystore.c` 92.96%, `transcript.c`
88.79%) and the **apps layer the worst** (`auth_server.c` 61.17%,
`auth_client.c` 62.99%, `net_io.c` 68.65%) — which is precisely the layer the
daemon replaces. `mldsa_wrap.c`'s 57.69% is the lowest in `src/`: liboqs
failure paths unreachable without fault injection.

The measurement is run from a **separate `build-cov` tree**, never from a gate
tree: instrumented objects would poison the mutation runner's fingerprints and
`check_build_current.sh`'s no-op-rebuild proof.

### Two normative requirements have no executable pin

Of spec-v2 §4's thirteen security requirements, eleven are pinned by a test or
a tool. **Req 4.8 (build hardening) and Req 4.9 (no secret-dependent control
flow) are pinned by nothing** — the only matches in the tree are comments
mentioning them. 4.8 now has `tools/audit/check_hardening.sh`, written to
become a gate in V4-11 (`--require`); 4.9 has no timing test and is argued by
code review alone, which is now recorded rather than assumed.

### The audit tools are committed, and each can fail

`tools/audit/` follows V3-4's rule that an uncommitted verification is an
unverifiable claim. Each script refuses to pass vacuously and has a
demonstrated failure mode: coverage responds to removing a test (session
branch coverage 95.99% → 76.28% with the session tests excluded);
`check_hardening.sh` fails when a property is absent and refuses to pass when
it finds no executables; the constant-time inventory fails if it finds zero
constant-time calls, i.e. if its own grep broke.

### What this audit does not establish

It is still single-agent review — the agent that wrote v1–v3 audited them.
The document therefore separates what was **machine-checked** from what was
**read**, and V4-14 produces a packet for an external cryptographic review.
No timing measurements were taken; the pinned dependency versions were not
re-checked against advisories in this pass.

## V4-2 — the spikes: measuring what the design was assuming

Seven time-boxed experiments, each with a pass criterion fixed **before** it
ran, in a scratch directory on a **space-free path** (finding F13: this
working copy lives under `…/PQ Authentication protocol/…`, which libtool
cannot handle). No repository code changed; this section is the deliverable.

Three of the seven changed a design decision, and one produced a number the
plan had assumed and got wrong.

### S1 — libsodium hands back unlocked memory and says nothing

Measured on Linux with 1,000 concurrent `sodium_malloc(32)` blocks (the daemon
holds ~10 per in-flight handshake):

| `RLIMIT_MEMLOCK` | allocations succeeding | `VmLck` | verdict |
|---|---|---|---|
| 8 MiB (container default) | 1000 / 1000 | 4,000 KiB | every block locked |
| **64 KiB** | **1000 / 1000** | **64 KiB** | **~16 blocks locked; the rest silently unlocked** |

Under a tight limit **every allocation still succeeds** and roughly sixteen of
a thousand blocks are actually locked. Nothing returns an error, nothing is
logged: the secrets quietly become swappable. This confirms finding F6 as a
*live* operational hazard rather than a theoretical one, and it is the reason
`LimitMEMLOCK` is a correctness setting for this daemon, not a tuning knob.

Cost measured at **9.5 KiB of RSS per 32-byte secret** (guard pages plus page
rounding), so ~95 KiB per in-flight handshake. `LimitMEMLOCK` must therefore
be at least `4 KiB × 10 × max_in_flight`; V4-11 derives it from the configured
slot count instead of guessing, and the daemon logs the limit at startup.

### S2 — the ledger scan fails the plan's own budget at 4,096

`find_slot` is a deliberate constant-time full scan (`handshake.c:74-90`).
Cost per handshake (four scans), measured:

| capacity | per scan | per handshake | |
|---|---|---|---|
| 256 | 2.55 µs | 10.2 µs | |
| 1,024 | 9.95 µs | 39.8 µs | |
| **2,048** | **19.90 µs** | **79.6 µs** | under the 100 µs budget |
| 4,096 | 39.88 µs | 159.5 µs | **over** |
| 8,192 | 79.89 µs | 319.6 µs | **over** |

The plan said "acceptable to ~4096"; measurement says the ceiling is
**2,048**. V4-12 therefore caps capacity at 2,048 and uses **TTL** as the
other lever: capacity ÷ TTL is the sustained rate, so 2,048 with a 10 s TTL is
~205 handshakes/s — two orders of magnitude above what one website needs.
Beyond that the answer is an indexed store, which is out of v4's scope.
(Measured in a container on Apple silicon; the x86 VPS will differ, and V4-12
re-measures there rather than porting this number.)

### S3 — full hardening links, and F0 blocks the gcc half

A Release, `-fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`,
`CMAKE_POSITION_INDEPENDENT_CODE=ON` build against the static liboqs and
libsodium:

- **clang: builds.** `check_hardening.sh --require` reports the complete set
  (PIE, RELRO, BIND_NOW, NX stack, canaries) on **all 15 executables**, and
  `check_backend_symbols.sh` still proves exactly one optimized backend with
  no portable-C symbols — hardening does not cost Req 4.10.
- **gcc: fails**, on audit finding **F0** (`-Werror=unused-result` on
  `symlink`). So F0 does not merely block a Release build; it blocks the
  *hardened* build on the compiler a distribution is most likely to use. Its
  fix in V4-5 is a prerequisite for V4-11, not an independent tidy-up.

### S4 and S5 — the client address, and a correction of my own making

**S4.** Caddy 2.10.2 → Unix-socket upstream, WebSocket upgrade, with
`header_up X-Real-IP {remote_host}` and `header_up -X-Forwarded-For`. A client
that sent `X-Real-IP: 1.2.3.4-SPOOFED` and `X-Forwarded-For: 9.9.9.9-SPOOFED`
produced, at the upstream: `x-real-ip: 127.0.0.1` and
`x-forwarded-for: <absent>`. Spoofing is defeated, and `SO_PEERCRED` on the
Unix socket returns the proxy's pid/uid/gid, so the daemon can verify *who*
connected. The WS frame arrived masked, as a browser sends it.

**S5 — and a result I had to throw away.** My first run reported "PROXY v2
upstream: NOT supported". That was a **brace error in my own Caddyfile**, not
a missing feature: the error text was a Caddyfile parse failure, not an
unknown option. Re-run with a correct config — and with a control proving
`caddy validate` discriminates (a knowingly bogus transport option *is*
rejected) — the answer inverts: **`proxy_protocol v2` to the upstream is
supported by the stock binary.**

This changes the design. PROXY v2 is prepended by the proxy *before* any
client byte and cannot be forged by the client at all, so V4-10 uses it as the
primary mechanism and keeps the S4 header arrangement as the fallback for a
proxy that cannot emit it. The near-miss is worth recording for its own sake:
a tool's error message must be read, not pattern-matched, and a negative
result needs a control just as much as a positive one.

### S6 — the browser gate passes, on the pinned liboqs, with no fallback needed

The gate the whole of milestone B hung on. The pinned liboqs 0.16.0 contains
**zero** mentions of Emscripten or wasm, so nothing suggested it would build.

1. **libsodium 1.0.22** (the pinned tarball) via `emconfigure`: builds;
   **102 `crypto_pwhash` symbols** in the archive, so Argon2id is available.
2. **liboqs at the pinned commit**, with the project's exact options
   (`OQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"`, `OQS_USE_OPENSSL=OFF`,
   `OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=generic`): builds, 247 KB archive.
3. **The project's own `src/` plus `tests/test_vectors.c`** compiled to wasm
   and run under Node 26:

   > **27 checks in wasm, 27 native, and the two lists are byte-for-byte
   > identical** — including `mldsa65_kat` and `mlkem768_kat` matching
   > liboqs's published single-vector SHA-256 hashes, RFC 7748 X25519,
   > RFC 5869 HKDF and RFC 8439 ChaCha20-Poly1305.

4. Performance (Node, Apple silicon): `mldsa_sign` 0.410 ms, `mldsa_verify`
   0.070 ms, `mlkem_encaps` 0.035 ms, `mlkem_decaps` 0.041 ms →
   **0.556 ms for the entire login-critical path** against a 50 ms criterion,
   and **Argon2id(3, 64 MiB) at 111.5 ms** against 2,000 ms. Module: 102 KB
   (bench) / 171 KB wasm + 91 KB JS (full test binary), against a 1.5 MB
   budget.

**Verdict: PASS, with ~90× headroom on the crypto and ~18× on the KDF.** The
fallback (vendoring mldsa-native/mlkem-native directly) is not needed and is
not adopted. Two practical findings for V4-13: wasm's default stack is 64 KiB
and this codebase faults immediately on it (ML-DSA keys are 4 KB,
`handshake_ctx_t` ~3.9 KB) — `-sSTACK_SIZE=8MB` is required; and the KAT tests
need liboqs's **internal** archive (`liboqs-internal.a`) for the NIST DRBG,
exactly as `tests/CMakeLists.txt:27` links `oqs-internal` natively.

Measured on a fast machine. A mid-range phone will be several times slower,
and the headroom absorbs that; V4-13 re-measures in real browsers rather than
extrapolating.

### S7 — the model checker is available, and modelling is not a formality

`brew install opam` (2.5.2) → an OCaml 5.1.1 switch → `opam install proverif`
**fails**: the package pulls `conf-gtk2` for ProVerif's optional GUI and GTK+2
is not present. The prover itself does not need it, so ProVerif 2.05 was built
from its source tarball against that switch instead; its `build` script exits
2 (the GUI half fails) while still producing a working **5.7 MB CLI binary**.
Recorded because V4-4 will hit the same wall: *install the CLI from source,
not from opam*.

Functionality confirmed on a toy sign-then-KEM model: ProVerif **proves**
`not attacker(secretMsg)` — a real secrecy proof — and correctly **reports
violations** of injective agreement, including on a deliberately broken
variant with the signature check removed.

What it did **not** do is prove injective agreement on my toy model, and that
is the useful part of the result. Two successive attempts — first without a
nonce, then with a responder challenge signed into the transcript — both came
back `false`. That is not a tool problem and not (as far as this spike
establishes) a protocol problem: it is that a faithful agreement property
needs the *whole* transcript binding the real protocol has (`session_id`,
both nonces, `handshake_id`, both identities — spec-v2 §6.3), and a toy model
that abbreviates it will not prove what the real one should.

So S7 passes its stated criterion (the toolchain is available and provably
functional) while demolishing the assumption underneath it: writing the V4-4
model is genuine protocol work, not a box to tick. Budget it accordingly, and
keep the broken-variant control — it is what proves the model can fail.

### What the spikes cost the plan

Two numbers the plan asserted were wrong (the ledger ceiling, and PROXY v2
support), one hazard was confirmed as live (silent mlock failure), one
prerequisite was discovered (F0 gates hardening, not just Release), one
step was found to be larger than budgeted (V4-4's model), and the single
largest unknown — whether a browser can run this protocol at all — is now
answered with byte-identical known-answer tests rather than an opinion.

Seven spikes, six passes, one pass-with-a-warning. Nothing in the roadmap
needs reordering; V4-3 can now write a spec whose browser section rests on
a measurement instead of a hope.

## V4-3 — specifying the daemon before building it

`docs/mldsa-authd-spec.md` (19 sections) specifies `mldsa-authd`: the
application messages above spec-v2's record layer, the store, the local API,
the key envelope, the identity lifecycle, logging and deployment. No code.

The project wrote spec-v2 first and implemented against it for nine steps
without ever editing it to match the code; the same discipline applies here,
for a larger surface. V4-2's S7 made the argument concrete: a *toy* model of
this message flow already needed real care, so committing the byte layouts to
prose — where a flaw costs a paragraph rather than a rewrite — is the cheap
place to be wrong.

**Nothing on the wire changes.** The document says so in §0 and adds the rule
that where it and spec-v2 disagree inside spec-v2's scope, spec-v2 wins and
this document is wrong. Both protocol specs are byte-identical.

### What the spikes wrote into the specification

V4-2 was not a box-ticking exercise; four of its results are load-bearing text:
the ledger ceiling is **2048** rather than 4096 (§17, from S2); the client
address arrives by **PROXY protocol v2** with the header arrangement as
fallback (§7.2, from S4/S5); `LimitMEMLOCK` is described as a **correctness**
setting derived from the slot count rather than a tuning knob (§16, from S1's
silent unlocked-memory finding); and §14 asserts browser feasibility on the
measured evidence — 27 wasm checks identical to 27 native — rather than on
hope, and adopts no fallback backend.

### Two design points worth their own record

**The envelope authenticates its own header.** `MLDSAEK1` uses an AEAD with
bytes [0, 67) as associated data rather than `crypto_secretbox`, because a
secretbox authenticates nothing outside the box: an attacker who could write
the file could rewrite `memlimit` to 1 GiB and turn every start-up into memory
exhaustion. Parameter bounds close that anyway; binding the header costs one
argument and closes it twice. The plaintext is the exact `MLDSASK2` image, so
the existing loader validates it unchanged after decryption.

**The token never reaches JavaScript.** The daemon issues a single-use login
code bound to `{user, handle, handshake_id, SHA-256(state)}`; the site
exchanges it over the local socket for the token. An XSS that steals the code
cannot exchange it, and the `state` binding kills login-CSRF at the exchange
step. Signed or structured tokens were rejected: offline verification would
need an ML-DSA implementation in the site's language and would lose instant
revocation, for no gain, since the credential is a bearer token either way.

### The specification is checkable, and was checked

`tools/audit/check_spec_constants.sh` re-derives thirteen sizes from
`session.h`, `transcript.h`, `mldsa_wrap.h` and the envelope arithmetic and
diffs them against the document — `ROTATE` body 8611 and content 8612,
`AUTHD_MAX_RECORD` 12313, the 281-byte `LOGIN_CODE` record, the `MLDSASK2`
image at 6025 + id_len, the 67-byte envelope header, the 6142-byte sealed file
for a 34-byte handle. All thirteen matched on the first run. **Control:**
changing one digit (8611 → 8610) fails the check, and the restore is
`cmp`-identical.

Also verified: all **14** §5 requirements are numbered (the V4-1 conformance
matrix found two requirements in spec-v2 pinned by nothing; this document
starts with none, and each step ships the pin for the requirements it
implements); the only labels it defines are `mldsa-authd/v1/{rotate-old,
rotate-new,audit-mac}` and it redefines no spec-v2 label; every relative link
resolves.

### What this does not settle

The spec is written by the agent who will implement it — the single-agent
problem the V4-1 audit named. Numbering every requirement is what makes an
external reviewer able to work through it one claim at a time, and V4-14
produces that packet. V4-4's model is deliberately the next step, so the
message layouts meet a checker before they meet a compiler.

## V4-4 — a machine-checked model of the handshake, login code and rotation

`formal/authd.pv` models, in ProVerif's symbolic (Dolev–Yao) setting, the
spec-v2 handshake (§6.3) plus the two things `mldsa-authd-spec.md` adds: the
login-code exchange (§6.2) and rotation (§6.3). It runs before any of that is
implemented, so a flaw is found in prose, not in C — V4-2's S7 already showed a
*toy* model of this flow needed real care, and it did here too.

### What it proves, and what makes the proofs non-vacuous

Base model (all `true`): injective mutual agreement on
`(A, B, session_id, nonce_B, key)` both directions; key confirmation on the
initiator's first decrypted record; session-key secrecy; login-code secrecy;
that a site login under a `state` was begun by that device with that `state`;
and that a committed rotation was requested in that session.

`gen_controls.py` derives eight variants by exact string replacement, each
asserting the edit bit. Three **resilience** runs must still prove — leak the
ML-KEM secret, leak the X25519 secret, or leak the record key — and the first
two are the hybrid claim *checked* rather than asserted: either KEX half
surviving keeps the key secret. Five **controls** must stop proving: signing
only `ClientHello` breaks mutual agreement; ablating one KDF half while leaking
the other makes the key recoverable (so both halves are load-bearing);
dropping `handshake_id` from the rotation digest, or skipping the outgoing
key's signature, unbinds rotation from its session.

`formal/run.sh` requires `is true` for the base and resilience runs and
anything-but-`is true` for the controls, and refuses a control file identical
to its base. It runs in the nightly (`formal` job), which builds the ProVerif
CLI from a **SHA-256-pinned** tarball — opam's package needs GTK (S7), so the
CLI is built from source with only OCaml and ocamlfind.

### Two honest wrinkles, recorded not hidden

**An over-sequentialized first model proved its controls vacuously.** I first
put the site's `EXCHANGE` and the client's `ROTATE` inline in the daemon's
client-facing session, so a broken variant could not even *reach* the event it
was meant to break, and every control passed for the wrong reason. The fix was
to model the daemon's three concerns as the separate processes and channels
they are in the deployment — the client session on the network channel, and
the site's `EXCHANGE` on the peer-authenticated local socket — which is exactly
the S7 warning made concrete.

**Two rotation controls land on "cannot be proved", not "false".** Injective
agreement with a leaked record key is a hard case for ProVerif's resolution
(the P5′ risk V4-4 named). The base model *proves* rotation binding "true"; the
control moves it to "cannot be proved". That regression is the result — the
check under test is what took the property from provable to unprovable — so
`run.sh` treats "no longer provable" as a passing control and the reasoning is
written down rather than papered over with a forced "false".

### What the model does not cover

TOFU registration is out of scope by decision (spec-v2 §6.2 puts it out of
band), so long-term keys are honest and pre-pinned. The `state` binding's value
against a *leaked* login code (an XSS-class threat, §14) is outside a symbolic
model where the code stays secret; it is proven where the model can see it (the
code is secret; a site login implies a real handshake for that device) and the
XSS argument stays in the threat model. The model is only as faithful as its
author — which is why every construct cites its spec line, why the controls
exist, and why V4-14's external-review packet includes `formal/`.

## V4-6 — the MLDSAEK1 key-at-rest envelope

Identity keys are encrypted at rest (spec mldsa-authd §12, Req 10): the daemon
and CLIs never write a plaintext secret key to disk. `apps/authd/keyfile.c`
seals the exact `MLDSASK2` image under Argon2id + XChaCha20-Poly1305, published
atomically (temp + `O_EXCL` + `link` + `fsync`, never in place, mode 0600).

### One validator, not two

The spec says the existing loader validates the image after decryption, and
that is implemented literally: `demo_keys.c`'s inline MLDSASK2 validation was
factored into `demo_keys_load_identity_from_image()` and
`demo_keys_build_sk2_image()`, and both the file loader and the envelope call
them. The file loader now reads into secure memory and delegates; behaviour is
unchanged (16/16, and — since this is the released, mutation-covered core — the
**v29 campaign was re-run, all 9 KILLED**, proving the refactor preserved every
digest/id/self-test check). Verifying the envelope's own checks: `mutate_v46`
E2–E7, all KILLED (seal and open parameter bounds, the AEAD result honoured, no
clobber, the image validated, mode 0600). `test_authd_keyfile`: 17 checks
including a tamper sweep over the header fields and ciphertext; fresh ASan and
UBSan clean.

### The header authenticates itself, and E1 was dropped for a real reason

Bytes [0, 67) are the AEAD's associated data, so the KDF parameters are bound.
The mutation that was to prove this (E1) **survived**, and the survival is the
finding: every header field is *independently* range-checked (magic, version,
alg ids, `ct_len`) or feeds the KDF/AEAD (salt, nonce, opslimit, memlimit), so
a single-byte header flip is caught with or without the AAD. The AAD is genuine
defense-in-depth — exactly what §12 already says ("the bounds close that
anyway; binding the header closes it twice") — so E1 was dropped rather than
mis-asserted, and the tamper sweep (which does verify tampering is rejected)
stays as a positive unit check.

### Two self-inflicted incidents, both recovered and recorded

A defense-of-the-attack detail worth keeping: **exercising a parameter bound by
feeding an over-limit value, then removing the bound by mutation, drives
Argon2 into a multi-gigabyte / multi-minute run** and hung the mutation runner
twice — first from the dedicated `memlimit`-over-ceiling check, then from the
tamper sweep flipping the `memlimit` byte. The fix is to exercise the bounds
with **opslimit**, whose over-ceiling value (11) is a handful of iterations, and
to keep the two KDF work-factor fields out of the byte-flip sweep. Their
integrity is covered by the PARAMS checks and by being AAD. A mutation-tested
security check must fail *cleanly*, not by exhausting the machine.

And, recorded in [[destructive-action-discipline]]: clearing a killed run's
`MUTATION` residue with `git checkout -- apps/ src/` also reverted V4-6's own
uncommitted work (the `demo_keys.c` refactor, a CMake edit). Recovered
byte-exact from the runner's preflight `snapshot_v2/`, then committed
immediately. The rule is now: commit the step's intended work before any
campaign or residue-cleanup checkout.

### Remaining V4-6 item

`fuzz_envelope`. Fuzzing `keyfile_open` naively is an OOM hazard: an in-bounds
`memlimit` of up to 1 GiB means the fuzzer could burn a gigabyte and seconds
per input. It is therefore built on a pure `keyfile_parse_header()` extraction
(everything before the KDF), fuzzed with an independent model, while the
KDF/AEAD/image path stays covered by the low-parameter unit test. Landed as the
closing piece of the step.

## V4-7 — the store: a pinned SQLite, atomic operations and an audit chain

The daemon's persistence layer. It is the first V4 step with a third-party
dependency and the first with an on-disk format that is not a key file, so the
decisions below are mostly about what is enforced *where*.

### SQLite is pinned by artifact, not by version string

`sqlite.org` publishes a SHA3-256 for every amalgamation, so the pin is the
exact archive: `2026/sqlite-amalgamation-3530400.zip`, 2 946 650 bytes,
SHA3-256 `628a44cf…934e`, verified by `URL_HASH SHA3_256=` at population time
— before any of the source reaches a compiler. That is stronger than the
libsodium pin's mechanism only in hash family; the property is the same one
this project has required since V2-2, and CMake's cache key already hashes
`cmake/Dependencies.cmake`, so bumping the pin invalidates the CI cache
automatically (the V3-3 rule) with no extra work.

`file(SHA3_256)` was **checked, not assumed**: CMake 4.4.3 computes the
published digest of `"abc"` correctly, and SHA3 has been in CMake since 3.8, so
the planned "bundled fallback if unavailable" was dropped as unnecessary rather
than carried as dead code.

The plan proposed 3.47.x; the current release is 3.53.4, and pinning the
current stable is the conservative choice for an auth store, so that is what
landed. The amalgamation has no build system of its own, so — unlike libsodium
— it is **not** affected by the Autotools path-with-spaces bug (A31/F13) and
builds straight in the build tree. It is compiled with `SQLITE_THREADSAFE=0`
(the daemon is one event loop), `SQLITE_OMIT_LOAD_EXTENSION` (no `dlopen`
surface), `SQLITE_DQS=0` (a mistyped identifier is an error, not a silent
string), `DEFAULT_FOREIGN_KEYS=1`, and with the project's `-Werror` explicitly
**not** applied: it is third-party code, and bending 9.5 MB of it to this
project's warning set would be pretending to a review that did not happen.

### The invariants live in the schema, not in C

Spec §9.2's two hardest invariants are enforced by the DDL: `CREATE UNIQUE
INDEX one_active_key ON device_keys(handle) WHERE status='active'` makes "at
most one active key per handle" unrepresentable, and `pk BLOB UNIQUE` makes a
public key unique across every device and every state, forever. A bug in
`store.c` therefore cannot violate either one silently. This also decided the
order inside `store_rotate_key`: the old key must be superseded *before* the
new one is inserted, because the index would otherwise reject the insert.

A consequence worth recording rather than hiding: the duplicate-public-key rule
is guarded **twice**, by `pk_exists()` and by the schema. Removing either alone
leaves the other catching it, so neither is independently mutation-killable.
That is defense in depth working, not a coverage gap, and `mutate_v47.py` says
so in its header instead of shipping a mutation that would prove nothing.

### One transaction per operation, proven by injecting a fault

Req 14 says a partially applied lifecycle change is impossible. Asserting that
is easy; the step proves it. `store.c` carries a fault hook compiled in **only**
under `MLDSA_STORE_FAULT_HOOK`, which the test target defines and no normal
build does. The test arms it to fire in the one window that matters — between
superseding the old key and inserting the new one — then **closes and reopens
the store** and requires the handle to still have exactly its old active key.
The reopen is the point: an in-process assertion would only prove a cached view,
not durability.

`tools/check_store_fault_hook.sh` keeps the affordance where it belongs. It
requires the symbol to be **absent** from the shipped library and every shipped
executable *and* **present** in the test binary — because an "absent everywhere"
check that no longer matches the symbol name would pass vacuously forever. All
three of its failure modes were demonstrated (hook leaked into the archive;
test binary without the symbol; empty build directory), each exiting 1.

### The audit chain, and what "fields" had to mean

Spec §9.2.4 fixes `mac_i = crypto_auth(key_audit, prev_mac || seq || at ||
event || 0x00 || fields)` but leaves `fields` abstract. An implementation has to
choose, so `audit_mac_input()` fixes a length-prefixed encoding (u8 user_id, u8
handle, u16 detail) which is **injective** over the row: no two distinct rows
can produce the same MAC input by shifting a delimiter. That is now part of the
on-disk format and cannot change without a schema version bump, which is why it
is written down here and in the source rather than left implicit.

`key_audit = HKDF-SHA256(ikm = envelope KEK, salt = store_id, info =
"mldsa-authd/v1/audit-mac")`, and `store_id` only exists once the store has been
created — so the derivation has to happen inside `store_open`, and the **KEK
itself** must cross the boundary. Hence the one approved change to V4-6's
surface: `keyfile_open` gained an optional `kek_out`. It is zeroed on entry so
every failure path leaves it clean, filled only on success, and the envelope
test now pins all three properties (filled on success, identical on re-derive,
zeroed on a wrong passphrase) so the new parameter is not a blind spot.

Tamper and truncation are both demonstrated against a real database file, using
the test's own `sqlite3` handle rather than the `sqlite3` CLI — the first draft
shelled out and would have **silently SKIPped** on any runner without the CLI,
which is exactly the class of hollow gate this project keeps finding. Each has a
present-canary control: the edit is asserted to have actually happened before
the detection is asserted.

### Scope held

V4-7 delivers correct, atomic building blocks. The policy that sequences them —
recovery lockout counting, ticket and token TTL rules, the decoy flow — is
V4-9's, and `store.h` says so. No fuzz target was added: nothing here parses
attacker-controlled bytes (the daemon and local API validate lengths before the
store sees them), and adding a target to fuzz our own callers would be
ceremony. If V4-8/V4-9 expose a parse, that is where the target belongs.

### What V4-7's verification found in V4-6

Two defects in the step before this one, both of the same shape — a list that
had to be updated by hand and was not:

1. **`run_fuzz.sh` never ran the envelope fuzzer.** Its default target list was
   the literal `wire handshake session frame keys`. V4-6 added `envelope` to
   `FUZZ_TARGETS` in CMake but not to that line, and CI's fuzz job invokes
   `run_fuzz.sh smoke build-fuzz` with **no target arguments** — so the
   per-push smoke exercised five targets and never the sixth. The V4-6 exit
   report's green CI therefore said less than it appeared to. The list is now
   derived from `CMakeLists.txt`'s `FUZZ_TARGETS` with a hard failure if the
   parse yields nothing, so a target added to the build cannot be skipped by
   the runner again.
2. **The README's `fuzz_replay_* (5)` was stale** (there are six), and
   `test_authd_keyfile` had no row in the test table at all.

Neither is exotic. Both are the "a human-maintained list drifted from the
machine-readable one" failure this project has now hit three times (V3-4's
untracked campaigns, V3-6's four stale counts, and these). The fix applied here
is the same one that worked before: derive the list, and make an empty
derivation a failure rather than a quiet no-op.

## V4-8a — the daemon's transport skeleton

V4-8 was planned as one step and is being built as two, approved at planning:
**V4-8a** is the transport (event loop, slots, reassembly, config, logging) and
**V4-8b** is the connection state machine (handshake, decoy flow, `LOGIN_CODE`).
The roadmap's single ~2 400-line commit would not have been reviewable to this
project's standard, and V4-13 already carried the "sub-steps planned at its
turn" precedent.

### A second I/O layer, on purpose

`apps/frame.c` and `net_io.c` are blocking-with-deadline (`net_read_exact`,
`frame_recv(deadline)`) and are depended on by the demo apps, `test_net` and
`demo_e2e`. The daemon is one `poll()` loop over many slots and must never
block on a single peer. Bending those functions into both shapes would rewrite
a surface three verified things rely on, so `conn_io.{c,h}` is a separate
reassembler and the duplication is deliberate. It owns no socket and makes no
syscalls — bytes are pushed in, frames come out — which is what lets the test
drive **every one of the 16 split points** of a two-frame stream and prove a
frame becomes available on exactly its final byte and not before.

### Time is an argument

`evloop_run_once(ev, poll_timeout, now_ms)` takes the clock as a parameter.
That is the difference between a deadline test that is exact and one that is
wall-clock flaky, and it makes the V4 cross-cutting rule cheap to honour: every
deadline check here proves the connection is **still open one millisecond
before** its deadline and gone at it. Without the lower bound, a loop that
closed every connection instantly would pass.

### Fixed slots, and refusal as the correct behaviour at capacity

Slots are allocated once at startup and never grown; after `evloop_init` the
loop allocates nothing. A connection is a slot index. At capacity the daemon
**closes the new connection immediately** rather than queueing it — cheaper for
us than for the peer, and it keeps the memory budget something an operator can
compute (~24 KB of I/O buffers per slot, so `max_slots` is a number with a
meaning). `AUTHD_MAX_RECORD` was re-derived from the tree and is **12 313**,
matching the spec exactly.

### The config parser fails closed, and the fuzzer proved it did not

The parser refuses an unknown key, a duplicate key, an out-of-range value, a
missing required key, a value with a NUL in it, and a config with no listener
at all. Two things are worth recording:

1. **`fuzz_authd_config` found a real bug on its first run.** The oracle is not
   a re-implementation — for a line-based parser a second line-based parser is
   just a second copy of the same misunderstanding — it is the parser's own
   *contract*: on OK every documented bound must hold for the returned struct;
   on failure the struct must equal the defaults. That second clause failed
   immediately: the `UNKNOWN_KEY`, `SYNTAX` and `LINE_LONG` paths returned
   without resetting, so a file with valid keys followed by a bad one left a
   **partially applied config**. Fixed structurally rather than by patching
   four return sites: the parse now writes to a local and commits to `*out` at
   a single point, which makes the whole class unrepresentable. The oracle
   proved its own non-vacuity by catching this, so no synthetic control was
   needed.
2. **Check order is now structural, not incidental.** A duplicate key is a
   structural error whether or not its value happens to be valid, so key
   resolution and duplicate detection both precede value parsing. The first
   version parsed the value first and reported `RANGE` for a repeated key with
   an out-of-range value, which told the operator the less useful of the two
   true things.

### Logging cannot carry a secret, by API shape

`authd_log.h` offers no function that takes a byte buffer. Key material,
session keys, signatures, nonces, raw frames, decrypted payloads, tokens and
codes therefore cannot be logged by using the interface correctly — the
never-list (spec §15) is a property of the API rather than of the caller's
discipline, and there is deliberately no debug level that relaxes it. The one
peer-influenced field, an identifier, is escaped (non-printable bytes become
`.`) and truncated at 64 bytes with a `~`, so a hostile handle can neither
inject a newline nor forge a second log line. The test uses a **present
canary**: it first proves an identity *is* logged, so the escaping and absence
checks are examining a stream that actually contains something.

### What V4-8a deliberately does not do

The daemon binary builds, validates config, listens, accepts, reassembles,
enforces deadlines and drains on SIGTERM — and then **closes any complete frame
unserved**, logging `frame-not-implemented`. It does not speak the protocol
until V4-8b. Shipping a handler that looked like it worked would be worse than
one that refuses, so the refusal is explicit in the code and in `--check-config`
output rather than implied.

### Two survivors in the first v48a run, and what each meant

The campaign is reported here as it actually ran, including the first attempt,
because both survivors were informative and neither was re-run to green.

**D4 (a released slot is not wiped) SURVIVED, and that was a gap in the test.**
The canary frame had been fully consumed, and `conn_io_consume_frame` already
zeroes the buffer it slides down — so by the time `evloop_close_slot` ran there
was nothing left for its wipe to remove, and removing that wipe changed
nothing observable. The real case for a wipe-on-close is a **partial frame that
never completes**: those bytes are never consumed, so only the close wipes
them. The test now sends a frame declaring 32 bytes and supplying 4, proves the
fragment is genuinely buffered (a present canary, so the check is not vacuous),
and then proves it is gone once the slot is released. D4's expectation points
at that check, and it kills.

**D7 (the sticky `failed` flag is not honoured in `conn_io_push`) SURVIVED, and
it is an equivalent mutant.** After an illegal declared length the offending
4-byte header is still at offset 0 and is never consumed, so the next push
re-reads it through `note_header()` and is refused again — with or without the
flag. The flag is genuine defense in depth (it keeps the refusal sticky if a
future change ever made the buffer recoverable) but nothing through this
interface can distinguish its removal today. It is therefore **absent from
`spec_v48a.txt`**, for exactly the reason N7 is absent from v25: a documented
survivor must never be a pass criterion. The reasoning lives in the campaign
script's header so the next person to read it does not "fix" the omission.

The distinction between the two matters and is worth stating plainly: D4 was a
weakness in the tests and was fixed there; D7 is a property of the code that no
test at this interface can see, and is recorded rather than papered over.

### The nightly gap, and closing it

V4-6, V4-7 and V4-8a each committed a campaign that was not added to the
nightly matrix at the time. That was a deliberate cost trade-off -- one
bring-up costs a multi-hour nightly dispatch, so three steps' worth of rows
were batched into one -- and it was recorded in `tools/README.md` rather than
left implicit. It is worth being precise about what it did and did not cost,
because the answer is not "nothing":

The per-push CI was never blind. The full suite, both sanitizers, gcc and the
60 s smoke over every target ran on Linux on every push, so a functional
regression in the store or the event loop would have been caught. What was
suspended is narrower and more important: **the mutation campaigns ran
nowhere automatically.** They existed as committed files plus one agent's
assertion that they passed locally -- which is exactly the condition V3-4
diagnosed and committed the campaigns to the repository to end. A test that has
quietly stopped being able to fail is the defect this project's whole
verification method exists to catch, and for three steps nothing was checking
for it.

The deferral was also open-ended, with no trigger condition, which is how a
deferral becomes permanent. The honest lesson is not "batching was wrong" --
batching saved two dispatches and the batch was green on the first try -- but
that a deferral of an assurance gate needs a stated expiry, and this one did
not have one until it was questioned.

Closed in one bring-up: eleven Linux campaigns + v35 on macOS + seven 600 s
fuzz targets, green on the first run, with all 21 new mutations KILLED on Linux
under `objdump`-based fingerprinting. The control (v48a's D1 expectation rotted
to text no check prints) turned that row and only that row red with
`SURVIVED(BAD:)`, then was reverted byte-exactly.

## V4-8b — the connection state machine, and the first login the daemon serves

V4-8a's daemon accepted, reassembled, timed out and drained, then closed every
frame unserved. V4-8b puts the protocol on it. At the end of this step an
enrolled operator connects, authenticates with the real library handshake, and
receives a login code — **milestone A, locally.**

### The decoy flow is what makes the pin a daemon decision

Spec §7.3 / Req 6 require an unknown, revoked, superseded or disabled identity
to be indistinguishable from a known identity whose signature is wrong. The
library refuses an unknown id at `accept_client_hello()` with
`UNKNOWN_IDENTITY` — before any ServerHello — which is precisely the
enumeration channel. So the daemon chooses the pin *first*: it peeks the
ClientHello with `decode_client_hello()` (public, and already used this way at
`apps/demo_app.c:260`), asks `store_lookup_active()`, and pins either the real
key or the store's decoy into a per-slot scratch keystore. V4-7's three-join
lookup is what makes this cheap to get right: unknown, revoked, superseded and
disabled all collapse to one `STORE_ERR_NOT_FOUND`, so there is exactly one
branch to be uniform about and no way to add a fifth case that forgets.

`accept_client_hello()` can therefore never return `UNKNOWN_IDENTITY` in the
daemon, and **no library code changed** (V4 decision 3 held).

The test measures the property rather than asserting it: a known handle signing
with the wrong key and an unknown handle reach the same client-side outcome,
neither receives a record, and — the canary that stops it being trivially true
— the unknown handle still gets a ServerHello it can *verify*, so both sides
really did complete the same exchange. The decoy branch is deliberately not
distinguished in the log either; that would reopen the channel one layer up.

### 64 KB of keystore per slot, accepted with the number written down

A slot is ~91 KiB, of which the scratch `keystore_t` is 64 552 B — 69 %, to
hold exactly one of its 32 entries. At the default `max_slots = 256` that is
23.9 MB total and unremarkable; at the 4 096 ceiling it is 382 MB, of which
264 MB is dead keystore. The alternative — a ~45-line lookup callback in
`handshake.h` — would be the first change to the verified handshake since
v2.0.0, so it is deferred to **V4-12**, which already opens `handshake.{h,c}`
for the ledger and can re-verify both edits in one campaign. The number is
recorded here so `max_slots` is a budget an operator can compute rather than a
surprise.

### One clock, pushed in

`evloop_run_once()` already took `now_ms`; rather than widen the callback
signature, `authd_app_t` carries `now_ms`/`now_unix` and the main loop sets
them immediately before each iteration with the same values it gives the loop.
The pending ledger and the session both take the library's
`handshake_clock_fn` pointed at that field, so ledger expiry, session limits
and login-code expiry cannot disagree, and the test drives all of them exactly.

**A plan item that turned out to be a tautology, removed rather than faked:**
V4-8b's plan promised a startup check that `handshake_timeout_ms` does not
exceed the ledger TTL. But the daemon sets the TTL *to* the handshake timeout,
so the invariant holds by construction and a test for it would assert
`x <= x`. The check is not implemented and no test pretends to cover it.

### The login code

The first record is the confirmation record (spec-v2 §6.4.4 permits content),
carrying `LOGIN_CODE`: 43 bytes of content, a 281-byte record at bucket 256 —
both pinned by `_Static_assert` against the spec's own numbers rather than
retyped. The store receives `SHA-256(code)` (Req 4) bound to
`{user, handle, handshake_id, SHA-256(state)}` (Req 5); the code itself exists
only inside the sealed record and is wiped immediately after. `code_expires` is
`now + 60 s` — Req 5's ceiling, expressed as the constant
`AUTHD_LOGIN_CODE_TTL_S` so it cannot drift below by accident.

On the raw/tunnel listener `state` is the **empty string**: §7.1 puts `state`
on the WebSocket URL, which a tunnelled operator CLI has no equivalent of, and
login-CSRF is a browser threat. The *mechanism* is built and tested now — a
code issued against one state is refused against another — and V4-10 gives the
WebSocket listener a real value. Only the raw listener's value is fixed.

After the login code the daemon accepts exactly `BYE`. A well-formed `ROTATE`
gets `ERROR(0x02 not permitted)` and a close, because rotation is V4-9's: a
half-implemented rotation that answered would be worse than one that refuses.

### The passphrase is a file, and that is a security decision

`key_passphrase_file` is a required config key. Environment variables and argv
are readable by other processes; a file is not, and a systemd credential *is* a
file under `$CREDENTIALS_DIRECTORY`, so V4-11 points this at the credential and
changes nothing else. The daemon refuses anything that is not a regular 0600
file of at most 4 KiB, strips one trailing newline (every editor and
`systemd-creds` adds one), reads it into secure memory and wipes it the moment
`keyfile_open` returns. The KEK it returns is passed to `store_open` for the
audit key and wiped immediately after.

### The fuzz oracle was weak, and the probe is what found it

`fuzz_authd_conn` drives one slot in-process. Its oracle is the state machine's
invariants, not a re-implementation — predicting the stage for arbitrary bytes
would mean re-implementing `decode_client_hello` and the responder handshake,
which is two copies of one misunderstanding. The invariants: the stage never
moves backwards or skips a step; `SERVING` is unreachable by a decoy or without
a resolved user id (a decoy reaching `SERVING` would hand a login code to an
unauthenticated peer); a login is counted only on entering `SERVING`; and a
closed connection retains nothing.

The non-vacuity probe earned its keep. Deleting the handle wipe from
`conn_reset()` **did not** fail the oracle: the check tested `handle_len == 0`,
which the mutation left true, while the bytes stayed in the buffer. The oracle
now asserts `sodium_is_zero()` over the handle and user-id buffers themselves,
and the same probe fails it immediately. A wipe check that only reads the
length is not a wipe check.

### Three survivors in the first v48b run — three different things

Reported as the campaign actually ran. None was re-run to green, and the three
needed three different answers, which is the point of reading a survivor rather
than reacting to it.

**C4 (the `state` binding broken) SURVIVED — my SPEC was wrong, not the test.**
Zeroing `state_hash` still makes the code refuse a *different* state, so the
check the spec named kept passing. What actually breaks is the very next check:
consuming with the correct `SHA-256("")` now mismatches, so the code cannot be
redeemed at all. The spec now names that check. A mutation that is killed by a
test other than the one the spec names is a bookkeeping error, and the fix is
to the bookkeeping.

**C6 (the handshake not wiped on release) SURVIVED — a real gap in the test,
the same shape as V4-8a's D4.** The wipe test used a *successful* connection,
and on that path `session_init_from_handshake()` has already consumed the
handshake context, so `handshake_ctx_wipe()` is a no-op and its removal cannot
be observed. The path where it matters is a connection abandoned
**mid-handshake**: the context is still live, and wiping it is what CANCELS its
pending-ledger entry. That is not tidiness — at a 256-entry ledger, an
abandoned handshake holding capacity until its TTL is a denial-of-service
lever. The test now opens a connection, sends only the ClientHello, confirms
the ledger holds exactly one entry (canary), abandons it, and requires the
entry to be released immediately. C6 kills against that.

Twice now — D4 and C6 — a wipe has survived because the test exercised the path
where the wipe was redundant. The lesson is specific and worth stating: **test a
wipe on the path where something is still there to wipe.**

**C8 (the `decoy || no-user-id` guard before issuing a code) SURVIVED — an
equivalent mutant, and the guard stays.** It protects a state the rest of the
design makes unreachable: a decoy pin has no secret key, so no `sig_A` over it
can ever verify, and `store_lookup_active` never returns OK with an empty user
id. Nothing reachable through the daemon's interface can distinguish its
removal. Absent from `spec_v48b.txt` for the same reason N7 and D7 are, with
the reasoning in the campaign header so nobody "restores" it later. The
`fuzz_authd_conn` oracle asserts the same property as an invariant, which is
where it would be caught if a future change ever made the state reachable.

### What the pre-push Linux check found this time

V4-8a's lesson was "verify on Linux before pushing, not after". Doing that here
caught a real gcc error before CI ever saw it: `(void)system(...)` does **not**
silence gcc's `warn_unused_result` — the identical trap V4-5 fixed for
`symlink()` (finding F0). It was in the new `test_authd_conn.c` and, once
looked for, in two files already on `main`
(`test_authd_keyfile.c`, `test_authd_store.c`) that CI's gcc had not flagged.
All three now consume the result. Fixing the two out-of-scope files rather than
leaving known landmines is a deliberate departure from the declared file list,
reported here rather than buried in the diff.

Running the same check at `-O2 -D_FORTIFY_SOURCE=2` — which CI does not build
for gcc — surfaced a second, pre-existing issue: a `-Werror=format-truncation`
error in a V4-6 test helper. It is **not** fixed in V4-8b, because it belongs
to neither this step's code nor its scope; it is recorded as audit finding
**F19** and owned by V4-11, where a Release+gcc build is actually required.
The honest summary is that the project has a configuration nothing builds
today, and two findings now live in it.

### GitHub's scheduled runs lag by hours on this repository — measured

The nightly's cron is `17 3 * * *` (UTC). Observed, twice:

| cron slot | run actually created | lag |
|---|---|---|
| 2026-09-16 03:17 | 2026-09-16 **08:34** | 5 h 17 m |
| 2026-09-17 03:17 | not created within 2 h of watching | ≥ 2 h |

This is GitHub's documented behaviour — scheduled workflows are queued on a
best-effort basis and are delayed, or dropped entirely, when the hosted-runner
pool is busy; low-activity repositories are delayed the most. It is **not** a
configuration fault, and the cron path itself is proven: the 2026-09-16 run
fired and went green.

It is recorded because the failure mode is misreading it. A missing 03:17 run
is not evidence that the nightly is broken, and equally "the badge is green"
is not evidence that it ran *today*. Two things already guard against drawing
comfort from a nightly that silently stopped: the README's note that GitHub
disables a schedule after 60 days without a commit, and the fact that every
matrix row is also exercised by a push-triggered bring-up before it is merged.
When a nightly result is actually needed on demand, `workflow_dispatch` is the
reliable trigger, not the clock.

## V4-9a — the local API, tokens, and the first thing a site can actually call

V4-8b made the daemon serve a login code. Nothing could use it: no way to
exchange it, no way to verify a token, no way to enroll or revoke without
writing C against `store.h`. V4-9a closes that. A site can now `EXCHANGE` a
code for a token and `VERIFY` that token on every request, and the reference
handler under `examples/site-node/` does exactly that against a real daemon.

V4-9 is being built as **three sub-steps** (9a the API and tokens, 9b the two
CLIs and the e2e script, 9c rotation and recovery). One step carrying fourteen
socket commands, fifteen CLI subcommands, a new wire message and ~30 mutations
would not be reviewable, which is the same reason V4-8 was split.

### A second framing mode in the same loop

Spec §8 is line-oriented; the protocol listeners are frame-oriented. Rather
than a second loop or a thread, `conn_io` gained a MODE and the event loop a
second slot pool. The mode is not cosmetic: in FRAME mode the first four bytes
are a length, in LINE mode they are the start of a command, and confusing them
would make `PING` a 1 347 375 947-byte frame.

The local pool is **separate on purpose**. Sharing one would let a burst of
256 handshakes occupy every slot and lock the site out of `EXCHANGE` — the
site would be unable to finish a login exactly when logins are busiest. Two
pools make that impossible rather than unlikely.

`AUTHD_MAX_LISTENERS` went 2 → 4, and that was found by a test rather than by
reading: the daemon now needs loopback, proxy, site and admin, and the fifth
`add_local_listener` silently returned -1 while the socket file still existed,
so connections were accepted by the kernel and never served. The daemon now
prints which listener it could not register.

### Two dispatch tables, not one table and a flag

Req 11 says operator enrollment must be impossible from the site's uid **by
construction**. So `ADMIN_TABLE` and `SITE_TABLE` are separate arrays and an
administrative command is simply *absent* from the site one. There is no
conditional anyone can later invert. The refusal is deliberately identical to
the answer for a nonsense command, so the site socket is not an oracle for
which administrative commands exist — the test asserts the two responses are
byte-identical.

The uid allowlist is **config, not a constant**: `admin_uids` defaults to root
but can be set. An admin socket only root can reach is an admin socket that
never gets tested, and an untested gate rots.

### Hex everywhere, and what that buys

Every binary value on the wire is lowercase hex, including labels and reasons.
That means the protocol has **no escaping rules at all** — one decoder to get
right, one decoder to fuzz, and no way for a label to contain a newline and
split a response. `fuzz_localapi` asserts exactly that as invariant 2.

### Three spec gaps, recorded rather than invented away

1. **`not-permitted`** is returned for an unknown command and for an admin
   command on the site socket. §8 lists per-command codes and says "refused"
   without naming one.
2. **`ENROLL` has no `role=`**, so a new `user=` becomes a `user`-role user and
   `ENROLL-OPERATOR` an operator; an existing user is never silently re-roled
   (`role-mismatch`).
3. **List responses are bounded** at `AUTHD_LIST_MAX` (24) because a list is
   built in one buffer and sent as one reply; exceeding it answers
   `ERR code=too-many` rather than truncating. Streaming is a V4-10/V4-11
   option if a deployment needs it.

All three are recorded in `docs/v4/audit.md`. The spec is not edited to match
the code — that rule has held since V2-1 and holds here.

### What the tests and the fuzzer found

**The fuzz oracle was wrong before the code was.** Its first run reported a
"missing END line" on a perfectly correct `REVOKE-TOKENS` reply. The cause is
a real property of §8: `REVOKE-TOKENS` answers a single-line `OK count=N`, and
a list answers `OK count=N` … `END`. The prefix alone is ambiguous, and a
client must know which command it sent. The oracle is now command-aware, and
the Node handler decides the same way — which is exactly why it has a
`LIST_COMMANDS` set rather than sniffing the reply.

**The Node handler hung on that ambiguity for real.** A refused list command
answers one `ERR` line with no `END`, and the first version waited for `END`
forever — 24 seconds, until the fixture daemon exited. Found only because the
Node tests run against a real daemon rather than a mock.

**The fixture mixed two clocks.** The harness starts on a fixed fake clock
(which is what makes the C tests exact); the Node fixture then advanced real
time, so every login code was stamped in 2023 and instantly `expired`. It now
switches to real time *before* issuing anything.

**The audit-chain invariant was proven non-vacuous before being trusted** —
V4-8b's lesson, applied up front this time. A probe that made every refusal
also write an audit row fired the invariant with the right message. The first
placement of that probe was never reached (the seed failed on a short `pk`
before it), which is its own reminder that a probe must be shown to execute.

### Three survivors in the first v49a run — all three were the TESTS

Reported as it ran. None was re-run to green, and all three had the same
shape: the check passed for a *second* reason, so the mutation changed nothing
it could observe.

- **T2 (`VERIFY` never slides the idle window).** The test advanced past the
  original window and asserted expiry — but an unrefreshed token expires there
  too, so the assertion held either way. The discriminating moment is *after*
  the original window and *inside* the refreshed one: only a token whose window
  was actually slid survives it. That check now exists, and T2 dies on it.
- **X1 (duplicate keys accepted).** `VERIFY token=aa token=bb` is malformed
  because `aa` is not a 32-byte token, with or without duplicate detection. The
  test now duplicates a *well-formed* token, so the duplication is the only
  fault — and it carries a canary asserting that the same token alone is merely
  `unknown`, which is what makes the first assertion discriminating.
- **X2 (unknown keys ignored).** `VERIFY nosuchkey=aa` has no `token=` at all,
  so it is malformed either way. The test now sends a valid `token=` *plus* an
  unknown key.

The pattern is now familiar enough to name: **V4-8a's D4, V4-8b's C6, and these
three all survived because the test exercised a path where the mutation was
redundant.** A check only tests what it can distinguish. Writing the negative
case is not enough — the negative case has to fail for the reason under test
and no other, and the cheapest way to confirm that is a canary asserting the
same input fails *differently* when the rule is not the thing at fault.

## V4-9b — the two command-line tools, and the first login a person can perform

V4-9a made the local API real: a site could `EXCHANGE` a login code for a token
and `VERIFY` it. Nothing a human could run drove any of it. There was no way to
create a store, generate an operator key, enroll one, or log in except from a C
test harness. V4-9b adds `authd_admin` (12 subcommands), `authd_client`
(`keygen`, `login`) and `tests/authd_e2e.sh`, which performs the whole of
milestone A with the shipped binaries as real processes.

### Passphrases are files, and there is no prompt

The daemon's `key_passphrase_file` already said why: argv and the environment
are readable by other processes on the host, and a systemd credential *is* a
file under `$CREDENTIALS_DIRECTORY`. The CLIs use the same rule and the same
reader.

A TTY prompt was considered and deliberately not built. It is better for the one
case of an operator generating a key on their own laptop — the passphrase never
touches disk — but it would be the first termios code in the tree and the
prompt path cannot be covered by CTest without a pty, which would make it the
only security-relevant path in this project verified by hand. The interactive
passphrase experience is designed once, in V4-13, alongside the browser
client's, which needs the same strength rules and the same wipe discipline.

### `read_passphrase` became a library function, and grew an owner check

It was `static` in `authd_main.c`. Three copies of a custody rule is three
chances to relax one of them, so it moved to `authd_secret.{c,h}` and all three
callers share it. Two changes came with the move. It returns a status with a
name, because spec §13 requires every failure to print a status name from the
same enums the daemon logs and `"mldsa-authd: ... mode must be 0600"` is neither.
And it now checks `st_uid == geteuid()`, which spec §12's load order applies to
the key file and which the daemon's copy had never applied to the passphrase.
`LoadCredentialEncrypted` delivers a 0400 file owned by the service user, so the
deployment path this exists for is unaffected.

### `init` writes the passphrase, then reads it back, then seals

Spec §12 says the server passphrase is "32 random bytes from `authd_admin
init`". The obvious implementation — generate 32 bytes, seal under them, write
them out — has a defect that would have shipped: the reader strips one trailing
newline, so whenever the last random byte is `0x0A` the daemon derives its key
from **31** bytes and `keyfile_open` fails forever, with `init` having reported
success. One time in 256. At roughly a dozen full-suite runs per mutation
campaign that is a ~5% chance of one inexplicable `decryption-failed` per
campaign, which is precisely the kind of failure that gets blamed on the test.

So `init` writes the file first, reads it back through the shared reader, and
seals under *that* buffer. The same ordering is what makes `init`'s second
Argon2id worth its second second of CPU: the reopen verifies the
file-to-key binding rather than re-deriving an answer already known.

`init` also refuses if the key, the store **or** the passphrase file exists, and
names which. This is not tidiness. `store_open()` succeeds on an existing store
and derives `key_audit = HKDF(KEK, store_id, …)`; a second `init` with a
different passphrase derives it from a *different* KEK, every subsequent audit
row chains under the wrong key, and `store_audit_verify()` fails permanently —
with nothing reported at the moment of damage. The command is not resumable and
says so, printing the exact paths to remove.

### Req 10 forbade the obvious reuse

`demo_keys_generate_files()` writes the plaintext `MLDSASK2` file
unconditionally. Spec Req 10 says no plaintext secret key is written to disk by
any daemon or CLI command, so none of the three keygen paths can use it. They
build the image in `secure_mem`, seal it with `keyfile_seal()`, and publish the
public half through a new `demo_keys_write_public()`.

The reason this needs its own check rather than a code review is that **every
functional check still passes if it is violated**: the `.ek` and `.pub` are
correct, enrollment works, login works. Mutation `K1` adds the plaintext write
and is caught only by a directory scan for the `MLDSASK2` magic.

### One framing rule, three consumers

Spec §8's replies cannot tell you how to read them:

- `REVOKE-TOKENS` answers `OK count=N` on ONE line, exactly like a list
  *header*. A reader that waits for `END` on any `OK count=` hangs on it.
- A **refused** list command answers a single `ERR code=` line with no `END`, so
  a reader that always waits for `END` on a list command hangs on that. That one
  is not hypothetical: it hung the Node handler's own test suite for 24 seconds
  in V4-9a.

The caller knows which command it sent, so that is what decides.
`localcli_is_list_command()` is now the single authority, and
`tests/authd_harness.h` was moved onto it — its own copy classified any
`OK count=` reply as a list, which is wrong and survived only because no test
had ever sent `REVOKE-TOKENS` through it.

The mutation that proves this (`L1`) is the one worth describing, because the
first draft of the plan would have let it survive. Adding `REVOKE-TOKENS` to the
list table causes a hang — but no `authd_admin` subcommand issues that command,
so no CLI path reaches it. The check therefore had to be **table-level**:
`test_authd_cli` sends every probe command to a live daemon through
`h_local_drain()`, which applies no framing rule at all, measures whether the
reply really ends with an `END` line, and requires the table to agree. It also
requires both `OK count=` shapes to have been observed, so the test cannot pass
against a table that is a constant.

### Three defects fixed, and a fourth found by running the thing

Planning found three defects in existing daemon code, all recorded as F21–F23:

- **The server key was left unwiped on two listener-failure paths.** They did
  `free(slots); return 1;` while the decrypted ML-DSA secret was live in secure
  memory — a Req 2 violation — while the four sibling paths for the local
  sockets correctly `goto listener_failed`, whose epilogue wipes and frees
  everything. An inconsistency, not a missing epilogue.
- **`admin.sock` was 0660**, where §8 says 0600. The uid allowlist still refused
  a stranger, so nothing was exploitable; the second layer is the point.
- **A configuration failure exited 1**, where §13 says 3.

A fourth appeared only when the new `backup` command was run and its output
looked at: `store_backup` used `VACUUM INTO`, which creates the destination with
the **daemon's** umask — 0644 from an interactive shell. A backup is a
byte-for-byte copy of the credential database. It is now 0600, like the store it
copies (F24).

`R1`, the mutation for the key-wiping fix, could not rest on a leak detector:
LSan does not run under macOS ASan, and this project's campaigns run locally.
What the epilogue *also* does is close and unlink every socket it already
created, and that is observable on both platforms and true exactly when it ran.
The e2e starts a daemon whose admin socket path is a regular file — a realistic
leftover after a crash, which passes every configuration check because its
directory exists — and requires the other two sockets to be gone afterwards.

### One config validator with two entry points

§13 lists `--check-config` under `authd_admin`; the daemon already had it. The
answer is not a second implementation: two validators drift, and the one an
operator runs before starting the service would then approve a configuration the
one that matters rejects. `authd_admin --check-config` calls the same
`authd_config_load()`, and both binaries call a new shared
`authd_config_check_paths()`.

That function exists for one case in particular. `AUTHD_PATH_MAX` is 255 while
`sun_path` is 104 bytes on macOS and 108 on Linux, so a configuration with a
long socket path passed every byte-level check, `--check-config` said "valid",
and the daemon then failed to bind (F28). Mutation `C2` gives `authd_admin` its
own parser; it is killed by comparing both binaries' exit code *and* the exact
status name across six different malformed configurations, because a second
parser agreeing accidentally on one input is the whole failure mode.

### Responses are printed as hex, on purpose

Identifiers and labels are hex on the wire and this tool prints them back as
hex. Spec §3.2 calls them attacker-influenced strings that must be escaped
anywhere they are displayed; printing the hex means there is no display decoder
to get wrong and no terminal-escape hazard at all. It is worse to read and
`xxd -r -p` decodes one value when an operator wants it. This is also why V4-9b
adds **no fuzz target**: the only new parse is `localcli`'s response reader,
whose input is the local daemon over a 0600/0660 socket on the same host, and it
is deliberately shaped so there is nothing to get wrong — bounded lines, `END`
compared as a whole line rather than as a substring (`detail=` is the one field
`localapi` does not hex-encode), and the first token deciding the exit code.

### The handle is the authority, not the file

`enroll-operator` requires `--handle` and validates the `.pub` against it, so a
`.pub` whose embedded id disagrees is `id-mismatch`. This is V2-9's rule —
migration must not be the one path that trusts a file's own label — applied to
enrollment: taking the handle from the file would let a renamed or swapped
`.pub` silently enroll a different device under the operator's user. Mutation
`E1` does exactly that, and the check asserts the **status name**, because
"non-zero" also means "file not found".

### Not done, and named

`authd_client rotate` and the recovery flow are V4-9c, so the subcommand is
absent rather than stubbed; the usage string says which step brings it. There is
no `ping` subcommand: §13 does not list one, and `list-users` serves as the
end-to-end script's readiness probe without inventing a command the spec does
not have. Five further spec gaps are recorded as F25–F29 rather than resolved by
editing the spec — including F29, that `store_audit_verify()` is reachable from
nothing, so a deployed operator cannot check their own audit chain. That one
deserves the errata step's attention most.

### The first campaign run had four survivors, and all four were mine

Reported because the pattern is worth more than the outcome. None of the four
was a defect in the code under test; each was an error in how the campaign was
written, and two of them repeat mistakes this file already records.

- **C1** — the expected-failure text began with `--check-config`, and the runner
  matches expectations with `grep -F "$w"`, which read the leading `--` as an
  option and errored out. V2-7's R3 established "no expectation string begins
  with a dash" and it is written down in `tools/README.md`. Writing it down was
  not enough; the fix is that the string no longer starts with one.
- **K1** — the mutation wrote its forbidden plaintext key to `/tmp`, while every
  Req 10 scan looks inside the directory under test. A mutation that lands
  outside the observer's field of view is not a weak check, it is no check. It
  now writes the copy beside the sealed key, which is also the defect a real
  implementation would have.
- **P1** — the expectation named `init` returning 0, but the mutation leaves
  `init` succeeding: it corrupts the passphrase buffer *after* the read-back and
  then uses that same buffer for its own verification reopen, so init verifies
  against the corruption and is satisfied. The check that actually
  distinguishes it is the test's INDEPENDENT reopen with the bytes the file
  holds — which is the check written for exactly this, aimed at the wrong
  target in the spec.
- **P2** — writing the passphrase file 0644 is caught *earlier* than intended,
  because `init` reads the file back through the same custody-checking reader
  the daemon uses, so the file is refused before anything is sealed and the
  e2e's mode assertion never runs. That is the system working; the spec now
  names the refusal that happens rather than the one that was predicted.

C1 and P1 are both the recurring shape named in V4-9a — *a check only tests what
it can distinguish* — arriving from the other side: not a check that passes for
a second reason, but a spec entry pointed at a check that cannot see the
difference. The campaign catching all four before the commit is what the
campaign is for; a mutation suite whose first run is perfect is usually a
mutation suite that is not asking anything.

### The Linux gate found three more, and one of them only at `-O0`

The pre-push Linux matrix — clang and gcc, `-O0` Debug and
`-O2 -D_FORTIFY_SOURCE=2` Release — refused this step's first two attempts.
All three defects were in code written for V4-9b, none was visible on macOS, and
two of them are classes this file already names:

- `tests/test_authd_cli.c`, `(void)fread(...)`: **the `(void)` cast does not
  silence gcc's `warn_unused_result`.** That is F0, verbatim, from V4-5 — where
  the same mistake was found in `(void)system(...)`. The fix is the same: use
  the result. Here it became a real assertion, because a short read would have
  compared uninitialised bytes against spec §12's parameters and the test would
  have been lying about what it checked.
- `tests/authd_harness.h`, `snprintf(a.sun_path, …, "%s", path)`:
  `-Werror=format-truncation` at `-O2`. That is F19's class, and gcc is right —
  a truncated `sun_path` connects to a *different socket*. Replaced with an
  explicit bound, the same one `net_connect_unix()` applies.
- `tests/test_authd_cli.c:413`, another `-Werror=format-truncation` — and this
  one fired at **`-O0` but not at `-O2`**, because gcc's value-range analysis
  differs between them. It is the single best argument for checking both
  optimisation levels rather than assuming the stricter one subsumes the other.

The invocation itself also improved. Earlier steps passed `-DCMAKE_C_FLAGS` and
left `CMAKE_BUILD_TYPE` at its default; this run sets Debug and Release
explicitly, which is what the deployment actually builds and what surfaced two
of the three. The gcc Release suite is now run on Linux as well, not just built.

### The nightly caught three rotted anchors, which is what it is for

The first scheduled nightly after V4-9a went **red**, and the cause was V4-9a
itself. Three mutations in already-wired campaigns no longer matched anything:

```
v47   S6: FATAL apply: anchor for S6 matched 0 times in apps/authd/store/store.c
v47   S8: FATAL apply: anchor for S8 matched 0 times in apps/authd/store/store.c
v48a  D4: FATAL apply: anchor for D4 matched 0 times in apps/authd/evloop.c
```

V4-9a rewrote `store_consume_login_code` into its `_ex` verdict form, replaced
`store_verify_token` with a joined verdict lookup, and gave `evloop`'s slot
release a mode to restore — and each edit moved or dissolved the exact text an
older mutation patched. Nothing about the *properties* changed; the anchors
pointing at them did.

Two things are worth stating. First, this is the failure mode working: a rotted
anchor is `FATAL`, not a silent `SURVIVED` and not a silent pass, so the gate
went loudly red rather than quietly proving less than it claimed. Second, **the
local campaign could not have caught it**: a step runs its own campaign, and
v47/v48a are not its own. The nightly running *every* committed campaign is the
only thing that sees a step damage an older one — which is precisely the
argument V3-4 made for committing campaigns and running them all, now
demonstrated rather than asserted.

The repair, in V4-9b: S6 and D4 re-pointed at the current code and each
re-verified by an actual campaign run (S6 killed by 3 named checks, D4 by 2,
residue 0, artifacts restored). **S8 was retired rather than re-pointed**, with
the reason in `mutate_v47.py`: the token lookup no longer filters on expiry in
SQL, so the string it patched exists nowhere, and the property it guarded is
now guarded by v49a's T3 against the replacement check. Re-pointing it would
have produced a duplicate of T3, which proves nothing twice. The committed
total is therefore 110, not 111.

## V4-9c — key rotation, and what the spec could not say

A device's key was permanent. Suspecting a laptop key had leaked meant
revoke-and-re-enrol: a new handle, an administrator, every token gone. V4-9c
lets a device replace its key and keep its identity, with proof of possession
of both keys and no window in which two keys authenticate.

This is the step `formal/authd.pv` was written for. P5 —
`inj-event(rotated) ⟹ inj-event(rotateRequested)` — was proven in V4-4 with two
ablation controls (`rot_hsid.pv`, `rot_sigold.pv`) that make it fail. V4-9c's
job was to make the C match that model. Worth noting where the model is
*weaker* than the spec: its `mrot` is `(hsid, A, pk_old, pk_new)` and omits
`flags` and `handle_len`, which §6.3's `M` includes. The model therefore proves
nothing about those two fields, and mutation W1 exists because of it.

### The digest cannot be tested by a round trip

The client that signs and the daemon that verifies share one
`authmsg_rotate_digest`. Any error in it moves both sides together and they
still agree — so a "rotation works end to end" test kills no digest mutation at
all. What kills them is a hand-built literal vector, spelled out field by field
from §6.3 with the label as literal characters, and a test that transmits
something different from what was signed. Both are in `test_authd_conn`, and
W1, W2 and W5 are the mutations that would otherwise have sailed through.

### Two of the spec's acceptance steps are unimplementable as separate checks

`pk_exists` is `SELECT 1 FROM device_keys WHERE pk=?1` across **all** states.
It therefore already covers "`pk_new` unused by any device, in any state" and,
because `pk_old` is itself a row, "`pk_new ≠ pk_old`". A daemon-side pre-check
for either would be a branch no end-to-end test could distinguish: delete it and
the request still fails, with the same coarse code, closing the same way. The
daemon has neither, and the campaign declares both as equivalent mutants rather
than pretending to kill them — the register v48a's D7 and v48b's C8 established.

### Every rejection is one error code, and the residual is recorded

Handle mismatch, key already in use, either signature, the store's refusals —
all `ERROR(0x03)`. A distinct code for "that public key is already enrolled"
would hand any authenticated user an oracle for the deployment's whole key set:
the cross-device twin of the enumeration §7.3's decoy flow closes. The
fine-grained reason goes to the operator's journal and never to the peer.

What that does **not** fix is timing: §6.3 orders the cheap store query before
the ~100 µs signature verification, so "in use" is still distinguishable by
elapsed time. Reordering would contradict the spec, so it is recorded as F37
rather than silently deviated from.

### Three defects the design walked into, and one found by running it

- **`store_rotate_key` would have rotated a revoked device's key** (F30).
  `active_key_of` joins nothing, so §6.3's "confirm device and user are still
  active" could only have been a caller-side pre-check — and `authd_admin` is a
  *different process* writing the same file, so that is a race, not a check.
  **Req 9 would have failed.** The predicate now runs inside the transaction
  that commits.
- **A session established before a rotation could rotate afterwards** (F31),
  superseding a key its signatures said nothing about. Found while writing the
  mutation table: W4 had no way to fail, which meant the property it was
  supposed to guard did not exist. `store_rotate_key` now pins the expected old
  key inside its transaction.
- **8612 is not the maximum ROTATE.** The spec quotes it "with a 34-byte
  handle"; `handle_len` is 1..64, so the real maximum is 8642, and a buffer
  sized from the quoted figure overruns by thirty bytes. Both constants are
  pinned, under names that say which is which.
- **The first working `rotate` wrote the device's new public key into the
  *server's* directory** and left the device's own `.pub` naming the old key.
  Found by rotating a key and looking at the files, not by reading the code —
  the same way V4-9b found the world-readable backup.

### `.ek.next`: the spec's rule inverted, because the spec's rule is unobservable

§10.2 says: "if it is unknown, the server never committed". Req 6 and §7.3
guarantee the client **cannot** tell unknown from revoked from bad-signature —
every one of them pins the decoy and fails at the same point. "Unknown" is not
observable, so that inference is drawn from something the client never learns.

The implemented rule is the contrapositive on the other file, and it is
stronger:

> **`.ek` authenticating proves the server did not commit** — there is exactly
> one active key per handle — and only then may `.ek.next` be discarded.
> **`.ek.next` failing proves nothing.**

So nothing is ever deleted on ambiguity. The asymmetry is the whole argument: a
stale file costs one confusing directory entry; a wrong delete costs the only
copy of a live key, and there is no recovery from that but re-enrolment. Both
crash windows were exercised by hand — a `.ek.next` the server never saw (the
client falls back and keeps it) and a `.ek.next` the server committed (the next
`login` completes the rename). `login` runs the probe too, because every
invocation of a CLI *is* a startup, and `login` is the command that will
actually find an interrupted rotation.

`keyfile_promote` is the one function in this project that overwrites a key
file. §12 says "never in place, never clobbering" and §10.2 says "renames it
over the current file"; the more specific rule wins here, and the contradiction
is recorded as F34 rather than resolved by editing either section.

### `rotation_due` is config, not an invented constant

§6.2 defines the flag; neither §10.2 nor §17 defines a cadence. Rather than
hardcode a number and bury it in a comment, `rotation_due_age_s` is an operator
policy with a default of 180 days and `0` meaning "never hint" — so the
invented number is visible, bounded by the config parser, covered by
`fuzz_authd_config` for free, and recorded as F36. Its input comes from a
separate `store_active_key_age()` rather than a widened `store_lookup_active`,
because that function runs on an *unauthenticated* ClientHello on the code path
whose entire job is to look identical for a real and a decoy identity.

### One exit, one wipe

`on_record` now dispatches to a handler with eight rejection paths. If each
returned directly, each would be a separate place to forget
`sodium_memzero(pt, …)`, and a mutation deleting one of them would be
unkillable by any test and invisible to a sanitizer. There is one `goto done`
and one wipe. That is also why no mutation targets it: with the single-exit
shape there is nothing observable to break, and the shape *is* the mitigation.

### One mutation survived, and it was the right kind

`W6` removed the explicit handle-equality check from `on_rotate` and the
campaign still killed nothing. That is not a gap; it is the design being
stronger than the check.

The daemon digests `c->handle` — the handle that **authenticated this session**
— never `m.handle` from the message. A ROTATE naming a different handle
therefore produces a digest over the session's handle, which the peer's
signature (made over the handle it named) cannot match, and it is rejected one
step later by `sig_old`. **The handle binding is cryptographic, not a
comparison.** The explicit check remains, because it gives the operator a
precise journal line and skips a pointless ~100 µs signature verification — but
nothing observable changes without it, so it is recorded as an equivalent
mutant rather than campaigned, in the register v48a's D7 and v48b's C8 set.

The mutation that *would* be meaningful — digesting `m.handle` instead of
`c->handle` — is not a defect in this code but a different and worse design: it
would let the peer choose what its own signature is bound to.


### The end-to-end script gains the one rotation check no C test could make

`authd_e2e.sh` now rotates a key with the shipped binaries as real processes:
the store's reported fingerprint changes, the handle does not, there is still
exactly one device, the rotated key logs in, the superseded one gets no login
code, the rotation is audited **with a user attributed to it**, and the daemon
logged both fingerprints per §15.

One of those checks exists because of a defect found by running the thing
rather than by reading it: the first working `rotate` left the device's own
`.pub` naming the superseded key. Nothing in a C test can see that — the
rotation succeeds, the daemon is correct, the next login works — and the next
administrator to enrol from that file would install a key the server has
already superseded. It is now mutation **W15**, the one v49c row killed by the
end-to-end script.

The `.pub` fingerprint is extracted with `dd`, not `xxd`: `demo_e2e.sh` avoids
`xxd` deliberately, because it ships in a vim package rather than a base image.

### A flaky gate is worse than a missing one, and this one had been leaking for three steps

Re-running v49c after the e2e rotation leg landed, mutation W4 reported
`CLEAN-SUITE=FAIL(BAD)`: a test failed on **restored, unmutated** sources. That
is the single most misleading verdict a campaign can produce, because it looks
like the step under test broke something.

It had not. `tests/authd_node_fixture.c` built its temp directory as
`/tmp/authd-node-<pid>` and removed it with a best-effort `rm -rf`, so every run
that was killed — every interrupted campaign, every `Ctrl-C` — leaked one. Once
the OS reused that pid, `mkdir` failed and the fixture exited immediately, about
a second in. There were **1,214** of them on this machine by the time it
surfaced, accumulated since V4-9a.

The fix is `mkdtemp`: the name is unique *by construction* rather than by hoping
the cleanup ran, which is exactly why `demo_e2e.sh` and `authd_e2e.sh` use
`mktemp -d`. The C fixture had been the one place that did it the other way.

Two things worth keeping from this. First, the campaign found it — a flake that
only shows under load, in a test that passes six times out of six in isolation,
surfaced because something runs the whole suite a dozen times in a row. Second,
`restored=clean | CLEAN-SUITE=FAIL(BAD)` is a verdict shape worth recognising on
sight: the sources are provably back, so the failure is the *suite's*, not the
mutation's.

## V4-9d — recovery, and the cost of being able to get back in

A device's key could be replaced (V4-9c) but only from a device that still
worked. Lose it and the identity was gone: for the operator who *is* the
administrator, a locked door with the key inside. §10.3's answer is recovery
codes — 80 bits on paper, one of which buys a ten-minute enrollment ticket.

### The blocking KDF is accepted, and now it has a number

§10.3 puts recovery codes behind `crypto_pwhash_str` at ops 2 / 64 MiB. The
daemon is one process, one thread, one `poll()` loop (V4 decision 2), and
`localapi_on_line` runs inline from `slot_readable` — so a verification loop
stops the world while it runs. That was accepted in planning on condition it be
measured. Measured, natively, at the spec's parameters (Apple M4 Pro, `-O2`):

| | |
|---|---|
| one `crypto_pwhash_str` | **53.8 ms** |
| one `crypto_pwhash_str_verify` | **51.4 ms** |
| `RECOVERY-ISSUE count=16` | **0.86 s** |
| `RECOVERY-USE`, worst case (16 unused, no match) | **0.82 s** |
| `RECOVERY-USE`, typical (10 codes, match at the 5th) | **0.26 s** |

The only figure the project had before this was **111.5 ms for Argon2id(3,
64 MiB) in wasm** (V4-2 S6) — a different parameter set on a different runtime,
and no basis for a claim about the daemon.

What makes 0.82 s defensible is not its size but that it is *bounded*, on three
independent sides, each of which is a mutation:

* **at most 16 unused codes**, because issuing supersedes the previous
  generation. Left additive — which is what §10.3 literally permits, since it
  says nothing — the loop would grow by `count` on every re-issue and the
  measurement above would describe nothing. (G9)
* **at most 5 attempts per hour**, the §10.3 lockout. (G5, G6)
* **the lockout is read before any hashing**, so a locked user costs zero. A
  lockout enforced after the loop returns the identical error code while still
  spending the second — which is the entire thing it exists to prevent. No
  status can tell those apart, so `authd_app_t` carries `recovery_kdf_calls`
  and the test asserts on the counter. (G4)

Remove any one and the bound is gone. The honest residual is recorded as
finding **F39**: a handshake already near its 10 s deadline can be timed out by
someone else's recovery attempt, because deadlines are judged against a clock
captured before the handler ran. Threads, a work queue and a KDF helper process
were all rejected as contradicting V4 decision 2; if the daemon ever serves
more than operators this is V4-10/V4-11's problem, stated rather than deferred
silently.

### Crockford base32, and where normalisation lives

§10.3 fixes the shape (10 bytes, 16 characters, 80 bits) and names no alphabet.
Crockford is chosen because this is the one value in the system a human reads
off paper and retypes, possibly months later, possibly having just lost their
only device: it omits I, L, O and U so the confusable shapes are never *issued*,
and its decoder nevertheless accepts `I`/`l` as 1 and `O` as 0, in either case,
ignoring `-`. 80 bits is exactly 16 symbols, so there is no padding and a
16-symbol string decodes and re-encodes to itself — which is why normalisation
is a per-character map and why there is no `base32_decode()` for the daemon to
get wrong.

**What is hashed is the canonical string**, and normalisation lives in the
daemon beside the hash — never in the site's JavaScript. Two sites that
normalised differently would disagree about what a code *is*, and the user
would be locked out of their own recovery codes by a bug in a language the
daemon never sees. `examples/site-node/authd.mjs` says, in as many words, to
pass the code through verbatim.

The encoder is pinned by literal vectors (`00 44 32 14 c7` → `01234567`, and a
20-byte vector that renders the alphabet in order), because a round trip cannot
catch a wrong alphabet: encoder and normaliser share one table, so a wrong one
moves both together and the code still verifies against its own hash. (G3)

### Base32 text on the wire, and why that does not break §8's one-decoder rule

`localapi.h` states that binary values are lowercase hex so that "there are NO
escaping rules anywhere in the protocol". §8 nevertheless specifies
`OK codes=c1,c2,…` and `code=`, which are text. Both hold at once: the
Crockford charset plus its tolerated confusables is a subset of `[0-9A-Za-z-]`,
which contains no comma, space, LF or `=`, so a comma-separated list of codes
is unambiguous without an escaping rule. The header comment now says so rather
than contradicting the code.

### Verify outside the transaction, mutate inside

§9.3 requires code use to be exactly one transaction. Holding a write
transaction open across 0.8 s of KDF work would block every other store
operation for that time, so the verification runs outside and
`store_recovery_consume` re-checks inside the transaction what the caller
checked outside it: the row is still unused *and* still this user's. A code
spent by another connection in the meantime comes back as `invalid`, which is
also what a wrong code returns — the right answer either way. A fault point
inside that transaction proves the alternative is impossible: a crash between
"code spent" and "ticket issued" would cost the user their one way back in and
hand them nothing. (G7, G8)

### The four V4-7 primitives were deleted, not kept

`store_add_recovery_code`, `store_mark_recovery_used`, `store_add_ticket` and
`store_consume_ticket` were added in V4-7 as "primitives; policy in V4-9".
V4-9 decided the policy is transactional, and the pair did not compose in any
case: the adder returned no `code_id`, the marker required one, and **nothing
could enumerate a user's unused codes at all** — the one operation
`RECOVERY-USE` is made of. All four were uncalled by production code and
untested. Keeping them would have left a second, non-atomic way to do the same
thing, so they were removed and replaced by six functions that own their own
transaction boundaries. This is wider than the plan's "delete the two that
cannot be called safely"; the other two became unreachable for the same reason
and are recorded here rather than left as dead API.

### An operator's recovery is administrative (Req 11)

Found by the e2e, because its user happened to be an operator. `RECOVERY-ISSUE`
and `RECOVERY-USE` live in the **site** table — the site is what a locked-out
user reaches — but `ENROLL-OPERATOR` is deliberately absent from it. Without a
rule, a compromised site process could issue itself an operator's recovery
codes, spend one, and redeem the ticket for a device it controls: exactly the
escalation Req 11 exists to prevent, reached by a different door. Both commands
now refuse an operator user on the site socket. The ticket's own role check is
not sufficient on its own, because it refuses only at the last step — by which
point the codes have been minted. Recorded as **F43**; §10.3 says nothing about
it and should.

### Two gates found their own defects before the campaign did

`fuzz_localapi`'s standing invariant — an `ERR` never advances the audit chain —
fires on a failed `RECOVERY-USE`, and correctly: that row *is* the failure count
the lockout is built on. Rather than punch a hole in the invariant, it was split
in two: for `RECOVERY-USE` answering `invalid` the chain **must** advance, and
for everything else it must not. A change that silently stopped counting
failures — a lockout bypass — now fails the fuzz target. The new assertion was
then proven non-vacuous against a deliberately broken build.

Its first ASan run immediately found a bug in that new assertion: the condition
matched `user=` by substring, so the mutated line `user=753167` — a *different*,
nonexistent user whose hex merely starts with `7531` — satisfied it. Now the
whole token is compared. A prefix test in an oracle is the same class of defect
as a prefix test in a parser.

Two vacuous passes were caught by their own present canaries while the tests
were being written: a store scan that found neither the plaintext nor any
Argon2id hash (WAL mode — the row was in the `-wal` file), and an `ENROLL`
request truncated by a 1024-byte buffer against a 3904-character public key,
which made "via=site with a ticket is malformed" pass for entirely the wrong
reason.

### What the spec could not say

Four items for the errata step, in addition to V4-9c's four: §8 gives
`RECOVERY-ISSUE` no error codes (**F42**); §10.3 does not say whether re-issuing
supersedes (**F44**, decided here); §10.3 does not say that an operator's
recovery is administrative (**F43**, decided here); and §15 names
`log_identities` and `log_client_ip`, which exist nowhere, while its promised
field vocabulary does not match what is emitted (**F46**).

## V4-10a — WebSocket, and three bugs a fuzzer found before a browser could

Milestone A could log in, rotate and recover — over a raw frame stream on a
loopback socket reached through an SSH tunnel. It could not face a browser.
V4-10a puts the browser transport in front of the same protocol: spec §6.5's
framing rides inside WebSocket binary messages, and `src/` does not change by
a byte.

### The shape the code already wanted

Two findings made this far smaller than the roadmap implied.

**No new listener.** `listen_unix` was already "the proxy-facing Unix socket"
and already carried the marker `V4-10 adds the proxy uid check`. It becomes the
WebSocket listener; the loopback port stays raw for the operator's tunnel. That
matters because `AUTHD_MAX_LISTENERS` is 4 and all four were consumed, and
exceeding it is a *silent* no-service that already cost V4-9a a debugging
session.

**No third slot kind.** §7.1 says "one reassembler serves both the WebSocket
listener and a raw listener", and `conn_io` already dispatched on a `mode` in
exactly the three places a third needs. `CONN_IO_MODE_WS` leaves
`slot_readable`, `take_slot`, both `pool < 2` loops and the `on_frame` callback
untouched; a third `slot_kind_t` would have touched ten sites in `evloop.c`.
The output side needed nothing either: the write path goes through
`conn_io_pending/_ptr/_sent`, so giving the WS handshake and control replies
priority *there* is the whole integration, and `slot_writable` is unchanged.

### A vendored SHA-1, and why that sentence is not as bad as it reads

RFC 6455 fixes the accept value as `base64(SHA-1(key ‖ GUID))`. libsodium
1.0.22 ships SHA-256, SHA-512, SHA-3, BLAKE2b, HMAC and HKDF and **no SHA-1**;
the project links no OpenSSL; and Caddy has no "WebSocket in, raw stream out"
mode, so the daemon must complete the handshake itself. There was nothing to
choose between.

It is not a security primitive here and RFC 6455 §1.3 does not treat it as one:
no secret enters it, nothing is authenticated by it, and its collision
resistance is irrelevant to every property this daemon claims. Its job is to
prove the server actually read the client's header, so a caching intermediary
cannot be tricked into replaying a non-WebSocket response. **Scope is the
control**: it is `static`-scoped to the WS layer, `git grep sha1` should only
ever find `ws.c`, and it is pinned by FIPS 180-1's three published vectors and
RFC 6455's own worked example (`dGhlIHNhbXBsZSBub25jZQ==` →
`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`). Recorded as finding F53.

### `state` became real, and cost no new storage

`authd_conn.c` hashed a literal `SHA-256("")` and said in a comment that V4-10
would give the WebSocket listener a real value. It now hashes the slot's state
— which lives in the slot's `conn_io`, where the upgrade parser put it. There
is no second copy to keep in step and nothing extra to wipe, because
`conn_io_reset` already zeroes it. The verifying half needed no change at all:
`h_exchange` already hashed whatever the site presented and
`store_consume_login_code_ex` already returned `STORE_CODE_STATE_MISMATCH`.
Req 5's login-CSRF binding is therefore real on the only transport a browser
uses, and still the empty string on the tunnel, which has no URL to carry one.

### Three bugs, all found by fuzz_ws, none by the tests

This is the part worth reading.

`fuzz_ws` drives `conn_io` in WS mode — the upgrade parser, the frame decoder,
the unmasking and the frame reassembler in one place — and its oracle is
**self-consistency**: feeding the input in one push and one byte at a time must
produce the same frames and the same verdict, because §7.1 says message
boundaries on input are irrelevant.

1. **A request split across reads poisoned the connection (F50, High).**
   `conn_io_next_frame()` calls `note_header()`, and the event loop calls it
   after every read — so a buffered `"GET "` was read as a 1195725856-byte
   frame length. `push_ws` already knew not to interpret those bytes; the
   second caller did not. It only appears when the request arrives in more than
   one read, which is what a real network does as soon as the request crosses a
   segment boundary. **Every hand-written test wrote the request in one
   `write()` and passed.**
2. **An upgrade pipelined with its first frame was refused (F51).** The
   4096-byte cap was applied to the whole buffered stream rather than to the
   header block.
3. **Bytes after a Close were dropped in one push and an error in the next
   (F52).** Both safe, but disagreeing — and a coalescing proxy turns that into
   a spurious protocol error in the operator's log.

None of these is exotic. All three are what a proxy and a real network do
routinely, and all three would have shipped.

### The oracle was wrong once, and that is recorded too

Between (1) and (2) the target flagged a divergence that was **the oracle's
fault, not the code's**: the harness drained frames between pushes, so
byte-at-a-time freed buffer space that one big push did not, and the two runs
legitimately hit capacity at different points. The first fix weakened the
assertion to a common-prefix comparison — and that was worse, because a
probe (a mask offset that fails to carry across a split payload) then passed
undetected: the broken run failed early, leaving a zero-length prefix that
compared equal. The real fix was to remove the asymmetry rather than the
assertion: nothing is drained between pushes, both runs hit every bound at the
same point, and the comparison is exact again. An oracle that states more than
it can justify is a false alarm waiting to happen; one that states less is a
bug waiting to ship.

### Scope taken deliberately, and declared

`authd_client` learned to speak WebSocket. The plan had the e2e move to a
loopback port instead, which would have needed a fixed port (a CI collision
risk, since `listen_port = 0` means *disabled*, not ephemeral) and would have
left the new parser tested only in-process. Teaching the CLI instead keeps
`authd_e2e` exercising the shipped binaries over the real transport — a full
post-quantum login, plus the rotation and recovery legs, now run over
WebSocket across real processes. The cost is one client-side reader, and it
lives in `ws.c` so the CLI, the test harness and the fuzz target share it
rather than growing three copies.

The CLI's first draft had its own bug worth recording: it read the opcode out
of `h[0]` *after* the extended-length read had overwritten `h`. It surfaced on
the 4545-byte ServerHello, the first message long enough to need a 16-bit
length — which is to say, on the first real message, not on a contrived one.

### What V4-10b owes

The proxy's uid check (`authd_main.c` still says so in a comment), PROXY
protocol v2 fail-closed, the rate limiter — whose numbers the spec does not fix
anywhere, so they become bounded config keys — the Caddy configuration, and the
nightly bring-up that also discharges **v49d**, **v50a** — this step's own
campaign, which is owed a bring-up exactly as v49d is — and
**`tools/audit/check_mutation_anchors.py`**, which V4-9d committed and wired
nowhere. That tool earned its keep during this step: it caught v48b's C4 anchor
rotting against the `state` change *before* the campaign ran.

## V4-10b — the client's address, and the first thing that can say no

V4-10a gave the daemon a browser-shaped transport. It did not give it any
reason to refuse one. The proxy-facing listener accepted **any** uid — the
`(uid_t)-1` sentinel makes `listener_accept_ex` skip the credential check
entirely — the daemon had never in its life obtained a client address (audit
finding **F10**, open since v1), and there was no rate limit of any kind
(ledger item **A4**, listed as blocking this deployment).

That last one is not a comfort feature. §7.3's uniform responder flow pins a
decoy public key for every identity that is not active and signs a real
`ServerHello` anyway, so that an unknown handle is indistinguishable from a
known one. The spec states the consequence in one sentence and then walks away
from it: *"This costs one signature per probe, which is the rate limiter's
problem."* Until this step, nobody owned that problem — one connection, one
ML-DSA-65 signature, no ceiling.

### Where the decision has to be taken, and why it could not be anywhere else

The limiter has to fire **before** `handshake_responder_create_server_hello`,
or it has already paid for the thing it exists to stop. The client's address is
known the moment the PROXY v2 preamble completes, which is strictly before the
HTTP upgrade and long before the first frame — so that is where the decision
goes, and `evloop` gained exactly one new callback (`on_addr`) to report the
moment. The loop reports; it takes no view. Whether a missing address or a
spent token means refusal is policy, and policy lives in `authd_conn.c` with
the log line that explains it.

The pin for "before the signature" is the pending ledger:
`create_server_hello` is what inserts into it, so an empty ledger after a
refusal is proof that no signature was spent. That is a test, not a comment.

### Nothing can be sealed before a session, so the refusal is HTTP

Spec §6.5 defines `ERROR 0x1F`, and §6.5 also defines **`ERROR 0x04` for a
refused connection** — and neither can be emitted here. Every `ERROR` goes
through `fail_with_error` → `queue_sealed` → `session_seal`, and a connection
refused for its address has no session and never will;
`authd_conn.c:132` has said so since V4-8b ("no session exists yet: nothing to
reply with"). Mutation **W11** additionally pins `0x04` as the *wrong* code for
the ROTATE-conflict path, so the byte is doubly spoken for.

The one channel that exists before a session is the connection's own HTTP
identity, which has not yet become a WebSocket. So a rate-limited connection is
answered `HTTP/1.1 429 Too Many Requests` and a limiter with no room left to
track addresses answers `503` — its capacity problem, not the caller's rate —
and a connection with **no client address** is answered with nothing at all and
closed. That `0x04` remains unemitted is recorded as **F56**, not papered over.

`conn_io_ws_silence()` exists for a reason worth stating. If the preamble and
the HTTP request arrive in one read — which is what a coalescing proxy does —
`ws_upgrade` has already built a 101 by the time the address is judged; if they
arrive separately it has not. Without an explicit discard, the same refusal
would be `101`-then-EOF on one scheduling and a bare EOF on another. That is
**F52's** divergence in a new place, and this time it was designed out rather
than found.

### The F50 trap did not recur, and the reason is structural

The PROXY v2 signature begins `\r\n\r\n`, which as a big-endian length is
**218,893,066** — the same shape as the `"GET "` that poisoned V4-10a's
connections (F50). The plan said `note_header`'s guard "must be widened in the
same edit". **It did not need widening.** The preamble is consumed strictly
inside `WS_STAGE_UPGRADE`, and its bytes never reach `in` at all, so the
existing condition already covers it — and adding `|| proxy_pending` would have
been an *equivalent mutant*, indistinguishable from the code without it. The
argument is written next to the guard, the equivalent mutant is declared in
`spec_v50b.txt`'s docstring, and the test that would have caught the bug is
written anyway: the preamble, the upgrade and the first frame are split at
**every** offset and must arrive intact.

### Decisions

1. **PROXY protocol v2 only.** §7.2 lists an `X-Real-IP` fallback; it is not
   implemented and no code path can be made to read it (**F61**). Two trust
   paths for one fact is one more parser to attack, and the header form
   additionally depends on the proxy remembering to overwrite a client-supplied
   value — a configuration mistake with no local symptom.
2. **The TLV region is skipped by length, never walked.** Nothing here wants a
   TLV, and a parser that is not written cannot be wrong. A declared body over
   **1024** bytes is refused, so a 16-bit length field cannot decide how long a
   connection may occupy a slot having said nothing.
3. **`LOCAL` and `AF_UNIX` are well-formed and carry no client.** They are
   reported distinctly from a malformed header, because an operator whose
   health checker is talking to the login socket should be able to tell that
   from an attack. Both are still refused: Req 12 is about having an address,
   not about having a header.
4. **IPv6 is keyed on the /64.** A /64 is the smallest unit a single customer
   is routinely given; keying on all 128 bits would let one host rotate through
   2^64 addresses and meet the limiter exactly never.
5. **Admission is one call that does everything or nothing.** `ratelimit_admit`
   either takes a token from both buckets *and* counts the connection, or
   changes nothing at all. A half-applied decision is not representable, and
   mutation J9 exists because "refused but counted anyway" is the natural way
   to get this wrong.
6. **The table refuses rather than evicting.** Forgetting the address that is
   attacking you is the one behaviour a limiter must not have. It recovers on
   its own instead: an entry whose bucket has refilled to the brim and which
   holds no connection says nothing a fresh address does not, so reclaiming it
   forgets nothing. That *is* the expiry condition; there is no timer.
7. **Integer arithmetic in thousandths of a token**, and `last_ms` advances
   only by the time that actually produced whole milli-tokens. A limiter whose
   refill depends on floating point is a limiter whose boundary cannot be
   asserted exactly — and the boundary is the whole test: empty at 11999 ms,
   full at 12000.
8. **The numbers are config, with defaults.** §17 has no row for them. 5 a
   minute per address with a burst of 10, 50 a second globally, 8 concurrent
   connections per address — generous to a human, useless to a prober, and
   bounded by the parser so nobody can set `rate_per_min = 0`.
9. **The limiter is attached only where an address exists.** A daemon with
   `proxy_protocol = none` has `app.rl == NULL`. Keying every addressless
   connection on "no address" would not be rate limiting; it would be one
   bucket with everyone in it, and Req 12 refuses those connections anyway.

### `proxy_protocol` defaults to OFF, and that is the uncomfortable one

`v2` is the secure setting and Req 12 fails closed without an address. But
there is no default that is right for both "Caddy is in front" and "an
operator's `authd_client` is connected directly", and a daemon whose first
start refuses every connection teaches an operator to disable things. So the
key exists to be **set**: the deployment runbook sets it, the Caddy
configuration in `tests/caddy_proxy.sh` sets it, `--check-config` now prints
it, and — the part that makes this not a cop-out — **`authd_client --proxy-v2`
exists so `authd_e2e.sh` runs the whole deployed configuration with the shipped
binaries**, including a named check that a login with no preamble is refused.
Recorded as **F63**, because a `--check-config` that passes still does not mean
the limiter is on.

### Where the address lives, and where it does not

On `conn_io`, which parsed it, and nowhere else. The plan put a copy on
`authd_slot_t`; the slot carries only two lifecycle flags (`addr_settled`,
`addr_admitted`) and asks `conn_io_client_addr()` for the value. One copy of a
fact is one thing that can be stale, and `conn_io_reset` already wipes it on
slot reuse — the same argument V4-8b used for keeping the WebSocket `state`
there rather than duplicating it into the connection record.

It does **not** go in the store. The plan's roadmap row said "the client
address in the store and the log", but §9.1's schema — which
`store/schema.sql.h` carries verbatim, so that the DDL that runs is the DDL
under review — has no column for one anywhere, and the standing rule is that a
spec is never edited to match the code. So: the log, and `authd_log_slot_addr`.
That function takes an `authd_addr_t` **by struct**, deliberately: `authd_log_fp`
takes a bare 32-byte pointer and an enrollment ticket's hash is also 32 bytes,
which is why its guarantee is prose and why **F41** is open. A secret is not an
`authd_addr_t`.

### The connection cap could not go where the plan put it

The plan placed it in `accept_ready`, before `take_slot`. That is not
implementable for this listener: the client's address arrives as **data**, so
at accept time the only address known is the proxy's. `max_conns_per_addr` is
therefore enforced at the earliest moment it *can* be — the same moment the
token is taken — and released by `authd_conn_on_close`, which the loop calls
before it resets the slot. The deviation is stated rather than quietly taken.

### Two defects this step found in the step before it

**F55, High.** `authd_client`'s `cs_send` called `cs_send` where it meant
`frame_send`, so `login --port` — the operator's SSH-tunnel path, the entire
reason milestone A has a raw listener — recursed into itself until the stack
gave out. It shipped in V4-10a and survived a whole step because **every test
and every e2e leg used `--unix`**, where `cs->ws` is 1 and the branch is dead.
At `-O2` the recursion is a tail call, so a Release build hangs rather than
crashing — the worse of the two. It was found by the first check that ever
drove `--port`, which is now an `authd_e2e` leg, and mutation **J12** restores
it so it cannot come back quietly.

**F54, Low.** `h_stop` closed the loopback, site and admin listeners and not the
WebSocket one, so every fixture leaked a descriptor and a socket file. Nothing
failed, because no suite starts enough daemons to exhaust a descriptor table —
which is exactly why it went unnoticed.

### The Caddy leg runs a real Caddy, and it had to be one container

`tests/caddy_proxy.sh` puts **Caddy 2.10.2** (`sha256
501e955fa634c5aab63247458c3ac655cfdd6cbf1e0436528f41248451c190ac`, linux/arm64)
in front of the daemon, builds the daemon and the CLIs from this tree inside
the same container, and performs a real post-quantum login through the proxy.

Everything is in **one** container, and that is not laziness. The proxy-facing
listener is a Unix socket, and a Unix socket cannot be crossed between a macOS
host and a Linux VM: virtiofs shares the inode, not the listening kernel
object, so a guest `connect()` to a host-created socket is refused. Caddy on
the host is no better — it is not installed, and installing it changes the
developer's machine. One namespace removes both problems and is also how the
thing actually runs.

Two things had to be added to make the leg real rather than a simulation.
`authd_client --ws` speaks WebSocket over `--port`, because a browser reaches
the daemon as WebSocket **over TCP** through a TLS proxy and until now `--unix`
implied WebSocket and `--port` implied raw frames — the one arrangement a real
deployment uses was the one shape the tree could not take. And `caddy validate`
is run twice: once on the configuration under test, and once on the same
configuration with `proxy_protocol v9` — one character from the value that
matters. V4-2's S5 spike reported "PROXY v2 upstream: NOT supported" and was
wrong, because of a brace error in its own Caddyfile, so a `validate` that
passes proves nothing until a near-miss is shown to fail.

The leg's last check is the one that makes the others mean something: with
`proxy_protocol` removed from the Caddyfile and Caddy reloaded, the login must
**stop working**.

It is not a CTest. A suite gate that silently depends on a container registry
is a gate that fails for reasons that have nothing to do with the code.

### The nightly gap closes

The nightly had been verifying **123 of the 160** mutations it claimed
authority over. `v49d`, `v50a` and `v50b` join the campaign matrix, `ws` joins
the 600-second fuzz budgets, and `check_mutation_anchors.py` becomes a job that
**gates** the campaigns (`needs:`) rather than running beside them — a rotted
anchor aborts the runner, and learning that after three hours of mutation runs
costs three hours to discover what five minutes knew. That tool earned the
position during V4-10a by catching v48b's C4, and it caught two of this step's
own anchors on their first dry run.

Brought up on its own branch, per V3-3 decision 1, and all three states are on
the record:

- **Green**, run `35464513850`, 33/33 on the first attempt. v49d G1–G15,
  v50a H1–H9 and v50b J1–J13 every one `KILLED`, each campaign ending `final:
  all sources restored; all artifacts identical to clean fingerprints`;
  `fuzz_ws` 671,534 runs at `max_len 16384`, crashes 0, artifacts 0; the
  anchors job reporting `180 anchors checked; 160 mutations across 19
  campaigns`.
- **Red**, run `35468417507`, with v50b's J1 expectation rotted to text no
  check prints:

      J1  mutant-in-binaries  SURVIVED(BAD: [CONTROL: this text is printed by
      no check anywhere]) | restored=clean | clean-suite=PASS | residue=0

  and `mutations · v50b` was the **only** campaign that failed — the redness
  was targeted, not collateral. A gate that has never been shown to fail is
  exactly what this milestone exists to stop.
- **Green again**, run `35471972896`, 33/33, after restoring the expectation
  byte-exactly (`sha256 dbbeea8c484ba007a8fa0a9391d0cef61935ae3ade21d15e97d709f262855b8d`,
  matching the pre-control commit) — J1 back to `KILLED(2 named)`.

Every committed campaign now runs nightly: 160 mutations across 19 campaigns,
eighteen on Linux and v35 on macOS, plus eleven fuzz targets at 600 s each.

### Two defects that only a push could find

The first CI run that ever saw V4-10a was V4-10b's push, because V4-10a had
been held back for an instruction. `ubuntu-latest·clang·ubsan` went red
immediately: `fuzz_ws.c` copies the input to compare against later, and
libFuzzer hands a NULL pointer with a zero length for the empty input, which
glibc's `nonnull` declaration of `memcpy` makes undefined behaviour. **macOS
UBSan does not diagnose it** — so a fresh local UBSan suite, run to this
project's full standard, passed through it twice (**F64**).

That is the same shape as **F55**, one layer up: local verification here is
macOS-shaped, and the CI matrix exists precisely because it is. A verified
commit waiting on an unrelated instruction defers the half of the verification
that cannot be reproduced on the developer's machine, and nobody notices for a
step. Recorded as **F65**, because the lesson is about the process rather than
about either defect.

### Spec gaps recorded, not fixed

**F56** (`ERROR 0x04` is unemittable), **F57** (Req 11 says "Local API callers"
while §7.2 cites it for the proxy socket), **F58** (no document states the
proxy listener's mode), **F59** ("fails closed" is never defined as a wire
behaviour), **F60** (`threat-model.md` still describes the `X-Real-IP`
arrangement S5 superseded) and **F61** (the fallback is deliberately not
implemented). Six for the errata step, none of them fixed by editing a spec to
match the code.

## V4-10c — the specification, corrected, and two vocabularies that can no longer drift

`docs/mldsa-authd-spec.md` was written in V4-3, before any of the daemon
existed, and had not been edited since — deliberately. Every step from V4-6
onward held to one rule: **a specification is never edited to match the code.**
A disagreement between the two is recorded as a finding and left for a step
whose job is to decide which side was wrong, because the alternative is a
document that agrees with whatever was implemented last and therefore says
nothing.

Eight steps later the register held **19 errata items**, plus **F26**, which
asks for a §3.1 change and had been mis-filed under V4-11. Reading the document
end to end for this step turned up **five more contradictions no finding
covered** (F66–F70). Twenty-five corrections is past the point where the rule
protects anything, and the spec is now the document V4-11 will package, V4-14
will hand to a reviewer, and a browser client will be written against.

What it was telling a reader, as of V4-10b: that `ERROR 0x04` means "rate
limited" (nothing can emit it); that `bad-handle` is an error code (nothing
emits it); that `log_identities` and `log_client_ip` control logging (neither
exists anywhere in the tree); that key files are "never clobbering" four
sections after telling a client to rename one over another; and that a client
recovering an interrupted rotation should branch on whether the server found a
key "unknown" — a distinction §7.3's decoy flow exists to destroy.

### The rule is suspended once, and replaced by a stricter one

Every change cites a finding, and **§20 Errata** lists all twenty-six with the
section, what v1 said, what v1.1 says and which finding forced it. No
correction was taken that no finding asked for. The document is **v1.1**: the
body is corrected so §§1–19 are true on their own, rather than leaving a reader
to apply an errata list by hand while reading.

`docs/v4/audit.md` marks all twenty-five items RESOLVED — twenty-four in the
spec, plus **F60** in the threat model, which still described the `X-Real-IP`
arrangement V4-2's S5 spike superseded.

### The part that outlives the step

Numbers were never the problem. §6 and §12's byte tables have been right since
V4-3 because `check_spec_constants.sh` re-derives them from the headers. What
drifted was the prose that enumerates **names** — and it drifted in both
directions at once:

- §8 listed `bad-handle` for eight steps and nothing ever emitted it;
- §8 defined no code at all for a refused command, while the daemon answered
  `not-permitted` from the day the local API existed;
- §15 promised the fields `ev`, `conn`, `stage`, `status`, `ms`, `rx`, `tx`,
  none of which the daemon has ever emitted.

Each was found by a person reading the document one step at a time, which is
the slowest detector there is. `tools/audit/check_spec_vocabularies.py` is the
fast one, and it fails **both ways**: a name the daemon can emit that the spec
does not define is a failure, and so is a name the spec defines that nothing
emits. The second half is the one that matters — an undefined name is a
documentation gap, but a **defined** name nothing emits is a promise to a
reader that the software does not keep, and no test can see it.

It is exact rather than heuristic because every call site passes a string
literal: 101 `send_err` calls covering 17 codes, 53 event names (one a ternary
of two literals, which is why the second argument is parsed as an expression
rather than matched as a token), and a fixed set of formats in `authd_log.c`.
**A non-literal at any of those sites is itself reported as a failure**, so the
check cannot quietly start covering less than it claims.

The cost is stated rather than discovered: §15 now enumerates all 53 event
names, so **adding a log event is a change to the specification**. That is the
same cost `FUZZ_TARGETS` imposes, and §15 drifted precisely because nothing
made it cost anything.

Six controls, all shown: a code defined but unemitted; a code emitted but
undefined; an event removed from the catalogue; a field renamed; §15
restructured so a heading moves (which fails with "a §15 heading is missing"
rather than thirty lines of noise — the first version content-sniffed for the
field block and produced exactly that noise); and a new `send_err` code with no
spec entry.

`check_spec_constants.sh` grew from 27 checks to **38**, covering §17's new
rows: the token lifetimes, the four rate-limit defaults, the rotation cadence,
the line limit and `AUTHD_MAX_CONTENT`.

### One code change: `audit-verify`

§9.2 calls the audit head MAC "detectable from a second trust domain", and
`store_audit_verify()` was **reachable from nothing at all** (F29) — no §8
command, no §13 subcommand. A deployed operator could not check their own
chain, which made the property a claim rather than a control.

`authd_admin audit-verify` is offline by design: it opens the key envelope for
the KEK, opens the store, re-computes the whole chain, and prints the head MAC
and a verdict. Offline is half the point — **the same command runs against a
backup**, which is where a tampered chain is most likely to be noticed and
least likely to be repairable.

Two details are not decoration. It prints the **entry count**, because an empty
chain verifies trivially: without the count, a command that had walked nothing
would look identical to one that had verified three hundred rows, and the first
version of the e2e check was vacuous for exactly that reason until the count
existed to assert on. And it prints the head **on failure too** — a tamper that
rewrites a row without touching its stored MAC leaves the head unchanged, so an
operator comparing it against yesterday's learns whether the chain was
truncated or rewritten, which the verdict alone does not say.

A wrong passphrase is reported as a **key** failure, never as a corrupt chain:
the chain is keyed from the envelope KEK, so failing to open the key means the
verification never ran, and an operator told "corrupt" would go looking for an
intruder instead of for their passphrase file. That is mutation **O4**.

Campaign **v50c, letter O** (F and Z remain), all four killed in `authd_e2e` —
the only place a real chain with real entries exists. Not mutated, with the
reason stated: "the KEK is not wiped". The leak is real and LeakSanitizer would
catch it **on Linux**; LSan does not run under macOS ASan, so the mutation would
SURVIVE on the machine this campaign is usually run on and be killed only in
the nightly. A mutation whose verdict depends on which platform ran it is worse
than no mutation — it teaches that a survivor is normal.

## V4-11 — packaging, and the difference between "hardened" and "hardened by four flags nobody measured"

Milestone A worked. It was not deployable: no `install()` target anywhere, no
service unit, no runbook, a `Debug` default build, and a default CPU target
(`auto` = `-march=native`) the README itself describes as liable to fault on
another machine. The daemon ran from a build directory. This step ends that,
and closes the largest single block of open findings in the register: F4, F6,
F7, F12, F13, F17, F63.

### The hardening gap was one property, not five

The register said "no PIE/RELRO/BIND_NOW/noexecstack". Measured on a Linux
Release build of the daemon before writing a line of CMake:

```
BINARY        PIE   RELRO  BIND_NOW  NX-STACK  CANARY
mldsa-authd   yes   yes    no        yes       yes
```

**One property was missing.** Modern toolchains supply PIE, partial RELRO, NX
and canaries by default; the gap was full RELRO plus `BIND_NOW`, which is
`-Wl,-z,relro -Wl,-z,now`. The number is recorded because a step that claims to
add five things and adds one is a step nobody can check — and because the four
flags would have been added either way, with three of them doing nothing and
no one the wiser.

**And "one property" turns out to be compiler-dependent — which the CI control
found, not the measurement.** Removing `-Wl,-z,now` on the bring-up branch
turned the clang release job red (`BIND_NOW no`, three properties absent) and
left the **gcc** one green: Ubuntu patches gcc's default specs to link
`-z now` already, so on that toolchain the property is present whether this
project asks for it or not. Two consequences worth stating plainly. The flag is
doing real work for clang and no work for Ubuntu's gcc — and the gcc job's
green tick therefore does *not* demonstrate that our flags work, only that the
shipped binary has the property, which is the thing that actually matters for
deployment. A gate that reads the BINARY rather than the build files is why
both statements can be true at once, and is the reason `check_hardening.sh` was
written that way in V4-1.

Two platform facts constrain how they are added, both established by probe
rather than recall: `-Wl,-z,...` **does not link on macOS** (`ld: unknown
options: -z`), and `-fcf-protection` is rejected on arm64. So the flags are
**probed, not guessed** — `check_linker_flag()` per flag, plus
`check_pie_supported()` — and a toolchain that refuses one simply does not get
it. This is also why the `--require` gate is meaningful **only on Linux**:
`check_hardening.sh` reports RELRO and BIND_NOW as `n/a` on Mach-O, so a macOS
`--require` run passes on three properties out of five. It is run on both and
the macOS output is quoted precisely to show that it proves less.

The flags go on the ~25 existing `target_link_options` sites rather than into a
global `add_link_options`, for the reason the compile flags are already
per-target: a global would reach the vendored liboqs, libsodium and SQLite
targets, which this project does not get to relink on its own terms.

### The daemon checks its own locked-memory limit, because a unit file only protects the operators who use the unit

V4-2's S1 spike measured the hazard exactly. Under a 64 KiB `RLIMIT_MEMLOCK`,
1,000 concurrent `sodium_malloc` allocations **all succeeded** and about 16
were actually locked. libsodium calls `mlock()`, ignores its failure, and hands
back memory indistinguishable from locked memory. Nothing errors, nothing logs,
and the daemon's secret key, session keys and login codes quietly become
swappable — with no symptom of any kind.

`LimitMEMLOCK` in the unit fixes that for anyone running the unit. It does
nothing for a host that is not. So the daemon reads `RLIMIT_MEMLOCK` itself at
startup, logs it against the derived need (4 KiB × 10 blocks × `max_slots`,
S1's formula), and raises the line to WARN when it falls short.

**It warns rather than refuses**, deliberately. Linux's usual 8 MiB default is
already below the need at the default `max_slots = 256`, so refusing would
convert a widespread misconfiguration into an outage — and would stop every
development run and the end-to-end test besides. The loud line is what makes
the misconfigured host visible; the unit is what fixes it.

The level decision is a named function, `memlock_log_level()`, not a ternary at
the call site. That is not tidiness: "the short case is LOUD" is a requirement,
and inside `main()` it had no oracle, because the ambient `RLIMIT_MEMLOCK`
decides which branch runs and differs by platform. As a function a test names
both answers directly, which is what makes mutation Z4 killable at all.

Campaign **v51 (Z1–Z5)**. Two of the five are about the formula rather than the
comparison: Z3 drops the ten-blocks factor and Z5 halves the page size, and
both leave a check that reads correctly, compares correctly and reports a
plausible number. That is why the test asserts `memlock_required_bytes` against
**literals** (40960, 10485760, 167772160) rather than against the macros the
implementation uses — an expectation computed from `MEMLOCK_PAGE_BYTES` would
move with the mutation and could never catch one.

Not mutated, with the reason stated: "the daemon refuses to start when the
limit is low" would be a mutation against the design rather than against a
defect; and "getrlimit's failure is treated as OK" is reachable on no platform
this project builds on, so it would survive everywhere and teach that a
survivor is normal. Both join the equivalent-mutant register (N7, v48a D7,
v48b C8, v49c's pair, v49d's).

### The offline cache: three pin checks, and a failure mode the proof found on its first run

F12 said an offline build was impossible. `MLDSA_DEPS_CACHE` plus
`deploy/fetch-deps.sh` closes it, and the design point is that **every pin
survives**: liboqs is cached as a local clone used as `GIT_REPOSITORY`, so both
existing checks still run — the `PATCH_COMMAND` at population time and the
re-check after `FetchContent_MakeAvailable`. `FETCHCONTENT_SOURCE_DIR_LIBOQS`
was the obvious alternative and is the wrong one: CMake's design makes it
bypass the population-time `PATCH_COMMAND`, and the V2-10 retrospective already
had to record a period when the liboqs pin was enforced through one of its two
points. libsodium and SQLite become local `URL`s with their `URL_HASH`
untouched.

The proof is a build in a container with **`--network none`**, with
`getent hosts github.com` failing first so the test cannot pass by quietly
still being online. It found a real defect on its first run, now **F72**: git
refuses to read a repository owned by another user (its `safe.directory` rule),
and with the cache used as a `GIT_REPOSITORY` the refusal surfaces as
`Failed to clone repository` from a generated FetchContent subbuild script,
with the actual cause buried in a log the operator has no reason to open. The
container reproduced it exactly — the cache arrived carrying the host's uid
while the build ran as root — which is the shape of an operator who populates a
cache as themselves and builds as root.

The fix is one `git rev-parse HEAD` against the cache at configure time, which
answers both questions at once: whether git will read this directory at all,
and whether it holds the commit this build is pinned to. An ownership refusal
is re-reported naming the remedy (`chown`, not a `safe.directory` exception —
the cache is a build input and should belong to whoever builds). So an offline
build is now verified **three** times and an online one twice; the probe adds
a check, it does not replace one.

Three controls, all executed:

| control | staged as | result |
|---|---|---|
| unreadable cache | cache left owned by another uid | refused, naming `dubious ownership` and the `chown` |
| corrupted archive | one byte of the libsodium tarball changed | refused by `URL_HASH`, expected value printed |
| cache off the pin | a new commit built with `commit-tree` (the cache is a **bare, shallow** clone: no work tree to commit in and no `HEAD~1` to step back to) | refused, and `_deps/liboqs-src` was never created |

The third control is the one worth having: it proves the refusal happens
*before* anything is populated, so a drifted cache cannot be half-unpacked
into a build tree.

### The unit is gated, not reviewed — and the first gate is shaped by a measurement

`systemd-analyze verify` **exits 0 for an unknown directive**. Probed: a unit
carrying `BogusDirective=yes` prints `Unknown key name … ignoring` on stderr
and exits 0. So the exit status is worthless as a gate, and the real signal is
the **output**: a clean unit produces none. The second gate is
`systemd-analyze security --offline=true`, which scores the unit; the unit
scores **1.7** ("OK") against a threshold of 4.0.

That threshold needed its own control, and the first one chosen failed:
removing `MemoryDenyWriteExecute` did not move the score at all (1.7 → 1.7). So
every directive was measured individually and the control became
`CapabilityBoundingSet`, which moves it to **3.4**. The whole table is recorded
in the script. A gate whose control does not move it is a gate that is not
measuring what its author thinks.

`deploy_checks.sh` is not a CTest, for the reason `caddy_proxy.sh` is not: a
suite gate that silently depends on a container registry fails for reasons that
have nothing to do with the code.

### What this step does not do

It ends at **provably installable**, not installed. The VPS is not mine to
reach, so everything that does not need it is proven here and the rest is a
numbered runbook someone runs. That boundary is stated rather than blurred,
and it is where the remaining risk lives.

### Two gates caught this step's own work

Worth recording because it is what the previous two steps were for.
`check_spec_vocabularies.py` failed on `memlock-limit` — the new event was in
the spec and the *call site was unreadable*, because the gate required
`AUTHD_LOG_` to appear in the level argument and `memlock_log_level(ms)` does
not contain that text. The gate was right to complain and wrong about what to
complain about: what it exists to pin is the **event name**, which is argument
two. The level may legitimately be a literal, a ternary or a named function —
and a named function is precisely the shape a level takes once it is a
requirement somebody has to test. The requirement was relaxed to "the call has
two arguments"; a site whose *event* is not a literal is still reported, which
is the case that could evade the vocabulary entirely.

And `check_mutation_anchors.py` was run before and after every source edit —
189 anchors, 169 mutations, 21 campaigns, all OK — because this step touches
`authd_main.c`, which carries other campaigns' anchors.
