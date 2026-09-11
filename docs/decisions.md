# Protocol Decisions (through Step 7)

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
(only `OQS_SIG_ml_dsa_65_*` symbols present). This will need revisiting
when/if v2 adds ML-KEM-768.

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
- **F5:** a structural file model.

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
  (8 + 1 + 5 + 1952 + 4032), not 6 002 as the plan said.

### OPEN finding: the demo loader accepts a corrupted t0 component

Found by the `fuzz_keys` smoke on its first run, and committed as
`tests/fuzz/regressions/keys/t0-corruption-accepted-*`, a 9-byte
instruction program.

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

The fix belongs in `apps/demo_keys.c`, which is outside Step 7 scope, so it
is deferred. Proposed fix: add an integrity digest to the demo key format
(SHA-256 over magic ‖ id ‖ pk ‖ sk, checked on load; a format version
bump), plus a deterministic T14 test with a t0-corrupted key. Until then
the F5 oracle asserts only the loader's documented contract.
