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

**Superseded in V4-16 (F105)** — see § *V4-16 — the secret scanner counts
only wholly secret windows*. The argument below holds for the one fixture
whose public key it measured: `rho[17..32) || K[0]` matches any input that
holds that fixture's `rho` followed by a byte equal to its `K[0]`, and for a
fresh key the coincidence is one in 256. The scanner now keeps the 3906
windows of the "alternative reading" below. The rest of this section is
left as written, as the record of why that reading was declined.

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

**Extended in V4-16 (F105)** — nineteen controls now, C1-C8: C5 covers the
new rule's three boundaries and C8 is F105's case; see § *V4-16*.

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

## V4-12 — two ceilings, and the walk nobody had counted

The daemon could serve 256 concurrent handshakes no matter how it was
configured, and spent 69 % of every connection slot on a table holding one
entry. Both are ceilings; they are not the same ceiling, and keeping them
apart is most of what this step had to get right.

### The throughput ceiling and the latency ceiling

**Capacity is the throughput ceiling.** A completed handshake leaves a
CONSUMED tombstone that only expiry reclaims and `cancel` refuses to erase —
that tombstone *is* the replay record for the remainder of the TTL, so this is
replay protection working as designed, not a defect. The consequence is
arithmetic: the sustained rate is `capacity ÷ TTL`, which at 256 entries and a
10 s timeout is **25.6 handshakes per second**. That is audit finding F1, and
`handshake_pending_store_init_ext` raises it to 205/s by letting the operator's
own `max_slots` size the ledger.

**The scan cost is the latency ceiling**, and it is where the number 2,048 comes
from. `find_slot` is a deliberate constant-time full scan with no early exit,
so cost is linear in capacity.

### The correction: five walks, not four

V4-2's S2 spike measured one scan and multiplied by four. Writing the comment
for `HANDSHAKE_PENDING_EXT_MAX` meant justifying that multiplier, and counting
the walks in the code gives **five**:

| where | walks |
|---|---|
| `handshake_pending_insert` | `sweep`, `find_slot`, the placement loop |
| `handshake_pending_get_digest` | `find_slot` |
| `handshake_pending_consume_success` | `find_slot` |

Four are unconditionally full; the placement loop early-exits on the first free
slot, which means it is *also* a full walk exactly when the store is near
capacity — the case the budget is about. So at 2,048 the figure is
**~99.5 µs against a 100 µs budget**, not the recorded 79.6 µs.

And the model was still optimistic. Measured end to end on arm64 Release, the
ledger's share of a handshake is **137 µs at capacity 2048** and 62 µs at
1024 — because a hot-loop scan is not what a handshake performs. Between the
five walks sits ML-DSA signing and verification, which evicts 147 KB of ledger
from cache, so every walk is cold. The progression is worth keeping: S2 said
79.6 µs, counting the walks said ~99.5, and measuring said 137.

**The cap stays at 2048 and the budget is revised instead**, which is the
opposite of this project's usual direction of fit and so is argued rather than
assumed. What §17 carried was not a requirement but a *justification*, and it
was a measurement that turned out to be wrong; a document may not keep citing a
number its own tooling has disproved. The trade is concrete: capacity is the
throughput ceiling, so 2048 buys 205 handshakes/s against 1024's 102/s, on a
handshake already dominated by ML-DSA. The cost — 24 % of a handshake, where
V4-2's budget would have allowed about 18 % — is accepted with the number
written down. Recorded as F77 and spec erratum 30.

**Measured on x86_64 afterwards** (`bench.yml` run 35812305959, AMD EPYC 9V74
on a shared Azure VM, median of three runs): one scan at 2048 costs 39.80 µs,
twice arm64's, and the ledger's share of a handshake is **248.7 µs — 24.0 %**,
against arm64's 23.8 %. The microseconds double and the fraction does not
move, because the scan and the ML-DSA around it slow down together. On x86_64
even capacity 1024 costs 123 µs, over the 100 µs budget. So the decision to
keep 2048 and state the cost as a share of the handshake turned out to be the
only framing that survives the change of architecture: V4-2's budget, in
absolute microseconds, was never portable.

The benchmark had to be corrected too, and the mistake is instructive: its
first draft compared handshakes by ledger **occupancy**. `find_slot` iterates
`i < s->capacity` whatever the store holds, so both rows paid the same scan and
the difference measured cache effects. Cost is linear in capacity, so the rows
vary capacity. An arm64-in-a-container number that was already
marginal is a poor thing to extrapolate from, which is why the x86_64
re-measurement stopped being tidy-up.

**And the sustained rate is not measured at all.** It is `capacity ÷ TTL` by
construction; timing it would be reporting an arithmetic identity as an
observation, the same shape as the start-up check V4-8b removed for asserting
`x <= x`.

### The slot: 91 KiB to 31 KiB, measured

V4-8b gave each connection a scratch `keystore_t` — 64,552 bytes to carry
exactly one of its 32 entries — because milestone A would not change the
library. V4-12 changed it, and the numbers are printed by `bench_authd` rather
than quoted:

```
authd_conn_t   67.6 KB -> 6,256 B
slot total     ~91 KiB -> 31.0 KiB
at 4096 slots  382 MB  -> ~127 MB
```

`handshake_lookup_fn` is responder-only. An initiator pins the one identity it
chose to dial and is a one-shot process; fewer public entry points is less to
verify on the first change to the verified handshake since v2.0.0. The internal
resolver is role-agnostic, so an initiator form later is a ~10-line change —
recorded as a decision rather than left to read as an omission.

The keystore path is **bit-identical**, not merely equivalent: `keystore_lookup`
sets `*out = NULL` on every non-OK status, so "NULL" and "!= KEYSTORE_OK" are
the same condition. Every pre-existing test passes untouched, which is the
compatibility proof.

### The edit that compiles when it is wrong

Nine accessors moved from `s->entries[i]` to `s->slots[i]`. Every one of them
**still compiles** if missed, and a missed one is invisible to every test
written before this step, because they are all inline and cannot tell the two
addresses apart. Three independent guards, because one would not be enough:
mutation **P4** (chosen precisely because the compiler is blind to it), tests
that fill and read an external array past index 256, and a mechanical grep that
`s->entries[` appears **zero** times. Four address comparisons on `s->entries`
remain and are intentional.

### F8, answered rather than carried

"~10 `sodium_malloc`/`free` pairs per handshake, measure under load" has been
open since v2. It is **12 and 12**, balanced, counted with the same counting
allocator `test_session_alloc` uses — reused, not copied, so it cannot drift
from the real allocator. The bench proves the counter is live before trusting
the balance, because `0 == 0` is also what an unwired counter reports, and it
fails outright if the two ever differ.

### Three things the gates caught, not me

**The spec gate caught an event that had become unemittable.** Deleting the pin
branch removed the only thing that could fail there, so `pin-failed` survived
in §15's catalogue and nowhere else. `check_spec_vocabularies.py` said
`defined but NEVER EMITTED` immediately. Keeping a tautological guard to
preserve the event was considered and rejected — `decode_client_hello` already
enforces the id bounds, so the check would assert `x <= x`. Spec v1.3,
erratum 29, finding F76.

**Two mutations were re-authored before they ever ran.** P7 and P10 both failed
`-Werror` on a variable their own defect made unused — `KILLED(compile)`, which
proves the compiler works and nothing about the check under test. That is now
five occurrences (v50b J1, v50c O3, v51 Z4, and these two), and the pattern is
worth naming: a mutation that deletes a *use* tends not to compile, so the
defect should change what a value **is**, not whether it is read.

**An anchor was hiding outside the table.** P10 needs three edits across two
files, and the second file's two anchors initially lived in a helper list
outside `M` — where `check_mutation_anchors.py`, which reads these tables
statically, would never have seen them. An anchor nothing verifies is the exact
failure that tool exists to prevent. P10 became a shape the checker
understands, and the count went 200 → 202.

### F62, which stopped being latent

`AUTHD_SLOTS_POLL_MAX` was `AUTHD_SLOTS_MAX` restated as a literal, and the
poll set was filled protocol-pool-first, so at a high `max_slots` the local API
could never be polled — the failure the separate pools exist to prevent,
reintroduced by the array that polls them. Latent only because the default was
256; raising capacity is exactly what would have made it real. It is now
derived from both maxima, bounded per pool, and refused at registration, and
the test drives a genuinely full 4,096-slot pool — one quiet socket standing in
for every slot, since `poll()` accepts the same fd repeatedly.

## V4-13a — one client, two transports

Milestone B is people signing in from a browser, and spec §14 had already
decided how: the protocol's own C code compiled to wasm, a thin JavaScript
transport, no cryptography in JavaScript. Planning found the obstacle was not
logic — every client protocol step already existed as a pure C function --
but packaging. The client's login, rotate and keygen were tangled with
sockets, files and stdout inside `authd_cli.c`, which also held the admin
commands, so `authd_client` linked sqlite3; the MLDSAEK1 envelope could be
sealed only to a path and opened only from one; and the one piece of client
logic with real consequences — the `.ek.next` rotation recovery — had no
end-to-end test at all.

V4-13 was split three ways (user decision): **13a** a single client core,
everything native, fully verified; **13b** that core in wasm, logging in
against the real daemon from Node, in CI; **13c** the browser. And the native
CLI is rebuilt on the core rather than left beside it — one implementation,
so every e2e login is now a regression test for exactly the code a browser
will run.

### Characterise first

The refactor's first commit touches no C. It adds three legs to the e2e that
pin what the shipped client does after an interrupted rotation: a stale
`.ek.next` beside a live `.ek` (use `.ek`, say so, delete nothing); neither
file authenticating (refuse, and both files byte-identical afterwards);
the server committed but the rename was lost (the next login finishes it).
They describe the client as it WAS, so the refactor cannot change it unseen,
and the audit row that says the path had no test (**F80**) is closed by them.

The REFUSE leg asserts the files before the message, because `fail()` stops at
the first failure and the property — not its report — is what a defect
should be caught by. Its probe exposed something older, below.

### W14, and eleven more like it

v49c's W14 promotes a `.ek.next` that does not authenticate. Its committed
replacement, `if (next_present)`, leaves `next_ok` unused, so `-Werror`
refuses to build it and the runner scores `KILLED(compile)`. It had scored
that every night since V4-9c without a single test ever running against it.
Re-authored as `next_ok >= 0` it compiles, and the REFUSE leg catches it.

A compile kill proves the compiler works. The last full nightly had **12 of
180**: v24 M8 is legitimate (it trips a `_Static_assert`, which is the point
of that mutation); v24 M4 has rotted (it names `KEX_KDF_LABEL`, which no
longer exists); the other ten — v26 Q5, v48a D6, v48b C4, v49a A1 T4 T5,
v49b L2, v49c W1 W7 W14 — delete a use rather than change a value. Recorded
as **F79**. W14 is re-authored here because it moved with this step's code;
the rest are separate work, not folded into a step that did not touch them.
v53 is written to the rule F79 implies: every mutation changes what a value
is, none deletes a use.

The count also depends on the compiler. Re-running v49b here, C2 scored
`KILLED(compile)` too: Apple clang 21's `-Wuninitialized-const-pointer`
refuses it, while the Linux nightly's clang builds it and a test kills it by
name. It does the same on the tree before this step, so it is not this step's
doing, but it means a campaign's verdict is a fact about a compiler as well as
a tree, and a macOS-only compile kill hides from the nightly that is supposed
to catch it.

### The core

`apps/authd/client_core.{c,h}`: buffer in, buffer out, a caller-owned state
struct, no sockets, no files, no stdout, no statics. Every message is one
whole `len4 || payload` frame — one WebSocket message — and the header must
equal the bytes present and lie inside the bounds of the state that is
waiting; the payload is then `msg+4` for `msg_len-4`, never the header's
claim. Any failure is terminal and wipes every secret the core holds. The
clock is injected, because a browser tab's timers are not something to trust
with session expiry, and a test proves the injected one is what governs.

**The secret key's lifetime is as short as the protocol allows**, and that is
shorter than §14 promised but longer than it said. §14: "opened into wasm
memory only to sign ClientAuth". `handshake_initiator_init` takes the keypair
(`handshake.c:525`), so the key must exist from ClientHello until ClientAuth is
signed — one round trip — and rotation signs ROTATE with the old key after
the session exists. The core frees an owned key the moment ClientAuth is
built and on every failure, drops a lent key's pointer at the same point, and
`CC_KEEP_FOR_ROTATE` extends that to `cc_rotate_build` and no further. The
spec is corrected (erratum 31, finding **F82**) rather than the code bent to a
sentence it could not meet.

**One deliberate behaviour change**: the handshake is finished and the session
keyed *before* ClientAuth leaves, not after. Both are local steps the peer
cannot influence in between; the difference is observable only if one of them
fails internally, and adding an API step for a path that cannot occur was
worse than stating it here.

### The CLI on the core, and proof its words did not change

`client_cli.c` keeps only what a browser does differently: sockets, the PROXY
v2 preamble, the WebSocket upgrade, files with custody rules, passphrase
files, stderr. The transport code moved verbatim, J12's F55 guard and W15's
`.pub` rename included. The core reports failures in the stage names the CLI
always printed (`cc_diag_t`), and the claim that nothing an operator sees
changed was tested, not asserted: the e2e ran once with the pre-split client
(built from the previous commit in a scratch worktree) and once with the new
one, every call's stderr and exit status logged through a shim. After
normalising handles, temp paths, pids and seconds-remaining: **identical**,
44 lines over 15 calls, four of them failures.

`authd_client` now links `mldsa_client_cli` and nothing of the daemon's. That
is proven on the binary by symbol — a static library links whatever it is
never asked for, so "it built" proves nothing — with a canary that must show
the daemon's 270 `sqlite3_` symbols, and a `WILL_FAIL` control that runs the
same script on the daemon forever.

### The KAT is 13b's contract

`test_client_core_kat` substitutes a deterministic generator (TEST ONLY) for
libsodium's, routes liboqs to it through `cc_use_sodium_rng_for_oqs()` — the
very function wasm init will call — runs one device lifetime against a fake
server, and diffs the SHA-256 of eleven artefacts against a committed golden.
Two runs in one process must also agree with each other, so randomness that
escapes the generator is reported by the artefact where it first appears.
13b's wasm build must reproduce every line. The routing function exists
because liboqs's default under Emscripten may `fopen("/dev/urandom")` and
`exit()`; it mutates process-global state, so it is called by the KAT and
by wasm init only — never by the CLI, never by a test that shares a process
with the daemon.

### Fuzzing what a phishing server controls

`fuzz_client` hands the core every frame the daemon sends — ServerHello,
first record, rotate reply — after replaying a whole login from a reset
generator, so the genuine frame for each moment is the same bytes on every
input and the oracle is exact: accepted **iff** byte-identical to the genuine
one; otherwise FAILED, nothing written, no key reachable, every later call
refused. `fuzz_envelope` gained the matching property for the in-memory
opener, run only on headers the model rejects, since an accepted one costs at
least 8 MiB of Argon2id per input.
600 s each on the libFuzzer tree: `fuzz_client` 373,381 runs, `fuzz_envelope`
122,901,616, `fuzz_keys` (which gained buffer-versus-file parity) 1,841,144 —
no crash, no artifact. Two probes show `fuzz_client`'s oracle is not
decorative: a refusal that leaves the core usable, and a record that failed
authentication being parsed anyway, each abort the replay on the named
property.

### What 13c has to decide, recorded now

Two things the specification does not say and the browser cannot avoid
(**F83**): how the login code gets from the page to the site (the CLI prints
it for a human to paste), and what replaces the `.ek.next` file rule in
IndexedDB, where "rename over" is not an operation. And a promise V4-10b made
and did not keep: its plan said the per-address rate limit's hostility to a
carrier NAT would be "recorded as a finding for V4-13 rather than discovered
there". It had not been. It is now, as **F81**.

### Verification

Seven commits, each built normal, fresh ASan and fresh UBSan, each tree proven
current and instrumented in the same invocation as its suite (35 tests at the
end). Every new test shown able to fail by a marked probe with a build
fingerprint and a byte-exact restore, before the campaign that makes it
permanent. Campaigns re-run in full wherever this step's edits could reach an
anchor: v46 and v29 (the envelope and key-file buffer paths), v49b, v49c, v50b
and v50c (the CLI split) — 58 mutations, all killed — and v53 itself, **12 of
12 by name, none by the compiler**.

v53's first run was 9 killed and 3 `SURVIVED(BAD)`, and all three were the
campaign's own defects: two spec lines named two tests as `^(a|b)$`, and the
spec format's field separator is `|`; and F4 predicted a check would fail that
could not see what F4 does — `cc_wipe` zeroes the struct, so a leaked key's
pointer reads NULL too. The check was renamed to what it asserts and F4 is
killed where the free is observable. A survivor that exposes a check weaker
than its name is the campaign working.

### After the push

Two things only CI could say. The Linux gcc Release job refused a test this
step added: `malloc((size_t)fsize(ek))`, where `fsize` returns -1 for a
missing file, which gcc follows at `-O3` into an allocation of `SIZE_MAX`
(`-Werror=alloc-size-larger-than`). Local verification never built with gcc.
It was reproduced before the fix was pushed — Homebrew gcc 16 with the Release
tree's own flags gives CI's exact error — and every C file the step touched
was compiled the same way. One more failure appeared, `fuzz_keys.c:865`, which
is older than this step and which CI's gcc 13.3 accepts; it is **F86**, the
first error of a compiler upgrade nobody has scheduled.

The nightly bring-up then went 37/38, 37/38 (the control, v53 red as
intended), 38/38. The first run's red was not v53 but v52: `authd_e2e` failed
1.24 s into a clean suite and passed in both later runs. Why is not known,
because the campaign keeps only ctest's summary for a failing clean suite —
**F84** records the failure and its leading, unconfirmed hypothesis (a fixed
e2e port inside Linux's ephemeral range), and **F85** the missing evidence,
which has to be fixed before F84 can be diagnosed rather than guessed at.

## V4-13b — the same client, in WebAssembly

13a built one client core and a golden file of eleven SHA-256 hashes, and
called the golden a contract for the wasm build. 13b is that build, and the
first thing it did was keep the contract: **the wasm KAT reproduced the native
golden byte-for-byte on its first run**, all eleven artefacts, with
`test_vectors`' 27 checks alongside (V4-2 S6's result, now a permanent test).

### What was decided (user decisions in brackets)

- **One pinned compiler.** `emcmake cmake` builds the client only — core, key
  formats, WebSocket framing, client core — and configure refuses any
  Emscripten but 6.0.9 (`MLDSA_EMSCRIPTEN_VERSION`; a control with 6.0.8 is
  refused). A KAT golden is a contract for the compiler it was checked
  against. libsodium is the same tarball and hash through
  `emconfigure`/`emmake` with its own emscripten script's options; liboqs is
  the same commit, still verified twice, at `generic`.
- **An export shim, built natively too** [shim built natively too].
  `client_wasm.c` is 22 flat functions over the core — pointers, 32-bit
  lengths, ints, doubles — and plain C, so `test_client_wasm` drives it on
  the ASan tree and campaign v54 mutates it with the ordinary runner. It
  decides three things no page can override: identities are sealed at the
  browser's Argon2id parameters; the session clock is the caller's, finite,
  monotonic, and a login cannot *begin* until it is set; `ccw_init` routes
  liboqs to libsodium's generator (proved with a deterministic generator:
  two identities from one state are identical).
- **A module whose surface is checked, not declared.** `web/mldsa_client.mjs`
  + `.wasm`: an ES module factory for the web, workers and Node, with no
  filesystem and no dynamic code (`-sDYNAMIC_EXECUTION=0`, so a strict CSP can
  serve it). `wasm_module_gates` loads it as a page does and requires its
  callable functions to be exactly `web/exports.txt`, and the raw module to
  export exactly those plus one runtime function and one memory —
  `EMSCRIPTEN_KEEPALIVE` exports a function whether or not it is listed, so
  the list is checked against the module. **187,603 bytes** against S6's
  1.5 MB budget.
- **A minimal transport** [minimal transport]. `web/client/authd-client.mjs`
  moves whole frames between a WebSocket and the module and nothing else;
  `web_no_crypto` fails the build if it ever reaches WebCrypto, Node's crypto,
  `getRandomValues` or `Math.random`.
- **The real daemon, reached from Node** [test fixture TCP-WS]. Node's
  WebSocket dials only TCP; the daemon offers WebSocket only on the Unix socket
  Caddy reaches. The harness gained an option that puts the WebSocket listener
  on loopback TCP *instead* (the fixture already uses all four listener slots),
  and `wasm_interop` logs in with the same two files a page loads.

### What the interop test shows

Ten checks against the in-process daemon, passing on the first run and under
the ASan and UBSan fixtures: a wasm-made key enrolled through the site socket;
a login over `ws://` whose code the site EXCHANGEs once and only once; a
different key pinned under the server's id → refused at `server-hello`,
`signature`, **with only the ClientHello ever sent**; a wrong passphrase →
`decryption-failed` with **nothing** sent; a rotation the daemon acknowledges,
after which the old key is refused and the new one logs in.

Measured (Node 24.21.0, Apple silicon): Argon2id at 3/64 MiB **101.5–128.4
ms** across runs (S6: 111.5 ms); a whole login round trip, opening the key
included, **106–118 ms**. Real browsers and phones remain 13c's to measure.

### The gate that was fooled (F87)

A probe added one unlisted export to the shim; the export gate caught it;
the source was restored byte-exactly — and the next suite still found the
export. macOS's `/usr/bin/make` is GNU make 3.81, which compares timestamps to
the second, and the restore landed in the same second as the probe's link.
Make called the module up to date, and **`check_build_current.sh` agreed**,
because its proof was a no-op rebuild. It now rebuilds the project's own
artefacts from scratch (never `_deps`), the semantics the campaign runner has
always had and which never fooled it. A deterministic control — probe built,
source restored with an older mtime — shows the old gate saying "current"
with the probe string still in the object, and the new one reporting STALE.
On first use it found two native trees stale; every suite was re-run on trees
it had just proven current.

### Things Emscripten 6.0.9 would not do, recorded

- Export names are minified at `-O2`, and neither way of keeping them works
  with `MODULARIZE` (`MINIFY_WASM_EXPORT_NAMES` is internal;
  `DECLARE_ASM_MODULE_EXPORTS=0` is refused). The raw export check is
  therefore by count, and the named check is on what a page can call.
- The ELF link-hardening probe passes under `emcc` — `wasm-ld` only warns on
  an unknown `-z` — so `relro`/`now`/`noexecstack` reached every wasm link as
  noise until emptied for Emscripten. The modules' bytes did not change.
- CTest runs the wasm tests with the node Emscripten's config names (locally
  Homebrew's 26.8.2); CI passes its own pinned Node explicitly.

### Campaign v54 — the first two-letter IDs

v53 took F, the last free letter, so v54's IDs are a letter pair and a number
(`WA` = wasm shim), assigned per campaign and never reused; nothing in the
runner or the anchors checker changes, an ID having only ever been a string.
Nine mutations of the shim, every one changing a value (F79): the clock guard,
a backwards clock, a NaN clock, the operator's KDF memory, liboqs unrouted, a
refused record's code left behind, a reported length one too long, the pin's id
checked against itself, a handle before init. On the fresh ASan tree **9 of 9
killed by name**. WA7 first scored `KILLED(5 named via abort)`: the broken
login left the test indexing `g_in[m - 1]` with `m == 0`. The test was
guarded — a failure path must report, not crash — and WA7 re-run: `KILLED(10
named)`, clean. The JavaScript transport and the module gates are outside the
runner's reach (it snapshots and rebuilds C); their controls were run by hand —
an unlisted export fails both export checks, a `getRandomValues` line fails
`web_no_crypto`, a transport that ignores the ServerHello refusal fails the
interop test's phishing check.

### Verification

Every tree proven current by the from-scratch gate in the same invocation as
its suite: native normal, ASan and UBSan 38/38 (with `wasm_interop`, the daemon
fixture under each sanitizer), the wasm tree 3/3. gcc 16 at the Release flags
compiled every C file the step added or changed, before any push (13a's lesson).
Anchors 223 across 24 campaigns. `check_spec_constants.sh` now also checks
§14's Emscripten version against the CMake pin (control: 6.0.8 in the spec
fails it).

## V4-13c — the browser client, end to end

13b left a module that logs in from Node. 13c is the part a user sees: pages,
storage, the site around them, and a real browser driving all of it. It closes
**F83**, the two things 13a found the specification did not say. V4-13 was split
again (user decision): **13c** is the browser; **13d** is the deployment switches
F14 and F81, the CLI's interactive prompt, phone timings and the public runbook.

### What was decided (user decisions in brackets)

- **The login code reaches the site in a POST body** [same-origin POST]. The
  page sends it to the site's own endpoint on the same origin. The site checks
  `Origin`, EXCHANGEs the code with the per-login `state` it put in the session
  (and the page put in the WebSocket URL), and keeps the token server-side. The
  code is never in a URL, so never in a proxy log, a `Referer` or history, and
  page script never holds the token. The alternatives were a redirect with the
  code in the query (every log on the path) or `postMessage` to a site frame
  (a second origin to get right). Spec erratum 34.
- **The `.ek.next` rule as transactions** (erratum 33). IndexedDB has no
  rename, but it has transactions that commit whole or not at all. The pending
  envelope is written in its own transaction, and `ROTATE` is not sent until
  that transaction has *committed*. One transaction promotes it. After an
  interruption the decision is `client_key_plan`, the CLI's own function,
  reached through the shim, so the browser cannot reimplement it slightly
  differently. A pending key is discarded only by a rotation, and only after
  the current key has been proven live by a real handshake.
- **One passphrase policy, in the C core** [policy in the C core]. It needs at
  least 12 code points (not bytes) and strict UTF-8. It refuses a pinned
  9,913-entry common list, including those passwords with digits or symbols
  wrapped around them, and needs an estimate of at least 50 bits, where
  repeats, runs, keyboard walks and a repeated unit count for almost nothing.
  The estimate is integer milli-bits from a table: no libm, so the number is
  the same on every platform, wasm included. `ccw_seal_new_identity` enforces
  it, so a page cannot seal around it. The CLI's prompt calls the same
  function in 13d. It refuses the obviously weak and does not certify
  strength, and the enrollment page says so. Erratum 35.
- **A reference site, not a framework.** `examples/site-node/server.mjs` uses
  `node:http` and nothing else. It sets HttpOnly SameSite=Strict session
  cookies, refuses a POST from another origin, and sends one strict CSP on
  every response: `script-src 'self' 'wasm-unsafe-eval'`, `connect-src
  'self'`, `default-src 'none'`. `'wasm-unsafe-eval'` is what compiling
  WebAssembly requires and it allows nothing else. There is no inline script
  or style on any page. The site proxies `/authd/v1` to the daemon, the job
  Caddy does in production, so the test's page is same-origin with its
  WebSocket exactly as a deployed one is. `deploy/Caddyfile.example` gained
  the same headers and the site route.
- **A browser test with no dependencies** [CDP driver, no deps].
  `tests/browser/cdp.mjs` speaks the DevTools protocol over Node 24's
  built-in WebSocket to a headless Chrome or Edge found at configure time
  (`MLDSA_BROWSER`). There is no Puppeteer or Playwright, and nothing
  downloaded at test time.

### What the browser test shows

`browser_e2e` runs the real daemon fixture, the reference site and headless
Edge 154.0.4258.37. Every check passed:

- Enrollment with the policy enforced in wasm (a weak passphrase refused by
  the policy), then login.
- The code in the POST body and in **none of the 11 URLs** the browser
  requested; the session cookie invisible to page script; `/api/me` answers
  who is logged in and never with the token.
- An injected inline script blocked, with the violation reported.
- A cross-origin POST refused with 403.
- In IndexedDB: a stale pending key left alone by login, and a lost ACK
  completed by the next login in one transaction.
- A rotation from the account page, after which the new key logs in; five
  recovery codes; and a ServerHello signed by the wrong key refused after one
  frame (`server-hello/1`).
- Recovery on a fresh browser profile enrolling a new device.

`web_flows` drives the same flows under Node with a `MemoryStore`, one
scenario per branch of the rule, including the one the browser test does not
reach: neither key works → refused, store untouched.

**Measured in the browser** (headless Edge 154, Apple silicon): Argon2id at
3/64 MiB **89–94 ms**, a whole login round trip **89–96 ms**, across the runs
recorded. That is faster than Node's 101–128 ms (13b). Phones remain 13d's.

Headless Edge did not grant `navigator.storage.persist()`. The enrollment page
reports this ("the browser did not promise to keep this storage") rather than
hiding it. §14 already lists eviction among the honest limits, and recovery
codes are the answer to it.

### Controls, each run and each restored byte-exactly

- **C1**, the CSP with `'unsafe-inline'` → both CSP checks fail.
- **C2**, the code also put in the URL → both hand-off checks fail.
- **C4**, the site returning the token to the page → the token check fails.
- Login discarding a pending key it had only proven stale → `web_flows`'
  "LEAVES the pending key alone" fails.
- Guessing on ambiguity (promoting when neither key works) → `web_flows`'
  "store is exactly as it was" fails. `browser_e2e` stays green for that one,
  because it does not drive that branch; `web_flows` is where it is covered.
- A tampered common-password source → the generator refuses it (pinned
  SHA-256).
- 49 bits in the spec → `check_spec_constants.sh` fails.

### Campaign v55 — PP, the passphrase policy

Twelve mutations, each changing a value (F79): the minimum one short or
counted in bytes, two UTF-8 rules (high surrogates, overlongs), the core's
stripping and case folding, the list's binary search, the repeat,
keyboard-walk and repeated-unit discounts, the floor lowered to 39 bits, and
the shim sealing under a refused passphrase. On the ASan tree the first run was 10 killed by name, PP5
`KILLED(compile)` and PP7 `SURVIVED(BAD)`. Both were the campaign's defects, not
the code's:

- **PP5** first read `c >= 0xD800u && c <= 0xD7FFu`, an empty range that
  clang refuses under `-Werror`, so the compiler killed it and nothing was
  tested. It now lets the high surrogates through, and is killed by name.
- **PP7** disabled the repeat discount. The test's only repeat case was also
  caught by the repeated-unit rule, so the mutant was invisible. The test
  gained `ggggmmmmssssxxxx`, four runs in no repeating unit, asserted at
  exactly 30 bits. PP7 re-run: killed.

**12 of 12 by name.** Anchors: 235 across 25 campaigns.

### Two things that were the test's fault

- `web_flows`' lost-ACK case was refused at first. The fixture's handshake
  ledger had 8 entries, and each login leaves a 10 s tombstone, so the fixture
  throttled itself to 0.8 handshakes a second. Four probes in a row ran out.
  The fixture now sizes its ledger `HANDSHAKE_PENDING_MAX` (256), as the daemon
  does; the throttle was the fixture's, not the daemon's.
- `tests/caddy_proxy.sh` failed its login leg once `Caddyfile.example` routed
  everything else to `localhost:8080`, which is the test's own port. The
  example now names `127.0.0.1:9080`, and all seven Caddy checks pass.

### Verification

- Every tree proven current by the from-scratch gate in the same invocation as
  its suite. Native normal, fresh ASan and fresh UBSan: **41/41** each,
  `browser_e2e` included (the daemon fixture under each sanitizer). The wasm
  tree: 3/3.
- `tests/caddy_proxy.sh`: 7/7.
- gcc 16 at `-O3 -Wall -Wextra -Werror` compiled all seven C files the step
  added or changed. A control with a known truncation fails it.
- Anchors OK, spec constants OK, `git diff --check` clean.
- The CI browser job (a pinned Chrome for Testing) and v55's nightly row come
  with the bring-up.

### After the push (recorded in V4-13d)

- **Chrome for Testing 154.0.8037.57**, pinned by SHA-256 (`ceee2972…0302`).
  The pin came from one download whose size (196,223,440 bytes) and MD5
  matched the bucket's own metadata; Google publishes no SHA-256 for it.
- **Ubuntu 24.04 blocks the kernel feature Chrome's sandbox needs** (unprivileged
  user namespaces, via AppArmor). The CI job lifts that rule on the throwaway
  runner rather than running the browser with `--no-sandbox`. It worked on the
  first run.
- **Bring-up on `ci-bringup`.** Baseline 13/13 (run 36263175336), with the
  browser job running 6 of 6 tests (`browser_e2e` 12.7 s). The control, the
  site's CSP with `'unsafe-inline'` added, turned exactly the browser job red,
  on exactly the two CSP checks (run 36263733028). The revert, byte-identical
  to the baseline, went 13/13 (run 36264697135). Landed on `main` as
  `552513f` by fast-forward; CI 13/13 there (run 36265280103).
- **Nightly on `main`, dispatched: 40/40** (run 36263185573). v55 killed
  12 of 12 mutations by name on Linux ASan, matching the local result.

## V4-13d — what a public deployment needs

13c put the client in a browser. 13d is what changes when the people using it
are the public: their identifiers are personal data, their phones share
addresses, some of them will type a passphrase into a terminal, and someone
has to deploy all of it from a document.

### What was decided (user decisions in brackets)

- **The journal's two switches** [full by default; key derived from the KEK].
  `log_identities = full | hashed | off` and `log_client_ip = full | prefix |
  off` (spec v1.7 errata 36, 37; finding F14). Both default to `full`, which is
  what every earlier release logged, so an upgrade changes nothing it was not
  asked to. `hashed` writes `idh=`: the first 8 bytes of keyed BLAKE2b-128 of
  the WHOLE identifier, never a fallback to it. The key is
  `key_log = HKDF(KEK, store_id, "mldsa-authd/v1/log-pseudonym")`, derived in
  `store_open` beside `key_audit`; the logger gets a callback, not the key.
  It is stable across restarts and computable only with the server
  passphrase, so `authd_admin pseudonym --id X` lets an operator find one
  person's lines and a reader of the journal cannot test guesses. `prefix`
  writes `/24` or `/48`. The store's audit chain keeps the real identifiers
  under every setting.
- **The refund** [refund on success] (erratum 38; finding F81). A connection
  pays one per-address token at admission, before any signature. When its
  ClientAuth verifies against an active key and a code is issued, the token
  comes back: refilled to now, capped at the burst, once per connection, and
  never to the global bucket, which bounds total signing work. So only
  handshakes that fail drain an address, and the phones behind one
  carrier-NAT address no longer spend each other's budget on logins. The
  refund needs the key's secret, which a prober lacks whether the handle
  exists or not, so Req 6 is untouched. What it cannot fix is now a §18
  limitation: one prober behind a shared address still empties it for
  everyone there.
- **The terminal prompt** (erratum 39). `authd_client --passphrase-prompt`
  opens `/dev/tty`, so neither prompt nor passphrase touches stdin or stdout,
  and reads one line with echo off into locked memory. It restores the
  terminal on every path: four signals are caught for the read, the terminal
  put back, and the signal re-raised. keygen holds a new passphrase to the one
  policy whichever way it arrives, a file included, and explains a refusal in
  the enrollment page's words (`pp_explain`, which the test checks against
  `web/pages/enroll.mjs`). rotate does not re-check: it re-seals under the
  same passphrase, and refusing would strand an identity that predates the
  policy.
- **Phone timings** [timing tool you open]. `tools/phone_timing.mjs` serves
  the test daemon and the reference site on an address the phone reaches and
  collects what `web/pages/timing.html` measures: a throwaway identity, five
  real logins, the identity deleted. The invite rides the URL fragment, which
  no request carries.

**The phones were not measured.** The page was served on the development
Mac's Tailscale address for an hour, and again for two hours after a session
restart; no phone reported. The tool itself was run end to end with headless
Edge standing in for the phone -- a new identity in 106.4 ms, five logins in
84.7-152.9 ms, the code EXCHANGEd each time -- so what is missing is the
measurement, not the means. Spec §14 (erratum 40) and the runbook say so, give
the headless-Chromium figures as the only in-browser numbers, and name the
tool.

### What writing the runbook found (F88)

The reference site could not be deployed the way its own header described.
Its command line had no way to set `secure`, so behind the TLS proxy it
expects -- where a browser sends `Origin: https://...` -- every POST was
refused as cross-origin while the pages still loaded. Every test drove
`startSite()` directly over loopback http, where the mismatch cannot happen.
It also took the sign-up invite on argv. Step 14 of the runbook was written
by running it. `--secure` and `--invite-file` were added and the command was
executed both ways: without `--secure`, `403 cross-origin POST refused`; with
it, `200` and a `Secure` cookie, while an http Origin is still refused. The
same exercise caught step 14's copy putting the site one directory too
shallow to find its pages, and ran the invite command on Ubuntu 24.04. It
also caught the module size the runbook quoted: V4-13b's 187,603 bytes, where
V4-13c's common-password list has since made it 301,278.

### Two things that were the tests' fault

- The first version of the refund test waited for a login code from a decoy
  handshake. A decoy's ClientAuth fails *retryably*, so the daemon keeps the
  connection open and says nothing, and the wait ran out its full read loop:
  `test_authd_ws` went from 10.6 s to 233.6 s while passing. It now pumps
  until the daemon has logged `client-auth-retryable` for that probe, by
  count, which also proves the failure path was reached before "no refund" is
  asserted (9.6 s).
- The Caddy test's new leg said the first daemon "did not stop". It had: the
  container's PID 1 is `sleep 3600`, which reaps nothing, and `kill -0`
  succeeds on a zombie. The leg now requires the daemon's own `event=stopped`
  and a process that is gone or in state Z.

### Controls, each restored byte-exactly

- No refund at all fails 4 checks; a refund on the retryable failure fails 2.
- A prompt that leaves echo on fails 4 checks; keygen skipping the policy for
  a file fails 3.
- A spec field list without `idh` fails the names check.
- The config parser storing an out-of-range mode fires the new fuzz property
  on its first seed.
- The Caddy public-journal leg with `log_identities = full` goes red.

### A gate that was blind

`check_spec_vocabularies.py` finds the event-logging functions by matching
prototypes in `authd_log.h` up to the next `;`. A comment mentioning
`authd_log_set_privacy()` has no `;`, so the match ran from the comment into
the next prototype, took `set_privacy` for an event function and hid
`authd_log_slot_id`: eight events "defined but never emitted". It now strips
comments first.

### The trees that vanished

Between two sessions macOS emptied `/var/folders/.../T/`, where
`cmake/Dependencies.cmake` puts libsodium's build and install prefix (libtool
cannot build under the repo's parent path, which has spaces). All five trees
lost `sodium.h` at once, and the campaign runner said
`FATAL: clean tree does not build`. The old trees were left alone; five fresh
ones were configured with `TMPDIR=~/.cache/mldsa-tmp`, which macOS does not
clean. The fresh wasm module is byte-identical to the old one.

### Campaign v56 — MB, milestone B's switches

Twenty mutations, every one written to change a value (F79): ten on the log
switches and the pseudonym, five on the refund, five on the prompt and the
policy's words. On the fresh ASan tree the first run killed 19 by name and
scored MB15 `SURVIVED(BAD: unattributable build failure)`: it replaced
`now_ms` with `0u`, which left `now_ms` unused, and `-Werror` refused the
mutant before any test could see it. That is F79's trap one more time, in a
campaign written to avoid it. MB15 now refills to `now_ms / 1000u`, which
keeps the use and moves the clock, and is `KILLED(2 named)`. **20 of 20 by
name.** MB9 -- the daemon applying `log_client_ip` but ignoring
`log_identities` -- is killed only by `authd_e2e`, the one test that runs
`authd_main`'s wiring. Anchors: 255 across 26 campaigns.

### Verification

- **Each code commit on its own**: normal, ASan and UBSan trees each proven
  current by the from-scratch gate, with the sanitizers proven linked, in the
  same invocation as the suite. 42/42 after commits 1 and 2; 43/43 plus the
  wasm tree's 3/3 after commit 3.
- **At the end, on the five fresh trees**: normal, ASan and UBSan 43/43 each,
  wasm 3/3, and the fuzz tree's 36 fuzz-labelled tests.
- **600 s of fuzzing** each on the targets the step changed:
  `fuzz_authd_config` 130,109,806 runs, `fuzz_authd_conn` 5,490,229 runs; no
  crash and no artifact.
- `tests/caddy_proxy.sh`: 8/8, the public journal behind a real Caddy included.
- **gcc 16** at `-O3 -Wall -Wextra -Werror` compiled every C file each commit
  touched. It also refuses `tests/test_authd_cli.c:123`, which this step did
  not touch and only macOS can show (F86).
- Anchors 255 across 26 campaigns, spec constants and names OK, `git diff
  --check` clean.

## V4-14a — honest gates before the review packet

V4-14 hands the work to an external reviewer. Before it does, every gate a
reviewer will read should mean what it says. Five findings were open against
the gates themselves, all recorded since V4-10b and none scheduled (user
decision: clear them first as 14a, then build the packet as 14b). Clearing
them found two properties no test had ever checked, and a secret-scan check
that had been vacuous one run in 64.

### The compile kills (F79)

The last nightly scored eleven mutations `KILLED(compile)`. One is honest:
v24 M8 exists to trip a `_Static_assert`. The other ten deleted a *use*
rather than changing a *value*, so `-Werror` refused the mutant and no test
was ever asked. v24 M4 had rotted besides: it named `KEX_KDF_LABEL`, which V2-5
deleted. The sweep had failed to compile for a reason unrelated to what it
tests.

All ten, plus v49b C2 (which Apple clang refused for an uninitialised
`cfg`), were rewritten to change a value and keep every use. Each was first
applied to a scratch copy and compiled under clang and gcc 16. Then their
seven campaigns were re-run in full on the ASan tree:

- **M4, D6, A1, T5, C2, W1** were killed by name at once.
- **Q5, T4, W7** were killed, but by checks their specs had not predicted.
  The specs were written when the compiler killed them, so no one had seen
  which test fires. The specs now name the real ones.
- **C4 and L2 survived. No test could see either.**
  - C4 binds `SHA-256("")` instead of `SHA-256(state)`. Every EXCHANGE check
    logged in over the raw listener, whose state is the empty string by
    definition, so the two are the same there. `test_state_binding_ws` now
    logs in over the WebSocket with a real state, and EXCHANGE must refuse the
    empty one and accept the page's own.
  - L2 makes the local-API client stop reading a list at its header. The
    framing check drained replies with the test harness's own reader, so
    `localcli_call`'s -- the code `authd_admin` actually runs -- was on the
    path of no test. `test_localcli_split_list` serves a list in two writes,
    200 ms apart.

  Both are then killed by name. Those two properties had been untested for
  months while their mutations scored as killed.

**And a gate instead of a habit.** The runner now scores a compile kill
`KILLED(compile)-NOT-ALLOWED(BAD)` and fails the run, unless
`tools/mutations/compile_kills_allowed.txt` names the mutation and says why
the compiler IS the check. It lists one: v24 M8. Control, on a one-line spec:
with M8 listed, `KILLED(compile)` and exit 0; without it,
`KILLED(compile)-NOT-ALLOWED(BAD)` and exit 1.

### The runner's missing evidence (F85), and what it caught at once (F89)

The runner ran its whole-suite checks as plain `ctest`, which keeps one line
per failing test and none of its output. Both now use `--output-on-failure`
(control: a deliberate failing check reached the log by its own line).

The first campaign after the change caught `authd_e2e` failing in a
*restored, clean* tree, and this time kept why. The line before
`FAIL: the login code appears in the daemon log` was
`grep (BSD grep, GNU compatible) 2.6.0-FreeBSD`. The check ran
`grep -q "$CODE" authd.log`, and a base64url code begins with `-` one time in
64, which grep reads as options:

- `-V...` prints the version and exits 0: a false FAIL.
- Most other shapes exit 2, or read an empty stdin and exit 1: the check
  passes without searching anything.

It is now `grep -qF -- "$CODE"`, and the recovery-code scans got the same.
Both old shapes and the new one were demonstrated by hand.

### The rest

- **F84.** `authd_e2e`'s raw-listener port moved from `40000 + pid % 20000`
  (inside Linux's ephemeral range) to `20000 + pid % 10000`, below Linux's and
  macOS's. This follows the leading hypothesis; the failure was never
  captured, and F85 is now what would capture it.
- **F86.** A whole gcc 16 Release tree failed in exactly two places, both an
  unchecked `snprintf` of a directory entry. Both now check their length and
  fail closed: the secret scanner counts an unholdable path as a violation
  (control: a 1,346-byte path, 1 violation, where it had been skipped), and
  the absence check counts it as found. The gcc 16 tree then builds with no
  error and no warning, and its suite passes. It is the first gcc-built macOS
  tree this project has run. gcc 16 also refused this step's own new test at
  first, for the same `snprintf` shape, and it was fixed the same way.
- **F74.** `caddy_proxy.sh` passes bsdtar's flags only to bsdtar. Under GNU
  tar 1.35 the step now archives the tree where the old command was refused;
  on macOS the script still passes 8/8.

### Verification

- **Suites.** Normal, ASan and UBSan trees 43/43 each, every tree proven
  current and the sanitizers linked in the same invocation as its suite. The
  gcc 16 Release tree: 40/40.
- **Campaigns.** The seven affected campaigns were re-run in full on ASan:
  67 mutations killed by name, and one compile kill, M8, which is allowlisted.
  v24 and v48a ran once (7 of 7 by name each). v26, v48b, v49a, v49b and
  v49c ran twice, the second time with the new tests and specs: 53 of 53 by
  name.
- **The Linux nightly.** It will run every campaign under the new runner, and
  the gate, when these commits are pushed.
- **Documents.** Anchors OK; spec constants and names OK; `git diff --check`
  clean.

## V4-14b — the review packet

V4-1 said the work needed an outside reviewer, because the author of every
line had also audited it. This step builds what that reviewer gets:
`docs/review/`, a claim map checked against the tree, the first comparison of
the pinned dependencies with published advisories, and a tag to freeze it
(user decisions: in-repo plus an annotated tag; the advisory check done
online).

### The claim map, and what building it found

Both specifications number their security requirements: 13 in spec-v2 §4 and
14 in the deployment spec's §5. §5 says each requirement is "pinned by a named
test", and cited almost no pins. `docs/review/CLAIMS.md` now maps all 27 to
their evidence: 94 named checks, 60 mutations, 2 ProVerif queries, 15 fuzz
oracles, 13 gate scripts and 5 CI jobs, each with a line on what it does
**not** establish.

`tools/audit/check_claim_map.py` fails when:
- a requirement in either spec lacks an entry, or an entry's title differs
  from its requirement's;
- a cited check text is not in its test, a mutation is not in its campaign, a
  query is not expected by `formal/run.sh`, or a CI job is not named by any
  workflow.

All 189 citations resolved on the first run. Five controls then each failed
on exactly the defect injected: a changed check text, a missing entry, a
nonexistent mutation, a wrong title and a nonexistent job. The checker reads
the citations, not the prose; "not established" stays a judgement.

Three read-only agents drafted the evidence. Their most serious limits were
verified in the code before any was recorded. Five became findings:

- **F92** (Med). An omitted `site_uids` or `proxy_uids` turns off the
  peer-credential check Req 11 requires, and a config naming neither passes
  `--check-config` as valid (demonstrated).
- **F93** (Med). RECOVERY-USE with `revoke=all` spends the code and then
  revokes each device in its own transaction, which is the partial lifecycle
  change Req 14 forbids.
- **F94** (Med). The UBSan build does not stop on undefined behaviour, so a
  UB report prints and the test still passes. The last local run and the
  latest CI sanitizer jobs contain no `runtime error` line, but that gate had
  never been able to fail on UB.
- **F95** (Low). Req 3 lists secret hashes among the values compared in
  constant time; the store finds them by SQLite equality.
- **F96** (Info). A login code is "bound to `handshake_id`" only in the sense
  of "recorded with": nothing checks it when the code is spent.

None is fixed in this step. The packet names them first.

### The advisories

Nothing had ever compared the pins with published advisories. Now it has been
done, with controls, since a lookup that can only say "nothing" proves
nothing. OSV.dev was queried by commit and returns CVE-2025-6965 for SQLite
3.50.1, so that channel works. **OSV does not cover libsodium at all**: even
1.0.18 returns nothing. The libsodium answer therefore rests on NVD and on
reading the pinned source: CVE-2025-69277's fix is in 1.0.22's
`ge25519_is_on_main_subgroup`, and the project never calls the affected
function.

One advisory is in range: **GHSA-wh5q-mpc8-67wf** (2026-09-22), an LMS/HSS
out-of-bounds read patched in liboqs 0.17.0. The build compiles only ML-DSA-65
and ML-KEM-768, and the library holds 0 LMS/HSS symbols, so it is not exposed
(F91, with a pin bump to do). Also recorded: **F90**, the nine mutations the
V4-14a nightly showed killed without a named check.

### What was not done here

- The formal model was not re-run locally, because ProVerif is not installed
  on this machine. `REPRODUCE.md` points at the nightly job's log instead.
- The phones remain unmeasured (V4-13d).
- The tag is created only on instruction, after the CI step that runs the
  checker has been brought up on a branch and shown red.

## V4-14c — the three medium findings, fixed before the packet is frozen

The packet (V4-14b) surfaced three medium findings against requirements it
describes. The user's decision: fix them first, so a reviewer gets a tree in
which they are closed. Each was demonstrated before it was fixed, and each fix
comes with a test that has been shown able to fail.

- **F92: an omitted allowlist** (spec erratum 41). The listener treats an
  empty uid allowlist as "check nothing", and the configuration could produce
  one without a word. The parser now refuses `site_socket` without
  `site_uids`, and `proxy_protocol = v2` without `proxy_uids`. The
  proxy-facing listener without PROXY v2, the development shape that believes
  no address, still takes `proxy_uids` optionally. It is pinned by five
  `test_authd_evloop` checks and by a `fuzz_authd_config` property that
  neither combination is ever accepted.
- **F93: `revoke=all`** (spec erratum 42). The revocation became
  `revoke_device_locked`, which runs inside its caller's transaction;
  `store_revoke_device` wraps it in one of its own. `store_recovery_consume_ex`
  runs it for every active device inside the transaction that spends the code
  and issues the ticket. A new fault point sits between two revocations. The
  test gives a user two devices and fires the fault after the first
  revocation: after a reopen, both devices are still active and the code is
  unspent. The control recreates the old shape by committing after each
  revocation; it fails with "not one of two". v49d G14's anchor lived in the
  handler's old loop and was re-anchored into the store, still as a changed
  value.
- **F94: UBSan that could not fail.** The UBSan configuration adds
  `-fno-sanitize-recover=undefined`. The same planted signed overflow in
  `test_passphrase` was run both ways: under the old flags it printed
  `runtime error` and **Passed**; under the new ones, `Subprocess aborted`.
  `authd_e2e` also now fails on any sanitizer report in the logs of the
  daemons it starts, which ctest never saw. The fix is a CMake flag, which no
  mutation can reach, so the control stands in for one.

Campaign **v57 (HC)**: five mutations over the new code, each changing a value
(HC1–HC2 the config refusals, HC3–HC5 the one transaction). The claim map now
cites the new checks, and its D11, D12, D14 and P8 entries say what was fixed
and what is still not established.

### Verification

- **Campaigns**, on the fresh ASan tree: v57 5 of 5 by name; v47 7 of 7 (S5's
  text moved into the helper intact); v49d 15 of 15 (G14 in its new place).
- **Suites.** Normal, ASan and UBSan 43/43 each, each tree proven current in
  the same invocation. The UBSan tree was built with the new flag -- its first
  full run that could fail on UB -- and holds 0 `runtime error` lines. The
  gcc 16 tree 40/40, and the fuzz tree's 36 fuzz-labelled tests.
- **Fuzzing.** `fuzz_authd_config` 600 s: 144,445,331 runs, no crash.
- **gcc 16** at `-O3 -Werror` compiled every changed C file.
- **Documents.** Anchors 260 across 27 campaigns; spec constants and names
  OK; the claim map's 196 citations all resolve.

## V4-14d — the packet's four small findings, and the tag

Housekeeping first: the five superseded build trees and `build-gcc16` were
deleted (the -v413d trees and `build-wasm-d` are current). Then the four
findings the packet left open, before the review tag freezes the tree.

- **F95 and F96 were wording** (spec v1.9, errata 43–44). Req 3 listed token,
  code and ticket hashes among values compared in constant time; the store
  finds them by SQLite index equality. Req 3 now names that as its one
  exception and says why it is acceptable: each is the SHA-256 of a 256-bit
  random secret, so a timing leak reveals how much of a *hash* matches, which
  brings no one closer to a preimage. Req 5 said a login code is bound to its
  `handshake_id`; nothing checks that at EXCHANGE, and nothing can, since the
  site does not know it. It now says the id is *recorded* with the code.
- **F91: liboqs 0.17.0 does not exist yet.** The advisory says "patched in
  0.17.0"; GitHub has no such tag (404) and 0.16.0 is the latest release, so
  the planned bump could not happen. Pinning an unreleased commit is a
  decision for the user, not this step. What this step could do is turn "the
  minimal build compiles no LMS or XMSS" from a claim about a CMake variable
  into a gate: `liboqs_minimal` reads the linked `liboqs.a` with `nm`, fails
  on any LMS, HSS, LM-OTS, XMSS or XMSS^MT symbol, and must first find ML-DSA
  and ML-KEM symbols, so an empty archive or a wrong path cannot pass. The
  first pattern also matched `stfl`, and failed the real archive: liboqs'
  generic stateful-signature dispatcher is compiled into every build. It is
  harmless with no algorithm to dispatch to, and the pattern now names
  algorithms only. Controls: an archive with `OQS_SIG_STFL_lms_verify` added
  fails; an empty one fails the canary.
- **F90: every kill is now named.** Each of the nine mutations F90 listed was
  re-run on the ASan tree and its log read. Every kill was real, and none was
  by accident, but in seven the check that fired printed something the
  runner could not see:
  - the fuzz oracle (`FUZZ ORACLE FAILURE`, v28 X1 X4 X5 and v29 Y9) and the
    key scanner (`SCANNER ABORT`, X6) printed no `FAIL: `;
  - `bench_fail` printed `BENCH FAILED:` (U2), and `bench_smoke`'s own checks
    were CMake `FATAL_ERROR`s, which CMake re-wraps at about 80 columns, so
    "has no 'cpu' line" (U3) arrived split across three lines.

  Each now prints a `FAIL: ` line (the smoke script through a `smoke_fail`
  helper whose STATUS line is verbatim), and each spec line names its check.
  Two die where no check can speak: **M6** reads past an exact-size
  ClientHello copy, which returns plausible bytes and is visible only to
  ASan, and **Q2**'s unbounded `content_len` makes the padding check's length
  wrap, so `sodium_is_zero` runs off the mapping inside the library. For
  those the runner gained one other expectation form, `ASAN in <function>`,
  which needs an AddressSanitizer ERROR report with a stack frame in that
  function.

  **The census had counted the wrong thing.** F90 was found by counting
  `KILLED(0 named)` rows. Counting empty spec lines finds a tenth: v23 K4b,
  whose kill prints `FAIL: mlkem768_contracts: free() clears the key and
  NULLs the pointer` before the double free crashes. It scored `1 named`
  because the runner counts every `FAIL: ` line, but no spec line recorded
  which check that was. Its spec line now does.

  The runner now refuses a spec line with no expectation before it builds
  anything, and `check_mutation_anchors.py`, which CI runs, refuses one
  statically. Both were shown firing on an emptied M6 line.

### Verification

- **Campaigns**, in full on the ASan tree: v23 6/6, v24 8/8 (M6 by
  `ASAN in decode_client_hello`, M8 by its allowlisted compile kill), v26
  9/9 (Q2 by `ASAN in sodium_is_zero`), v28 10/10, v29 9/9, v35 2/2 -- 44 of
  44, every row restored clean, the clean suite passing after each, no
  residue.
- **Suites.** Normal, ASan and UBSan 44/44 each (`liboqs_minimal` is the
  44th), each tree proven current in the same invocation; UBSan 0
  `runtime error` lines. The fuzz tree's 36 fuzz-labelled tests pass.
- **Fuzzing.** `fuzz_keys` 600 s: 1,918,221 runs, no crash.
- **gcc 16** at `-O3 -Werror` compiled every changed C file.
- **Documents.** Anchors 260 across 27 campaigns, and no spec line without an
  expectation; spec constants and names OK; the claim map's 197 citations
  all resolve; the repository secret scan finds 0 violations.

## V4-15a — the claim map's daemon gaps, closed with checks that can fail

V4-14 froze the review packet with 27 "not established" gaps in its claim
map. The user chose to work down the ones engineering can close, starting
with the deployment spec's daemon and store claims (D4, D5, D7/P7, D8, D9,
D11, D14); V4-15b takes the protocol and crypto ones. Every new check below
has a v58 mutation (prefix GA) that it catches; where an older check catches
the same mutation as well, the entry says so.

### Three findings, found by closing the gaps

- **F97: Req 7's "logged" half was missing on three paths.** The daemon logs
  a known handle's different key (`enroll-key-mismatch`, both fingerprints)
  from a pre-check that sees only ACTIVE key, device and user. `via=recovery`,
  a site request naming a handle whose owner is disabled (naming the owner
  itself is refused earlier, as `user-disabled`) and one naming a revoked
  device's handle all fell through to the store, which refused them and
  rolled back, and the daemon answered `pk-in-use` in silence. The tests were
  written first and printed six FAIL lines against the unfixed daemon, a
  wrong reply and a missing log per path. The fix is `refuse_conflict`: on a
  store CONFLICT the daemon asks `store_handle_last_key` for the key the
  handle holds or last held and, when it differs, logs Req 7's three lines
  and answers `exists-different-key`. It explains a refusal the store has
  already made; it does not second-guess it.
- **A deviation from the approved plan.** The plan named `store_active_key_of`,
  over the ACTIVE key. That leaves the revoked-handle refusal unlogged, and
  handles are never reused, so a revoked handle can only ever hold the key it
  had. The helper reads the handle's last key instead.
- **F98: four documents said a Req 7 refusal is audited.** Spec §10.1, F9's
  closure, a store.c comment and store.h's contract. Since F47 a refused
  enrollment writes nothing: the row `enroll_device_locked` appends is rolled
  back on both daemon paths, and `fuzz_localapi` asserts a refusal never moves
  the audit chain. The user's decision: the journal is the log. Erratum 45
  (spec v1.10) says "rejected and logged" on every path, and the comments now
  say what the code does. Each Req 7 test asserts the audit head is unchanged.
- **F99: the fault-hook gate ran nowhere.** `tools/check_store_fault_hook.sh`
  is D14's cited evidence, but no CTest and no workflow ran it. It is the
  CTest `store_fault_hook` now (the suite is 45). Its control was run by hand:
  the hook compiled into `mldsa_authd` turned it red with 12 FAIL lines (the
  library, the daemon, `authd_admin` and nine test binaries), and the CMake
  file was restored byte-exact.

### The gaps

- **D5, expiry at EXCHANGE.** At exactly 60 s a login code is refused as
  expired, and at 59 s the same code still exchanges: the refusal did not
  spend it, and the boundary is `now >= expires_at`. GA1 moves the boundary,
  and only the new check sees it. GA2 stores an expiry an hour late while the
  wire still says 60 s: the new check catches it, and so -- the campaign's
  log showed, not the plan -- does the older sweep check, which reads the
  same column. The claim map's "untested" was true of the refusal at
  EXCHANGE, not of the stored value.
- **D4, plaintext in the store.** The database and its WAL hold no 16-byte
  window of the login code, the live token or the ticket, and no 32-character
  window of their hex, while each one's SHA-256 is there. GA3 and GA4 park
  half the code or token in the non-secret `handshake_id` column, which
  nothing reads back (erratum 44), so every round trip still works and only
  the scan sees them.
- **D8, sig_old alone.** The old key signing the rotate-NEW digest makes a
  ROTATE whose only defect is sig_old; it is REJECTED and the journal says
  `detail=rotate-sig-old`. GA5 ignores sig_old's verdict.
- **D9, revocation.** DISABLE-USER and RECOVERY-USE `revoke=all` close the
  user's live sessions (another user's and a `revoke=none` session stay
  open); a device marked revoked with its key row still active does not
  resolve, which is the lookup's device clause holding on its own -- GA6
  removes that clause and nothing else notices, because revocation also
  revokes the key. `authd_e2e` now revokes: `disable-user` refuses dave's next
  login and `enable-user` restores it, and a REVOKE-DEVICE over site.sock
  (`e2e_site.mjs --revoke`; `authd_admin` has no revoke command, by design)
  refuses it for good.
- **D11, peer credentials through `main`.** No in-process path runs
  `authd_main.c`, so the check is an e2e leg: a third daemon whose site and
  admin allowlists name another uid refuses this process on both sockets --
  one `listener-peer-rejected` each, counted in its journal, since even an
  error reply would mean served -- and still serves carol on the proxy
  socket. GA13 and GA14 register either socket with an empty list.
- **D14, crashes mid-way.** Five new fault points: revoke before its commit,
  disable after the status write, and enrollment after the user, after the
  device row and after the ticket's spend. After each fault a reopen shows
  nothing applied. The revoke point sits in `store_revoke_device`, not in the
  helper revoke=all shares, so HC3's `store_fault_arm(1)` still fires where
  it did. GA15-GA19 commit what comes before each point. GA15, GA16 and
  GA18 only the new fault tests see. GA19 is also caught by an older check (a
  refused recovery enrollment must not spend the ticket, and its rollback
  crosses the same line), and GA17 is v49d G15's defect again -- the user
  committed apart from its device -- which G15's census also catches.

### What stays open

Written into the claim map entry by entry: the journal is only as durable as
its sink; base64, upper-case hex, backups and memory are not scanned; the
foreign uid is this process's plus one, not a second real user; revoke=all is
in-process only; and each operation is faulted at one point, not every write.

### Verification

- **Campaigns**, on ASan trees, in two lanes -- this checkout, and a detached
  worktree at `adbb110` with its own tree configured like the first, removed
  afterwards. v58 19 of 19 by name. Every campaign whose kills run through a
  test this step changed, or whose anchors sit in a file it changed, re-run in
  full: v47 7/7, v48b 7/7, v49a 11/11, v49b 13/13, v49c 13/13 (HC3's fault
  arm still fires where it did), v49d 15/15, v50a 9/9, v50b 13/13, v50c 4/4,
  v52 11/11, v56 20/20, v57 5/5. 147 of 147, every row restored clean, the
  clean suite passing after each, no residue. The plan listed eleven
  campaigns; v50c joined because four of its kills run through
  `test_authd_localapi`.
- **Suites.** Normal, ASan and UBSan 45/45 each, each tree proven current in
  the same invocation; UBSan 0 `runtime error` lines. The fuzz tree's 36
  fuzz-labelled tests pass.
- **Fuzzing.** `fuzz_localapi` 600 s: 10,181,495 runs, no crash -- its oracle
  that a refusal never moves the audit chain held throughout. Whether its
  corpus reaches the new `refuse_conflict` branch was not measured.
- **gcc 16** at `-O3 -Werror` compiled every changed C file, and `store.c`
  both ways: in the library and with the fault hook.
- **Documents.** Anchors 279 across 28 campaigns, and the nightly matrix
  names all 28; spec constants and names OK; the claim map's 244 citations
  all resolve; the repository secret scan finds 0 violations.

## V4-15b — the protocol's gaps, and the constant-time gate

V4-15a closed the claim map's daemon gaps; this step takes the protocol's.
The pattern the research found is the same one each time: a test existed, but
it exercised only the case its author had in mind, so a defect one step to
the side passed every named check.

### Tests that could not fail, and what they now cover

- **Replay (P5).** S4 replays the record just accepted and S5 opens seq 1
  first. A REPLAY check narrowed to "the previous record", or an OUT_OF_ORDER
  check narrowed to "a gap of one", passed both -- and the record it let
  through then decrypts, because it was sealed genuinely at its own seq. S4b
  replays an OLDER record and S5b opens seq 2 first (GB1, GB2).
- **The ledger (P5).** Two of its five CONSUMED checks, in `record_failure`
  and `consume_success`, had no test: no protocol path reaches either (T9's
  context refuses a replay first), so each is defence in depth that could
  have been deleted unseen. Step4 T34 calls the store API directly (GB3, GB4).
  The plan called it T33; that number was taken.
- **Padding (P13).** P4(b) and (c) set the first and the last padding byte;
  a check of only those two passed. P4(g) sets each of the fifty middle bytes
  of a 64-byte inner, one fresh pair each (GB5).
- **What is signed (P4).** No mutation had ever dropped a field. GB6 and GB7
  drop the client's nonce from TH_server_auth and sig_B from TH_client_auth,
  in BOTH roles, so the library stays self-consistent -- the case a round-trip
  test can never see. The hand-built peers H1 and H2 bring their own bytes and
  catch them; so does the client-core KAT golden.
- **The decoy (D6).** `test_uniform_responder` compared two lengths that were
  constants set to 1. It now measures the ServerHello in six cases -- good,
  wrong key, unknown, disabled, superseded, revoked -- and all equal
  SH_unsigned + 2 + 3309 bytes. The plan said the superseded case gets the
  decoy; it does not, and the test now says so: the handle is active under
  the new key, which is what gets pinned, so the old key fails exactly as a
  wrong key does. The same sequence, by the other route. The lengths are equal
  by construction, so no mutation isolates that check.

### The constant-time gate (P3, D3)

`tools/audit/constant_time_inventory.sh` reported every comparison and nothing
ran it; v49c and v52 declined the one mutation in this area that changes no
function's result -- `sodium_memcmp` swapped for `memcmp` -- because "the
inventory is a report, not a gate". `tests/constant_time_sites.sh` is the
gate: every `sodium_memcmp`/`sodium_is_zero` call in `src/` and `apps/` is
checked against `tests/constant_time_sites.txt` both ways, comment lines
skipped -- a missing site is a swap or a deletion, an unlisted one an
incomplete list. Sites carry no line numbers, so an edit elsewhere cannot rot
them. Controls by hand: a listed call swapped for `memcmp`, and an unlisted
call added, each turned it red, and both files were restored byte-exact.
GB8-GB10 are the swap, at three sites. It still pins which function
compares, not how long it takes.

**F100** and **F101** were stale references: audit row 4.3 carried V4-1's
inventory figures (48 sites; the tree has 172 lines, and the script counts two
comments as constant-time sites), and F18 cited `demo_keys.c` lines that had
moved.

### Verification

- **Campaigns**, on ASan trees in two lanes (this checkout, and a detached
  worktree at the test commit with its own tree, removed afterwards): v59 10
  of 10 by name. Re-run in full because their kills run through a test this
  step changed: v24 8/8 (M6 still by `ASAN in decode_client_hello`), v25 7/7,
  v26 9/9 (Q2 by `ASAN in sodium_is_zero`), v27 6/6, v48b 7/7, v49c 13/13,
  v52 11/11, v58 19/19. 90 of 90, every row restored clean, the clean suite
  passing after each, no residue.
- **Who else catches GB6 and GB7.** GB6 is killed by H1 and by every check that
  builds its own ServerHello (H2's sig_B, H3, T14); GB7 by H2 and every check
  that builds its own ClientAuth (H1, T10, T29, T32). The client-core KAT
  golden catches both, at the artefact each first changes: `server-hello` for
  GB6, `client-auth` for GB7. That run needed care: a hand loop that applied
  GB7 in the same second GB6's object was compiled tested GB6's binary --
  macOS make's one-second timestamps -- which the identical hashes gave away;
  GB7 alone, rebuilt, is the result above, and `check_build_current` proved
  the tree clean afterwards.
- **Suites.** Normal, ASan and UBSan 46/46 each, each tree proven current in
  the same invocation -- a macOS update had left objects from the previous
  compiler in all three, which the check rebuilt and reported VOID before it
  passed; UBSan 0 `runtime error` lines.
- **Fuzzing.** The update also left Homebrew clang with a sysroot that does
  not exist (`CommandLineTools/SDKs/MacOSX27.sdk`), so the old fuzz tree
  could not build. A new one, `build-fuzz-v415`, is configured with Xcode's
  SDK; its 36 fuzz-labelled tests pass. `fuzz_session` 600 s: 151,927,764
  runs, no crash; `fuzz_handshake` 600 s: 1,313,537 runs, no crash.
- **gcc 16** at `-O3 -Werror` compiled all three changed test files.
- **Documents.** Anchors 291 across 29 campaigns, and the nightly matrix
  names all 29; spec constants and names OK; the claim map's 267 citations
  resolve; the repository secret scan finds 0 violations.

## V4-15c — the artifact-side gaps: primitives, the envelope, build flags, keys at rest, the journal

The last of the claim map's gaps that engineering can close were all claims
about how something was BUILT -- which primitives the code contains, how the
key envelope is formed, which flags the compiler was given, what reaches the
disk and the journal -- each resting on a description rather than a check.

### What each now rests on

- **No hand-rolled primitive (P1, D1).** `no_hand_rolled_primitives` scans
  `src/`, `apps/` and `web/client/` for the constants a primitive cannot do
  without (SHA and Keccak round constants and IVs, the ChaCha sigma, the
  Poly1305 clamp, the X25519 a24, the AES S-box, the lattice moduli and
  roots). They may appear only in `sha1.c`, which is also the canary, and
  only `ws.c` may call `sha1()`. The last rule replaces F53's description,
  which said the SHA-1 was `static`-scoped and that `git grep sha1` finds only
  `ws.c`; neither was true (F102). Shown red by hand in C and in JS.
- **The envelope by §12 alone (D1).** `test_envelope_spec` reads MLDSAEK1
  with nothing but §12's table and raw libsodium, both ways, and the raw key
  is exactly `keyfile_open_buf`'s KEK. Its negative controls show what §12
  makes load-bearing: the associated data, all of it, the Argon2 variant, and
  the memlimit the header states. The first draft asked Argon2i for a key at
  opslimit 1 and got an error, not a different key -- Argon2i's floor is 3 --
  so the variants are compared there. That also changed GC2: "the KDF becomes
  Argon2i" would have broken every ordinary round trip at opslimit 1, which
  is not the self-consistent defect the test exists for; "the KDF uses half
  the stated memlimit" is -- a key that claims a cost it never paid.
- **Build flags (P8).** `check_hardening.sh` reads the linked binary, and its
  canary line cannot fail for this project's code: vendored liboqs and sqlite
  import `__stack_chk_fail` themselves (F104, the F75 class). `build_flags`
  checks what is attributable: `compile_commands.json` for every project
  translation unit, and the project's own archives. A probe on the msi
  laptop's WSL (gcc 11.4, glibc 2.35) settled the FORTIFY question the plan
  left open: at `-O0` the define compiles under `-Werror` and is inert (no
  `__strcpy_chk`); at `-O2` it is active. CI's Linux debug jobs therefore
  carry the define and none of its checks; the claim map says so.
- **Keys at rest, by content (D10).** `test_authd_cli` opens each sealed key
  and scans its directory for every 16-byte window made wholly of the key's
  secret bytes (inside `K`, or in `s1`/`s2`/`t0`) after keygen-server, rewrap
  and client keygen, and in a migrate-key leg -- the first test ever to run
  migrate-key, whose plaintext input is exempt by name and is the scan's
  canary. `authd_e2e` repeats its header scan at the very end. The first
  rule was not this one; see below.
- **The journal (D13).** `test_authd_conn` captures the journal across a
  login, a ROTATE and a BYE and searches it, in hex of either case and in
  base64 at every alignment, for every secret the connection touched,
  including the X25519 private key and the ML-KEM shared secret, snapshotted
  by a stepwise handshake before the library wipes them, and for both
  signatures' `c~ || z` -- not their hint, which is mostly zero padding.

F103 corrected a runbook step that cited a script path that does not exist.
F106 corrected three statements of the nightly's total -- in `README.md`,
the claim map's legend and `tools/README.md` -- that V4-15a and V4-15b had
left at 238 while raising the count beside them. The total is stated in
seven places, and nothing reads a count written in prose.

### The first window rule failed on one fresh key in 256

The first draft of the two scans kept every window holding at least one
secret byte -- the rule `fuzz_keys`'s scanner has used since V2-8, and the
one the draft's comment cited. Two of this step's own campaign rows came back
`CLEAN-SUITE=FAIL(BAD)` for it: v56 MB13 and v49c W3, each with its mutation
killed by name and its sources restored clean, and each whole-suite run
failing one check -- `test_authd_cli`'s "client keygen: no window of the
device's secret key is in any file under its directory (Req 10)".

- **The mechanism.** The window at offset 17 is `rho[17..32) || K[0]`.
  `rho` is the public key's first 32 bytes, and a `.pub` file holds it
  followed by `t1[0]`, so that window is in every file holding the public
  key whenever `K[0] == t1[0]`: one fresh key in 256. `test_authd_cli`
  scans three independent keys, each beside its own `.pub` (the server's,
  the device's and migrate-key's -- checked by running the commands), which
  predicts about one run in 85. V2-8 weighed exactly this window and kept
  it: for its one fixed fixture the coincidence is a fixed fact, and false.
  For fresh keys it is a die with 256 faces.
- **Measured, not argued.** Over 300,000 fresh keys the old rule found a
  window of the key in its own public key for 1,129 (1 in 266; one in 256
  predicts 1,172 ± 34), always first at `sk[17..33)`, and for exactly the
  keys with `K[0] == pk[32]`. The rule now in place: none.
- **Reproduced in the real binary.** A diagnostic now prints the file and
  window of any hit. With it, and with the old rule put back by hand,
  `test_authd_cli` failed 3 of 480 runs (the model predicts 5.6), each
  naming a `.pub` and `sk[17..33)`: the device's twice and `mig.pub` once.
  With the campaigns' two, that is five failures in about 590 runs, on two
  of the three keys; the server's is as exposed, its `a.pub` holding the
  raw key too, and simply was not hit. Restored byte-exact and rebuilt --
  the first rebuild relinked nothing, macOS make's one-second timestamps
  again, which the binary's hash gave away -- it passed 800 of 800, and
  every run printed exactly one hit: the canary's, `mig.sk` at `sk[32..48)`.
- **The rule now.** A window counts only if it is made wholly of secret
  bytes: inside `K`, or in `s1`, `s2` and `t0` -- 3906 of the 4017, V2-8's
  "alternative reading". Every secret byte is still inside a window that is
  looked for. The journal scan applies it per window length (16 bytes for
  hex, 12 for base64), and no longer looks at a signature's hint: 61 bytes,
  mostly zero padding, whose windows would match any run of zeros.
- **The scanner is unchanged**, and recorded as F105: it fails closed, and
  its controls and V2-8's X campaign are derived from its 3951 windows.
- **What was re-run.** The fix changes which windows two checks look for and
  nothing else, and only v60 names those checks. So v60 was re-run for its
  kills, and v56 and v49c in full for their clean suites: 37 of 37 by
  name, every clean suite passing. GC3 dies by the same eight checks as
  before, each hit now naming a sealed file that holds the key in the clear;
  GC4 by the journal scan, which names `keys_c[32..48)` in hex. The
  other six campaigns' results stand as run: their kills name other checks,
  and their clean suites passed.

### Verification

- **Campaigns**, on ASan trees in two lanes: this checkout, and a detached
  worktree at the test commit with its own tree, removed afterwards. v60, 4
  of 4 by name: GC1 and GC2 by `test_envelope_spec`; GC3 by the four
  key-window scans and by four pseudonym and rewrap checks that a plaintext
  envelope also breaks; GC4 by the journal scan alone. Re-run in full
  because their kills run through a test this step changed: v56 20/20, v58
  19/19, v52 11/11, v48b 7/7, v49b 13/13, v49c 13/13, v50b 13/13, v50c 4/4.
  104 of 104 by name, every row restored clean, no residue; two clean suites
  failed, on the rule above. With the rule fixed, v60, v56 and v49c again:
  37 of 37, every clean suite passing.
- **Suites.** Normal, ASan and UBSan 49/49 each (`fuzz_libfuzzer` is skipped
  outside the fuzz tree), each tree proven current in the same invocation,
  ASan and UBSan linked into all 42 executables; 0 ASan reports, 0 UBSan
  runtime errors. The currency check found two trees stale -- the UBSan
  tree's `test_envelope_spec`, and in the fuzz tree the two scan tests,
  `test_envelope_spec` and a CMake compiler-identification object -- because
  the targeted builds here rebuild only what they name. Both were rebuilt,
  and every result above is from after the rebuild.
- **Fuzzing.** `build-fuzz-v415`'s 36 fuzz-labelled tests pass, and the
  three new tests pass there too, `build_flags` expecting no FORTIFY.
  `fuzz_envelope` 600 s: 123,078,132 runs, no crash.
- **gcc 16** at `-O3 -Werror` compiled the three changed test files.
- **Controls by hand**, each restored byte-exact: `no_hand_rolled_primitives`
  red for a SHA-256 IV planted in C, the ChaCha sigma in JS and a stray
  `sha1()` call; `build_flags` red on all 111 translation units with
  `-Werror` removed; the key-window scans' old rule, put back, red 3 times in
  480 runs.
- **Documents.** Anchors 297 across 30 campaigns, and the nightly matrix
  names all 30; spec constants and names OK; the claim map's 284 citations
  resolve; the repository secret scan finds 0 violations in 28 files.

## V4-16 — the secret scanner counts only wholly secret windows

F105, open since V4-15c. `fuzz_keys --scan-secret` is the admission gate for
every committed fuzz input: the CTest `fuzz_no_committed_secrets`, CI's
repository secret scan and `add_regression.sh` all run it. Since V2-8 it
kept every 16-byte window of the fixture secret key that holds at least one
secret byte: 3951 of 4017, among them the 45 that straddle a boundary of
`rho`, `K` and `tr`.

### Why V2-8's rule was right only for its fixture

V2-8 weighed the window at 17, `rho[17..32) || K[0]`, and kept it: in the
fixture's public key the byte after `rho` is `t1[0]`, not `K[0]`, so a
public-key file cannot match. That is one fixed fact about one key. An input
holding the fixture's `rho[17..32)` followed by any byte equal to `K[0]`
does match -- one in 256 of the public-mode inputs a fuzzer changed there --
and the gate refused it although it holds nothing secret. It failed closed,
which made it noise rather than a hole. V4-15c's scans copied the rule for
fresh keys and turned the same coincidence into a test that failed on one
key in 256 (1,129 of 300,000, measured).

### The rule now

A window is kept only if it is made wholly of secret bytes: inside `K` (17
windows) or in `s1 | s2 | t0` (3889) -- 3906, the "alternative reading" V2-8
declined. Every secret byte is still inside a kept window, so any 16
contiguous secret bytes are still caught; what is no longer counted is a
window that is mostly public, a match on which is evidence of nothing. The
predicate is now `window_touches_public()`, and the arithmetic keeps V2-8's
shape: three static asserts (4017, 111, 3906) and both in-loop bounds.

### The controls: three boundaries, and F105's case

The rule has three boundaries where V2-8's had two: where `rho` ends
(31|32), where `K` meets `tr` (48|49) and where `tr` ends (127|128). C5 now
scans the single window either side of each. C5.1-C5.4 keep V2-8's roles --
the last window excluded and the first kept, on the `rho` side and on the
`tr` side -- which is what lets v28's X9 and X10 keep their kills (C5.2,
C5.4); C5.5 and C5.6 are the new boundary. C8 is F105, executable: the C3
public-key file with the byte after `rho` set to the fixture's `K[0]` must
scan clean. C1 and C2 now expect exactly 3906 hits. Nineteen controls, from
sixteen.

### Campaigns: v28 re-anchored, v61 new

Six of v28's ten mutations were anchored on lines this step rewrote, and the
anchors checker would have reported them rotted. Each now makes the same
defect in the new rule -- the exclusion disabled (X1, X8), the `rho` and
`tr` boundaries off by one with the arithmetic unchanged (X4, X5) or slipped
with it corrected (X9, X10) -- and `spec_v28.txt` did not change: every kill
is by the same check as in V2-8. X2, X3, X6 and X7 are byte-identical.

v61 (SW1-SW4) covers what is new. SW1 and SW2 move the K|tr boundary, with
the arithmetic unchanged (killed by the in-loop bound) and corrected (C5.5
alone). SW3 restores V2-8's rule with its own arithmetic, so every count
agrees and C1/C2 pass at 3951: only C5.1, C5.3, C5.6 and C8 can object, and
those four, exactly, kill it. That is the step's purpose stated as a
mutation -- the old rule is now caught by name. SW4 is test-side: C8
expecting the one hit V2-8's rule produced.

`test_authd_cli.c` carried a comment calling the straddling rule "the
fuzz_keys scanner's rule"; it now says the rule was the scanner's until
V4-16. The edit kept the line count, and the test's text is identical in all
three trees, so no campaign that kills through it needed a re-run. The three
scans -- the scanner and V4-15c's two -- now share one rule, written three
times; a common header would have changed two tests' code and forced nine
campaigns to re-run, for no change in behaviour.

### Verification

- **The scanner, before and after.** Before: 16 controls, and 0 violations
  over the gate's 28 files and over all 323 tracked files. After: all 19
  controls pass on the fixture, C1 and C2 at exactly 3906 hits, and the same
  two scans are still 0 -- in the normal, ASan, UBSan and fuzz trees.
- **Campaigns**, on ASan trees in two lanes (this checkout, and a detached
  worktree at the test commit with its own tree, removed afterwards): v61 4/4
  by name -- SW1 by the in-loop bound, SW2 by C5.5 alone, SW3 by exactly
  C5.1, C5.3, C5.6 and C8, SW4 by C8; v28 10/10 re-derived, X9 and X10 again
  by C5.2 and C5.4 alone; v29 9/9, re-run because Y9 kills through
  `fuzz_replay_keys`, the same changed binary. 23 of 23, every row restored
  clean with a passing clean suite, no residue. A hand probe of the 14
  scanner mutations before the campaigns predicted every one of these kills.
- **Suites.** Normal, ASan and UBSan 49/49 each, each tree proven current in
  the same invocation, ASan and UBSan linked into all 42 executables; 0 ASan
  reports, 0 UBSan runtime errors. The UBSan and fuzz trees were stale (the
  changed scanner not yet built there); the currency check rebuilt them and
  every result above is from after the rebuild.
- **The comment edit.** `test_authd_cli`'s text hash is identical before and
  after in all three trees (7d5e850a..., ee249807..., caa16193...); the fuzz
  tree's currency check, too, found its object changed and its executable
  not.
- **Fuzzing.** The fuzz tree's 36 fuzz-labelled tests pass. `fuzz_keys`
  600 s: 1,899,795 runs, no crash.
- **gcc 16** at `-O3 -Werror` compiled `fuzz_keys.c` and `test_authd_cli.c`.
- **Documents.** Anchors 307 across 31 campaigns, and the nightly matrix
  names all 31; spec constants and names OK; the claim map's 284 citations
  resolve; every audit row has its 8 cell separators; the repository secret
  scan finds 0 violations.

## V4-17 — the Linux runner image becomes a choice: ubuntu-26.04

GitHub moves `ubuntu-latest` from Ubuntu 24.04 to 26.04 between 2026-10-19
and 2026-11-19 (actions/runner-images#14748). Every Linux job in CI, the
nightly and the bench workflow used that label, so the toolchain every gate
had been proven on was about to change under it, on GitHub's schedule,
between one nightly and the next -- with nothing in this repository saying
so. Every Linux job now names `ubuntu-26.04`, and does so only because both
workflows were run on it first and compared, job by job, with the last
24.04 runs (CI 37164058206, nightly 37154953425).

### What changed under the gates

| | Ubuntu 24.04 | Ubuntu 26.04 |
|---|---|---|
| gcc | 13.3.0 | 15.2.0 |
| clang | 18.1.3 | 21.1.8 |
| CMake | 3.31.6 | 4.4.3 |
| Python | 3.12 | 3.14.4 |
| OCaml (ProVerif's build) | 4.14 | 5.4.0 |

Every Linux job now records its image -- `/etc/os-release` and the
compiler, CMake, Python, Docker or OCaml it uses -- so each result carries
the toolchain that produced it.

### What did not change, measured

- **CI** (37725908821, 13/13): every Linux job ran the same tests -- 46 per
  suite tree, `fuzz_libfuzzer` skipped on both images; 36 fuzz-labelled; 3
  and 6 in the wasm job, `browser_e2e` among them. The hardening gate's
  table is identical under gcc and clang: all five properties on all three
  shipped binaries. gcc 15 raised no warning under `-Werror`, which the
  local pre-check predicted: all 111 project translation units compile
  under gcc 16.2 at `-O0` and `-O2`.
- **Nightly** (37724972569, 46/46): 274 of 275 mutation rows identical in
  every field -- verdict, named-failure count, provenance, restore, clean
  suite, residue -- and all 31 campaign preflights at 45 tests on both. All
  12 fuzz targets ran 600 s with no crash or artifact. ProVerif, built
  against OCaml 5.4.0 rather than 4.14, produced a byte-identical verdict
  block: the base model proves, resilience holds, every control fails.
- **The one row that differed is chance.** v49d G2 breaks base32's
  confusable normalisation; its named check fires on both images, but the
  number of FAIL lines was 3 on 24.04 and 13 on 26.04. The other ten come
  from a recovery check that retypes a RANDOM code with `o` for `0` and `l`
  for `1`: when the code holds neither digit -- (30/32)^16, 36% -- the
  retyped code is the issued one and nothing cascades. Six earlier 24.04
  nightlies already alternated (13, 3, 13, 13, 3, 13).

### What broke, and it was this step

The probe's record line, `{ . /etc/os-release ...; } || sw_vers`, killed
all three macOS suite jobs before they configured: macOS has no
`/etc/os-release`, and its bash 3.2 exits outright when `.` cannot find a
file, so the fallback never ran. Reproduced locally with the same bash and
fixed by testing for the file first. The same log showed what
`macos-latest` means today: macOS 26.6.2. That label moves on Apple's
schedule and GitHub's, with no announcement yet, and is the one moving
image left in the workflows.

F107 corrected the README's test counts, three steps out of date in three
places.

### Verification

- The comparison above, read from both images' full logs, not only their
  conclusions: CI 37725908821 13/13 and nightly 37724972569 46/46 on 26.04,
  against CI 37164058206 and nightly 37154953425 on 24.04.
- The README's counts re-derived from `tests/CMakeLists.txt` (Node gates 2
  tests, the WebAssembly tree 2, the browser 1) and matched against CI's 46.
- Document gates: anchors, claim map, spec constants and vocabularies, the
  audit table's separators, `git diff --check`; the three workflows parse.

## V4-18 — the macOS runner image: macos-26

V4-17 left `macos-latest` as the one image still chosen by a moving label.
GitHub's runner-images README maps `macos-latest` and `macos-26` to the same
image -- macOS 26 Arm64 -- so naming `macos-26` in the three macOS suite jobs
and in v35's macOS-only campaign changes nothing on the day it lands. It
means that when `macos-latest` next moves, these gates do not move with it
unless a commit says so. Every runner image in the workflows is now named;
none is chosen by `-latest`.

The nightly's macOS job now records its macOS version, as CI's suite jobs
have since V4-17.

### Verification

- **CI** 37790472870, 13/13. The three macOS jobs record what the last
  `macos-latest` run (37770417177) recorded: macOS 26.6.2, Apple clang 21.0.0
  (clang-2100.1.1.101), and 46 tests passing in each.
- **The nightly's v35 job** on `macos-26` (37790600157, carrying the control):
  macOS 26.6.2, the same Apple clang, preflight 45 tests, and U2 killed by 3
  named checks -- all as in the last `macos-latest` nightly (37764177687).
  With U3's expectation rotted it went red on exactly that job, 45/46: the
  gate can still fail on the named image.
- The workflows parse; anchors, claim map and `git diff --check` OK.

## V4-19 — actions/checkout v4.4.0 → v7.0.1

All 13 checkouts were pinned to v4.4.0 (`11d5960`), which declares
`using: node20`. GitHub has deprecated Node 20 for actions and was already
forcing it onto Node 24, with an annotation on every job; when Node 20
support ends, a pin to it stops being a choice this repository made. The
pin is now v7.0.1 (`3d3c42e`, `using: node24`), still by SHA, with the
version beside it.

The three majors in between change nothing these workflows use: v5 is the
runtime; v6 moves persisted credentials to a separate file, which matters
only to authenticated git after checkout, and the workflows run none (the
only clones are public, and no step uses a token); v7 blocks fork checkouts
under `pull_request_target` and `workflow_run`, triggers they do not have.

### Verification

- **CI** 37948939024, 13/13, every test count as before (46 per suite job on
  both platforms, 36 fuzz-labelled, 3 and 6 in the wasm job). Node 20
  annotations: 13 on main's last run (37831304231), one per job; 0 now.
- **The nightly**, with v58 GA1's expectation rotted (37949015834): red on
  exactly that job, 45/46.
- The workflows parse; anchors, claim map and `git diff --check` OK.

## V4-20 — an audit row's clock, whose handle it is, and five rows that said less than the tree

The first step taken in a Linux cloud session rather than on the developer's
Mac, from the owner's request to fix the open register items smallest first.
Three small items, in that order: register rows that had fallen behind the
tree, F45 and F48. F41 was the next by size and is deliberately not here
(below).

### What was decided (user decisions in brackets)

- **[F48's refusal is `pk-in-use`, with no new error code.]** It is the code
  the store's own conflict path already gives a key on record, and it is
  accurate: the key IS enrolled, under a handle the requester does not own.
  Erratum 46 widens its definition rather than adding a name every site must
  learn.
- **[F41 is the next step, V4-21, not this one.]** A distinct fingerprint type
  changes a header every daemon file includes and turns v49d G12 into a
  compile kill that has to be allowlisted, which is a step's worth of design
  on its own.
- **[The README's stale campaign count is recorded as F108 and fixed here]**,
  since this step changes the count and has to touch every statement of it.
- The step was begun before the owner's handoff document arrived and two
  commits were made without a plan; the rest was planned and approved, and
  those two are reported here as what they are.

### The register's stale rows

Five rows said less than the tree. F0 (Release + gcc does not build) still
read as open: both `symlink()` calls have checked their return since
`176d786`, and CI's `release` job (V4-11) builds, tests and installs Release
with gcc and clang on every push. F19's disposition described F0's fix
instead of its own (the checked `snprintf` in both `path()` helpers). F29
carried V4-9b's "Open" beside its V4-10c closure, though `authd_admin
audit-verify` has existed since V4-10c. F17 now records 4.8 closed and 4.9
partly pinned (which function compares, not how long). F5 stays open and now
says why: coverage was measured once, before the daemon existed.

### F45 — an audit row is stamped with its transaction's clock

`audit_append` read the wall clock for itself, so a primitive driven by the
caller's clock wrote its own columns at that time and its audit row at
another: a rotation at 1000 had `valid_from` 1000 and a `key-rotate` row
dated today. The register called it harmless because only a test could see
it. It was not only a test's: the daemon's clock is taken once per pass of
the event loop, so a row could already disagree with its own transaction by
however long the pass ran -- up to ~0.8 s through RECOVERY-USE's Argon2id
loop (F39).

`audit_append` takes `now`. Every primitive that has a caller's clock passes
it -- rotation, enrollment, recovery issue, use and failure, and revoke=all,
whose `revoke_device_locked` now stamps `revoked_at`, the key's `valid_to`
and its audit row with the recovery's clock. The primitives with no clock
read the wall clock once and use it for every column they write.
`add_user_locked` keeps its signature because v49d G15 anchors on its call.

The new block in `test_authd_store` runs each clock-driven primitive at a
time no wall clock will read (1000..1300) and printed six FAIL lines before
the fix -- rotation, issue, a failed attempt, the lock, the use, revoke=all's
two revocations -- while its canary passed: the rows written without a clock
carry the wall time, so the reader does see `at`.

### F48 — only the handle's own user re-enrolls it

`ENROLL user=u2 handle=<u1's> pk=<u1's> via=site` answered
`OK fp= idempotent=1`. Reproducing it found the register's row too narrow:
the store's own idempotent branch never asked whose handle it was either, so
**via=recovery** had it -- u2's ticket naming u1's handle and key answered a
plain `OK fp=` and stayed unspent. Nothing was written on either path; the
reply asserted a device u2 does not hold.

Both layers are fixed. The store answers CONFLICT unless the handle's device
belongs to the user (`device_owned_by`, SQL equality, so no identifier is
compared in C), with no audit row, like any other key reuse; both daemon
paths already roll back on CONFLICT, so no user is created (F47) and no
ticket spent. The pre-check reads the owner from `store_lookup_active` and,
on a mismatch, leaves the decision to the store, whose refusal
`refuse_conflict` answers as `pk-in-use`. That comparison is a new
`sodium_memcmp` site, listed in `tests/constant_time_sites.txt` in the same
commit. The text v49a V2 and v58 GA11 anchor on is byte-identical.

Five named FAIL lines before the fix, two in `test_authd_store` and three in
`test_authd_localapi`, with canaries at both layers: the owner's own
re-enrollment is still idempotent, the refused request created no user, and
the ticket still enrolls u2's own new device afterwards.

### Campaign v62 — AO, the audit clock and ownership

Five mutations, each changing a value and keeping every use, each named:

| ID | Defect | Killed by |
|---|---|---|
| AO1 | `audit_append` reads the wall clock whatever `now` it is given | all six clock checks |
| AO2 | revoke=all revokes on the wall clock | the revoke=all check alone |
| AO3 | the rotation's audit row alone on the wall clock | the key-rotate check alone |
| AO4 | the store's ownership query matches every user | the two store owner checks |
| AO5 | the pre-check keeps `idempotent=1` on an owner mismatch | the two site-path checks alone |

AO4 and AO5 are the point of the campaign: each layer's half of F48 is
caught without the other's help. AO5 cannot be seen through the store,
because the pre-check answers before the store is asked; via=recovery never
reaches the pre-check, so only the store's half covers it.

### A campaign killed mid-mutation

The four campaigns ran in one lane, one background job -- and the session
kills a background job at two hours. It died during v58, between applying
GA5 and restoring it, and left `authd_conn.c` carrying
`... != 0 && m.sig_old_len == 0u) { /* MUTATION GA5 */` in the working tree.
It was found by looking (`git status`, then a grep for `MUTATION` across
`src apps tests bench`), restored from `HEAD`, which this step never changed
for that file, and compared with the runner's own snapshot: all 133
snapshotted sources equal the tree. v58 was then finished from GA5 in two
runs of seven and eight, each well under the limit, with the spec split in
scratch so the committed one did not change; each run's preflight rebuilt
the ASan tree from scratch, which is what clears a mutant's objects. GA1-GA4
had already been killed and restored before the cut. The lesson for this
environment: a job that can mutate the tree is sized to finish inside the
limit, never trusted to be stopped cleanly by it.

### Where this ran, and what it could not

A Linux container (gcc 13.3, clang 18.1), not the Mac: no gcc 16, no macOS,
no wasm or browser trees, and none of the project memory. **sqlite.org is
denied by the session's network policy**, so the pinned amalgamation could
not be fetched. Every local tree took SQLite 3.45.1 from the system's static
archive through a scratch-only `FETCHCONTENT_SOURCE_DIR_SQLITE3_AMALG`
override -- the repository is unchanged -- linked as a standard library so
that only binaries referencing sqlite pull it in. A first attempt linked the
system's dynamic library instead, and `client_links_no_sqlite` failed on its
canary (the daemon showed 0 `sqlite3_` symbols): the gate doing its job on a
build it was not written for. The clang sanitizer and libFuzzer runtimes were
installed from the Ubuntu archive for the same reason. So every local result
below is on SQLite 3.45.1, not 3.53.4; the pinned build is CI's to prove.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before the fixes.** F45: six named FAIL lines in `test_authd_store`,
  canary passing. F48: five, two in `test_authd_store` and three in
  `test_authd_localapi`, canaries passing. After: both pass (230 and 282
  checks).
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 46/46; ASan 46/46 and UBSan 46/46, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; the fuzz tree
  81/81 (36 fuzz-labelled, `fuzz_libfuzzer` run rather than skipped); Release
  with gcc 13 at `-O2 -D_FORTIFY_SOURCE=2` and `x86-64-v3`, CI's release
  shape, 46/46. 46 is CI's native count; the 3 that need a wasm tree or a
  browser were not built here.
- **A currency check that went stale on a comment.** Two comments were
  corrected after the campaigns (`revoke_device_locked`'s, which said `now`
  stamps "all three writes" -- the token delete has no timestamp -- and
  `store.h`'s enrollment contract, which did not mention the owner), with
  line counts kept. The Release tree stayed current, but the four `-g` trees
  went STALE: in the Debug tree 18 objects changed and no executable's text did. clang 18
  writes DWARF 5, whose line table carries each source file's MD5, so a
  comment changes every object that includes the file. Per the rule, every
  `-g` suite above is from AFTER that rebuild; the campaigns ran on code the
  Release tree shows to be identical.
- **Campaigns**, on the ASan tree, one lane: v62 5/5, each killed by
  exactly the checks predicted; and, re-run because they mutate the two files
  this step changed in the functions it changed, v49a 11/11 (V2 runs through
  the pre-check's untouched anchor), v57 5/5 (HC3 through revoke=all) and v58
  19/19 (GA11 inverts the pre-check's key comparison, killed by 8 named
  checks). 40 of 40, every row restored clean with a passing clean suite and
  no residue. Not re-run here: the other six campaigns that mutate those
  files -- v47, v49b, v49c, v49d, v56 and v59, 78 mutations -- whose anchors
  all still match; the nightly runs them.
- **Control.** v62's AO3 with its expectation replaced by text no check
  prints: `AO3 SURVIVED(BAD: [CONTROL: ...])`, runner exit 1, restored clean.
  The committed spec was never edited; the control spec lived in scratch.
- **Fuzzing**, 600 s each: `fuzz_localapi` 10,544,792 runs, `fuzz_authd_conn`
  1,696,537, 0 crashes, 0 artifacts. `fuzz_localapi`'s standing invariant --
  a refusal never advances the audit chain -- covers F48's refusals.
- **gcc 13 at `-O3 -Werror`** compiled the four changed C files clean, as a
  stand-in for the Mac's gcc 16, which is not here.
- **Documents.** Anchors 312 across 32 campaigns, 280 mutations, and the
  nightly matrix names v62; the claim map's 294 citations resolve; spec
  constants and names OK; `constant_time_sites` passes at 25 calls; every
  findings row has its 8 separators; the secret scan finds 0 violations in
  CI's 28 files and in 275 files across `tools tests docs apps src`;
  `git diff --check` OK. Every statement of the mutation and campaign counts
  was re-grepped and updated (`README.md` twice, `tools/README.md`,
  `docs/review/README.md`, `REPRODUCE.md`, `CLAIMS.md`), plus F108's.
- **CI** 38026028830, dispatched on the pushed branch at `9481e6d`: 13/13,
  every test count as V4-19's run -- 46 per suite job on Linux (clang debug,
  ASan, UBSan; gcc debug; Release with gcc and with clang) and on macOS
  (clang debug, ASan, UBSan), 36 fuzz-labelled, 3 and 6 in the wasm job,
  each suite proven current in its own step; the 12-target fuzz smoke 0
  crashes and the secret scan 0 violations. This is where the pinned SQLite
  3.53.4, macOS and the wasm and browser tests ran.
- **The nightly**, with v62 AO3's expectation rotted (38027637759): red on
  exactly that job, 46/47. AO3 `SURVIVED(BAD:)`; AO1, AO2, AO4 and AO5
  killed by the same named-check counts as locally (7, 2, 3, 3). Every
  other campaign's verdicts match its spec -- 278 killed in the binaries,
  v24 M8 by its allowlisted compile kill -- which includes the six this step
  did not re-run locally (v47, v49b, v49c, v49d, v56, v59). The twelve fuzz
  targets ran 600 s each with 0 crashes.
- **Not run anywhere:** gcc 16, which is the Mac's.

## V4-21 — a fingerprint is a type, so a secret cannot be logged as one

F41, open since V4-9a. `authd_log_fp` is the logging API's one byte sink:
spec §15 requires a public-key fingerprint on every enrollment, every Req 7
refusal and every rotation. Its parameter was `const uint8_t fp[32]`, which C
reads as a bare pointer, so any 32-byte buffer type-checked: a login code, a
recovery ticket or its hash, half the session keys. The guarantee lived in a
comment, and three mutations (v49c W12, v49d G12, v60 GC4) made the leak a
campaign failure rather than a convention. The register's proposal was a
wrapper type that "would make it structural".

### What was decided (user decisions in brackets)

- A fingerprint is `authd_fp_t`, a struct of 32 bytes, and `authd_fp_of_pk`
  is the one way to make one: SHA-256 over exactly `AUTHD_FP_PK_BYTES`,
  asserted equal to `MLDSA_PUBLIC_KEY_BYTES` so it cannot drift.
  `authd_log_fp` takes `const authd_fp_t *`. `authd_log.h` stays
  self-contained; the store keeps its own `pk_fingerprint` for its column.
- **[The three leak mutations are re-authored, not allowlisted.]** Each now
  casts its secret to `authd_fp_t` -- the one shape left in which the leak can
  be written -- and keeps its expectation, so the journal scans still have
  mutation evidence. Allowlisting them as compile kills would have left the
  scans untested, the F79 lesson in reverse.
- No byte of output changed (`event=... fp=<64 hex>`), so there is no spec
  erratum.

### Before and after

A probe of the old shape -- `const uint8_t h[32]` passed to `authd_log_fp` --
compiled clean at `-Werror` under clang 18 and gcc 13 on the V4-20 tree.

The new CTest `log_fp_type` compiles two probes with the build's own compiler
at `-std=c11 -Wall -Wextra -Werror -fsyntax-only`, identical but for the
argument: an `authd_fp_t` made by `authd_fp_of_pk` must compile (the canary)
and a bare 32-byte buffer must not. On the V4-20 header the gate is red, and
it is the canary that says so: the bare-buffer probe failed there only because
`authd_fp_t` did not exist yet, which is exactly the false pass the canary is
for. After the change both lines pass, under clang and under gcc. In
`test_authd_log`, `authd_fp_of_pk` is checked against an independent SHA-256
of the whole key, and the logged line against that hex.

Every call site builds its fingerprint with `authd_fp_of_pk`: enrollment,
recovery, Req 7's two lines, and the rotation, which now keeps `fp_old` and
`fp_new` apart instead of reusing one buffer; the ROTATE_ACK still carries
`fp_new`. Two anchors moved with their call sites and were re-anchored with
their defects unchanged: v60 GC4, and v58 GA10 (the logged `fp_old` computed
from the presented key).

### Campaign v63 — FT, the fingerprint type

Two mutations, each changing a value and keeping every use, each named:

| ID | Defect | Killed by |
|---|---|---|
| FT1 | `authd_log_fp`'s parameter widened to `const void *`, header and definition, the body casting back -- the "make it generic" regression | `log_fp_type` alone: "a 32-byte buffer passed to authd_log_fp does not compile -- it COMPILED" |
| FT2 | `authd_fp_of_pk` hashes one byte short of the key | `test_authd_log`: both fingerprint checks |

FT1 is the one no test binary can see: every caller still compiles and every
byte logged is the same. Only a gate that compiles something can object, and
that is why the gate exists. A hand probe on a scratch copy of the sources
showed the same before the campaign ran.

The re-authored mutations are killed by the same checks as before: W12 by
"logscan: the login code never appears in the daemon's log", G12 by
"recovery: the enrollment TICKET never appears in the log (§15)", GC4 by the
journal's session-key scan, and the re-anchored GA10 by "req7(site): the
refusal is logged with both key fingerprints".

### Environment

As for V4-20: a Linux container, every local result on SQLite 3.45.1 from the
system's static archive (sqlite.org is denied by the session's network
policy), clang 18 with its sanitizer and libFuzzer runtimes, gcc 13. Deleting
the V4-20 scratch branch from this session was refused by its git proxy
(HTTP 403); it is left for the owner to delete.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** The old shape compiled at `-Werror` under clang 18 and gcc 13,
  and `log_fp_type` was red on the V4-20 header (its canary).
- **Suites**, each tree proven current in the same invocation: Debug (clang)
  47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into all 42
  executables, 0 ASan reports, 0 UBSan runtime errors; Release with gcc 13 at
  `-O2 -D_FORTIFY_SOURCE=2` and `x86-64-v3` 47/47; the fuzz tree 82/82. Each
  suite is one more than V4-20's, the new `log_fp_type`. `test_authd_log` has
  33 checks.
- **Campaigns**, on the ASan tree, in three runs each sized under the
  session's two-hour job limit: v63 2/2; the three campaigns whose mutations
  were re-authored, v60 4/4, v49c 13/13 and v49d 15/15; and the re-anchored
  v58 GA10 1/1 from a scratch spec. 35 of 35 killed by name, every row
  restored clean with a passing clean suite and no residue. Campaigns that
  mutate the touched files elsewhere are left to the nightly; their anchors
  all match (315 across 33 campaigns).
- **Control.** FT1 with its expectation replaced by text no check prints:
  `SURVIVED(BAD: [CONTROL: ...])`, runner exit 1, restored clean; the
  committed spec was never edited.
- **Fuzzing**, 600 s each: `fuzz_localapi` 12,004,652 runs, `fuzz_authd_conn`
  2,163,928, `fuzz_authd_config` 51,118,917; 0 crashes, 0 artifacts.
- **gcc 13 at `-O3 -Werror`** compiled all six changed C files clean, as a
  stand-in for the Mac's gcc 16.
- **Documents.** Anchors 315, 282 mutations, 33 campaigns, and the nightly
  matrix names v63; the claim map's 298 citations resolve, `log_fp_type`
  cited as a tool, the form `check_build_flags.cmake` already uses; spec
  constants and names OK; `constant_time_sites` passes; every findings row
  has its 8 separators; the secret scan finds 0 violations in CI's 28 files
  and in 278 across `tools tests docs apps src`; `git diff --check` OK.
- **CI** 38085627662, dispatched on the pushed branch at `f8d3433`: 13/13;
  47 per suite job on Linux (clang debug, ASan, UBSan; gcc debug; Release
  with gcc and with clang) and on macOS (clang debug, ASan, UBSan) -- one more
  than V4-20's, the new `log_fp_type`, which so also passed under Apple clang;
  36 fuzz-labelled, 3 and 6 in the wasm job; the fuzz smoke 0 crashes on 12
  targets and the secret scan 0 violations. This is where the pinned SQLite
  3.53.4, macOS and the wasm and browser tests ran.
- **The nightly**, with v63 FT1's expectation rotted (38085646710): red on
  exactly that job, 47/48. FT1 `SURVIVED(BAD:)`; FT2 killed. Every other
  campaign's verdicts match its spec -- 281 killed in all, v24 M8 by its
  allowlisted compile kill among them -- including the re-authored W12, G12
  and GC4 and the re-anchored GA10, each by its usual check. The twelve fuzz
  targets ran 600 s each with 0 crashes.
- **Not run anywhere:** gcc 16, which is the Mac's.

## V4-22a — the claim map's test-level gaps

Asked for "liboq 0.17.0 and claim map gaps". liboqs 0.17.0 still does not
exist: on 2026-10-11 the project's public tags are `0.16.0` and
`0.16.0-rc1`, with no 0.17.0 and no release candidate for it, so F91's bump
waits, as its row says; the re-check is recorded there. Of the claim map's 27
"Not established" paragraphs, the ones that need a timing lab, memory
inspection or an outside reader stay as they are (P3, P9, D1, D3, the ProVerif
abstractions). **[All seven engineering-closable gaps were chosen -- D9, D8,
D4 and P13 at test level, D12, D11 and D14 as larger items -- and taken as
three sub-steps in V4-15's a/b/c shape.]** This is V4-22a, the four
test-level ones; V4-22b (Caddy in CI, a real second user) and V4-22c (a fault
after every write) follow, each with its own plan, exit report and commits.

### What was decided

- **Each gap gets a check shown failing first, and a mutation that names
  it.** Every mutation in campaign v64 except TG2 was first run against the
  suite as it stood (V4-21's tree): each passed every test, which is what
  makes it a gap rather than a restatement.
- **D9, the key clause.** `test_authd_store`'s new `keyfilter` block mirrors
  V4-15a's device-clause test: the key row is marked revoked behind the
  store's back while the device and user stay active, and the lookup must
  refuse it, after the same handle resolving first as the canary. The
  obvious mutation, the key clause removed outright, is not a gap: rotation
  tests kill it, because a superseded key would resolve. The one that
  survived V4-21's whole suite (47/47) excludes only superseded keys --
  `dk.status<>'superseded'` -- and that is TG1.
- **D9, revoke=all end to end.** A third form of `tests/e2e_site.mjs`,
  `--recover-all <user> <code>`, spends a recovery code with `revoke: 'all'`
  through `examples/site-node/authd.mjs`'s own `recoveryUse`. In
  `authd_e2e`'s revocation section, bob's two devices -- the first, which the
  earlier `revoke=none` recovery left active, and the one it enrolled -- each
  log in first (the canary), the second issued code is spent, and both are
  then refused at login; the code is checked absent from the journal.
  - *Placed in the revocation section, not in `e2e_recovery.mjs` as planned*:
    the spend adds audit rows, and there it would have pushed
    `device-enroll` out of the later `audit-tail --n 10` window.
  - *TG2 is v49d G14's shape, as planned, named against `authd_e2e`.* A
    mutation only the e2e can see exists -- `recoveryUse` sending
    `revoke: 'none'` whatever it is given -- and a hand probe showed the new
    leg kill it ("after RECOVERY-USE revoke=all, bob's first device still
    obtained a login code (Req 9)"). It is not committed: the runner
    snapshots, restores and fingerprints C sources and binaries only, so a
    JavaScript mutant would be left unrestored and called
    `MUTANT-NOT-IN-BINARY`. Teaching the runner other languages is outside
    this step.
- **D8, sig_old by another key.** `build_rotate_ex` takes the sig_old signer;
  `build_rotate` passes the old key, so every existing case is
  byte-identical. Two new cases sign the CORRECT rotate-old digest with a key
  enrolled nowhere and with the incoming key, and each must be refused with
  the journal naming `rotate-sig-old`. TG3 accepts sig_old under `pk_old` or
  `pk_new` -- an attacker holding only the incoming key could rotate to it --
  and passed V4-21's `test_authd_conn` (176 checks); only the incoming-key
  case sees it. That case runs last, because when it is wrongly accepted the
  rotation happens and every later session under the old key fails too:
  TG3's 19 named FAIL lines are that cascade, the two it is named by among
  them.
- **D4, more encodings and the backup.** `secret_absent` also looks for each
  secret's hex in upper case and for every 12-byte window in standard and
  URL-safe base64 -- `test_authd_conn`'s journal rule. After the exchange's
  and recovery's scans, `store_backup` writes a `VACUUM INTO` copy and the
  same scans run over it, with the hashes present in the backup as the
  canary; for recovery, the code's canonical base32 is looked for as well.
  TG4 parks the token's base64 in its row's `handshake_id` column, where
  v58 GA4 parks its raw half; V4-21's `test_authd_localapi` (282 checks)
  passed it.
- **P13, every bucket.** P4(h) sets every padding byte, one at a time, in 20
  inners: for each bucket from 16 to 4096, empty content, content one byte
  under and one over a bucket boundary, and the last one bucket on --
  10,907 cases (bucket 1 pads nothing).
  - *The first version took 35 s at -O0*, one full handshake per case, and
    overflowed the fixture's 256-entry pending store on the way. It now
    opens each case on a white-box clone of the bucket's freshly initialized
    receiver -- `tests/fuzz/fuzz_session.c`'s technique: the struct copied
    and its key block refilled, which works because `terminate` zeroes the
    block and never frees it -- in 0.8 s. The canary is that each inner
    opens through such a clone while its padding is clean.
  - *TG5 caps the check at 64 padding bytes where `pad_len` is computed*,
    not in the `sodium_is_zero` call: the first form also failed
    `constant_time_sites`, which pins that call's text, so it was not a gap
    of the claim. The 64-byte inner of P4(b), (c) and (g) has 52 padding
    bytes, and V4-21's `test_session` passed TG5.
- **Records.** D13's last sentence still said the logging sink accepts any
  32-byte secret, which V4-21 made false (**F109**). Two lines above the
  register's count in `docs/review/README.md`, the counts of findings and of
  errata had missed V4-20's F108 and erratum 46 (**F110**) -- found because
  this step had to change the first.

### Campaign v64 — TG, the test gaps

| ID | Defect | Killed by |
|---|---|---|
| TG1 | the lookup's key clause excludes only superseded keys | `keyfilter: a revoked key does not resolve even while its device and user are active`, alone |
| TG2 | revoke=all's device search matches nothing (G14's shape) | `authd_e2e`: bob's first device still logs in |
| TG3 | sig_old accepted under `pk_old` or `pk_new` | the incoming-key case and its journal line, then the cascade (19 named) |
| TG4 | the token's base64 in its row's `handshake_id` | the store scan and the backup scan |
| TG5 | the padding check capped at 64 bytes | P4(h), alone |

### Environment

As for V4-20 and V4-21: a Linux container, every local result on SQLite
3.45.1 from the system's static archive (sqlite.org is denied by the
session's network policy), clang 18 with its sanitizer and libFuzzer
runtimes, gcc 13; no macOS, no gcc 16, no wasm or browser trees. A Docker
client is installed but no daemon runs, which matters to V4-22b, not here.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** Each mutation except TG2 was run against V4-21's tests first
  and survived: TG1 the whole debug suite (47/47), TG3 `test_authd_conn` (176
  checks), TG4 `test_authd_localapi` (282) and five other daemon suites,
  TG5 `test_session` and every other CTest. Then each new check failed by
  name with its mutation applied by hand, and passed without it.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; Release with
  gcc 13 (`-O3 -DNDEBUG -D_FORTIFY_SOURCE=2`, `x86-64-v3`) 47/47; the fuzz
  tree 82/82. The test count did not change -- the new checks live in
  existing tests: `test_authd_store` 234 checks (230), `test_authd_conn` 186
  (176), `test_authd_localapi` 286 (282), `test_session` two more, and one
  more `authd_e2e` leg, whose PASS line and P4(h)'s 10,907 cases printed in
  every tree.
- **Campaigns**, on the ASan tree, each run sized under the session's
  two-hour job limit and none run beside another, since the runner mutates
  the shared working tree: v64 5/5, each killed by exactly the checks the
  table names. Re-run because this step changed the checks they are killed
  by -- from scratch specs, the committed ones unchanged:
  - `authd_e2e` stops at its first failure, so every mutation it kills after
    the new leg: v50c O1-O4, v56 MB9, v58 GA13 and GA14;
  - every `test_session` kill in v26 (Q1-Q9), v27 R4 and v59 GB1, GB2, GB5
    (GB5 and Q1 now also fail P4(h));
  - v49c's nine `test_authd_conn` rotation and journal kills, and v58 GA5,
    which the new sig_old cases also catch;
  - v58 GA3, GA4, GA6, GA9 and v49d G12, G14, the scans and revocation.

  41 of 41 killed by name, every row restored clean with a passing clean
  suite and no residue, every final fingerprint identical. The rest of those
  campaigns is left to the nightly; their anchors all match.
- **Control.** v64 TG4 with its expectation replaced by text no check prints:
  `SURVIVED(BAD: [CONTROL: ...])`, runner exit 1, restored clean.
- **gcc 13 at `-O3 -Wall -Wextra -Werror`** -- the Release tree's flags --
  compiled the four changed C test files clean, as a stand-in for the Mac's
  gcc 16.
- **No fuzzing**: no product source changed in this step.
- **Documents.** Anchors 321 across 34 campaigns, 287 mutations, and the
  nightly matrix names v64 (the nightly's own coverage check, run locally:
  34 committed, 34 wired); the claim map's 315 citations resolve; spec
  constants and names OK; `constant_time_sites` passes; F109 and F110 have
  their 8 separators (F14, F67, F69 and F105 carry `|` inside code, as
  before); the secret scan finds 0 violations in CI's 28 files and in 280
  across `tools tests docs apps src`; `git diff --check` OK. Every statement
  of the mutation, campaign, anchor, findings and errata counts was
  re-grepped.
- **CI** 38147742977, dispatched on the pushed branch at `cb2e168`: 13/13,
  every count as V4-21's run -- 47 per suite job on Linux (clang debug,
  ASan, UBSan; gcc debug; Release with gcc and with clang) and on macOS
  (clang debug, ASan, UBSan), 36 fuzz-labelled, 3 and 6 in the wasm job; the
  12-target fuzz smoke 0 crashes and 0 artifacts, the secret scan 0
  violations, the specification gates OK. The new checks live in existing
  tests, so here they show as those tests passing -- on the pinned SQLite
  3.53.4 and on macOS, which this container has neither of.
- **The nightly**, with v64 TG1's expectation rotted (38148560358): red on
  exactly that job, 48/49. TG1 `SURVIVED(BAD:)`; TG2-TG5 killed by the same
  named-check counts as locally (1, 19, 3, 1). Every other campaign's
  verdicts match its spec -- 286 of 287 killed in all, v24 M8 by its
  allowlisted compile kill among them, every row restored clean -- and the
  re-run kills show the same counts as here (GA5 25, W1 29, Q1 4, GB5 2).
  The twelve fuzz targets ran 600 s each with 0 crashes and 0 artifacts.
- **Not run anywhere:** gcc 16, which is the Mac's.

## V4-22b — Caddy in CI, and a real second user

The second of V4-22's three sub-steps: two claim-map gaps that need an
environment rather than a unit test. D12's map said the real-Caddy leg "is
hand-run, not a CTest and not in CI"; D11's said "no second real user
connects".

### What was decided

- **D12: the Caddy leg becomes a CI job, `caddy proxy (Linux, Docker)`**,
  shaped like the `deploy` job: `tests/caddy_proxy.sh` runs as written, a
  `SKIP:` line is an error and `PASS: CADDY: all checks` is required. It stays
  out of CTest for the reason its header gives. CI goes from 13 jobs to 14.
- **Both network inputs of that script are pinned.**
  - The image is `ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55`,
    the tag's multi-arch index digest as Docker Hub served it on 2026-10-11.
  - The Caddy 2.10.2 tarball's sha256 is now ASSERTED, per architecture,
    where it used to be printed for this log to record -- and only the arm64
    one ever was (V4-10b, above), while CI runs amd64. amd64:
    `5c218bc34c9197369263da7e9317a83acdbd80ef45d94dca5eff76e727c67cdd`;
    arm64: `501e955fa634c5aab63247458c3ac655cfdd6cbf1e0436528f41248451c190ac`,
    re-fetched today and unchanged.
  - Each was cross-checked against Caddy's published
    `caddy_2.10.2_checksums.txt`, which lists sha512: amd64's tarball hashes
    to `747df7ee…2646546`, its published value. That file is how anyone
    re-derives the pins offline, which answers the old comment's objection to
    "a hash hardcoded in a test that nobody can regenerate".
  - What stays unpinned is what apt installs into the image, and the
    dependencies the container build fetches are pinned by the project's own
    CMake as everywhere else.
- **D11: a real second user.** A new sub-leg of `authd_e2e`, after the uid+1
  leg. `nobody` connects, through `setpriv` with the daemon's group as a
  supplementary group -- spec 8's shape for the site's own user. It runs on
  Linux with `setpriv` and either uid 0 or passwordless sudo (CI's Linux
  runners, this container), and prints SKIP for itself elsewhere; the uid+1
  leg still runs everywhere.
  - Two barriers stand in front of a socket, and the leg separates them. File
    permission first: `$TMP` is 0700, `site.sock` and `p.sock` 0660,
    `admin.sock` 0600, so a real foreign uid never reached the peer check at
    all. The sockets live in their own 0711 directory, and `admin.sock` is
    opened to everyone for the leg, so the peer check has to hold by itself.
  - The checks: `nobody` is SERVED on `site.sock`, whose list names it (the
    canary: an answer, and no rejection counted); REFUSED at accept on
    `admin.sock` and on the proxy socket, whose lists do not, with `connect()`
    having succeeded (not `cannot-connect`) and one rejection counted each;
    and, as the control, stopped by file permission with `cannot-connect` and
    NOT counted when it lacks the daemon's group.
  - **RU1, campaign v65**: the allowlist scan compares `getuid()` -- the
    daemon's own uid -- instead of the peer's. It passed V4-22a's whole debug
    suite, 47/47: every test ran the client as the daemon's own user, so the
    two numbers were always equal. The new leg kills it at the canary.
  - Shown both ways it can run: as root here, and as an ordinary user with
    passwordless sudo -- a throwaway local user with a sudoers entry, both
    removed afterwards -- where `sudo -n setpriv` ran it and passed; without
    the sudoers entry the sub-leg printed its SKIP. LeakSanitizer runs under
    `setpriv` in the ASan tree as it is, so no `ASAN_OPTIONS` override was
    needed.
- **Departures from the plan.**
  - The plan re-ran the e2e's earlier kills (v50c O1-O4, v56 MB9, v58
    GA13-GA14, v64 TG2) in case the new leg pre-empted them. It cannot: every
    expectation those campaigns name is printed EARLIER in the script than the
    new leg, and the e2e stops at its first failure, so nothing it adds can
    stand in front of them. They were not re-run.
  - No local run of the Caddy leg. A Docker daemon is installed in this
    container, but the session's network reaches the internet only through a
    proxy that a container cannot reach without `--network host` and a
    trusted CA, which the script does not (and should not) set up -- and the
    build inside it needs sqlite.org, which this session's policy denies.
    The pin check was probed outside Docker with the script's own
    `sha256sum -c` line on the real amd64 tarball: the pin accepted, a pin one
    digit off refused, and the tarball with bytes appended refused. The whole
    leg is CI's to show.
- **F111** (Info, open): `listener.h:50` says an unlisted socket mode is
  `LISTENER_ERR_PATH`, and `listener_open_unix` returns `LISTENER_ERR_ARG`.
  Recorded, not fixed: outside this step.
- **Numbering:** V4-22c's fault sweep becomes campaign v66 (pair FW).

### Campaign v65 — RU, the real user

| ID | Defect | Killed by |
|---|---|---|
| RU1 | the allowlist scan compares the daemon's own uid, not the peer's | `authd_e2e`: "nobody, whom site_uids names, was not served on site.sock (the canary)" |

### Environment

As for V4-22a: a Linux container running as root, every local result on
SQLite 3.45.1 from the system's static archive, clang 18 and gcc 13; no
macOS. A Docker client and daemon binary are installed, and nothing here
could use them for this step (above).

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** RU1 applied by hand to V4-22a's tree: the whole debug suite
  47/47, so no check could see it.
- **The new leg**, as root: PASS, and RU1 killed at the canary ("...was not
  served on site.sock (the canary): ... io-error" -- refused at accept). As an
  ordinary user with passwordless sudo: PASS through `sudo -n setpriv`;
  without the sudoers entry: the sub-leg's SKIP line, and the rest of the
  e2e unchanged.
- **The Caddy pin**, probed outside Docker with the script's own
  `sha256sum -c` line on the real amd64 tarball: pinned digest accepted, a pin
  one digit off refused, the tarball with bytes appended refused.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; Release with
  gcc 13 47/47; the fuzz tree 82/82. The real-user leg printed its PASS line,
  as uid 65534, in all five, and its SKIP line in none.
- **Campaigns**, on the ASan tree: v65 1/1, killed by name, restored clean
  with a passing clean suite and no residue. **Control:** RU1 with its
  expectation replaced by text no check prints: `SURVIVED(BAD: [CONTROL:
  ...])`, runner exit 1, restored clean.
- **No fuzzing**: no product source changed.
- **Documents.** Anchors 322 across 35 campaigns, 288 mutations; the nightly's
  coverage check run locally: 35 committed, 35 wired; the claim map's 318
  citations resolve, among them the new `ci` one; spec constants and names OK;
  `constant_time_sites` passes; F111 has its 8 separators; the secret scan
  finds 0 violations in CI's 28 files and in 282 across `tools tests docs apps
  src`; `git diff --check` OK. Every statement of the mutation, campaign,
  anchor, findings and CI-job counts was re-grepped.
- **Not shown here, and CI's to show:** the Caddy job itself; the real-user
  leg on GitHub's runners, where it runs through `sudo -n`; and its SKIP on
  macOS.
- **CI** 38222870757, dispatched on the pushed branch at `8878d90`: 14/14.
  - The new `caddy proxy (Linux, Docker)` job's first run passed: on amd64,
    the tarball's printed sha256 `5c218bc3…7cdd` equals the pin, and all 9
    PASS lines through "all checks" printed. The container build took under a
    minute.
  - Every other count is as V4-22a's: 47 per suite job on Linux and macOS, 36
    fuzz-labelled, 3 and 6 in the wasm job, 12 smoke targets with 0
    artifacts, the secret scan 0 violations.
  - CI prints no per-check lines, so it shows `authd_e2e` passing on Linux and
    macOS but not which way the real-user leg went; the nightly shows that.
- **The nightly**, with v65 RU1's expectation rotted (38263676205): red on
  exactly that job, 49/50. RU1 `SURVIVED(BAD:)`; every other campaign's
  verdicts match its spec -- 287 of 288 killed, every row restored clean --
  and the twelve fuzz targets ran 600 s each with 0 crashes and 0 artifacts.

## V4-22c — a fault on every write

The last of V4-22's three sub-steps. CLAIMS D14's limit said "eight fault
points exist ... each after one write, not after every write; the rest rests
on the transaction boundary." V4-22b landed on main (`3395122`) while this
step was being built; V4-22c starts from it.

### What was decided

- **A second test-only fault hook, over every writing statement.**
  - Inside `store.c`'s existing `#ifdef MLDSA_STORE_FAULT_HOOK` block,
    `store_fault_step` wraps `sqlite3_step`, and a `#define` routes every
    call through it. The n-th statement for which `sqlite3_stmt_readonly`
    is false fails with `SQLITE_IOERR`, without running.
  - Mapping the store first showed why that reaches everything. Every
    INSERT, UPDATE and DELETE is a prepared statement; `sqlite3_exec` runs
    only BEGIN, COMMIT, ROLLBACK, the PRAGMAs and the schema.
  - No call site changes, so no campaign anchor in `store.c` moved.
  - The fault is never `SQLITE_CONSTRAINT`. `store_enroll_device` commits
    on a conflict by design (Req 7's refusal keeps its audit row), so a fake
    constraint error would commit half an enrollment.
  - The old countdown and its seven fault points are untouched; tests rely
    on their numbering.
  - The new symbols are named `store_fault_arm_write*`, so the existing
    `store_fault_hook` CTest, which greps for `store_fault_arm`, already
    proves them absent from the shipped library and binaries. It does:
    0 matches in `libmldsa_authd.a`.
- **The sweep.** 23 cases in `test_authd_store`, one per mutating primitive
  or variant, each on a fresh store with real work to do:
  - add-user;
  - enrollment three ways (creating the user, onto an existing user, and
    Req 7's refusal);
  - disable, enable, rotate with `drop_tokens`, revoke;
  - touch-last-seen;
  - verify-token's sliding update and the three token deletes;
  - add-token, add-login-code, consume-login-code;
  - recovery-replace over existing codes;
  - recovery-consume with `revoke=none` and with `revoke=all` over two
    devices;
  - note-failure, plain and the one that locks;
  - enroll-via-ticket;
  - the expiry sweep.

  For each case:
  - It fails write 0, 1, 2, ... in turn on ONE store handle.
  - While the fault fires, the call must fail and the committed database
    must be unchanged. That is a SHA-256 over every table, every row and
    every column's type and value, read through a separate connection, as
    another process would see it.
  - At the first N where the fault does not fire, the call must return
    what it should, and change the digest (the canary).
  - The write counts run from 1 to 12, `revoke=all`'s.
  - Not reopening the handle between attempts is deliberate. A primitive
    that left its transaction open after a fault fails its next attempt
    with the fault unfired, and the sweep reports exactly that. A reopen
    would have discarded the open transaction and hidden it.
- **Out of the sweep:**
  - `store_open`'s three schema-time meta writes;
  - `store_backup`, which writes a different file;
  - COMMIT, which runs through `sqlite3_exec`.
- **F112** (Info, open): a failed COMMIT is never rolled back. It is found
  by reading and recorded, not fixed.

### Campaign v66 — FW, a fault on every write

Both mutations passed V4-22b's whole debug suite (47/47) with both applied
at once: neither primitive has a fault point, and nothing else fails one of
their writes.

| ID | Defect | Killed by |
|---|---|---|
| FW1 | `store_recovery_replace` commits after superseding the old codes, then begins again before inserting the new ones | "sweep(recovery-replace)": after the fault at write 1, the committed database had changed |
| FW2 | one of `store_add_token`'s error paths returns without `tx_rollback` | "sweep(add-token)": the next attempt failed with the fault unfired |

### Environment

As for V4-22a and V4-22b: a Linux container, every local result on SQLite
3.45.1 from the system's static archive (`sqlite3_stmt_readonly` has existed
since 3.7.4; CI's pinned 3.53.4 has it too), clang 18 and gcc 13; no macOS.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** FW1 and FW2 applied together to V4-22b's tree: the whole debug
  suite 47/47. With the hook in and disarmed, the store suites and the
  `store_fault_hook` gate passed unchanged before the sweep was written.
- **The sweep:** 23 cases, from 1 write to 12. With FW1 the recovery-replace
  case fails at write 1, and with FW2 the add-token case fails on the next
  attempt. Each fails alone and by name, and nothing else fails with them.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; Release with
  gcc 13 at `-O3 -Werror` 47/47; the fuzz tree 82/82. `test_authd_store` has
  257 checks (234), and all 23 sweep lines printed in every tree.
- **Campaigns**, on the ASan tree, each run under the two-hour limit and none
  beside another: v66 2/2, each killed by name. Re-run because the wrapper now
  sits under their kills, from scratch specs: v47 S1, v49d G5 and G7, v57
  HC3, v58 GA15-GA19. 9 of 9 killed; most by more checks than before, since
  the sweep also sees the defects they plant. Every row restored clean with
  a passing clean suite, no residue, every final fingerprint identical.
  **Control:** FW1 with its expectation replaced by text no check prints:
  `SURVIVED(BAD: [CONTROL: ...])`, runner exit 1, restored clean.
- **No fuzzing**: the product's code is unchanged outside the test-only
  `#ifdef`.
- **Documents.** Anchors 324 across 36 campaigns, 290 mutations; the nightly's
  coverage check run locally: 36 committed, 36 wired; the claim map's 324
  citations resolve; spec constants and names OK; `constant_time_sites`
  passes; F112 has its 8 separators; the secret scan finds 0 violations in
  CI's 28 files and in 284 across `tools tests docs apps src`; `git diff
  --check` OK. Every statement of the mutation, campaign, anchor and findings
  counts was re-grepped.
- **CI** 38312954860, dispatched on the pushed branch at `a6467f3`: 14/14.
  Every count is as V4-22b's: 47 per suite job on Linux and macOS, 36
  fuzz-labelled, 3 and 6 in the wasm job, the Caddy job's 9 PASS lines, the
  secret scan 0 violations in 28 files. The claim map's gate resolved 324
  citations. `test_authd_store` and the `store_fault_hook` gate passed on
  all nine jobs that run the suite; CI prints no per-check lines, so the 23
  sweep lines are the nightly's to show.
- **The nightly**, with v66 FW1's expectation rotted (38315152955): red on
  exactly that job, 50/51 (v66 adds the 51st). FW1 `SURVIVED(BAD:)` and FW2
  `KILLED(2 named)`; every other campaign's verdicts match its spec -- 289
  of 290 killed, every row restored clean with a passing clean suite and no
  residue -- and the twelve fuzz targets ran 600 s each with 0 crashes and 0
  artifacts.

### V4-22 as a whole

Asked for "liboq 0.17.0 and claim map gaps". liboqs 0.17.0 is still
unreleased, so F91's bump waits. Of the claim map's "Not established"
paragraphs, the seven the user chose are taken, in three sub-steps. Each step
showed its new checks catching a defect that the suite before it let through
(campaigns v64-v66, 8 mutations). What each paragraph still says:

| Gap | Closed by | Still not established |
|---|---|---|
| D9 | key clause isolated; `revoke=all` through the shipped daemon | both clauses shown only for a state an attacker with the file creates; `revoke=all`'s session closing in-process only |
| D8 | `sig_old` by the incoming key and by an unenrolled key, over the right digest | three vectors, not every key |
| D4 | upper-case hex and both base64 alphabets; backups scanned | other encodings, pieces under a window, memory |
| P13 | every padding byte of 20 inners across the buckets | lengths no bucket makes, two bytes at once (the fuzz model) |
| D12 | the real-Caddy leg in CI, image and tarball pinned by digest | amd64 only; apt's packages unpinned; the proxy's own uid unchecked |
| D11 | a real second user, refused by peer credentials with file access granted | Linux with root or sudo; `nobody` standing in for the site |
| D14 | a fault on every write of 23 mutations, the committed database unchanged after each | COMMIT (F112); faults per statement, not crashes |

Found on the way and recorded:
- **Fixed:** F109 and F110, both stale prose.
- **Left open, each for the owner's word:** F111 (a stale comment) and F112
  (a failed COMMIT is never rolled back).

## V4-23 — F112, a failed COMMIT rolled back

The owner asked for F112's fix after V4-22 landed (`82c7f7e`). F112 (Info,
recorded in V4-22c): nothing rolled back when COMMIT itself failed.

### What was decided

- **The fix is one helper.** `tx_commit` now issues ROLLBACK whenever COMMIT
  fails, and returns `STORE_ERR_DB`.
  - SQLite documents both outcomes of a failed COMMIT: on `SQLITE_BUSY` the
    transaction stays active, and after some errors it is already rolled
    back. It advises an explicit ROLLBACK either way, which fails
    harmlessly when nothing is open.
  - Every caller is covered and none changed, so no campaign anchor in
    `store.c` moved. `tx_rollback`'s definition moved above `tx_commit`,
    which now calls it; no anchor cites either line.
  - `store_open` already rolled back through its `fail_tx`; it now rolls
    back twice on that path, and the second ROLLBACK fails harmlessly. It
    was left unchanged to keep the diff to the helper.
- **Mapping the sites again corrected F112's own row.** V4-22c counted 10
  `return tx_commit(s);` and 3 `r = tx_commit(s)`. There are 11 and 3, and
  Req 7's refusal path in `store_enroll_device` calls `(void)tx_commit(s)`
  and ignores the result outright: 16 call sites with `store_open`'s.
- **Req 7's refusal keeps returning CONFLICT when its COMMIT fails.** The
  refusal stands, and so does the daemon's journal line for it, which is
  Req 7's log (erratum 45). The store's own audit row of the refusal is
  lost with the transaction, as with any database failure. Returning
  DB-error instead would also fail closed, but would swap Req 7's journal
  line for a generic one.
- **A third test-only hook, over COMMIT.** `store_fault_arm_commit(n)` and
  `store_fault_arm_commit_left()`, in the same `#ifdef` block and shaped
  like V4-22c's write hook. When it fires, `tx_commit` fails WITHOUT running
  COMMIT, so the transaction is still open: what SQLite leaves on
  `SQLITE_BUSY`. The names contain `store_fault_arm`, so the
  `store_fault_hook` CTest proves them absent from what ships.
- **The checks.** V4-22c's sweep table gained a `commit_check`: a literal
  check name for each of the 18 cases that run a transaction, NULL for the
  five single-statement autocommit ones (touch-last-seen, verify-token and
  the three token deletes). For each of the 18, on a fresh store:
  - the commit hook is armed and the call made; the hook must fire, so a
    COMMIT made around `tx_commit` fails here;
  - the call must not return OK, and the committed database (V4-22c's
    digest, through another connection) must be unchanged;
  - a second store must open the same file, which takes the write lock;
  - the same handle must then make the call again and get what it should,
    changing the digest.

  `test_authd_store` has 275 checks (257), and prints one `commit(...)`
  line per case.
- **The old helper failed all 18 checks before the fix was written**, and at
  exactly the last two points: "a second store could not open the file: the
  write lock is still held" and "the same handle then returned
  database-error". That is F112's consequence shown, not read. The hook
  fired, the call failed and the database was unchanged in every case.

### A real COMMIT failure, by hand

Not committed; recorded here. A scratch program linked against the same
SQLite 3.45.1 archive registers a shim VFS over the default one that fails
the WAL file's `xWrite` or `xSync` while armed, and replays the store's own
pattern: WAL, `synchronous=FULL`, `BEGIN IMMEDIATE`, a prepared INSERT, then
`sqlite3_exec("COMMIT;")`.

| Injected at COMMIT | COMMIT returned | Transaction open after it | Another connection's `BEGIN IMMEDIATE` | Rows committed |
|---|---|---|---|---|
| WAL `xWrite` fails | `SQLITE_IOERR_WRITE` | no | OK | 0 |
| WAL `xWrite` reports a full disk | `SQLITE_FULL` | no | OK | 0 |
| WAL `xSync` fails | `SQLITE_IOERR_FSYNC` | no | OK | 0 |

Each was run with and without a ROLLBACK after the failed COMMIT; the
ROLLBACK then fails with "no transaction is active" and nothing else
differs. So for these failures SQLite rolls back by itself, and the store
never got stuck, before the fix or after it. The stuck state needs a COMMIT
that fails with its transaction still open -- `SQLITE_BUSY` -- which in WAL
mode with the write lock taken at `BEGIN IMMEDIATE` the probe could not
construct. F112 stays Info; its row now says the path is this narrow. The
probe ran on 3.45.1 only, not on CI's pinned 3.53.4.

### Campaign v67 — FC, a failed COMMIT

Both mutations passed V4-22c's whole debug suite (47/47), applied together
to the new `store.c` with V4-22c's test file: nothing before V4-23 failed a
COMMIT.

| ID | Defect | Killed by |
|---|---|---|
| FC1 | `tx_commit` does not roll back when COMMIT fails (F112 restored) | all 18 commit checks: the write lock still held, and the same handle unable to begin |
| FC2 | Req 7's refusal path commits with a raw `exec_simple(s->db, "COMMIT;")`, around the helper | "commit(enroll-req7)" alone: the call reached no COMMIT through `tx_commit` |

### Environment

As for V4-22c: a Linux container, every local result on SQLite 3.45.1 from
the system's static archive, clang 18 and gcc 13; no macOS.

The container restarted once during campaign v67, while FC2 was applied. The
restart stopped the runner before it could restore, so `store.c` was left
with FC2 in it. It was restored from a checksummed copy kept outside the
tree, nothing having been committed, and v67 was re-run from scratch; the
results below are that run's. FC1 had been killed the same way before the
restart.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** With today's `tx_commit` under the new checks, all 18 commit
  checks failed at exactly the second store and the same handle, and
  nothing else failed. FC1 and FC2 applied together to the new `store.c`,
  with V4-22c's test file: the whole debug suite 47/47 on a build proven
  current.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; Release with
  gcc 13 at `-O3 -Werror` 47/47; the fuzz tree 82/82. `test_authd_store`
  has 275 checks (257); all 23 sweep lines and all 18 commit lines printed
  in every tree. The `store_fault_hook` CTest passes: the commit hook's
  symbols are in the test binary and not in what ships.
- **Campaigns**, on the ASan tree, each run under the two-hour limit and
  none beside another: v67 2/2, FC1 by all 18 commit checks and FC2 by
  "commit(enroll-req7)" alone. **Control:** FC1 with its expectation
  replaced by text no check prints: `SURVIVED(BAD: ...)`, runner exit 1,
  restored clean. Re-run because `tx_commit` sits under their kills, from
  scratch specs: v47 S1, v49d G7 and G15, v57 HC3, v58 GA15-GA19, v66 FW1
  and FW2. 11 of 11 killed, FW1 now by one more check, since the commit
  checks also see its early COMMIT. Every row restored clean with a passing
  clean suite, no residue, every final fingerprint identical.
- **No fuzzing**: the product's change is the one helper; the fuzz tree
  builds and its suite passes.
- **Documents.** Anchors 326 across 37 campaigns, 292 mutations; the
  nightly's coverage check run locally: 37 committed, 37 wired; the claim
  map's 328 citations resolve; spec constants and names OK;
  `constant_time_sites` passes; F112's row keeps its 8 separators; the
  secret scan finds 0 violations in CI's 28 files and in 286 across `tools
  tests docs apps src`; `git diff --check` OK. Every statement of the
  mutation, campaign and anchor counts was re-grepped, the campaign count
  in words included.
- **CI** 38368545657, dispatched on the pushed branch at `d01c104`: 14/14.
  Every count is as V4-22c's: 47 per suite job on Linux and macOS, 36
  fuzz-labelled, 3 and 6 in the wasm job, the Caddy job through "all
  checks", the secret scan 0 violations in 28 files, the claim map's 328
  citations. `test_authd_store` and the `store_fault_hook` gate passed on
  all nine jobs that run the suite -- on CI's pinned SQLite 3.53.4, where
  every local result above is on 3.45.1, so the commit hook's model holds
  on both. CI prints no per-check lines; the nightly's logs carry them.
- **The nightly**, with v67 FC1's expectation rotted (38416921315): red on
  exactly that job, 51/52 (v67 adds the 52nd). FC1 `SURVIVED(BAD:)` and FC2
  `KILLED(2 named)`; every other campaign's verdicts match its spec -- 291
  of 292 killed, every row restored clean with a passing clean suite and no
  residue -- and the twelve fuzz targets ran 600 s each with 0 crashes and 0
  artifacts.

## V4-24a — F111, and the claim map's P11 and D13

After V4-23 the owner asked for "F111 and claim maps", and chose six items:
F111; the test-level gaps P11 and D13; the gate-level gaps P8 and P2; and
the e2e gap D10. As with V4-22, they split into sub-steps, each planned and
approved on its own: V4-24a takes F111, P11 and D13; V4-24b takes P8 and P2;
V4-24c takes D10. Every new check comes with a mutation that survived the
suite before it and is caught by name (campaign v68, pair CG, Claim Gaps).

### What was decided

- **F111.** `listener.h` now names the refusal its code makes,
  `LISTENER_ERR_ARG`. Nothing had called `listener_open_unix` with a mode
  outside spec 8's two, so the refusal itself was untested. `test_authd_ws`
  now opens 0666, 0644, 0700 and 0 and needs each refused, `fd` left at -1
  and nothing created at the path; 0660 and 0600 must open as exactly that
  mode (the canary). Cited under D11, next to admin.sock's 0600.
- **P11: the decapsulated bytes are chosen, not hoped for.**
  - A branch on one byte value of the decapsulated secret would fire for
    one random handshake in 256 across the whole suite, failing at random
    rather than by name. So the planted defect (CG2) needs two leading zero
    bytes, about one handshake in 65,536, and the check has to reach it on
    purpose.
  - A ciphertext found for one key is useless for the next handshake, which
    generates a fresh one; searching by real decapsulation per handshake
    would have cost about 139,000 of them. Instead the test predicts ML-KEM's
    implicit-rejection secret directly, FIPS 203's J(z || c) =
    SHAKE256(z || c), with z the last 32 bytes of the decapsulation key, over
    candidate ciphertexts (the honest one with a counter in its first eight
    bytes), until one has the property wanted. Each chosen ciphertext is then
    really decapsulated, and must match the prediction and differ from the
    honest secret: the canary that the model of implicit rejection is
    liboqs's.
  - 289 initiator handshakes, built on H3's hand-built responder: each value
    of the secret's first byte, a zero at each of the 32 positions, and two
    leading zeros. The initiator must complete, and both its keys must equal
    HKDF over exactly the decapsulated secret, from the test's independent
    reference. That is stronger than H3's "not the encapsulator's key and not
    the zero key", which it implies.
  - The whole of `test_handshake` takes 1.4 s in the Debug tree.
- **D13: raw frames, decrypted payloads, and the ROTATE's signatures.**
  - The journal test now keeps every byte the connection put on the wire --
    ClientHello, ServerHello, ClientAuth, and the login-code, ROTATE,
    ROTATE_ACK and BYE records -- and every payload a record carried,
    decrypted, in both directions. A new `exchange_record_wire` returns the
    records it sends and receives; the eight existing callers of
    `exchange_record` are unchanged.
  - The window search gained spans it does not look inside: a signature's
    mostly-zero hint, evidence of nothing, as before; and the ROTATE_ACK's
    `fp_new`, which the journal records on purpose. BYE's payload is one
    byte, below any window; its record is searched.
  - **F113** (Info, fixed): the claim map said the scan covered "each
    signature's `c~ || z`", and the ROTATE's `sig_old` and `sig_new` had never
    been looked for. They are now.
  - What the scans still cannot see: `authd_log_slot_id` prints bytes as
    escaped printable text, which these scans do not decode. Recorded in D13.
- **F114** (Info, open): six tests name their scratch directory after their
  PID and stop if it exists; a crashed run leaves its directory behind. It
  failed the first control campaign's clean suite (`FAIL: mkdir` in 0.01 s,
  three stale directories in `build-asan/tests`). The stale directories were
  removed and the control re-run clean. Outside this step's scope; recorded.

### Campaign v68 — CG, the claim gaps

All five passed V4-23's whole debug suite (47/47) applied together, with
V4-23's test files.

| ID | Defect | Killed by |
|---|---|---|
| CG1 | `listener_open_unix`'s refusal of an unlisted mode can never hold | "modes: a socket mode other than spec 8's two is refused ..." |
| CG2 | the initiator fails a handshake whose decapsulated secret starts with two zero bytes | "P11: a decapsulated secret whose first two bytes are zero ..." alone |
| CG3 | `on_rotate` logs the decrypted ROTATE's first 32 bytes | "journal: no window of any decrypted payload" |
| CG4 | `on_record` logs every received record's first ciphertext bytes | "journal: no window of any raw frame of the connection" |
| CG5 | `on_rotate` logs the start of `sig_old` | "journal: no window of the ROTATE's own signatures", and the payload scan, since `sig_old` is part of the decrypted ROTATE |

### Environment

As for V4-23: a Linux container, every local result on SQLite 3.45.1, clang
18 and gcc 13; no macOS.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** CG1-CG5 applied together to V4-23's tree, with V4-23's three
  test files: the whole debug suite 47/47 on a build proven current. CG2
  was then probed alone against the new sweep, before the campaign: only
  the two-leading-zeros check failed.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 47/47; ASan 47/47 and UBSan 47/47, instrumentation proven linked into
  all 42 executables, 0 ASan reports, 0 UBSan runtime errors; Release with
  gcc 13 at `-O3 -Werror` 47/47; the fuzz tree 82/82. `test_handshake`
  passes its four P11 checks in every tree, in 1.3-1.7 s for the whole test
  (77,561 to 189,832 secrets predicted, a run's luck); `test_authd_conn` has
  189 checks (186) and `test_authd_ws` 125 (123).
- **Campaigns**, on the ASan tree, each run under the two-hour limit and
  none beside another, every source backed up with checksums first and the
  tree checked for leftover mutations after: v68 5/5, each by the check
  named for it. **Control:** CG4 with its expectation replaced by text no
  check prints: `SURVIVED(BAD: ...)`, runner exit 1. Its first run also
  showed `CLEAN-SUITE=FAIL(BAD)`: `test_authd_conn` stopped at `FAIL: mkdir`
  before any check, a stale scratch directory from an earlier crashed run
  sharing its PID (F114). With the three stale directories removed it was
  re-run: the same verdict, the clean suite passing. Re-run because the
  journal test and H3's neighbourhood changed under their kills, from
  scratch specs: v60 GC4, v49c W12, v63 FT1 and FT2, v25 N6, v24 M1 and M2.
  7 of 7 killed; W12 now by one more check, since the payload scan also
  sees the login code. Every row restored clean with a passing clean suite,
  no residue, every final fingerprint identical.
- **After the campaign** two P11 check names, split across adjacent string
  literals, were joined into one literal each, so the claim map can cite
  them (V4-22a's lesson). The strings compiled are the same.
- **No fuzzing**: no product code changed beyond `listener.h`'s comment;
  the fuzz tree builds and its suite passes.
- **Documents.** Anchors 331 across 38 campaigns, 297 mutations; the
  nightly's coverage check run locally: 38 committed, 38 wired; the claim
  map's 339 citations resolve; spec constants and names OK;
  `constant_time_sites` passes; F111-F114 have their 8 separators (F113's
  `c~ || z` escaped); the secret scan finds 0 violations in CI's 28 files
  and in 288 across `tools tests docs apps src`; `git diff --check` OK. Every
  statement of the mutation, campaign, anchor and findings counts was
  re-grepped, the campaign count in words included.

## V4-24b — P8's UBSan gate, P2's secure-memory inventory, F115

The second of V4-24's sub-steps, on V4-24a's local commits. The owner chose,
for P8, the flags as told **and** a canary of what the compiler did; for P2,
an inventory of secure memory; and for F115, found while planning, a fix
here rather than a record.

### What was decided

- **P8, as told.** `build_flags` gained `EXPECT_ASAN` and `EXPECT_UBSAN`,
  set from the tree's INTENT -- `ENABLE_ASAN`, `ENABLE_UBSAN`, and
  `MLDSA_FUZZ`, which implies both -- never from `MLDSA_SANITIZE_FLAGS`:
  deleting a flag there must not delete the expectation with it. Every
  project TU of a UBSan or fuzz tree must carry `-fsanitize=` with
  `undefined` and `-fno-sanitize-recover=undefined` (or `=all`); of an ASan
  or fuzz tree, `-fsanitize=` with `address`; of any other tree, no
  `-fsanitize=` at all.
- **P8, as done.** A new CTest, `ubsan_aborts`, runs `tests/ubsan_canary.c`
  -- a signed overflow on a `volatile` value derived from `argc`, built only
  in UBSan and fuzz trees with the project's flags -- and needs a non-zero
  exit, UBSan's `runtime error` report, and no line printed after the
  overflow. `UBSAN_OPTIONS` is cleared for the run, so a caller's
  `halt_on_error` cannot make the canary pass for the build. Elsewhere it
  reports Skipped (77), as `fuzz_libfuzzer` does, so every tree's count rises
  by one.
- **P2.** The existing structural scan, `session_no_alloc_scan`, proves
  `session.c` does not allocate in its steady state; it says nothing about
  where secrets live. The new CTest `secure_mem_sites` lists the 35
  `secure_mem_alloc` sites in 13 files of `src/` and `apps/`
  (`tests/secure_mem_sites.txt`, the `constant_time_sites` format: path and
  whitespace-collapsed line, no line numbers, a repeated line listed twice)
  and checks them both ways; it also refuses a raw `sodium_malloc`,
  `sodium_allocarray` or `sodium_free` outside `src/util/secure_mem.c`, which
  the list could not see. Each site was read to hold a secret -- keys, shared
  secrets, passphrases, plaintext key images -- or, at `keyfile.c`'s `out` and
  `fbuf`, a sealed envelope kept with them.
- **F115** (Low, fixed). Five local-API error returns left a decoded secret
  on the stack: `h_exchange`'s malformed-`state` return, with a valid login
  code already decoded; its store-error path, which wiped `code_hash` but
  not `state_hash`; and the wrong-length returns for a code, a recovery
  ticket (`enroll_common`) and a token (`h_verify`, `h_logout`). Each of the
  six paths now wipes before it returns. The evidence is reading and the
  whole suite still passing; no check can read a dead stack frame, the
  reason v49c declined such a mutation.
- **F116** (Info, fixed). The documented test counts had drifted -- README
  46, the packet 49, REPRODUCE 40 tests and 41 executables -- and the
  README's table named none of the five gate CTests added since V4-15. All
  are restated from ctest after this step's two CTests: 49 in a native tree
  (47 without `node`), 51 with a WebAssembly tree, 52 with a browser too, 3
  in the WebAssembly tree; 42 executables in a plain or ASan tree, 43 in a
  UBSan tree. The table names all seven gates.

### P8's hand controls

The campaigns mutate C sources only, so the CMake side was shown by hand,
each edit restored byte-exact and the tree reconfigured after it:

| Control | `build_flags` | `ubsan_aborts` |
|---|---|---|
| `-fno-sanitize-recover=undefined` removed from the `ENABLE_UBSAN` branch (UBSan tree) | FAIL on 76 of 112 TU entries -- the other 36 are the fuzz replay binaries, which carry their own `-fno-sanitize-recover=all` and still stop | FAIL: the canary ran on past the overflow, exit 0 |
| the same in the `MLDSA_FUZZ` branch (fuzz tree) | FAIL on 112 of 136 entries -- the other 24 are the libFuzzer targets, compiled with their own `-fno-sanitize-recover=undefined` (`tests/fuzz/CMakeLists.txt`) | FAIL, the same |
| `-fsanitize=address` removed (ASan tree) | FAIL on all 111 entries | Skipped |
| a plain Debug tree configured with `-DCMAKE_C_FLAGS=-fsanitize=undefined` | FAIL on all 111: instrumented in a tree that is not a sanitizer tree | Skipped |

### Campaign v69 — SM, secure memory

Both passed the whole debug suite but the new gate (48/48) applied
together; the gate then named both.

| ID | Defect | Killed by |
|---|---|---|
| SM1 | the store's audit-MAC key `s->key_audit` allocated with `calloc`, released with `free` | "a listed secure allocation is gone ...: apps/authd/store/store.c: ..." |
| SM2 | the client's plaintext MLDSASK2 image at enrollment allocated with `malloc`, released with `free` (and `<stdlib.h>` included for it) | "a listed secure allocation is gone ...: apps/authd/client_core.c: ..." |

### Environment

As for V4-24a: a Linux container, every local result on SQLite 3.45.1, clang
18 and gcc 13; no macOS -- `ubsan_aborts` on macOS is first seen in CI.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** SM1 and SM2 applied together: the whole debug suite but the
  new gate, 48/48, on a build proven current; `secure_mem_sites` then named
  both. P8's four hand controls are in the table above.
- **Suites**, each tree proven current in the same invocation: Debug (clang
  18) 49/49; ASan 49/49 and UBSan 49/49, instrumentation proven linked into
  all 42 and 43 executables, 0 ASan reports, and in the UBSan log exactly
  one `runtime error`, `ubsan_aborts`'s planted overflow; Release with gcc 13
  at `-O3 -Werror` 49/49; the fuzz tree 84/84 (82 before), 55 executables.
  `build_flags` and `secure_mem_sites` pass in all five; `ubsan_aborts`
  passes in the UBSan and fuzz trees and is Skipped in the other three.
  `test_authd_localapi` passes its 286 checks with F115's wipes.
- **Campaigns**, on the ASan tree, each run under the two-hour limit and
  none beside another, sources backed up with checksums first, the tree
  checked for leftovers after and F114's stale directories cleared before:
  v69 2/2, each by the gate's line naming its site. **Control:** SM1 with its
  expectation rotted: `SURVIVED(BAD: ...)`, runner exit 1. A first control
  ran on a spec whose two expectations ended in the C line's own `;`, which
  the runner reads as a separator: harmless to the kills (bash drops the
  trailing empty field, so the expectation was the text up to `)`), but the
  rot then became a second expectation rather than a changed first one. The
  semicolons were dropped and the control re-run. Re-run because F115's
  wipes sit in `localapi.c` under their kills, from scratch specs: v49d G1-G5,
  G9, G10, G12-G15 and v62 AO5. 12 of 12 killed, every row restored clean
  with a passing clean suite, no residue, every final fingerprint identical.
- **No fuzzing**: no product code changed beyond F115's wipes; the fuzz tree
  builds and its suite passes.
- **Documents.** Anchors 336 across 39 campaigns, 299 mutations; the
  nightly's coverage check run locally: 39 committed, 39 wired; the claim
  map's 345 citations resolve; spec constants and names OK;
  `constant_time_sites` and `secure_mem_sites` pass; F115 and F116 have
  their 8 separators; the secret scan finds 0 violations in CI's 28 files
  and in 294 across `tools tests docs apps src`; `git diff --check` OK. Every
  statement of the mutation, campaign, anchor, findings and test counts was
  re-grepped, the campaign count in words included; REPRODUCE's UBSan
  `runtime error` count now says 1, the canary's.
- **CI** 38914988973, dispatched on the pushed branch at `8242c64`, V4-24a's
  two commits beneath it: 14/14. 49 per suite job on Linux and macOS (47
  before `ubsan_aborts` and `secure_mem_sites`), 36 fuzz-labelled, 3 and 6
  in the wasm job, the Caddy job through "all checks", the secret scan 0
  violations in 28 files, the claim map's 345 citations. `ubsan_aborts`
  passed in both UBSan jobs -- on macOS under Apple clang 21, its first run
  there -- and reported Skipped in the other seven; `build_flags` and
  `secure_mem_sites` passed in all nine. CI prints no per-check lines; the
  nightly's logs carry them.
- **The nightly**, with v68 CG1's and v69 SM1's expectations rotted
  (38916552671): red on exactly those two jobs, 52/54 (v68 and v69 add the
  53rd and 54th). Two campaigns joined at once, so the one control commit
  rotted one expectation in each, and each new job is shown able to go red.
  CG1 and SM1 `SURVIVED(BAD:)`; CG2-CG5 and SM2 killed by name; every other
  campaign's verdicts match its spec -- 297 of 299 killed, every row
  restored clean with a passing clean suite and no residue -- and the twelve
  fuzz targets ran 600 s each with 0 crashes and 0 artifacts.

## V4-24c — D10's rotation keys by content, F117 and F118

The last of V4-24's sub-steps, on main at `d37470e`. D10's limit ended
"Rotation and recovery keys are covered by the e2e's header scan only, since
the shell legs hold no plaintext key to look for." Two findings turned up in
the planning; the owner chose to fix both here rather than record them.

### What was decided

- **What the claim's words meant.** The e2e calls its three
  interrupted-rotation legs -- USE_EK, REFUSE, PROMOTE_NEXT -- "recovery",
  and that is where D10's word came from. Account recovery makes no key of
  its own: the replacement device's key is an ordinary `authd_client keygen`
  (`authd_e2e.sh`, bob2), which the client keygen scan already covers, and
  nothing in the recovery flow handles a secret key. The map says so, as
  reading.
- **Rotation, by content.** `cmd_client_rotate` and `client_resolve_key`
  (`apps/authd/client_cli.c`) seal the new key to `.ek.next`, write a
  `.newpub` temp file, rename `.ek.next` over `.ek`, unlink a stale
  `.ek.next`, and -- in a later login -- complete an interrupted rotation. No
  C test had run any of it; the e2e reads each file's first eight bytes, and
  a raw secret key carries no magic. `test_authd_cli`'s new
  `test_rotate_on_disk` runs the CLI's own `rotate` and `login` against the
  in-process daemon (`tests/authd_harness.h`). The CLI blocks on its socket
  and the harness is pumped in-thread, so each run is a forked child while
  the parent pumps, with a 60 s limit. Every key the device held is opened
  from its sealed file, and `any_file_has_key_window` -- the F105 rule,
  failing closed (F86) -- searches the device's and the daemon's
  directories for each:
  1. an acknowledged rotation, A to B;
  2. `.ek` put back to A and `.ek.next` to B, then a login, which must
     complete the rename (PROMOTE_NEXT);
  3. `.ek` put back to A again, then a rotation: the new key C is sealed to
     `.ek.next` first (spec 10.2), the daemon refuses A, and `.ek.next` must
     be kept, still sealed.
  A raw copy of B planted in the device's directory must be found (the
  canary).
- **F117** (Info, fixed). `test_recovery` issues three codes; its store and
  backup scans looked for the first only. Every code is now pulled out of
  the reply (`nth_code`), all three are looked for, and a canary needs them
  extracted and distinct. The check strings are unchanged.
- **F118** (Info, fixed). The rotation leg's third case found it: the two
  returns of `cmd_client_rotate` after the new key is sealed -- a failed
  reopen of `.ek.next`, and a session that cannot open -- bypassed `out:`,
  the only place `pub_tmp` was unlinked, and left
  `<key>.ek.next.newpub.<pid>` behind. Both now unlink it. On V4-24b's code
  the new check failed exactly so:
  `(left behind: .../rot/dev/d1....ek.next.newpub.635)`,
  `FAIL: stale rotate: no .newpub temp file is left behind (F118)`, every
  other check of the leg passing. No test reaches the reopen-failure return;
  that site rests on reading.
- **RK5 differs from the plan.** The plan had RK5 keep every Argon2id hash
  working and park the plaintext beside it. The store is handed only the
  hashes, and libsodium refuses a hash string with anything appended (both
  `$code` and a bare suffix, checked against the project's own libsodium),
  so no single-file mutation can do that. RK5 stores every code from the
  third on as itself instead: such a code can never be spent, but nothing
  spends a third code -- the e2e issues two and spends both -- and every
  check of V4-24b's suite passed with it.

### Campaign v70 — RK, Rotation and Recovery

RK1-RK5 were each applied to V4-24b's sources and passed its whole suite on
the ASan tree, 49/49; RK6 is F118's fix reverted at the one site a test
reaches.

| ID | Defect | Killed by |
|---|---|---|
| RK1 | rotate keeps the OLD key's raw secret as `<key>.prev` once both ROTATE signatures are made | "rotate: no window of the old or the new secret key ..." |
| RK2 | rotate writes the NEW key's raw secret beside `.ek.next` once it has reopened it | the same |
| RK3 | the login that completes an interrupted rotation keeps the superseded key raw as `<key>.superseded` | "interrupted rotation: after the login that completes it, no window of either key in any file (Req 10)" |
| RK4 | a rotation whose session cannot open keeps the new key raw "for a retry" | "stale rotate: no window of any of the three keys in any file (Req 10)" |
| RK5 | every recovery code from the third on stored as itself, not its Argon2id hash | "recovery: the plaintext code is NOT in the store (Req 4)" and the backup check |
| RK6 | the session-failure return no longer unlinks `.newpub` (F118 reverted there) | "stale rotate: no .newpub temp file is left behind (F118)" |

### Environment

A Linux container: SQLite 3.45.1, clang 18, gcc 13; no macOS -- the forked
rotation leg on macOS is first seen in CI.

### Verification

Every local result is on SQLite 3.45.1 (above), on Linux x86_64.

- **Before.** On V4-24b's code the new leg failed only its F118 check (the
  line quoted above), every other check of it passing. RK1-RK5 were each
  applied to V4-24b's sources and its whole suite run on the ASan tree, built
  first: 49/49 for every one -- the e2e's rotation, interrupted-rotation and
  recovery legs included.
- **Suites**, each tree proven current in the same invocation: Debug
  (clang), ASan, UBSan, Release with gcc 13 at `-O3 -Werror`, 49/49 each;
  the fuzz tree, 84/84. Sanitizer instrumentation proven linked in every
  ASan and UBSan executable; 0 ASan reports; 1 UBSan `runtime error`, the
  canary's, as REPRODUCE says. `test_authd_cli` passes its 146 checks (128
  before) and `test_authd_localapi` its 287 (286) in all five.
  `test_authd_cli` now takes about 90 s rather than 49 s: the leg opens or
  seals a key at the operator Argon2id cost about a dozen times.
- **Campaigns**, on the ASan tree, each run under the two-hour limit and
  none beside another, sources backed up with checksums first, the tree
  checked for leftovers after and F114's stale directories cleared before:
  v70 6/6, each by name. **Control:** RK1 with its expectation rotted:
  `SURVIVED(BAD: ...)`, runner exit 1. Re-run because their checks or the
  code under them changed, from scratch specs: every row killed through
  `test_authd_cli` -- v49b C2, K1, P1, P2, L1, L2, E1, I1, v49c W14 and v60
  GC3 -- the one row that mutates `cmd_client_rotate`, v49c W15, and v58
  GA12, the only existing row whose expectations reach `test_recovery`. 12
  of 12 killed, every row restored clean with a passing clean suite, no
  residue, every final fingerprint identical.
- **No fuzzing**: the product change is two `unlink` calls on error
  returns; the fuzz tree builds and its suite passes.
- **Documents.** Anchors 342 across 40 campaigns, 305 mutations; the
  nightly's coverage check run locally: 40 committed, 40 wired; the claim
  map's 355 citations resolve; spec constants and names OK;
  `constant_time_sites` and `secure_mem_sites` pass; F117 and F118 have
  their 8 separators; the secret scan finds 0 violations in 296 files across
  `tools tests docs apps src`; `git diff --check` OK. Every statement of
  the mutation, campaign, anchor and findings counts was re-grepped, the
  campaign count in words included. The test counts are unchanged: the leg
  extends an existing test.

## V4-24 as a whole

The owner chose six items after V4-23. What each still does not establish:

| Item | Closed by | Still not established |
|---|---|---|
| F111 | the unlisted-mode refusal is a check (v68 CG1) | -- |
| P11 | chosen ciphertexts reach every first-byte value, every zero position and two leading zeros of the implicit-rejection secret (v68 CG2) | a branch with no functional effect: a timing question, which nothing here measures |
| D13 | every raw frame, decrypted payload and the ROTATE's signatures are looked for in the journal (v68 CG3-CG5, F113) | one connection's login, ROTATE and BYE only, and no encoding but hex and base64 |
| P8 | `build_flags` checks each tree's sanitizer flags against its intent, and `ubsan_aborts` needs a planted overflow to stop the process (hand controls) | what the compiler DID is checked for UBSan alone; the hardening flags are still read as told, and `check_hardening.sh`'s binary canary cannot fail for this project (F104) |
| P2 | 35 secure-allocation sites pinned both ways, no raw `sodium_malloc` (v69 SM1-SM2) | which buffers belong on the list rests on reading; that stack copies are wiped on every error return rests on review |
| D10 | rotation's three on-disk states scanned for every key (v70 RK1-RK4) | a rotation whose reply is lost or refused after the session opens; the e2e's real processes; deleted temp files, swap and core dumps |

Three findings were fixed on the way (F115, F117, F118), two were
corrected in the records (F113, F116), and F114 stays open for the owner,
with F91.

### V4-24c: CI on the branch and the control nightly

- **CI** 39311658216, dispatched on the pushed branch at `e409628`: 14/14.
  - 49 per suite job on Linux and macOS, 36 fuzz-labelled, and 3 and 6 in
    the wasm job.
  - The Caddy, unit and offline-build jobs report "all checks"; the secret
    scan finds 0 violations in 28 files; the claim map resolves 355
    citations.
  - `test_authd_cli` took 80.5-85.0 s on Linux and 104.8-114.1 s on macOS:
    its first runs there with the rotation leg, against 36.1-38.9 s and
    58.9-63.1 s on main's CI before it (38969780717).
- **The nightly**, with v70 RK1's expectation rotted (39320603234), was red
  on exactly that job, 54/55. v70 adds the 55th job.
  - RK1 reported `SURVIVED(BAD:)`, naming the rotted text; RK2-RK6 were
    killed by name.
  - Every other campaign's verdicts match its spec: 304 of 305 killed, and
    every row restored clean with a passing clean suite.
  - The twelve fuzz targets ran 600 s each, with 0 crashes and 0 artifacts.
- **The control's revert** restores `tools/mutations/spec_v70.txt`
  byte-exact (sha256 `478757c2c9f3dd15...` before and after).

## V4-25 — phones measured (spec §14, erratum 47)

Since V4-13d, §14 had said "**Phones are not yet measured**". The tool
existed (`tools/phone_timing.mjs`), and it had been served for three hours
without a phone reporting. This step is the measurement, recorded. No code
changed.

### The run

The owner's Xiaomi 12 Pro, in Chrome 155 and Edge 155, over home Wi-Fi and
then over mobile data, plus the Mac's own Edge 155 and Safari 27.0.1: six
results, all in `bench/results.md` with their environment and method.
- **Identifying the phone.** The Chromium browsers report a frozen "Android
  10; K" to every site, so the model comes from Tailscale's device list.
- **The mobile runs really were off Wi-Fi.** Wi-Fi off cannot be checked from
  the page, so it was checked from Tailscale's side: the phone's path was
  direct from 25.241.208.153, a different public network from the Mac's
  172.56.34.86, and the bytes on that path grew between the two mobile runs.
- **The invite stayed in the fragment.** Each run's invite was fresh and rode
  the URL fragment, as the tool intends.
- **Both servers are gone.** They were stopped by hand afterwards; no fixture
  process remained, and the port refused connections.

### What it shows

- **The phone keeps Argon2id far inside V4-2's 2,000 ms budget.** Its new
  identity (keygen + Argon2id 3/64 MiB + sealing) took 255–393 ms.
- **The network costs only the login.** A login took 301–719 ms on Wi-Fi and
  512–645 ms on mobile data; the extra is network round trips, not
  computation.
- **Safari on the same Mac is about 21× slower than Edge**, uniformly:
  2,303 ms for a new identity, 2,290–2,443 ms per login. That is **F119**
  (Low, open). The cause is unknown; Lockdown Mode's global setting is unset.
  It matters beyond one Mac because every iPhone browser is WebKit, and no
  iPhone was measured.

### What broke on the way

Every existing build tree failed with `'sodium.h' file not found`.
`~/.cache/mldsa-tmp` -- the location the libsodium memory note chose
precisely because `$TMPDIR` gets cleaned -- had been emptied too, by
something outside this project. As that note prescribes, the old trees were
left untouched, and fresh ones were built beside them:
- `build-wasm-p`: Release, Emscripten 6.0.9, fingerprint `2c39f8ab7908049c`,
  3/3.
- `build-p`: native, pointing at it, fingerprint `d7e8a710c9ac77a9`, 52/52,
  `browser_e2e` and `wasm_interop` included.

Each was proven current before its suite ran. Deleting or rebuilding the old
trees is the owner's decision.

### Verification

- **Spot-checked against the raw data:** every figure in §14, the runbook,
  `bench/results.md`, F119 and this entry was compared with the tool's six
  JSON rows.
- **Gates:** spec constants and vocabularies, the claim map, anchors, the
  audit table's separators and `git diff --check` pass.
- **Scope:** only `docs/`, `bench/results.md` and `deploy/RUNBOOK.md`
  changed; no source or test file did, so no campaign is affected.

## V4-26 — F119's cause: Safari has no JIT on a non-secure origin (spec §14, erratum 48)

The first iteration of the owner's continuous loop (2026-10-20: "plan ->
execute -> ci/nightly -> continue", with bug fixes and cleanup every third
iteration). Under that instruction the plan was written down, not held for
approval. V4-25 had left F119 open: Safari 27.0.1 ran the client about 21×
slower than Edge on the same Mac, cause unknown.

### Finding the cause

The investigation used throwaway probes. Their sources and every raw row are
kept beside the repository in `jit-probe-2026-10-20/`, as V4-25's rows were.
Each probe was a page compiled against `build-wasm-p`'s own libsodium and
liboqs with the module's link flags, opened in Safari or Edge with
`open -a … URL`, which POSTed its times to a collector. The steps, in order:

1. **The components, on `http://127.0.0.1`.**
   - Argon2id(3, 64 MiB) took 77 ms in Safari against Node's 98.6.
   - ML-DSA-65, ML-KEM-768 and X25519 ran at Node's speed.
   - SHAKE256 took 1.7× Node's time and BLAKE2b 4.7×.

   No primitive explains 21×.
2. **The shipped module with the shipped JS client, the same origin.** A new
   identity took 81 ms and a login's first step 81 ms. Adding the site's
   exact CSP changed nothing. **Safari was not slow at all**, which is how
   it became clear that V4-25's origin was the variable.
3. **The same page from the Mac's LAN address**, which is what the tool
   serves: 2,133 ms and 2,143 ms. Everything was 8–30× slower, a
   crypto-free wasm loop included.
4. **Seven origins, each reporting `isSecureContext`.**
   - The 20× split follows the secure context exactly, for a plain
     JavaScript loop as much as for wasm.
   - `localtest.me` resolves to 127.0.0.1 and is still slow, so the
     network is not the cause.
   - `probe.localhost` is fast.
   - Edge showed no difference.

**Conclusion.** Safari 27.0.1 on this Mac runs a non-secure origin's pages
without its optimizing JIT. A web search found no WebKit or Apple document
describing this, and Lockdown Mode's global key is unset. Whether it is
Safari 27's default or this Mac's configuration is left open: one Mac, one
Safari.

### What was decided

- **F119 is RESOLVED, not FIXED: there was no defect in the client.** The
  defect was in the measurement: the tool served an origin no deployment
  has, and nothing in a row said so. A deployment is HTTPS behind the site's
  TLS proxy (§7.1), and therefore a secure context.
- **Record the origin rather than change it.** Serving the tool over HTTPS
  to a phone needs a certificate the phone trusts for a LAN or tailnet
  name. Tailscale's HTTPS certificates would do it, but they are a tailnet
  setting, which is the owner's call. So every row now carries:
  - `secure`, which is `window.isSecureContext`;
  - `jsLoopMs`, a fixed 10⁷-step xorshift loop, best of three, timed before
    any cryptography: a JIT indicator that does not depend on the module.
    It measured 13–14 ms in Edge, 62 ms in Safari on a secure origin and
    361 ms on a non-secure one.
- **The page shows a note on a non-secure origin.**
- **The site's route requires both fields.** A row without them is exactly
  the ambiguous kind V4-25 published.
- **`--auto`** starts the page from its fragment, so a desktop browser opened
  by a script, and the test, need no click.
- **The tool exits 1 when `--minutes` run out before `--count` results.** It
  exited 0 before, so a run that measured nothing looked like success.
- **On SIGTERM or SIGINT the tool takes the daemon fixture down with it.**
  Before, a killed tool left the fixture serving for its whole lifetime.
- **The tool notes a non-loopback `--host`** and names `--host 127.0.0.1` for
  same-machine browsers. The note says "Safari on a Mac" and that iPhones are
  unmeasured: it claims nothing about a device that was never timed.

### The test, and its controls

`phone_timing_tool` runs the real tool as a process and drives headless
Chromium through two origins of one server:
- `http://127.0.0.1:P`;
- `http://timing.test:P`, mapped to loopback by `--host-resolver-rules`, so
  it is a non-secure origin in CI without DNS or a second interface.

It makes 20 checks, listed in the `test:` commit. It is registered beside
`browser_e2e`, because it needs a browser and the wasm tree. CI's wasm job
runs it and asserts that both are registered. That loop runs outside CTest,
so it was executed under bash against `build-p`, both ways.

The nightly campaign tree has no wasm and no browser, so the controls were
run by hand, as V4-13c's were. Eight mutations, each restored byte-exactly,
with sha256 compared before and after and a residue grep for the marker:

| | Mutation | Red at |
|---|---|---|
| K1 | the page reports `secure: true` always | row 2 records secure: false |
| K2 | the route drops `secure` | row 1 records secure: true |
| K3 | the JS loop reports 0 | each row has … a JS loop time, all positive |
| K4 | `auto=1` ignored | the run completed (timed out waiting for leg 1's result) |
| K5 | the tool prints "yes" always | the tool printed "secure context: yes" … and "no" |
| K6 | the tool exits 0 on timeout | … the tool says "time is up" and exits 1 |
| K7 | the route accepts any `secure` | a row with secure "yes" or missing … is refused 400 |
| K8 | no note on a non-secure origin | leg 2: and shows the insecure-origin note |

**K7 first went red at the wrong check, which was the test's fault.**
Accepting `secure: "yes"` made that malformed row the tool's second result,
so the tool exited. The next probe's fetch then threw, and the run died
before reaching the 400 check. The probe now records a failed fetch as "no
response", and K7 goes red where predicted. All eight were then re-run
against the final test, and all eight were killed at their named checks.

Not gated: the tool's note for a non-loopback `--host`, since CI has no
second address to bind. It was checked by running the tool on
192.168.12.123; its output is saved in
`jit-probe-2026-10-20/tool-192.168.12.123.log`.

### The measurements

Recorded in `bench/results.md`: the seven-origin table, the component table,
the module table and the tool's own four rows. In the tool's rows:
- Safari on `127.0.0.1`: a new identity in 94 ms and logins in 85–100 ms.
- Edge on the same origin: 88.4 ms and 84.6–91.9 ms.
- Safari on the LAN address: 2,138 ms and 2,168–2,191 ms, V4-25's figure
  reproduced.

Every number in the new tables was checked by script against the raw logs:
33 rows, 0 missing. The Node baseline existed only in this session's
command output, so it was saved verbatim and also rerun. The rerun
reproduced it to within run-to-run spread; Argon2id 3/64 MiB was 81.8 ms
against 98.6 and 81.9 before.

### Still open (and said so in §14, the runbook and F119)

- **Safari on a non-local HTTPS origin.** That is a deployment's shape, and
  it needs a trusted certificate for a non-local name. Offered to the owner:
  Tailscale HTTPS for the Mac's tailnet name.
- **An iPhone.**
- **Chrome on Android on a secure origin.** V4-25's phone rows were taken
  on non-secure origins; Edge on the Mac shows Chromium unaffected.

### The fresh trees

`~/.cache/mldsa-tmp` had been emptied (V4-25), so the sanitizer and fuzz
trees were rebuilt beside the broken old ones, with the old trees' exact
configurations:
- `build-asan-p`: Debug, `/usr/bin/cc`, ASan, the wasm dir, Node and Edge;
- `build-ubsan-p`: the same with UBSan;
- `build-fuzz-p`: Homebrew clang, the Xcode SDK as sysroot, `MLDSA_FUZZ`.

Built from main `6008d70`'s C sources, which this step leaves unchanged:
ASan `88d7912493793fcf` 52/52 and UBSan `55d7cb28ec5c6421` 52/52, with 0
sanitizer reports. Fuzz `4ac22c8dbe47e497` 36/36 fuzz-labelled.
Its first currency check came back VOID: one object, CMake's compiler-ID
probe, differed, because `tests/CMakeLists.txt` was edited while the check
ran. The re-check was clean.

### Verification

- **Every tree proven current by the from-scratch gate**, with the
  sanitizer link proven, then its whole suite, at the branch's code head
  `c40213f`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `6256693b772a00b0`, 53/53;
  - ASan `88d7912493793fcf`, 53/53, with 0 reports;
  - UBSan `55d7cb28ec5c6421`, 53/53, with 0 runtime errors;
  - fuzz `4ac22c8dbe47e497`, 36/36 fuzz-labelled.

  `phone_timing_tool` passed in all three native trees. No fixture process
  was left running afterwards.
- **Controls K1–K8:** each killed by name, each restored byte-exactly, and
  no marker left behind.
- **Gates:**
  - spec constants and vocabularies, the claim map (190 checks), the anchors
    (342 across 40 campaigns), every audit row at 8 unescaped separators,
    and `git diff --check`;
  - `web_no_crypto` on `web/client` (the gate) and on `web/pages`, which
    shows the calibration loop trips nothing.
- **Branch CI** 39371836902 on `c40213f`: 14/14. In the wasm job,
  `phone_timing_tool` passed on Linux with Chrome for Testing 154 (7/7
  selected).
- **Scope:**
  - The page, the site's timing route, the tool, one new test and its
    registration, CI's wasm step, and the records.
  - No C file changed. So no campaign's code changed, and the nightly's
    campaigns are unaffected except as the bring-up's control.

## V4-27 — D10 in the browser: both profiles scanned for every key, and the passphrase

Loop iteration 2. CLAIMS D10 listed "the browser's IndexedDB" among what its
window scans did not reach.
- **The mechanism was argued, not observed.** The key is made, sealed and
  opened inside the wasm module, so IndexedDB is only ever handed the sealed
  envelope. Nothing had looked at what Chromium actually writes to disk.
- **Why it matters:** the browser is milestone B's client.

### What was built

- **`tests/envelope_key_scan.c`**, a native test helper. It takes an
  envelope read back from IndexedDB, opens it with the test's passphrase
  through the same `keyfile_open_buf` the module runs, and scans a directory
  for every 16-byte window of the secret key made wholly of secret bytes.
  - **Speed.** The windows are indexed by their first 8 bytes, so each file
    position costs a binary search. `test_authd_cli`'s `memmem` per window
    would be about 3,900 passes over a 15 MB profile.
  - **What it reads.** Every regular file, whatever its size; the CLI scan
    skips files over 1 MiB, and a profile has bigger ones. Symlinks and
    sockets are counted, not followed; a profile has a dangling lock
    symlink and a socket. A regular file it cannot read is an error.
  - **What it prints.** Positions and counts only.
  - **Two more modes.** `--needle` looks for arbitrary bytes, for the
    canary and the passphrase. `--plant` writes the opened key into the
    scanned directory in the clear, scans, and removes it again.
- **`browser_e2e` collects every envelope its store held**, as the flows
  create them:
  - the enrolled key;
  - the stale pending key;
  - the lost-ACK rotation's key;
  - the account page's rotation;
  - in the second profile, the recovered device's key.

  Before the browsers close, both profiles are scanned.
- **The canary is the precondition.** Each profile's first page writes 4,032
  random bytes into IndexedDB as a `Uint8Array` value, the way the store
  writes an envelope, so the canary is at least as old as any key. All 4,017
  of its windows must be found. They were, in the origin's LevelDB
  `000003.log`.
- **The key path proves itself the same way:** the last key, planted by the
  helper, must be found whole (3,906 of 3,906).
- **The passphrase is looked for as UTF-8 and UTF-16LE.** Chromium could keep
  form data, or a page could store it.
- **`MLDSA_KEY_SCAN` names the helper** through CTest's environment. Unset is
  a FAIL, not a skip.
- **F105's window rule moves to `tests/key_windows.h`.** `test_authd_cli` and
  `test_authd_conn` each had a copy; the helper is the third user. The check
  strings, and every campaign's anchors, are unchanged (0 campaigns anchor in
  those files).

### What the scan found

Nothing:
- every key, 0 of 3,906 windows;
- the passphrase, 0 of 13 (UTF-8) and 0 of 41 (UTF-16);
- profile 1 ran to 339 files and 15.0 MB, profile 2 to 307 files and
  14.3 MB.

The claim now has an observation behind it for headless Chromium at the
moment of the scan.

### Controls, by hand (the nightly tree has no browser)

| | Mutation | Red at |
|---|---|---|
| C1 | the helper ignores its hits | the canary, and the planted key, in both profiles |
| C2 | the helper indexes the public key instead | every key check (1,937 windows, not > 3,800), and the planted key (17 of 1,937 found: `rho`, which is `pk[0..32)` and `sk[0..32)`) |
| C3 | the canary is not written | the canary, in both profiles |
| C4 | the enroll page keeps the passphrase in `localStorage` | the passphrase, profile 1 (13 of 13 UTF-8 windows) |
| C5 | the helper skips `.log` files | the canary, in both profiles |

C4 shows the passphrase scan reaching a second storage area:
`localStorage`, flushed within the test's run.

**C2 first SURVIVED, and that was the stale-object trap again.** The
control script restored C1 and rebuilt the helper, then wrote C2's mutation
within the same second. `make`'s mtime test saw nothing to do, so C2 ran
the unmutated binary. The script now deletes the object and the executable
before every build and prints the resulting binary's sha256:
- baseline `d965b685`;
- C1 `9cbeb589`;
- C2 `e8be3b42`;
- C5 `06b103bc`;
- every restore different again, since macOS links are not byte-stable.

Re-run that way, C1, C2 and C5 were all killed. C3 and C4 change no binary.

### Still not established (said so in CLAIMS D10)

- **A later compaction.** LevelDB compacts its log into Snappy-compressed
  tables later. The canary shows what the scan sees in the state it
  scanned, and nothing after.
- **Memory, swap, Safari and Firefox.**
- **A CLI rotation whose session opens but whose reply is lost or refused.**

### Verification

- **Every tree rebuilt, proven current, and run in full** at `f29536f`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `65f2c1930ba2bf36`, 53/53;
  - ASan `d5adbb8aaf8ec45d`, 53/53, with 0 reports;
  - UBSan `56ecbea2b1433346`, 53/53, with 0 runtime errors;
  - fuzz `8e1a2f5379f53c6e`, 36/36.

  `browser_e2e`, with its at-rest checks, passed in all three native
  trees: the helper ran under ASan and UBSan. No fixture was left running.
- **Controls C1–C5:** all killed by name, each restored byte-exactly, with
  no marker left behind.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 194 checks and 16 tools, every cited check string found
    verbatim in its test;
  - anchors: 342 across 40 campaigns, unchanged;
  - audit separators and `git diff --check`.

### CI: on Linux, Chromium's IndexedDB is SQLite

CI 39378680825 failed one check in the wasm job: "every window of a
canary", with 4,002 of 4,017 found, in both profiles.
- **Two backends.** Chrome for Testing 154 on Linux keeps IndexedDB in
  SQLite: a database file and its `-wal`, where the canary was found. Edge
  155 on macOS keeps it in LevelDB, where the canary sat whole in the log.
- **Why 15 are missing.** SQLite stores a value longer than its in-page
  share in overflow pages, each of which begins with a 4-byte pointer. So
  the bytes are split once, and the 15 windows straddling the split are not
  contiguous on disk: 4,017 − 4,002 = 15.
- **No leak was found.** Every key check passed there too (0 of 3,906), and
  the planted key was found whole.
- **The canary was too strict for SQLite.** It now needs every window but
  at most two page splits, at least 3,987 of 4,017. A 4,032-byte value
  crosses at most two splits on 4 KiB pages.
- **The key checks are unchanged.** One window is a failure, and a key in
  the clear in SQLite would still show thousands.
- **The controls under the new condition.** C1, C3 and C5 were re-run and
  are killed by name (0 of 4,017 each). CLAIMS D10 cites the new check
  text.

Both of Chromium's IndexedDB backends are now scanned: LevelDB locally,
SQLite in CI.
## V4-28 — F114 fixed, and the working copy cleaned (the loop's third iteration)

Every third iteration of the owner's loop is bug fixes and repo cleanup.
This is the first.

### F114: scratch directories named after the pid

F114 was recorded in V4-24a and left "for the owner's word". The owner's
standing instruction to fix bugs every third iteration is that word.

- **The bug.** Seven tests made `/tmp/<name>-<pid>` (two of them relative to
  the build tree) with `mkdir`, and stopped if it existed. A run that crashes
  never reaches the cleanup at the end of `main`, so a later run that drew
  the same pid failed before its first check.
- **The fix.** Each now uses `mkdtemp`, which is unique by construction, as
  `authd_node_fixture` and `authd_wasm_fixture` already did.
- **The row was wrong in one detail.** It said `test_authd_cli` ignored the
  error, but that test had stopped on a failed `mkdir` since V4-9b
  (`cd85092`), before F114 was written. It is fixed with the others.
- **A gate keeps it fixed.** `scratch_dirs`, a new CTest in every native tree,
  fails if any line under `tests/` or `bench/` formats `getpid()` into a
  string. Its canary requires `mkdtemp(g_dir)` in each of the seven, so the
  gate cannot pass because a test stopped making its directory. It was shown
  red both ways by hand, each control restored byte-exactly (`cmp`):
  - **A pid name put back** in `test_authd_ws.c`: "a pid formatted into a
    string", naming the line.
  - **`mkdtemp` taken out** of `test_client_core.c`: "no longer makes its
    scratch directory with mkdtemp(g_dir)".
- **The counts.** Every native tree runs one test more: 50 (48 without
  node), 52 with a wasm tree, 54 with a browser. The README and REPRODUCE.md
  say so, and the README's table has the row.

### Three stray fuzz inputs, moved rather than deleted

The repository root held three untracked, gitignored files:
- `crash-45895c33…`, 132 bytes, from 2026-09-26;
- `crash-localapi-replay-input`, 4,021 bytes;
- `crash-keys-replay-input`, empty.

No record says where they came from.
- **Replayed today**, against all 12 libFuzzer targets and their 12 replay
  drivers in the fresh fuzz tree: every run exited 0, so neither non-empty
  input reproduces anything.
- **Never a committed regression:** `tests/fuzz/regressions/` holds only
  `.gitkeep` files.
- **Moved, with a note and their checksums,** to
  `stray-fuzz-inputs-2026-10-20/` beside the repository. Their contents
  cannot be recreated, so deleting them is not this loop's call.

### The old build trees

On 2026-10-19 `~/.cache/mldsa-tmp` was emptied, and six trees lost
libsodium's headers. None of them can build:
- `build-v413d`;
- `build-asan-v413d`;
- `build-ubsan-v413d`;
- `build-fuzz-v415`;
- `build-wasm-d`;
- `build-bench-v412`.

**Each has a proven replacement with the same configuration**, read from
its `CMakeCache.txt`:
- `build-p`, `build-asan-p`, `build-ubsan-p`, `build-fuzz-p` and
  `build-wasm-p`, all current and green since V4-26;
- for the Release bench tree (`/usr/bin/cc`, `auto`), a fresh
  `build-bench-p`, built here and run.

A build tree holds only what configure and build regenerate from the
source, so the old ones are deleted.

**Two directories are not build trees and stay:**
- `build-bench` holds `bench-results`;
- `build-fuzz` holds a 28 MB fuzz corpus and its logs.

Both are data, and both are the default paths the README and the workflows
name.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `85a1571`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `40b2e8bdfb822f12`, 54/54;
  - `build-bench-p` `6a19208817413ae5`, 50/50, `bench_smoke` included;
  - ASan `5595425cba5517b4`, 54/54, with 0 reports;
  - UBSan `a0eea500676dd628`, 54/54, with 0 runtime errors;
  - fuzz `674ded0df9b85b76`, 36/36.

  `scratch_dirs` passed in all four native trees.
- **Nothing left behind.** After every suite, `find` showed no scratch
  directory in `/tmp` or in any build tree, and no fixture process.
- **Gates:** spec constants and vocabularies, the claim map, the anchors
  (342 across 40 campaigns: no campaign anchors in the seven tests), the
  audit separators, and `git diff --check`.

## V4-26, V4-27 and V4-28 — CI on the branch and the nightly bring-up

**One bring-up for three steps.** V4-24a and V4-24b set the precedent. The
three steps land in order on one line, and none changes a campaign's code:
- V4-26 and V4-27 change pages, a tool, tests and documents.
- V4-28 changes seven tests' scratch directories and adds a gate.

So one control nightly shows the nightly can still go red. One final
nightly then runs every campaign against the final tree, the tests V4-28
changed included.

### CI on the branches (14 jobs each)

| Head | Step | Run | Result |
|---|---|---|---|
| `c40213f` | V4-26, the code | 39371836902 | 14/14; `phone_timing_tool` passed on Linux with Chrome for Testing 154 |
| `5a0fdc1` | V4-26, with its docs | 39374788675 | 14/14 |
| `45d24a3` | V4-27 | 39378680825 | **13/14**: the wasm job's IndexedDB canary on SQLite (V4-27's section above) |
| `19fce3a` | V4-27, the canary fixed | 39380060622 | 14/14 |
| `c906687` | V4-28 | 39383763957 | 14/14 |

### The control nightly

- **The control.** `9832761` rotted v70 RK6's expectation, appending
  "CONTROL -- a check no test prints (V4-26)", on V4-26's code. spec_v70's
  sha256 before was `478757c2c9f3dd15`.
- **The run.** 39373351325 was red on exactly `mutations · v70`, 54/55:
  - RK1–RK5 were killed by name;
  - RK6 was **SURVIVED(BAD)**, naming the rotted text;
  - every mutant restored clean, with a passing clean suite and residue 0.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with V4-29.
## V4-29 — D13: the journal scans read the escaped id= field (campaign v71)

Loop iteration 4. CLAIMS D13's own limits named the gap:
"`authd_log_slot_id` prints bytes as escaped printable text, which these
scans do not decode".
- **How the field is written.** With `log_ids = full`, the default, an
  identifier is printed as `id=<field>`. Each byte from 0x20 to 0x7e stands
  as itself and every other byte becomes `.`, truncated at 64 with `~`.
- **Why nothing saw it.** The journal scans looked for hex in either case
  and both base64 alphabets. A secret printed through that field matched
  none of those forms.

### The scan

The form is lossy, so it cannot be decoded back to bytes. The scan runs the
other way instead:
- **The match.** It applies the same transform to the secret and matches
  every 16-character window of every `id=` field against the secret's
  escaped image, one `memmem` per window. A window counts only with at least
  two printable characters, so a run of dots is never evidence.
- **Only `id=` fields are read**, because that is the only place the logger
  escapes.
- **No legitimate identifier can match by chance.** Handles and user names
  are all printable, so a match needs all 16 secret bytes equal to them,
  which is impossible in practice. The clean suites confirm it.
- **One shared copy.** The scan lives in `tests/journal_scan.h`, moved out of
  `test_authd_conn.c` with its hex and base64 forms. `test_authd_localapi`,
  whose code, token and ticket checks were a single hex `strstr` each, now
  uses it too: three new checks.

### Campaign v71 (EI1–EI5)

Each mutation hands `authd_log_slot_id` a secret under an event name it
already logs, so only the field's content changes.

| | The secret logged as `id=` | Killed by |
|---|---|---|
| EI1 | the login code, before it is wiped | `journal: no window of any decrypted payload` |
| EI2 | the ClientHello's nonce | `…either signature or of the ClientHello's nonce`, `…any raw frame` |
| EI3 | ROTATE's `sig_new` | `…the ROTATE's own signatures`, `…any decrypted payload` |
| EI4 | the EXCHANGE token, before it is wiped | `log: no window of the issued token in any form …` |
| EI5 | the RECOVERY-USE ticket | `recovery: no window of the enrollment TICKET in any form …` |

- **The gap, shown first.** Each mutant was built against V4-28's two
  scanning tests (`test_authd_conn` and `test_authd_localapi`) and passed
  them, then failed V4-29's at the predicted names. Every source was
  restored byte-exactly. Only those two tests were run against the old
  code, not the whole suite.
- **The campaign, on the ASan tree:**
  - preflight: 137 sources snapshotted, 113 objects and 43 executables
    fingerprinted, the clean suite passing;
  - 5 of 5 KILLED by name, each restored clean with a passing clean suite
    and no residue;
  - every artifact identical to its clean fingerprint at the end.
- **Totals:** 41 campaigns and 310 mutations, 347 anchors. v71 is in the
  nightly matrix.

### Not established (said so in CLAIMS D13)

- **Fewer than two printable characters.** An escaped window with fewer is
  not counted.
- **`log_ids = hashed`.** The field is then a keyed pseudonym, and no scan
  can relate it to a secret. That mode is the one meant for a public
  deployment.
- **Other paths.** Only the `id=` fields are read for the escaped form;
  every other line is still searched in hex and base64.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `c88d3e5`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `6be4f105bebacc98`, 54/54;
  - `build-bench-p` `c3c041cce8753f96`, 50/50;
  - ASan `f077bcc55dfbb352`, 54/54, with 0 reports;
  - UBSan `bcb3b0aa45691e08`, 54/54, with 0 runtime errors;
  - fuzz `55c4dcbc0c48943c`, 36/36.

  No fixture was left running.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 197 checks, 132 mutations, 17 tools;
  - anchors: 347 across 41 campaigns;
  - `git diff --check`.

## V4-30 — D4: the enrollment ticket, scanned after it is spent (campaign v72)

Loop iteration 5. CLAIMS D4's limits said: "No mutation leaks the ticket
past its round trip, so the ticket's scan shares the code's and token's
proof of liveness."
- **When the scans ran.** `test_authd_localapi` scanned the store and a
  backup for the ticket only when RECOVERY-USE issued it.
- **What they never covered.** ENROLL via=recovery receives the plaintext
  ticket, holds it until it hashes it, and keeps a free-form label in the
  store. No check looked at the store after the ticket was spent there.

### The scan

The ticket is now also scanned once it is spent, right after "enroll: the
recovered device is active with the NEW key":
- **The canary.** The store read must contain the recovered device's new
  key, which shows the read sees what that enrollment wrote.
- **The scan.** `secret_absent` runs over the store with its WAL, and over
  a fresh backup.

### Campaign v72 (TK1, TK2)

| | Mutation | V4-29's tests | V4-30's |
|---|---|---|---|
| TK1 | ENROLL via=recovery with no label stores the raw ticket as the device's label, before wiping it | **pass** | killed by both after-spend checks, by name |
| TK2 | RECOVERY-USE stores the raw ticket where its SHA-256 belongs | killed by "the plaintext ticket is NOT in the store" (and the canaries, and the enrollments that can no longer spend it) | the same, plus the after-spend checks |

- **TK1 is the gap.** Enrollment works, so only a scan after the spend can
  see it.
- **TK2 is the at-issue scan's first mutation kill.** Until now that scan's
  only evidence of liveness was the login code's and the token's.
- **How the gap was shown.** As for v71: each mutant was built against
  V4-29's `test_authd_localapi` and V4-30's, with every restore
  byte-exact.
- **Campaign v72 on the ASan tree:** 2 of 2 KILLED by name, each restored
  clean with a passing clean suite. Every artifact was identical to its
  clean fingerprint.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `34a8c8f`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `2e531641e5674504`, 54/54;
  - `build-bench-p` `278ef1ca056141be`, 50/50;
  - ASan `9f97699b777647ca`, 54/54, with 0 reports;
  - UBSan `94c4b1aa63af2ae7`, 54/54, with 0 runtime errors;
  - fuzz `bae3f1bf3b163c6a`, 36/36.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 200 checks, 134 mutations;
  - anchors: 349 across 42 campaigns, 312 mutations;
  - `git diff --check`.

## V4-31 — the daemon fixtures clean up when stopped (the loop's sixth iteration: fixes and cleanup)

### The bug

`tests/authd_node_fixture.c` and `tests/authd_wasm_fixture.c` each make a
`mkdtemp` directory under `$TMPDIR` holding a store (with its WAL and SHM)
and two sockets.
- **Their cleanup came too late.** It ran only after the serve loop's
  deadline: 20 s by default, 60 s or 300 s as the callers ask.
- **Every caller stops them first.** `wasm_interop`, `web_flows`,
  `browser_e2e` and `phone_timing.mjs` send SIGTERM. The site handler's
  tests (`examples/site-node/authd.test.mjs`) sent SIGKILL, which no
  handler can catch.
- **So no run ever cleaned up.** Measured this morning: 411 directories and
  119 MB in `~/.cache/mldsa-tmp`, from about a day of runs (307 and 91 MB
  when first counted).
- **A leak, not a collision.** `mkdtemp` still made each name unique, which
  is why the fixture's own comment about pid-keyed names did not cover it.

### The fix

- **The fixtures.** Both catch SIGTERM and SIGINT with a `sig_atomic_t` flag,
  installed before anything is created. The serve loop exits on the flag,
  and the existing cleanup (`h_stop`, then removing the directory) runs.
- **The callers.** The site handler's tests stop the fixture with SIGTERM
  and wait for it.
- **The checks.** `wasm_interop`, and every site-handler test through its
  `withDaemon` helper, check three things:
  - the directory exists while the fixture runs (the canary);
  - the fixture exits within 3 s of SIGTERM;
  - the directory is gone afterwards.
- **Why the 3 s bound.** Without it, a fixture that caught the signal and
  went on serving would have cleaned up at its deadline and looked tidy.
  Thinking through the controls is what found that.

### Controls, by hand

Each fixture was rebuilt from scratch, its binary's hash printed, and every
source restored byte-exactly:

| | Mutation | Red at |
|---|---|---|
| C1 | the wasm fixture installs no SIGTERM handler | `wasm_interop`: "fixture: stopped with SIGTERM, it removed its scratch directory (V4-31)" |
| C2 | the wasm fixture's loop ignores the flag | `wasm_interop`: "fixture: it exits within 3 s of SIGTERM, not at its deadline (V4-31)" |
| C3 | the node fixture installs no SIGTERM handler | `site_node_handler`: "the fixture, stopped with SIGTERM, removed its scratch directory (V4-31)", in all 8 tests |
| C4 | the node fixture's loop ignores the flag | `site_node_handler`: "the fixture exits within 3 s of SIGTERM, not at its deadline (V4-31)", in all 8 tests |

### Cleanup

- **The leftover fixture directories.** All 411 were removed by exact name
  pattern (`authd-node-XXXXXX` and `authd-wasm-XXXXXX`), after checking that
  no fixture was running. They are throwaway test stores that every run
  regenerates. The eight libsodium installs beside them were not touched.
- **Branches and the bring-up worktree.** The branches merged into main
  (`v4-26` … `v4-30`) and the `../mldsa-auth-bringup` worktree are removed
  once each has landed. Every branch is then contained in main, so it is
  recreatable by SHA.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `d7cf434`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `db37a89be25f62ac`, 54/54;
  - `build-bench-p` `10aa86de66fb7eca`, 50/50;
  - ASan `c0b0ed54b1fb3a83`, 54/54, with 0 reports;
  - UBSan `8c113229b9d2cb35`, 54/54, with 0 runtime errors;
  - fuzz `df58d74c967b911c`, 36/36.
- **The fix, measured.** Fixture directories in `$TMPDIR` were 0 before the
  first suite, 0 after each, and 0 at the end, across five trees' full
  suites, which start the fixtures dozens of times. No fixture was left
  running.
- **Gates:** spec constants and vocabularies, the claim map, anchors (349
  across 42 campaigns), and `git diff --check`.

## V4-32 — D9: revocation closes a live session, seen from another process

Loop iteration 7.
- **The gap.** CLAIMS D9 said closing a revoked device's live sessions "is
  checked in-process only". `test_authd_localapi` reads the daemon's own
  slot table, and `authd_e2e` checks only that a revoked device is refused
  at its next login.
- **What was missing.** No check stood where a real client stands: outside
  the daemon's process, holding a socket.

### The check

`wasm_interop` already runs the wasm client in Node against the fixture
daemon, a separate process.
1. It enrolls two more devices for the same user.
2. It logs each one in and keeps the session: the daemon serves on after
   issuing the code.
3. It has the site send `REVOKE-DEVICE` for the first.
4. The first device's WebSocket must be closed by the daemon within 3 s,
   observed as a `close` event in Node. The second's must still be open:
   the canary that the close was the revoked device's and not everyone's.

### Controls, by hand

`wasm_interop` runs only in trees with a wasm module, so the nightly
campaign tree cannot run it. Each control rebuilt the fixture and restored
its source byte-exactly:

| | Mutation | Red at |
|---|---|---|
| D1 | v49a's V1: REVOKE-DEVICE closes no live session | "revoke: the daemon closes the revoked device's live WebSocket, seen from the client's process (Req 9, D9)" |
| D2 | `close_matching` matches every live session | "revoke: the other device's live session stays open (the canary)" |

D2's first form was `if (0)`. It left `have` unused, `-Werror` refused to
compile it, and no test ran, which is not a kill. It was rewritten as
`if ((…) && 0)` so every variable stays used, and was then killed by name.

### Not established

- **`revoke=all` and DISABLE-USER.** Their closing is still observed in
  process only.
- **Raw-listener sessions.** Only WebSocket sessions were observed.

### Verification

- **Every tree proven current and run in full** at `808509b`. The
  fingerprints equal V4-31's, as they must: no C file changed.
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `db37a89be25f62ac`, 54/54;
  - `build-bench-p` `10aa86de66fb7eca`, 50/50;
  - ASan `c0b0ed54b1fb3a83`, 54/54, with 0 reports;
  - UBSan `8c113229b9d2cb35`, 54/54, with 0 runtime errors;
  - fuzz `df58d74c967b911c`, 36/36.

  Fixture directories in `$TMPDIR` stayed at 0.
- **Gates:** spec constants and vocabularies, the claim map (202 checks),
  anchors (349 across 42 campaigns), and `git diff --check`.

## V4-33 — D9: DISABLE-USER and revoke=all close live sessions, seen from another process

Loop iteration 8. V4-32 observed REVOKE-DEVICE's close from Node. D9's two
user-wide closes were still in-process only.

### The checks, in `wasm_interop`

Three more users each hold live WebSocket sessions against the fixture
daemon. Throughout, V4-32's surviving session of `u-wasm` is the canary that
a close reached only the user it named.
- **DISABLE-USER.** It is an operator command, sent on the fixture's
  `admin.sock` beside the site socket; the harness allowlists this uid. The
  user's session must be closed within 3 s, and another user's must stay
  open.
- **RECOVERY-USE with `revoke=all`.** Both of the user's sessions must close
  within 3 s.
- **RECOVERY-USE with `revoke=none`.** The user's session must stay open:
  the canary for the flag.

The checks print only the reply's verb. An earlier draft printed the first
characters of each throwaway ticket, which no check message should.

### Controls, by hand

Each control rebuilt the fixture, recorded the mutant's hash against the
clean one, and was restored byte-exactly:

| | Mutation | Red at |
|---|---|---|
| E1 | v58 GA8: DISABLE-USER closes no live session | the disable close check |
| E2 | v58 GA9: revoke=all closes no live session | the revoke=all close check |
| E3 | v58 GA7: live sessions no longer matched by user | the disable AND the revoke=all close checks |
| E4 | `close_matching` matches every session | all four canaries |

### What the first pass got wrong: the archive-level stale-object trap

E2 and E3 first SURVIVED, and their "mutant" fixtures had the same sha256
as the previous control's restored fixture.
- **The cause.** The control loop deleted the mutated source's object and
  the fixture, but not `libmldsa_authd.a`. macOS's make 3.81 compares
  timestamps to the second, and the rebuilt object was not newer than the
  archive linked in the same second. So the archive was kept, and the
  fixture linked the old code.
- **The fix.** Deleting the archive too, and calling a mutant VOID whenever
  its binary equals the clean one, made E2 and E3 KILLED by name.
- **What it called into question.** Every loop today that rebuilt a
  library source the same way. A KILLED verdict proves its mutant was
  linked, but a pass does not. Two results rested on passes:
  - **V4-29's gap,** "EI1–EI5 pass V4-28's tests";
  - **V4-30's gap,** "TK1 passes V4-29's tests".
- **Both redone,** archives deleted and each mutant binary hash-checked
  against its clean build:
  - all five EI mutants pass 2870470's `test_authd_conn` and
    `test_authd_localapi` while linked, and fail the current tests at the
    predicted names;
  - TK1 passes 83bd93e's `test_authd_localapi` while linked and fails the
    after-spend checks;
  - TK2 fails both.

  The records' claims stand.
- **Unaffected:** the campaigns (v71 and v72 ran through
  `run_mutations_v2.sh`, which deletes and fingerprints every artifact)
  and every KILLED hand control.

The rule is in the stale-object memory note: delete object, archive and
executable; hash the clean binary first; VOID, never SURVIVED, for a
mutant equal to it.

### Verification

- **Every tree proven current and run in full** at `a14f396`. The
  fingerprints are unchanged from V4-31, since no C file changed:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `db37a89be25f62ac`, 54/54;
  - `build-bench-p` `10aa86de66fb7eca`, 50/50;
  - ASan `c0b0ed54b1fb3a83`, 54/54, with 0 reports;
  - UBSan `8c113229b9d2cb35`, 54/54, with 0 runtime errors;
  - fuzz `df58d74c967b911c`, 36/36.

  Fixture directories in `$TMPDIR` stayed at 0.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 205 checks. It first FAILED on a single-quoted check
    whose source spelled `user\'s`; the string is double-quoted now, so it
    appears verbatim;
  - anchors: 349 across 42 campaigns;
  - `git diff --check`.

## V4-34 — a tested tool for hand controls, and the stated mutation counts gated (loop iteration 9: fixes and cleanup)

### Why a tool

Hand controls are how a check the nightly's campaign tree cannot run (the
wasm and browser tests, the tools) is shown able to fail: V4-13c, V4-26,
V4-27, V4-31, V4-32 and V4-33 each needed them.
- **Each step wrote its own script.** V4-33's deleted the mutated object
  but not `libmldsa_authd.a`, so two mutants "survived" on unmutated code,
  and two earlier gap demonstrations had to be redone.
- **A rule that lives in a throwaway script is lost with it.**

`tools/hand_control.py` keeps the rule:
1. Build the target clean and hash its binary. Before every build, delete
   the objects of the touched sources, **the static libraries those objects
   belong to**, and the executable.
2. Apply the mutation: an anchor that must match exactly once, or a
   campaign's own `mutate_vNN.py`.
3. Rebuild. A mutant binary equal to the clean one is **VOID**, never
   SURVIVED.
4. KILLED needs a nonzero exit and the named text: on a `FAIL:` line, or in
   a node:test assertion. A failed build is KILLED(compile), which is not a
   kill.
5. Restore byte-exactly (checked by sha256), and rebuild.

### Testing the tool: `hand_control_selftest`

It never mutates this tree. It generates a CMake project (a static library,
a probe linking it, a CTest) in a temporary directory and runs the tool
against it. Its 10 checks:
- each verdict: KILLED, KILLED(other), SURVIVED, VOID for a comment-only
  change (the binary is byte-identical), KILLED(compile);
- **the trap made real.** With the library's archive dated an hour ahead,
  deleting only the object leaves the old code linked: the probe still
  passes;
- **the trap defeated.** The tool, deleting the archive, still links the
  mutant and kills it;
- the probe project is left as found.

Three controls on the tool, each restored byte-exactly, are killed by name:

| | Mutation of the tool | Red at |
|---|---|---|
| H1 | archives not deleted | the archive-ahead check, and also the plain KILLED, SURVIVED and VOID checks: back-to-back controls in a quick project ran stale code without it |
| H2 | no VOID verdict | "a mutation that leaves the binary unchanged is VOID" |
| H3 | an unnamed failure taken as a kill | "… is KILLED(other) -- not a named kill" |

H1's spread is the point. The trap was not contrived: it hit ordinary,
quick, consecutive controls.

### The stated counts, gated

Three documents stated campaign and mutation counts, and nothing checked
them:
- **`README.md`:** "**all 305**" and "all forty … thirty-nine on Linux".
- **`tools/README.md`:** "305 must-kill mutations across 40 campaigns",
  "All thirty-nine", "thirty-eight" and "verifies **all 299**".
- **The truth:** 312 and 42, with 41 on Linux, since V4-29 and V4-30. Some
  of those figures were older still.

Changes:
- **`check_mutation_anchors.py` now checks all eight.** Each sentence must
  be found as well as agree, so rewording one fails the gate instead of
  retiring it. It failed 8 of 8 on the stale documents before they were
  corrected; the counts are digits now so they can be read.
- **It runs in CI's spec job too,** so an anchor rotted by another step,
  or a stale count, fails on push rather than in the nightly hours later.
- **`tools/README.md`** lists v71 and v72 and their letter pairs. Its
  introduction no longer claims nothing there is used by CMake: two tools
  are run by CTests.
- **The test counts move again** (`hand_control_selftest`, wherever
  `python3` is found): 51 native, 53 with a wasm tree, 55 with a browser.
  The README and REPRODUCE.md say so.

### Routine checks

F91: liboqs's latest release is still 0.16.0 (checked 2026-10-20).

### Verification

- **Every tree proven current and run in full** at `69c4220`. The
  fingerprints are unchanged from V4-31: a Python tool and its test add
  no compiled code.
  - `build-wasm-p`: 3/3;
  - `build-p`: 55/55;
  - `build-bench-p`: 51/51, the plain native count the README states;
  - ASan: 55/55, with 0 reports;
  - UBSan: 55/55, with 0 runtime errors;
  - fuzz: 36/36.

  `hand_control_selftest` passed in all four native trees. It left no
  `mldsa-hc-*` directory, and fixture directories stayed at 0.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map;
  - anchors: 349 across 42 campaigns, plus the new counts check, 8 of 8
    agreeing;
  - `git diff --check`.

## V4-35 — D10: a CLI rotation whose reply is refused or lost leaves no key in the clear (campaign v73)

Loop iteration 10. CLAIMS D10's limits: "A CLI rotation whose session opens
but whose reply is lost or refused is not scanned."
- **What was covered.** `test_authd_cli` scanned every file for every key
  after an acknowledged rotation, after the login completing an
  interrupted one, and after a rotation from a superseded key, whose
  session is refused before ROTATE.
- **What was not.** The two paths after ROTATE is SENT: the daemon refuses,
  or nothing comes back. `cmd_client_rotate` keeps `.ek.next`, sealed, on
  both, and nothing looked at the disk then.

### The two runs

`run_client_pumped` takes a hook called after every tick. Acting between two
loop turns is where nothing on the wire can interleave.
- **Refused.** The hook waits until the CLI's session is SERVING (its login
  code queued), then rotates the store's key behind the session to one the
  test made. The ROTATE that follows reaches the daemon's own
  `store_rotate_key`, whose `pk_old` is no longer active. It refuses: error
  0x03 on the wire, "the daemon refused the rotation".
  - The fault hook was not usable here: it is compiled only into
    `test_authd_store`'s own copy of the store.
- **Lost.** The hook waits until the handle's active key moves, which is
  the daemon's commit. The daemon queued its ACK in that same turn, and
  `conn_io_queue` only buffers; the write happens on a later turn's
  POLLOUT. Closing the session then loses the ACK, as a crash or a dropped
  link would, and the CLI says "no reply".
- **The canaries.** Each case checks that it is the path it claims:
  - refused: the store holds the test's key and never the sealed one;
  - lost: the store holds the sealed key, and at least one session was
    closed.

  Both: `.ek` unchanged and `.ek.next` kept, sealed. Then the same scan as
  the other cases, for both keys in every file.

### Campaign v73 (RL1, RL2)

Each mutation keeps the new key's raw secret as `<.ek.next>.retry` on one
path. The CLI frees the new key before it sends ROTATE, so each is two sites:
that free moved into the path that keeps the key.
- **The script as first written failed the anchors gate.** It used `%`
  formatting, which the static anchor extractor cannot evaluate (it parses
  the scripts and never runs them). The mutation texts are plain literals
  now, as every other campaign's are.
- **The gap, shown with hashes.** It used the archive-safe procedure, with
  `tools/hand_control.py`'s own artifact discovery. RL1 and RL2 were each
  linked (binary unlike the clean build), each passed V4-34's
  `test_authd_cli`, and each is killed by its named check:
  - RL1 by "rotate refused: no window…";
  - RL2 by "rotate lost: no window…".
- **The counts gate earned its keep at once.** Adding v73 made every stated
  count stale, and the gate said so: 11 problems before the documents moved
  to 314 mutations and 43 campaigns.
- **Campaign v73 on the ASan tree:** 2 of 2 KILLED by name, each restored
  clean with a passing clean suite. Every artifact was identical to its
  clean fingerprint.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `5f2021b`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `0a3d4a73c4b716ef`, 55/55;
  - `build-bench-p` `8cf184663a8e6ec9`, 51/51;
  - ASan `a8e2a8c4ce11e663`, 55/55, with 0 reports;
  - UBSan `e55a68821a621edd`, 55/55, with 0 runtime errors;
  - fuzz `f3a5a0d892136f61`, 36/36.

  Fixture directories stayed at 0.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 207 checks, 136 mutations;
  - anchors: 353 across 43 campaigns, and the 8 stated counts agreeing at
    314 and 43;
  - `git diff --check`.

## V4-29 to V4-35 — CI on the branches and the nightly bring-up

**One bring-up for seven steps,** as V4-24a/b and V4-26..28 did. The steps
stack on one line, and only V4-29, V4-30 and V4-35 add campaigns: v71, v72
and v73. So:
- the control nightly ran on V4-29..31's code and rotted one v72
  expectation;
- the final nightly runs every campaign against the final tree, which
  includes V4-35's v73 for the first time on Linux.

### CI on the branches (14 jobs each, all green)

| Step | Head | Run |
|---|---|---|
| V4-29 | `83bd93e` | 39396696722 |
| V4-30 | `a974a02` | 39404637352 |
| V4-31 | `6676460` | 39409550134 |
| V4-32 | `ce0578c` | 39420088841 |
| V4-33 | `aa38a5a` | 39426792410 |
| V4-34 | `6b0f3f6` | 39432985761 |
| V4-35 | `94c3bd8` | 39445471524 |

### The control nightly

- **How the control was built.** `a3deaba` is `nightly-bringup`'s previous
  head `52db54b` with V4-29..31 cherry-picked; its tree is `4b9eb47c`,
  equal to V4-31's `6676460`. On top, v72 TK2's expectation was rotted
  ("… CONTROL -- a check no test prints (V4-29..31)"). spec_v72's sha256
  before was `b8655c3e3b01f12f`.
- **Why cherry-picks.** A first control built on top of `6676460` itself
  could not be pushed without a force push. Cherry-picking onto
  `nightly-bringup`'s head keeps every push a fast-forward.
- **The result.** Run 39415250556 was red on exactly `mutations · v72`,
  56/57:
  - TK1 KILLED (3 named on Linux);
  - TK2 **SURVIVED(BAD)**, naming the rotted text;
  - every mutant restored clean.

  It was also v71's first run on Linux: green.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-36 — D5: the real daemon's clock, seen advancing (campaign v74); hand controls compare code

Loop iteration 11.

### The gap

Every expiry `mldsa-authd` enforces is `now_unix` plus a constant: a login
code's 60 s, a token's TTL, a ticket's ten minutes.
- **Who sets the clock.** `authd_main`'s loop sets `now_unix` from
  `time(NULL)` on every turn, while every C test drives `app.now_unix`
  itself.
- **The consequence.** Nothing had ever watched the real daemon's clock
  move. A loop that stopped updating it, which is campaign v74's CK1, would
  issue codes and tokens that never expire, and every check in the tree
  passed it.

### The check

`authd_e2e`'s site leg exchanged one code through `tests/e2e_site.mjs`. The
script now also prints the reply's `issued`, which is the daemon's clock at
EXCHANGE.
1. After a 2 s sleep, a third login's code is exchanged too.
2. The two `issued` values must be at least 2 s apart.
3. Each must be within 5 s of the shell's `date +%s`, so the daemon's clock
   is the wall clock, not merely a moving one.

No test waits out a real 60 s, and CLAIMS D5 says so.

### Campaign v74 (CK1)

CK1 keeps every use, per F79: `app.now_unix = app.now_unix + 0`. It passes
V4-35's `authd_e2e` (SURVIVED, with its code differing from the clean
build's). It is killed here by name: "the daemon's clock did not advance: a
code exchanged 2 s later was issued at 1792510237, the first at
1792510237".

### Two flaws in tools/hand_control.py, found by using it

1. **No way to name the binary.** `mldsa_authd_bin`'s OUTPUT_NAME is
   `mldsa-authd`, and the tool looked for a file named after the target, so
   it would have reported a failed clean build. It now takes `--binary`; the
   self-test gains a renamed-target case (11 checks).
2. **It hashed whole files.** Three links of `mldsa-authd` from identical
   source gave three file hashes and three LC_UUIDs, with one text hash
   (`d485e9ae`). `test_authd_cli` and `test_authd_localapi` behave the same.
   - So "the mutant binary differs from the clean one" was blind: a stale,
     unmutated binary would have differed too.
   - The tool now fingerprints the code, `otool -X -t` (or `objdump -d
     --section=.text`), exactly as `check_build_current.sh` does.

That also weakened evidence I had already recorded. The gap demonstrations
of V4-29 (EI1–EI5), V4-30 (TK1) and V4-35 (RL1, RL2) said "mutant linked"
from whole-file hashes.
- **They were sound for a different reason.** Deleting objects, archives
  and executables before every build defeats the stale trap by
  construction, and the self-test proves it.
- **The hash said nothing.** All eight were redone with the fixed tool:
  each mutant's code differs from its clean build's, and each survives its
  predecessor's tests. The claims stand, now with evidence that means what
  it says.
- **Campaign v74 on the ASan tree:** 1 of 1 KILLED by name, restored clean
  with a passing clean suite. Every artifact was identical to its clean
  fingerprint.

### Verification

- **Every tree proven current and run in full** at `3c56fc5`. The
  fingerprints equal V4-35's, since no C file changed:
  - `build-wasm-p`, 3/3;
  - `build-p`, 55/55;
  - `build-bench-p`, 51/51;
  - ASan, 55/55, with 0 reports;
  - UBSan, 55/55, with 0 runtime errors;
  - fuzz, 36/36.

  `authd_e2e`'s clock check and `hand_control_selftest` (11 checks) passed
  in every native tree. No fixture or `mldsa-hc-*` directory was left.
- **Gates:**
  - spec constants and vocabularies;
  - the claim map: 208 checks, 137 mutations;
  - anchors: 354 across 44 campaigns, the counts agreeing at 315 and 44;
  - `git diff --check`.

## V4-37 — the event-loop tests wait for conditions, not counts (loop iteration 12: fixes and cleanup)

### The risk

`test_authd_evloop`'s `pump(ev, now, iters)` ran a fixed 3 to 6 loop turns
at ten call sites. Its comment promised "until `pred` holds", a predicate
it never took. `test_authd_ws` pumped a fixed 50 ticks to "let the daemon
reap the slot".
- **Why it matters.** A machine under load (a busy runner, a sanitizer, a
  parallel ctest) can need more turns than a count allows. The test then
  fails for a reason that is not a defect, and that looks like a
  regression.
- **Its history.** The project's notes had carried it as a known risk since
  V4-24.

### The change

- **Every positive wait is `PUMP_UNTIL(predicate)`,** at ten sites: a
  connection held, a frame delivered, slots released, a partial frame
  buffered, a drain finished. Its ceiling is 2,000 turns.
- **The echo wait now covers the flush.** It waits for the reply to be
  written too, because the next line is a blocking `read`; an unflushed
  reply would have hung the test rather than failed it.
- **The one place nothing is awaited** (after the synchronous
  `evloop_close_all`) keeps a fixed `pump_n`, saying so.
- **A ceiling hit is a failed check** named by its predicate. The first
  control (P1 below) is why.
- **`test_authd_ws`'s reap** is `CHECK(H_PUMP_UNTIL(...), "ws: the daemon
  reaps a raw probe's slot once it closes")`.

All check names are unchanged. The tests now have 133 and 129 checks.

### The controls, and what the first one taught

They used `tools/hand_control.py`.
- **P1, a predicate that never holds:**
  `PUMP_UNTIL(… evloop_active(&ev) == 99u)`. It first **SURVIVED.** The
  pump ran out its 2,000 turns, the connection was accepted during them
  anyway, and the check after the wait passed. A wait that never ended as
  intended was invisible.
  - So a ceiling hit became a failed check, "ev: the loop reached, within
    2,000 turns: <predicate>", and P1 is now KILLED by exactly that name.
- **P2, a reap wait that never holds:** KILLED by "ws: the daemon reaps a
  raw probe's slot once it closes", once for each of the four probes.

### Whether the old tests ever flaked here: no

| Binary | Load | Runs | Failed |
|---|---|---|---|
| old `test_authd_evloop` (V4-36's) | 14 busy loops, 16 in parallel | 300 | 0 |
| old `test_authd_evloop`, ASan | 14 busy loops, 32 in parallel | 300 | 0 |
| new `test_authd_evloop` | 14 busy loops, 16 in parallel | 300 | 0 |
| new `test_authd_evloop`, ASan | 14 busy loops, 32 in parallel | 300 | 0 |
| new `test_authd_ws` | 14 busy loops, 16 in parallel | 150 | 0 |

So the fixed counts were enough on this machine, even under ASan, and this
change is **insurance, not a fix for an observed failure**. What it removes
for certain:
- a comment contradicting its code;
- a possible hang;
- ten waits tuned to one machine's speed.

The new named checks did not fail falsely under the same load.

### Verification

- **Every tree rebuilt, proven current, and run in full** at `c9c1cd7`:
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `33e75f1ea4f5b73b`, 55/55;
  - `build-bench-p` `84c658426e8025f9`, 51/51;
  - ASan `812bba1fc6bf2bbe`, 55/55, with 0 reports;
  - UBSan `196284b3c0dd6d71`, 55/55, with 0 runtime errors;
  - fuzz `c7dcfc497f0ab0c5`, 36/36.

  No fixture was left.
- **Gates:** spec constants and vocabularies, the claim map, anchors (354
  across 44 campaigns, the counts agreeing), and `git diff --check`. No
  campaign anchors in either test, and every check name is unchanged.

## V4-38 — the reviewer's reproduction page, re-run from a fresh clone (loop iteration 13: coverage)

### Why

`docs/review/REPRODUCE.md` is the first page a reviewer runs. It had last
been run as written in V4-14b (2026-09-27), and twenty-four steps had landed
since. Nothing checked that its commands still printed what it says they
print.

### The run

A fresh clone of V4-37's head `b05ed0b`, at a path without spaces (the
scratchpad), with every command copied from the page verbatim by a script
that greps out the lines the page quotes. macOS 27.0.1, arm64, 13:32 to
14:59.

| Block | Printed |
|---|---|
| the suite, `build` | current (`0373304110d9ffa7`), 51/51, two *Skipped* as the page says |
| ASan | current (`abb67318716d7a66`), instrumentation in all 43, 51/51 |
| UBSan | current (`9ed2208e7c985049`), instrumentation in all 44, 51/51; `runtime error` count 1, `ubsan_canary.c:15`'s planted overflow |
| gcc 16 Release | 51/51 |
| wasm, then the browser tests | 3/3, then 4/4 |
| fuzz tree, then `run_fuzz.sh … authd_config` | 36/36, then 600 s, 123,075,142 runs, `crashes=0 artifacts=0` |
| campaign v72 on the ASan tree | TK1 `KILLED(3 named)`, TK2 `KILLED(15 named)`, `residue: none`, `final: all sources restored …` |
| anchors | `ALL ANCHORS OK`, 354 anchors, 315 mutations, 44 campaigns |
| the three document checks | each `OK` |
| `caddy_proxy.sh`, `deploy_checks.sh` | 9 PASS lines and `PASS: CADDY: all checks`; exposure 1.7 and `PASS: DEPLOY: all checks` |
| the advisory queries | below |

Every command worked as written. ProVerif was not run (not installed here,
as before).

### What the page said that was no longer true

- **The counts:** "305 committed mutations in 40 campaigns" and "342
  anchors, 40 campaigns" (now 315, 44 and 354).
- **F90's sentence:** "Nine older mutations are killed without a named
  check". Since V4-14d a spec line without an expected check is refused, so
  there are none.
- **The CI and nightly runs it cited:** from `6f9269b`, with 13 jobs, 26
  campaigns and 223 of 233 mutations. Now 14 jobs on main `71c8fc0`
  (39474140277), and nightly 39447335408: 58/58, 314 of 314 by name.
- **The ProVerif log** was cited from that old nightly. It is now cited from
  39447335408, whose nine lines read the same.
- **Lines printed but not quoted.** The page now quotes:
  - the browser block's count;
  - the fuzz run's run count;
  - the full `PASS: CADDY:` and `PASS: DEPLOY:` lines;
  - the advisory queries' answers.
- **The campaign example** was v56, whose twenty mutations take hours. It is
  now v72 (two, about twenty minutes), with the difference stated.

### The counts gate now covers it

The page's counts had drifted because V4-34's gate in
`tools/audit/check_mutation_anchors.py` checked only README.md and
tools/README.md. Five patterns for REPRODUCE.md were added, for 13 stated
counts in all. The patterns cover the mutation and campaign counts and the
anchor line.
- **Shown red by hand:** with 342 written back in, the gate printed
  `COUNT docs/review/REPRODUCE.md: says 342 where the campaigns say 354` and
  `1 PROBLEM(S)`, exit 1. The file was then restored.
- **It then printed** "counts: the 13 stated counts in README.md,
  tools/README.md and REPRODUCE.md agree (315 mutations, 44 campaigns, 354
  anchors)". The sweep below took it to 16.

CI's spec job already runs the script.

### The advisories: one new, not exposed

All of ADVISORIES.md's queries were repeated, controls included:
- OSV by commit for the three pins and Emscripten;
- NVD for liboqs, libsodium, Emscripten and SQLite 3.53.4 / 3.50.1;
- the GitHub advisories for liboqs and libsodium.

One answer changed. GitHub lists **GHSA-xv6c-h66p-6mfq / CVE-2026-104255**
(2026-10-06, medium), affecting liboqs 0.11.0 through 0.16.0:
- **What it is:** LMS lock callbacks fail open, so a one-time key can be
  reused and a signature forged. LMS verification ignores the parameter set,
  and there are three defects on LMS key generation and signing.
- **What it needs:** every part requires `OQS_ENABLE_SIG_STFL_LMS=ON`.
- **This build:** it is OFF, as is
  `OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN`. The built
  `liboqs.a` has no LMS, HSS or LM-OTS symbol, including the advisory's
  exported `OQS_SIG_STFL_alg_lms_verify`. Its 21 `OQS_SIG_STFL_*` symbols are
  the generic dispatcher, with nothing to dispatch to.
- **The gate:** `liboqs_minimal` passes, and already fails the build if such
  a symbol appears.
- **The fix** is in 0.17.0, still unreleased (latest 0.16.0).

It is recorded in ADVISORIES.md and in F91's rows (Info, unchanged), and
the pin stays.

The run also found one NVD match the page had never accounted for:
**CVE-2024-37305**, the eighth match for "liboqs". It is in oqs-provider, a
separate project this one does not use. Everything else matched the page:
- libsodium's nine NVD matches (CVE-2025-69277 plus the eight wrappers it
  names);
- Emscripten's six;
- SQLite 3.53.4's one (CVE-2022-31631, PHP);
- SQLite 3.50.1's five, CVE-2025-6965 among them;
- OSV empty for libsodium 1.0.18 too;
- no libsodium GitHub advisories.

NVD did not yet list CVE-2026-104255.

### The sweep after it: the packet's front page, F120

With REPRODUCE.md fixed, every tracked document was searched for stated
counts of mutations, campaigns, anchors, tests, findings and errata. Five
more were stale:

| Where | Said | Is |
|---|---|---|
| `docs/review/README.md`, the register | 117 findings (F1–F119) | 119 (F0–F119; no F16 was ever assigned), 120 with F120 |
| `docs/review/README.md`, the spec | §20 lists 46 errata | 48 |
| `docs/review/README.md`, tests | 52 with the browser client | 55 |
| `docs/review/README.md`, mutations | 305 in 40 campaigns | 315 in 44 |
| `README.md`, the `tools/` row | 305 committed mutations | 315 |

That is F106, F110 and F116's class again, so it is recorded as **F120**
(Info, fixed). Ten new patterns now read these counts from their sources:
- **`check_mutation_anchors.py`:** eight. They cover REPRODUCE.md's five,
  the front page's two and README's one, for 16 stated counts in all.
- **`check_claim_map.py`:** two, comparing the front page's findings count
  and range with the register's rows, and its errata count with §20's rows
  (each must be found, and §20's numbers distinct).

Each was shown red once by a rotted count, and restored byte-exactly:

| Rotted | Gate | Printed |
|---|---|---|
| README 315 → 305 | anchors | `COUNT README.md: says 305 where the campaigns say 315` |
| front page 44 → 40 campaigns | anchors | `COUNT docs/review/README.md: says 40 where the campaigns say 44` |
| front page 315 → 305 | anchors | `COUNT docs/review/README.md: says 305 where the campaigns say 315` |
| 119 → 118 findings | claim map | `FAIL the register's stated size and range … page says 118 findings (F0–F119); the register holds 119` |
| 48 → 47 errata | claim map | `FAIL the spec's stated errata count … page says 47; §20 holds 48 row(s)` |

Before the fix, the claim-map checks failed on the stale page itself (117
and 46). That is the gap shown on the real defect, not only a planted one.

**The test counts are not gated.** They depend on the configuration (node,
python3, a wasm tree, a browser), which no static check sees. F107, F116 and
now F120 are three drifts of them, and a CTest that compares `ctest -N` with
what the README states for its own configuration is the next fixes-and-cleanup
iteration's candidate.

The front page's narrative also stopped at V4-36 and never mentioned V4-28,
so F114 still read as open there. V4-28, V4-37 and V4-38 now have their
sentences.

**"F91 is the only open finding" was not true.** The page said it in
V4-24a's paragraph, and this step's first draft of V4-28's repeated it. Then
every row's disposition was read: three rows older than the packet stay
open by their own account.
- **F5 (Med):** no coverage figure for anything under `apps/authd/`.
- **F15 (Info):** v1's x86_64 target can no longer be measured.
- **F17 (Med):** Req 4.9's timing is unmeasured.

The page's "Still open" table listed only F91 because it covers the seven
findings the packet itself found. The three older rows are now listed beside
it, both sentences say "since the packet was built", and F120 records it.
Which rows are open is prose, so no gate reads it.

### Verification

- **Gates:** spec constants and vocabularies, the claim map (with its two
  new count checks), anchors (354, with the 16 counts agreeing), the audit
  table's separators, and `git diff --check`.
- **The code changes** are the two gates' checks. Each ran green, and red
  under the hand controls above.
- **No source or test file changed,** so no campaign is affected.

## V4-39 — P10's backend check in every native tree, and shown able to fail (loop iteration 14: coverage)

### The gap

CLAIMS P10 rests on `tools/check_backend_symbols.sh`, which proves that one
optimised ML-DSA-65 / ML-KEM-768 backend is linked and no portable-C one. Its
own limit said two things:
- **It ran on Linux x86_64 only:** CI's Release job and bench.yml.
- **Nothing covered it.** It had never been shown to fail.

Three consequences:
- **macOS was unchecked.** The macOS CI jobs build liboqs with
  `MLDSA_OQS_OPT_TARGET=generic`, and ci.yml's comment asserted that this
  "still selects the AARCH64 backends". Nothing looked.
- **The tool disagreed with the spec on x86_64 `generic`.** Spec-v2 §3
  requires `generic` for distribution and says it "gives up the AVX2
  backend" on x86_64. There the one linked backend is portable C, which
  the tool would have failed.
- **"Exactly one optimised family" was claimed but not checked.** An
  executable with both aarch64 and x86_64 symbols would have passed as
  x86_64.

### The change

- **The tool:**
  - `--expect aarch64|x86_64|c` names the one family every executable must
    link, and no other family's symbols may appear beside it;
  - without `--expect` it behaves as before, for CI's Release step,
    bench.yml and the RUNBOOK, and now also fails on two optimised families
    (in one executable or across two);
  - a missing `nm` or `file` is a FAIL with its reason, not "no executables
    found".
- **A CTest, `backend_symbols`, in every native tree,** registered where
  `nm` and `file` exist. CI's suite step asserts that it is registered.
  - First it tests the tool on executables planted in a `mktemp -d` outside
    the tree. They are compiled with the tree's own compiler, each defining
    functions under the family prefixes. Eleven named checks each read the
    exit status and the line that explains it.
  - Then it runs the tool on the tree with `--expect`. The family is what
    the project intends, set at configure time, never what liboqs picked:
    aarch64 on arm64, x86_64 on x86_64, and `c` for x86_64 `generic`.
    `MLDSA_EXPECT_BACKEND` overrides it for a target the rule does not
    know. Taking liboqs's own choice would have made the test agree with a
    configure that silently lost the optimised backend.
- **Test counts:** native 52, with a wasm tree 54, with a browser 56.

### The controls

**Real builds, by hand.** Each scratch tree has `mldsa-authd`,
`auth_client` and `test_handshake` built; the clean tree has aarch64=147,
portable-C=0 in each. In every one, `backend_symbols` failed on "this tree
links one backend, aarch64, in every executable that links one":

| Control | aarch64 | portable-C | in each of the three |
|---|---|---|---|
| (a) `-DOQS_ENABLE_SIG_ml_dsa_65_aarch64=OFF` | 60 | 69 | FAIL |
| (b) `-DOQS_ENABLE_KEM_ml_kem_768_aarch64=OFF` | 87 | 45 | FAIL |
| (c) `OQS_DIST_BUILD ON` in `cmake/Dependencies.cmake`, in a separate worktree | 147 | 114 | FAIL |

The counts add up: 60 + 87 = 147, and 69 + 45 = 114. Runtime dispatch (c)
links both whole families, which is what P10 forbids.

**The tool's own verdicts, broken one at a time** and restored byte-exactly
(`cmp`). Each was killed by name:

| Control | Break | Killed by |
|---|---|---|
| D1 | `--expect` ignores another family beside the expected one | "two families in one executable fail when one is expected" |
| D2 | default mode ignores two families in one executable | "without --expect, two optimised families in one executable fail, named" |
| D3 | default mode ignores portable C | "without --expect, portable C fails" |
| D4 | the no-backend guard removed | "an executable with no backend at all proves nothing" |
| D5 | default mode ignores two families across executables | "without --expect, two optimised families in two executables fail" |
| D6 | the no-executables guard removed | "a directory with no executables proves nothing" |

Two things these runs taught:
- **D2 first SURVIVED.** The cross-executable guard caught the same input,
  and the selftest's expected line matched both guards' messages. The
  selftest now names the per-executable message, and has a case of its own
  (D5) for two families split across executables.
- **D7 was an equivalent mutant.** Making `--expect c`'s "has the expected
  family" condition always true changed nothing. Every executable that
  reaches it links some backend, so "none of the expected family" already
  implies another family's symbols. The redundant condition was removed,
  and the one left (D1') is killed by three named checks.

**In CI**, a control branch, `v4-39-ctl` (1487d05 on 376ae3a): v4-39 plus
`OQS_ENABLE_KEM_ml_kem_768_x86_64` forced OFF. Run 39485860730 went 8/14:
- **The six red jobs** are exactly the four Linux suite jobs (clang debug,
  ASan and UBSan; gcc debug) and both Linux Release jobs.
- **In each,** 1 test of 52 failed, `backend_symbols`, with x86_64=83 and
  portable-C=45 (41 in Release) in every executable.
- **Green:** all three macOS jobs, which the forced option cannot reach,
  plus the spec, fuzz-and-scan, wasm, deploy and Caddy jobs.

The branch was then deleted.

### What it shows

- **macOS.** In V4-39's green CI (39485765975), `backend_symbols` passed in
  all seven suite jobs. So `generic` on the macOS runner does keep the
  aarch64 backends, which ci.yml's comment had only asserted.
- **Still not established:**
  - "No runtime branching" is inferred from symbols, not by looking for
    CPU-feature branches.
  - libsodium's ChaCha20 selection is not covered.
  - The x86_64 `generic` expectation (`c`) is tested only on planted
    executables: no x86_64 machine here builds it.
  - No campaign covers the gate: the runner needs a mutant in the
    binaries, and a gate script or a CMake option is in none.

### Verification

- **Every tree rebuilt, proven current and run in full:**
  - `build-wasm-p` `2c39f8ab7908049c`, 3/3;
  - `build-p` `33e75f1ea4f5b73b`, 56/56;
  - `build-bench-p` `84c658426e8025f9`, 52/52;
  - ASan `812bba1fc6bf2bbe`, 56/56, instrumentation in all 43;
  - UBSan `196284b3c0dd6d71`, 56/56, instrumentation in all 44. Its one
    runtime error is `ubsan_canary.c:15`'s planted overflow;
  - fuzz `c7dcfc497f0ab0c5`, 36/36, and `backend_symbols` passes there too
    (Homebrew clang, the Xcode SDK passed as the sysroot).

  The fingerprints equal V4-37's: no C source changed.
- **CI:** 39485765975, 14/14.
- **Gates:** anchors and counts, the claim map, the spec checks, `git diff
  --check`, and the workflow YAML parsed.

## V4-40 — the daemon's coverage, measured for the first time (loop iteration 15: coverage; F5)

### Why

F5 (Med) was open by its own account: coverage had been measured once, in
V4-1, before the daemon existed. Nothing under `apps/authd/` had a figure.
Coverage is deliberately not a gate here; the campaigns are. But an
uncovered region is one no mutation can be killed in, so a figure finds
gaps that the claim map's "not established" entries can only name by
reading.

### What measuring it found first

**Forked test children were never counted.** A child leaves with `_exit()`,
which skips the hook the profile runtime writes from. The first run (via
`CMAKE_C_FLAGS`) put `cli_prompt.c` at 4.5% of lines, though
`test_client_prompt` drives the prompt through every path under `forkpty`.
Three tests fork such children:
- `test_client_prompt`: the prompt;
- `test_authd_cli`: the client CLI, run pumped;
- `test_net`: the demo server and proxy.

Their twelve `_exit()` calls now go through `tests/child_exit.h`. Under
`MLDSA_COVERAGE` it writes the profile first. In every other build it calls
`_exit()` and nothing else. It is not the same machine code: at `-O0` the
inline function is a real call, and the added `#include` shifts line
numbers. So the three tests' objects differ from V4-39's, and the plain
trees' fingerprints changed. No other source changed, and no plain tree's
compile commands carry a coverage flag (below). With the children counted:
- `cli_prompt.c` reads 67.2% of lines;
- `client_cli.c` reads 75.7%, up from 71.0%;
- `apps/authd/` as a whole reads 81.30%, up from 79.80%.

The profile count did not change (137), because `%m` in the profile name
makes a child merge into its parent's file.

**The tool had three defects of its own:**
- **An empty list, silently.** Its "uncovered regions by function (top
  25)" came out empty without saying so: the text report cannot be parsed
  under a path with spaces, and the source filter was relative.
- **CMake's probes in the totals.** Its totals counted CMake's
  compiler-identification programs.
- **Unscoped flags.** Instrumenting through `CMAKE_C_FLAGS` reached the
  dependencies too, and something run during that build wrote a stray
  `default.profraw` into the repository root (removed). With the new option
  it did not recur.

### The change

- **`-DMLDSA_COVERAGE=ON`** (clang only) adds the instrumentation after the
  dependencies are created: 112 project sources instrumented, 105 liboqs
  sources not. It also defines `MLDSA_COVERAGE` for `child_exit.h`.
- **`tools/audit/coverage.sh`:**
  - it refuses a tree without the option;
  - it finds the source tree from the cache;
  - it skips `CMakeFiles`;
  - it computes the totals by area and the functions under 80% from `llvm-cov
    export`, counting code regions only, as llvm-cov does. Its first count,
    of all region records, gave a one-line function 56 regions.
- **The record:** `docs/v4/coverage.md` holds the method, the figures by
  area and by file, and the triage.

### The figures

`build-cov-p`, all 56 tests, macOS, Apple clang 21:

| Area | Lines | Regions | Branches | Functions |
|---|---|---|---|---|
| `src/` | 83.67% | 92.02% | 73.37% | 100% |
| `apps/authd/` | 81.30% | 87.51% | 69.05% | 97.45% |
| all | 80.20% | 87.66% | 67.89% | 97.44% |

### The triage, and three findings

Most of what is uncovered is of three kinds:
- the failure of a primitive or an allocation, which needs fault injection;
- `EINTR` and `EAGAIN` retries;
- name tables.

Beyond those, three findings:
- **F121 (Info):** `conn_io_out_capacity`, `authd_conn_stage_name` and
  `listener_accept` have no caller. `listener_accept`'s `(uid_t)-1`
  sentinel becomes an empty allowlist, which means no credential check:
  F92's shape, unreachable. Their removal is the next fixes-and-cleanup
  iteration's.
- **F122 (Low):** five security checks no test drives to their refusal:
  - key-file custody (`keyfile_open`, `keyfile_promote`): the refusal ran 0
    times against 174 and 4 runs of the condition;
  - the CLI client's WebSocket frame reader, including its frame-versus-buffer
    bound;
  - `REVOKE-TOKENS handle=`;
  - `store_open`'s refusal of a damaged store;
  - the daemon's oversized-record, BYE-length and post-rotation drop paths.
  The code reads correctly; the evidence is what is missing. They are the
  next coverage iterations' work.
- **F123 (Low, for the owner):** with `handle=`, `REVOKE-TOKENS` validates
  `user=` and then ignores it. Nothing sends that form today, so nothing
  ever showed it. Its scope is a decision about the interface's meaning,
  so it is parked with a proposed fix: `AND user_id=?2`, answering `OK
  count=0` for a mismatched pair (no new error code), plus an erratum and a
  test.

F5 stays open: it has a figure, and the figure names F122.

### The controls

- **`coverage.sh build-p`**, a tree without the option, prints "FAIL: …
  was not configured with -DMLDSA_COVERAGE=ON", exits 2 and writes nothing.
- **The coverage tree's `test_client_prompt`** references
  `__llvm_profile_write_file`. Every plain tree's does not (below).
- **The flush itself** is shown by the before/after figures above, on the
  same tests: 8 of `cli_prompt.c`'s 177 lines before, 119 after.

### Verification

- **Every plain tree rebuilt, proven current and run in full,** with
  `MLDSA_COVERAGE=OFF` and no coverage flag in its compile commands:

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-wasm-p` | `2c39f8ab7908049c` | 3/3 |
  | `build-p` | `8133e8e65c9f728f` | 56/56 |
  | `build-bench-p` | `c36e71ec4d73e2db` | 52/52 |
  | ASan | `1c26ca6470293b67` | 56/56, instrumentation in all 43 |
  | UBSan | `4edf84ad150b8bfc` | 56/56, instrumentation in all 44; one runtime error, the planted canary |
  | fuzz | `bc023da52c87bbe5` | 36/36, `backend_symbols` 1/1 |

  In each, `test_client_prompt` references no `__llvm_profile_write_file`.
- **The coverage tree** `build-cov-p` (`5b44c662708d4ac3`): 56/56, 137
  profiles. The final `coverage.sh` was run end to end once more, since a
  script outside CTest is believed only when run. It matched the figures
  above, except for one branch fewer (a timing-dependent retry); the
  function list was the same apart from call counts.
- **Campaign v73 on ASan.** Its two mutations are killed through
  `test_authd_cli`'s pumped children, the path this step changed: RL1 and
  RL2 each `KILLED(1 named)`, `residue: none`, all sources restored.
- **Gates:**
  - anchors (354; 16 counts agreeing);
  - the claim map, including the register's size (123, F0–F123);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-36 to V4-40 — CI on the branches and the nightly bring-up

**One bring-up for five steps.** Only V4-36 adds a campaign (v74). So the
control nightly ran on V4-36..37's code and rotted v74 CK1's expectation.
The final nightly runs every campaign against the final tree, with V4-38's
gates, V4-39's `backend_symbols` and V4-40's `child_exit.h` in it.

### CI on the branches (14 jobs each, all green)

| Step | Head | Run |
|---|---|---|
| V4-36 | `b17d4f5` | 39458988769 |
| V4-37 | `b05ed0b` | 39466279083 |
| V4-38 | `fa074df`, then `322b2f4` | 39482219983, 39485600435 |
| V4-39 | `376ae3a` (`df2172e` adds only its decisions entry) | 39485765975 |
| V4-40 | `6b2635a` | 39507356666 |

**Superseded and control runs:**
- **39481080552,** V4-38's first head, was cancelled by CI's concurrency
  group when the second dispatch on the same branch went in. That is its
  design, not a failure.
- **39485860730,** V4-39's CI control on `v4-39-ctl`, was red on exactly the
  six Linux suite and Release jobs, as recorded in V4-39.

### The control nightly

- **How the control was built.** `20fa4ec` is `nightly-bringup`'s previous
  head `6649e49` with V4-36 and V4-37 cherry-picked; its parent's tree
  equals V4-37's `b05ed0b`. On top, v74 CK1's expectation was rotted ("…
  CONTROL -- a check no test prints (V4-36..37)"). spec_v74's sha256 before
  was `1eddf58883c83ac5`.
- **The result.** Run 39474217806 was red on exactly `mutations · v74`,
  58/59:
  - CK1 **SURVIVED(BAD)**, naming the rotted text;
  - `residue: none`, all sources restored;
  - across the 44 campaign jobs, 315 rows: 314 killed and 1 survived, the
    control;
  - all 12 fuzz jobs green.

  It was v74's first run on Linux.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-41 — F121's dead code removed, and the test counts gated (loop iteration 16: fixes and cleanup)

### F121: three functions nothing called

V4-40's coverage run found `conn_io_out_capacity`, `authd_conn_stage_name`
and `listener_accept` with zero calls.
- **Checked first:** nothing referenced any of them. No caller, campaign
  anchor, test, CLAIMS citation or wasm export.
- **Removed:** all three, with their declarations and comments.
  `listener_accept` was the one that mattered: a single-uid wrapper whose
  `(uid_t)-1` sentinel became an empty allowlist, which
  `listener_accept_ex` reads as "no check". That is F92's shape, now gone
  instead of merely unreachable.

### The test counts, gated

**Why.** The stated test counts drifted in F107, F116 and F120, each found
by a hand sweep. V4-39 drifted them again: it restated README.md and
REPRODUCE.md, but the review page kept 55 where the README said 56. A count
that depends on the configuration cannot be read statically, so it is
checked in the tree it describes.

**`doc_test_counts`, a CTest in every native tree.** CMake passes the
tree's configuration as six 0/1 flags (node, python3, nm and file, a wasm
tree, a browser, a fuzz tree), each the same condition the optional tests
are registered under. The script then checks:
- **The count.** It parses the README's sentence (native N, without node M,
  with a wasm tree W, with a browser B, and the "one fewer" rules for
  python3 and for nm/file). It computes this configuration's number and
  needs `ctest -N` to equal it.
  - A fuzz tree registers its 36 fuzz-labelled libFuzzer tests in place of
    the skipped `fuzz_libfuzzer` placeholder every other tree has, so the
    README's number is the unlabelled tests plus that placeholder. The
    label's own count must equal REPRODUCE.md's "out of 36".
- **The other documents.** REPRODUCE.md's N/W/B, its sanitizer-tree pair and
  its gcc 16 count, and the review page's browser-client count, must all
  equal the README's.
- **The table.** Every registered test needs a row in the README's table of
  tests, by name or by a `prefix_*` group row. The first run found three
  missing (`test_envelope_spec`, `client_links_no_sqlite_control`,
  `liboqs_minimal`), F116's other half. In the fuzz tree it found the 36
  labelled libFuzzer tests (`fuzz_seed_*`, `fuzz_seedgen_*`,
  `fuzz_libfuzzer_smoke_*`) described nowhere. All have rows now: one each
  for the three, and one group row for the 36.
- **The sentences.** Every sentence must be found, so rewording one fails
  rather than retiring a check.

**Its first run, before any document was touched,** failed on two things:
- the review page's 55 (**F124**, the real drift);
- the new test's own uncounted registration (57 against 56).

**The counts now:** native 53 (51 without node), 55 with a wasm tree, 57
with a browser.

### The controls

Each stated number rotted once and restored byte-exactly (`cmp`); each
failed by name:

| Rot | Failed check |
|---|---|
| README native 53 → 52 | REPRODUCE.md's three statements no longer equal the README's |
| README browser 57 → 58 | "this tree registers 57 tests; the README's count with a browser is 58", plus the three repetitions |
| README's "`node`" unquoted | "README's count sentence was not found whole" |
| REPRODUCE.md wasm 55 → 54 | "REPRODUCE.md states '53', '54', '57' where README states 53, 55, 57" |
| REPRODUCE.md sanitizer 57 → 56 | the sanitizer-tree pair |
| REPRODUCE.md gcc 16 53 → 52 | the gcc 16 count |
| review page 57 → 56 | "the review packet states '56' … where README states 57" |

**The configuration rule, run against `build-p` (57 registered).** Claiming
each tool absent moved the expected count by exactly the README's amount,
and failed:

| Claimed absent | Expected |
|---|---|
| python3 | 56 |
| nm and file | 56 |
| the browser | 55 |
| the wasm tree | 53 |
| node | 51 |

**The table check, by dropping rows** (each restored byte-exactly):

| Row dropped | Tree | Failed check |
|---|---|---|
| `liboqs_minimal` | `build-p` | "registered tests with no row in the README's table: liboqs_minimal" |
| the `fuzz_replay_*` group | `build-p` | the same check, naming all twelve `fuzz_replay_*` tests |
| the fuzz-tree group | `build-fuzz-p` | the same check, naming the 36 |

### Verification

- **Every tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-wasm-p` | `2c39f8ab7908049c` | 3/3 |
  | `build-p` | `1cdd7a4f02b16224` | 57/57 |
  | `build-bench-p` | `606671199b94b388` | 53/53 |
  | ASan | `9b92d914336932e4` | 57/57, instrumentation in all 43 |
  | UBSan | `1d54c40c332615db` | 57/57; one runtime error, the planted canary |
  | fuzz | `a8ff66a07508e0cf` | 36/36 |

- **`doc_test_counts`, run again in all six native trees** after the last
  document edit: 8 passing checks in each, 9 in the fuzz tree (its label
  count), none failing.
- **Coverage, re-measured** (`build-cov-p`, `00a48025fdefbcfc`, 57/57).
  `apps/authd/` now has 429 functions, three fewer, with the same 421
  covered (98.14%). Functions under 80% went from 76 to 73.
- **Gates:**
  - anchors (354 checked; 16 counts agreeing);
  - the claim map, including the register's size (124, F0–F124);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-42 — key-file custody, driven to its refusals (loop iteration 17: coverage; F122 item 1)

### The gap

Spec §12 keeps a key file to its owner. `keyfile_open` refuses one that is
not this euid's, or that has any group or other bit set, and
`keyfile_promote` (rotation's rename into place) refuses the same. V4-40's
coverage run found neither refusal had ever run: `keyfile_open`'s condition
was evaluated 174 times and refused 0. Deleting either half passed every
check. The demo apps' loader had such tests (`test_net` T14); the daemon's
and the client's key files had none.

### The tests

- **`test_authd_keyfile`, the mode half:**
  - The sealed key file is set to each group and other bit on its own
    (0640, 0620, 0610, 0604, 0602, 0601). Every open must return
    `KEYFILE_ERR_PERMISSIONS` and no key, so a check that kept only some of
    the bits fails.
  - Canary: 0600 and 0400 still open.
  - `keyfile_promote` with a 0640 candidate must refuse and leave both
    files as they were. A 0600 candidate must then rename over the current
    file (the canary).
- **`authd_e2e`, the owner half.** A file another user owns, mode 0600, is
  unreadable to the client, so it would fail with `io` before the owner
  check ever ran. Only root can read it, so the e2e's privileged leg
  (Linux, with root or passwordless sudo, as CI's and the nightly's jobs
  have) has root run the shipped client against a copy of the device key
  chowned to `nobody`. The leg needs:
  - `unsafe-permissions`;
  - the canary: root's own 0600 copy is not refused for that reason.

  On macOS the leg is skipped, as the second-user leg before it is.

### The controls: campaign v75 (KC1–KC5)

| ID | Mutation | Local (macOS, ASan) |
|---|---|---|
| KC1 | `keyfile_open` ignores the mode | KILLED(1 named) |
| KC2 | ignores the group bits only (`077` → `007`) | KILLED(1 named) |
| KC3 | ignores the other bits only (`077` → `070`) | KILLED(1 named) |
| KC4 | `keyfile_promote` ignores the mode | KILLED(2 named) |
| KC5 | `keyfile_open` ignores the owner | SURVIVED, as predicted: the owner leg does not run here |

KC5 is killed only where the privileged leg runs: CI's Linux jobs and the
nightly, like v58's GA13 and GA14. The first version of the mutate script
built its texts with `str.replace`. The anchors gate, which reads the
scripts statically, could not see them ("NO ANCHOR EXTRACTED"), so they are
literals, as v73's lesson said. `keyfile_promote`'s owner half has no test:
a rotation's candidate is always the client's own file.

### The counts

320 mutations in 45 campaigns, 359 anchors. All 16 stated counts were
restated; the counts gate failed on each until they were. v75 is in
nightly.yml's matrix.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `9ad8f7b5a5a66b10` | 57/57 |
  | `build-bench-p` | `978252cbe1c4ec2e` | 53/53 |
  | ASan | `3b54d98baeb50512` | 57/57, instrumentation in all 43 |
  | UBSan | `36ed159328b042c8` | 57/57; one runtime error, the planted canary |
  | fuzz | `6f9b9bf1bb9b36ff` | 36/36, and `test_authd_keyfile`, `backend_symbols` and `doc_test_counts` 3/3 |

  The four custody checks pass. The e2e's privileged leg printed its SKIP
  line here (macOS).
- **The owner leg's first CI run failed** (39526288606, on `67a3132`): all
  four Linux suite jobs and both Release jobs failed it, with the macOS jobs
  green, where it is skipped. Root's client never reached the key. It
  refused the passphrase file first, because the runner user owned it:
  "passphrase file …: not-owned-by-this-user". The client holds its
  passphrase file to the same custody rule (`authd_secret.c`'s owner
  check), so the failure was the leg's own bug, though it did show that
  check refusing on Linux. Root now gets its own 0600 copy of the
  passphrase file for both runs.
- **Gates:**
  - anchors (359; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-43 — the CLI client's WebSocket frame reader, driven to its refusals (loop iteration 18: coverage; F122 item 2)

### The gap

`ws_client_read_message` parses every frame a server sends the CLI. V4-40's
coverage run found none of its refusals had ever run, among them the one
check between a hostile server and a write past the caller's buffer:
`ws.c:544`, `len > cap`. The daemon's side of the same framing is fuzzed
(`fuzz_ws`); this side was reached only by well-formed frames from the
daemon itself.

### The tests

`test_authd_ws` gains `test_client_reader`, 16 checks. A byte-array reader
feeds frames built to the RFC's layout.
- **Canaries:**
  - a 7-bit, a 16-bit and a 64-bit length frame (70,000 bytes), each
    delivered whole;
  - a frame exactly the buffer's size.
- **The buffer's bound.** A frame one byte longer than a 16-byte buffer is
  refused, and the guard bytes after the buffer are untouched.
- **RFC 6455 §5 refusals:**
  - each RSV bit on its own;
  - a masked server frame;
  - text, continuation and unfinished (no FIN) frames;
  - a control frame over 125 bytes.
- **Control frames and end of stream:**
  - a ping and a pong are skipped, and the binary frame after them is the
    one delivered;
  - Close reports CLOSED;
  - a stream that ends at a boundary is CLOSED, inside a header or a
    payload IO.
- **The top bit of a 64-bit length.** It is checked on a Close as well as
  on a binary frame. On a binary frame the buffer's bound refuses such a
  length anyway, and on a ping the control bound does. So only on a Close
  does the top-bit rule alone decide, between PROTOCOL and CLOSED. Written
  on a binary frame alone, the check would not have pinned the rule.

### The controls: campaign v76 (WC1–WC9), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| WC1 | RSV bits ignored | KILLED(2 named) |
| WC2 | masked server frames accepted | KILLED(2 named) |
| WC3 | the 64-bit length's top bit allowed | KILLED(2 named) |
| WC4 | a control frame's length unbounded: a 126-byte ping read into the 125-byte drain | KILLED(0 named + ASAN), expected as `ASAN in ws_client_read_message` |
| WC5 | any data opcode accepted | KILLED(3 named) |
| WC6 | fragments accepted | KILLED(2 named) |
| WC7 | no bound against the buffer | KILLED(3 named), re-authored (below) |
| WC8 | a ping returned as an empty message | KILLED(2 named) |
| WC9 | a clean EOF reported as IO | KILLED(2 named) |

**WC7, first written as `if (0)`,** was refused by the compiler: "unused
parameter 'cap' [-Werror,-Wunused-parameter]", since that comparison was
`cap`'s only use. The runner scored it `KILLED(compile)-NOT-ALLOWED(BAD)`.
F79's rule is to re-author, not allowlist: `if (len > cap && 0)` keeps the
use, and it is killed by three named checks.

### The counts

329 mutations in 46 campaigns, 368 anchors; all 16 stated counts restated.
v76 is in nightly.yml's matrix.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `2060d47d6e17ff96` | 57/57 |
  | `build-bench-p` | `e29413bf4ef36ec2` | 53/53 |
  | ASan | `245118ef23ef6d34` | 57/57, instrumentation in all 43 |
  | UBSan | `7f1becb08d49e658` | 57/57; one runtime error, the planted canary |
  | fuzz | `982982e65f843a73` | 36/36, and `test_authd_ws`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_ws` has 145 checks, up from 129.
- **Gates:**
  - anchors (368; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-44 — the gates' inventory counts gated, and coverage re-measured (loop iteration 19: fixes and cleanup)

### The inventory counts

Two gates pin a list of sites, and four sentences say how many:
- CLAIMS: "at 25 sites" (constant-time comparisons) and "35 of them"
  (secure-memory allocations);
- the review page: 35;
- the README: 35.

All four were right, but nothing compared them: F17's row still said "the 24
sites" from V4-15b, before V4-20 added F48's owner comparison. That is the
class of F106, F110, F116, F120 and F124 again.

**The change.** `check_claim_map.py` counts the entries of
`tests/constant_time_sites.txt` (25) and `tests/secure_mem_sites.txt` (35).
It needs each sentence found and its number equal to its list's. F17's row
now gives the current count beside its dated one. The audit table's 4.3
row already recorded 24 becoming 25 in V4-20.

**The controls**, each restored byte-exactly, each failing "the stated
inventory counts" by name:

| Rot | Printed |
|---|---|
| CLAIMS 25 → 24 | "docs/review/CLAIMS.md says 24 constant-time sites; the list holds 25" |
| CLAIMS 35 → 34 | "… says 34 secure-memory sites; the list holds 35" |
| review page 35 → 36 | "docs/review/README.md says 36 …" |
| README's backticks removed | "README.md: no sentence matching …" |
| one line added to `constant_time_sites.txt` | "docs/review/CLAIMS.md says 25 constant-time sites; the list holds 26" |

### Coverage, re-measured

The same tree and command as V4-40, after V4-41..43 (`docs/v4/coverage.md`,
"Re-measured in V4-44"):
- **`apps/authd/`:** 81.64% of lines (from 81.30), 88.11% of regions (from
  87.51), 69.62% of branches (from 69.05), 98.14% of functions (from
  97.45).
- **`ws_client_read_message`:** 75 of 78 code regions, from 49. The three
  left are its null-argument guard and two I/O failures.
- **Functions under 80%:** 72, from 76.

### Verification

- **The changed script** (`check_claim_map.py`) was run green and under the
  five controls above; it runs in CI's spec job.
- **No source or test changed,** so no tree or campaign is affected. The
  coverage tree was rebuilt and proven current (`0ef7effc6e611498`), 57/57.
- **Gates:** anchors (368; 16 counts agreeing), the claim map, the spec
  checks, the audit table's separators, `git diff --check`.

## V4-41 to V4-44 — CI on the branches and the nightly bring-up

**One bring-up for four steps.** V4-42 adds campaign v75 and V4-43 adds v76.
So the control nightly ran on V4-41..42's code and rotted one v75
expectation. The final nightly runs every campaign against the final tree,
with v76 there for the first time on Linux.

### CI on the branches (14 jobs each, all green)

| Step | Head | Run |
|---|---|---|
| V4-41 | `bf60282` | 39515393093 (`doc_test_counts` passed in all nine suite jobs, 53 tests each) |
| V4-42 | `793e7aa` | 39527621667 |
| V4-43 | `7ce79e7` | 39544987452 |
| V4-44 | `283df66` | 39547042130 |

V4-42's first run (39526288606, `67a3132`) failed in its own new leg. That
failure is recorded in V4-42's entry.

### The control nightly

- **How the control was built.** `719ff95` is `nightly-bringup`'s previous
  head `75a3c82` with V4-41 and V4-42 cherry-picked; its parent's tree
  equals V4-42's `793e7aa`. On top, v75 KC1's expectation was rotted ("…
  CONTROL -- a check no test prints (V4-41..42)"). spec_v75's sha256
  before was `af3f4f6ecdb376d1`.
- **The result.** Run 39531728085 was red on exactly `mutations · v75`,
  59/60:
  - KC1 **SURVIVED(BAD)**, naming the rotted text;
  - KC2–KC4 killed by name;
  - **KC5 KILLED(1 named) on Linux.** This is the owner check removed,
    which survives on macOS. It shows `authd_e2e`'s privileged leg runs on
    the nightly's runners and catches it. CI's own logs cannot show that,
    because ctest prints a passing test's output only on failure;
  - every mutant restored clean;
  - across the 45 campaign jobs, 320 rows: 319 killed and 1 survived, the
    control;
  - all 12 fuzz jobs green.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-45 — a damaged store is refused at open (loop iteration 20: coverage; F122 item 4)

### The gap

`store_open` reads three values from `meta`:
- `schema_version`: a wrong length or a later schema is `STORE_ERR_SCHEMA`;
- `store_id` and `decoy_pk`: a wrong length is `STORE_ERR_CORRUPT`.

V4-40's coverage run found none of those refusals had ever run. Deleting any
of them passed every check. The last is the key the decoy ServerHello
carries for an unknown identity (D6).

### The tests

`test_authd_store` damages one `meta` value at a time in a fresh store with
raw SQL. Each open must be refused with its own status and return no
handle:

| Damage | Status |
|---|---|
| `schema_version` of 7 zero bytes | SCHEMA |
| `schema_version` 2 (a later schema) | SCHEMA |
| `store_id` one byte short | CORRUPT |
| `store_id` one byte long | DB: it overruns the read buffer and is refused one layer down, in `copy_blob_col` |
| `decoy_pk` one byte short | CORRUPT |

Every value is put back byte-exactly after each case, so each case damages
one thing. Two checks bracket them:
- the three values must have their expected lengths before any damage;
- the repaired store must open again (the canary).

### A one-line hardening the test needed

The first short-version case wrote `00…01` in 7 bytes. Without the length
check those 7 bytes are read together with the 8th byte of an uninitialised
stack buffer. That yields a version of at least 256, refused as SCHEMA
anyway. So the case could not have pinned the length check, and in the
mutant world it read stack memory. `store_open`'s `vbuf` is now
zero-initialised. The case writes seven zero bytes, which only the length
check can refuse: without it they read as version 0, which opens.

### The controls: campaign v77 (SD1–SD5), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| SD1 | a `schema_version` of any length is read | KILLED(2 named) |
| SD2 | a later schema opens | KILLED(2 named) |
| SD3 | off by one: the next schema version opens | KILLED(2 named) |
| SD4 | a `store_id` of any length is accepted | KILLED(2 named) |
| SD5 | a `decoy_pk` of any length is accepted | KILLED(2 named) |

`residue: none`, all sources restored.

### The counts

334 mutations in 47 campaigns, 373 anchors; all 16 stated counts restated.
v77 is in nightly.yml's matrix. CLAIMS D6 cites SD5 and its check.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `367eeb2c7c7ed48d` | 57/57 |
  | `build-bench-p` | `b8662d15109ee535` | 53/53 |
  | ASan | `b7574f79a6b57511` | 57/57, instrumentation in all 43 |
  | UBSan | `f3b1e0213421353d` | 57/57; one runtime error, the planted canary |
  | fuzz | `a7ef8691e61960ff` | 36/36, and `test_authd_store`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_store` has 283 checks.
- **The `store.c` change** (zeroing `vbuf`) moved no campaign anchor: 373 of
  373 match.
- **Gates:**
  - anchors (16 counts agreeing);
  - the claim map (the inventory counts included);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-46 — the daemon's record path: drop-tokens rotation and BYE length (loop iteration 21: coverage; F122 item 5)

### The gap, described correctly

V4-40's triage listed three uncovered branches on the record path in
`authd_conn.c`. The third it described wrongly, as "the closing of the old
key's other live sessions after a rotation". The branch (`dropped > 0`,
line 534) is the journal line for a ROTATE carrying the drop-tokens flag:
`store_rotate_key` deletes the device's tokens in the rotation's
transaction, and the daemon logs how many went. No test rotated a device
that held tokens, so a daemon that ignored the flag passed everything. F122's
row now says so.

### Two branches tested, one shown unreachable

- **The drop-tokens rotation.** `test_authd_conn`'s new
  `test_rotate_drop_tokens` enrolls two devices of one user. It gives the
  first two tokens and the second one.
  - A rotation without the flag keeps all three (the canary).
  - A rotation with it is acknowledged and drops the first device's two
    tokens and only those. The journal reads `event=rotate-tokens-dropped
    count=2`.
- **A BYE of the wrong length.** `test_bye_length` sends a BYE with a byte
  after its opcode on an authenticated session. It is refused as MALFORMED,
  not taken as a goodbye.
- **The oversized record cannot be reached.** `on_record` refuses `len >
  AUTHD_MAX_RECORD`, but `AUTHD_FRAME_MAX` is the larger of the record cap
  and the largest ServerHello, and the record cap is the larger: both are
  12,313 bytes. The frame layer refuses any longer frame before
  `on_record`. The check stays as a guard for a future where the caps
  differ, and the register says it is unreachable rather than claiming a
  test.

`test_authd_conn` has 207 checks.

### The controls: campaign v78 (RP1–RP5), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| RP1 | the daemon ignores the drop-tokens flag | KILLED(3 named) |
| RP2 | the journal line is not written | KILLED(2 named) |
| RP3 | the journal's count is off by one | KILLED(2 named) |
| RP4 | the store drops every token, not only the device's | KILLED(3 named) |
| RP5 | a BYE of any length is a goodbye | KILLED(2 named) |

`residue: none`, all sources restored.

### The counts and the map

339 mutations in 48 campaigns, 378 anchors; all 16 stated counts restated.
v78 is in nightly.yml's matrix. CLAIMS D9 cites RP1 and RP4, and P6 cites
RP5, each with its check. F122's item (5) is closed. Only item (3) is left,
`REVOKE-TOKENS handle=`, which waits on the owner's decision on F123.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `c2b6744b2be99cde` | 57/57 |
  | `build-bench-p` | `8b7b55000b6925e9` | 53/53 |
  | ASan | `885fc14002762f02` | 57/57, instrumentation in all 43 |
  | UBSan | `23af7d0959cd35da` | 57/57; one runtime error, the planted canary |
  | fuzz | `556bc63cd721a808` | 36/36, and `test_authd_conn`, `backend_symbols` and `doc_test_counts` 3/3 |
- **Gates:**
  - anchors (378; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-47 — T12's false failures, made inconclusive and retried (loop iteration 22: fixes and cleanup; F125)

### The failure

V4-45's CI (39557319345) failed one job, `macos-26·clang·ubsan`, in
`test_net`'s T12: "EINTR retries: client 0, server 0; 1 alarms in the
client". V4-45 did not touch `test_net` or the network code, and re-running
the job passed. It was the third sighting of the same shape on GitHub's
macOS runners:
- **V3-3:** a timer-driven storm, replaced by a dedicated signalling process.
- **V3-5:** the scenario starts only once the first alarm lands.
- **V4-45:** the signalling process was still not scheduled while the
  scenario ran.

T12 needs net_io's EINTR retries to have run under a signal storm, so a
storm that does not land during the scenario fails a correct implementation.
That is a false failure, never a false pass. It is recorded as **F125**
(Info); the register had never carried it.

### The fix

An attempt in which no EINTR retry happened is **inconclusive**: the retry
path never ran, so it says nothing either way. It is run again, up to five
attempts. The rules:
- a side failing under the storm fails the check at once;
- five inconclusive attempts fail it too, so the check still needs evidence;
- the check's name, which campaign v33 expects, is unchanged, and now ends
  with "attempt N of 5".

### The controls

| Control | What was changed | Result |
|---|---|---|
| C1, recovery | the first attempt runs without the storm | PASS on "attempt 2 of 5" |
| C2, the bound | the conclusive condition can never hold | FAIL on "attempt 5 of 5" |
| v33 S1 | the retry counter stops counting | KILLED(1 named): all five attempts inconclusive, "attempt 5 of 5" with 512 alarms delivered |
| v33 S2b | EINTR is no longer retried | KILLED(1 named): a side fails at once, "attempt 1 of 5" |

C1 and C2 are hand controls, restored byte-exactly; S1 and S2b ran as
campaign v33, locally on the ASan tree, with `residue: none`.

Locally the storm is strong (about 400 alarms, conclusive on the first
attempt), so the retry matters on loaded runners only. That is where it was
needed.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `04ceb46593834fba` | 57/57 |
  | `build-bench-p` | `730c02008bffe29f` | 53/53 |
  | ASan | `7d523d72862d0b50` | 57/57, instrumentation in all 43 |
  | UBSan | `5233949a733b7677` | 57/57; one runtime error, the planted canary |
  | fuzz | `e24e380c178fa2ca` | 36/36, and `test_net`, `backend_symbols` and `doc_test_counts` 3/3 |
- **Gates:**
  - anchors (378; 16 counts agreeing);
  - the claim map, including the register's size (125, F0–F125);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-48 — the passphrase file's custody, driven to its refusals (loop iteration 23: coverage)

### The gap

`authd_secret_read` is how the daemon and both CLIs read a passphrase file.
V4-44's re-measurement put `authd_secret.c` at 56.6% of lines, and only its
mode refusal had ever run. Never run:
- the symlink refusal (`O_NOFOLLOW`);
- the file-type refusal;
- the owner refusal;
- the size limits;
- the rule that an empty passphrase, after its one trailing newline is
  stripped, is refused.

The owner refusal was seen once, by accident, when V4-42's leg first ran in
CI.

### The tests

- **`test_authd_cli`'s `test_passphrase_custody`:** each case needs its own
  status and no buffer back.

  | Case | Status |
  |---|---|
  | a symlink to a good file | cannot-open |
  | a missing file | cannot-open |
  | a directory | not-a-regular-file |
  | each group and other bit on its own | unsafe-permissions |
  | an empty file | empty-or-too-large |
  | a file holding only a newline | empty-or-too-large |
  | one byte over `AUTHD_PASSPHRASE_MAX` | empty-or-too-large |

  The canaries:
  - the good file reads back without its one trailing newline;
  - a file of exactly the limit reads whole;
  - only one trailing newline is stripped, so `pw\n\n` reads as `pw\n`.
- **`authd_e2e`, the owner half.** In the privileged Linux leg, root's client
  is given a 0600 copy of the passphrase file that `nobody` owns. It must
  refuse it as not-owned-by-this-user before opening any key. Root's own
  copy, used by the leg before it, is the canary.

  The leg uses a copy, not the runner's own file. As root in a container,
  root owns that file, and nothing would be foreign.

### The controls: campaign v79 (PF1–PF7), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| PF1 | a symlink is followed | KILLED(1 named) |
| PF2 | any file type is read: a directory fails later, as short-read | KILLED(1 named) |
| PF3 | group and other bits ignored | KILLED(10 named) |
| PF4 | off by one: one byte over the limit is read | KILLED(1 named) |
| PF5 | every trailing newline stripped | KILLED(1 named) |
| PF6 | the owner ignored | SURVIVED, as predicted: the owner leg does not run on macOS |
| PF7 | a file holding only a newline gives an empty passphrase | KILLED(1 named) |

**PF4 is an off-by-one, not "an empty file accepted".** A zero-length
passphrase is refused again after the read, so dropping only the empty-file
check would leave a second check standing. Moving the upper bound has no
such backstop.

### The counts

346 mutations in 49 campaigns, 385 anchors; all 16 stated counts restated.
v79 is in nightly.yml's matrix. CLAIMS D10 cites PF1, PF3 and PF6 with
their checks, and its custody bullet covers the passphrase file.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `07a2e7d6ae0bce4c` | 57/57 |
  | `build-bench-p` | `466268021d41f845` | 53/53 |
  | ASan | `dd3764245fb47625` | 57/57, instrumentation in all 43 |
  | UBSan | `e71dc7f42881a5af` | 57/57; one runtime error, the planted canary |
  | fuzz | `3e7776254a79f056` | 36/36, and `test_authd_cli`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_cli` has 169 checks, 12 of them new.
- **Gates:**
  - anchors (385; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-49 — the listener's socket paths and allowlist bound (loop iteration 24: coverage)

### The gap

`listener.c` read 64% of lines in V4-44's re-measurement. Most of what was
uncovered is the failure of a system call, and lines 71 and 72 are a
measurement artifact: `htons` and `htonl` expand to byte-swap macros whose
constant branch never runs, attributed to the source line. Three checks
that matter had never run, or were named by no test:
- **`listener_open_unix`'s refusal of a path too long for `sun_path`.** A
  truncated `sun_path` would bind some OTHER path.
- **The refusal of anything at the path that is not a socket,** which leaves
  it in place. It ran, but no test named it.
- **`listener_accept_ex`'s bound on the allowlist,** `LISTENER_MAX_ALLOW`.

### The tests

`test_authd_ws`'s new `test_listener_paths`, 9 checks, sized from the
platform's own `sun_path` (104 bytes on macOS, 108 on Linux):

| Case | Expected |
|---|---|
| a path of the capacity less one | opens (the canary) |
| one byte over | refused, and no socket at the path or at its truncation |
| a regular file at the path | refused, its contents unchanged |
| a symlink at the path to a live socket | refused, the link still a link, its target still a socket |
| a stale socket left by a closed listener | replaced (the canary) |
| an allowlist of `LISTENER_MAX_ALLOW + 1` | `LISTENER_ERR_ARG` |
| an allowlist of exactly `LISTENER_MAX_ALLOW` | accepted (the canary) |

### The controls: campaign v80 (LP1–LP5), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| LP1 | off by one: a path with no room for its NUL is accepted | KILLED(2 named) |
| LP2 | anything at the path is removed, not only a socket | KILLED(3 named) |
| LP3 | `stat`, not `lstat`: a planted symlink is followed, removed and bound over | KILLED(2 named) |
| LP4 | a stale socket is never removed | KILLED(3 named) |
| LP5 | an allowlist of any length is accepted | KILLED(2 named) |

LP3 is the realistic one: a one-word slip that turns "refuse what is not a
socket" into "follow the attacker's link, then unlink it".

### The counts

351 mutations in 50 campaigns, 390 anchors; all 16 stated counts restated.
v80 is in nightly.yml's matrix. CLAIMS D11 cites LP1, LP3 and LP5 with their
checks.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `8a020cbd559e9378` | 57/57 |
  | `build-bench-p` | `bf51f472192261da` | 53/53 |
  | ASan | `8a1690d68afecf34` | 57/57, instrumentation in all 43 |
  | UBSan | `f157de80154f94a8` | 57/57; one runtime error, the planted canary |
  | fuzz | `f1358d38239c5860` | 36/36, and `test_authd_ws`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_ws` has 154 checks.
- **CI's first run failed on gcc** (39605350547, on `92bd836`): the gcc debug,
  gcc Release and wasm jobs. The cause was
  "'/lp' directive output may be truncated … [-Werror=format-truncation=]":
  `snprintf(dir, 256, "%s/lp", g_dir)` with `g_dir` itself 256 bytes, F19's
  class. Clang raises no such warning, so no local tree saw it. The buffers
  are now sized past `g_dir`, as the file's other paths are.
  - **The check that would have caught it:** compiling the file with gcc
    16, using `build-p`'s own compile command, reproduces the exact error on
    the old file and is clean on the fixed one, at `-O0` and `-O2`. It runs
    before pushing any new test code from now on.
- **Gates:**
  - anchors (390; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-45 to V4-49 — CI on the branches and the nightly bring-up

**One bring-up for five steps.** V4-45, V4-46, V4-48 and V4-49 add
campaigns v77, v78, v79 and v80. The control nightly ran on V4-45..46's
code and rotted one v78 expectation. The final nightly runs every campaign
against the final tree, with v79 and v80 there for the first time on Linux.
That includes v79's PF6, the passphrase file's owner check, which only
Linux can kill.

### CI on the branches (14 jobs each, all green)

| Step | Head | Run |
|---|---|---|
| V4-45 | `557b277` | 39557319345 |
| V4-46 | `63e8dcd` | 39569010960 |
| V4-47 | `9a46975` | 39577671001 |
| V4-48 | `62321f3` | 39593280371 |
| V4-49 | `a381ffc` | 39608009883 (the first run, on `92bd836`, failed gcc's `-Wformat-truncation`; see V4-49) |

**V4-45's run was 13/14 at first.** `macos-26·clang·ubsan` failed
`test_net`'s T12 with one alarm and no EINTR retry: the flake V4-47 then
fixed (F125). Re-running only that job passed, 14/14. V4-45 had not touched
`test_net`.

### The control nightly

- **How the control was built.** `845f4db` is `nightly-bringup`'s previous
  head `3fb4ba3` with V4-45 and V4-46 cherry-picked; its parent's tree
  equals V4-46's `63e8dcd`. On top, v78 RP1's expectation was rotted ("…
  CONTROL -- a check no test prints (V4-45..46)"). spec_v78's sha256 before
  was `b71254f129397e50`.
- **The result.** Run 39570441920 was red on exactly `mutations · v78`,
  62/63:
  - RP1 **SURVIVED(BAD)**, naming the rotted text;
  - RP2–RP5 killed by name;
  - v77's first Linux run: SD1–SD5 all killed;
  - across the 47 campaign jobs, 339 rows: 338 killed and 1 survived, the
    control;
  - all 12 fuzz jobs green.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-50 — the fixtures' cleanup re-checked, leftovers removed, F5's state stated (loop iteration 25: fixes and cleanup)

### Has the fixture leak come back?

V4-31 fixed a leak: 411 fixture directories and 119 MB, because the
fixtures cleaned up only at a deadline they never reached. The system temp
directory still held 40 `authd-wasm-*` directories. Before calling it a
recurrence, I checked:
- **Their dates.** 38 are from 00:45–00:50 on Oct 20, hours before V4-31's
  fix landed. Two are from 15:52 and 16:09 on Oct 19, the phone-timing
  session's fixture.
- **A fresh run.** The six fixture-using tests (`wasm_interop`,
  `web_flows`, `browser_e2e`, `phone_timing_tool`, `site_node_handler`,
  `authd_e2e`) ran in `build-p` with the default temp directory: 6/6
  passed. The count was 40 before and 40 after, and the newest was still
  Oct 20 00:50.

So the fixtures clean up today, and the 40 were the old leak's leftovers.
- **Removed:** the 38 from before the fix. Each held a scratch store and two
  socket files, nothing else.
- **Kept:** the two from the phone-timing session. They are left for the
  owner, rather than widening a deletion after the fact.
- **Also removed:** one `authd-ws-*` scratch directory, from 22:50 on Oct
  20. That was campaign v76's WC4, whose ASan abort stopped the test before
  its cleanup. A unique name makes such a leftover harmless (F114's fix),
  but it is still clutter.

### F5's state, stated

F5's row and the review page said only that F5 "stays open until those
[F122's checks] are covered". Four of the five now are (V4-42, V4-43, V4-45,
V4-46), and two more files the figures pointed at have tests (V4-48 the
passphrase file, V4-49 the listener's paths). The row and the page now say
what keeps F5 open:
- F122 (3), `REVOKE-TOKENS handle=`, whose meaning waits on the owner's
  decision on F123;
- the unmeasured wasm build.

### Housekeeping

The local `main` branch was 52 commits behind `origin/main`, with none of
its own, and has been fast-forwarded. No TODO, FIXME or XXX marker exists
in `src/`, `apps/`, `tests/`, `tools/`, `web/` or the build files.

### Verification

- **No source or test changed,** so no tree or campaign is affected. The six
  fixture tests above ran green.
- **Gates:** anchors, the claim map, the spec checks, the audit table's
  separators, `git diff --check`.

## V4-51 — the daemon's start-up refusals, on the shipped binary (loop iteration 26: coverage; F126)

### The gap

The largest uncovered function in the daemon is `authd_main.c`'s `main`:
58 code regions out of 223. Most are system-call failures, but three are
the start-up refusals that keep the daemon from serving with a file it
cannot trust:
- a passphrase file `authd_secret_read` refuses;
- a server key `keyfile_open` refuses, the wrong passphrase included;
- a store `store_open` refuses.

`authd_e2e` exercised configuration errors through `--check-config` and an
occupied socket path, but none of these.

### The test

A new leg in `authd_e2e` damages one copy of the server's files at a time:
- a group-readable passphrase file;
- a group-readable server key;
- the wrong passphrase;
- a store file that is not a database.

Each time it starts the shipped daemon. The daemon must exit non-zero, name
the file and its status, and leave no socket behind. The same undamaged
copies must then start (the canary).

**The deadline.** The daemon runs in the background with a 20-second
deadline. A daemon that wrongly STARTS would otherwise run forever, and a
campaign would see a ctest timeout instead of a named check. The campaign
below shows this is not hypothetical.

**One wording.** The first run expected the passphrase refusal to read
`unsafe-permissions`, the key file's name for it. The passphrase reader
says `permissions (mode must be 0600)`, which led to F126.

### The controls: campaign v81 (SU1–SU3), local, macOS ASan

| ID | Mutation | Verdict, and what the daemon did |
|---|---|---|
| SU1 | a refused passphrase file is ignored | KILLED(1 named): it went on to the key and named the wrong thing |
| SU2 | a refused server key is ignored | KILLED(1 named): **it started without its key and was still running 20 s later** |
| SU3 | a store that cannot be opened is ignored | KILLED(1 named): **it started without its store and was still running 20 s later** |

So each refusal is the only barrier: nothing later in start-up notices a
missing key or store. The spec lines name the phrase both possible failures
share (the damage's description), because whether a mutant crashes or keeps
running depends on what the missing file breaks first.

### F126, for the owner

Three diagnostics disagree, each failing closed but explained differently:
- **Exit codes.** A refused passphrase file exits 3 (configuration error,
  spec §13), a refused server key 1 (operation failed).
- **Names.** The same custody refusal is `unsafe-permissions` from the key
  reader and `permissions (mode must be 0600)` from the passphrase reader.
- **A misleading name.** `STORE_ERR_CORRUPT` is named `audit-chain-corrupt`,
  and `store_open` also returns it for a damaged `store_id` or `decoy_pk`.

Status names reach the journal and operators' scripts, so changing them is
an interface decision. The tests match today's names and pin no exit code
beyond "not 0".

### The counts

354 mutations in 51 campaigns, 393 anchors; all 16 stated counts restated.
v81 is in nightly.yml's matrix. CLAIMS D10 cites SU1 and SU2 and the
check.

### Verification

- **The changed script** (`tests/authd_e2e.sh`) passed in `build-p`,
  `build-bench-p`, ASan and UBSan. In the last two the shipped daemon runs
  sanitized through every refusal.
- **No C source changed,** so the trees' fingerprints are V4-50's.
- **Gates:**
  - anchors (393; 16 counts agreeing);
  - the claim map, including the register's size (126, F0–F126);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-52 — the local-API client against a daemon that misbehaves (loop iteration 27: coverage)

### The gap

`localcli.c` read 67% of lines in V4-44's re-measurement. `localcli_call`,
the client `authd_admin` uses for every local-API command, had only ever
talked to a well-behaved daemon. Never run:
- the refusal of a reply larger than the caller's buffer;
- the refusal of a reply the daemon closes before it is complete;
- the timeout;
- the refusal of a request over spec 8's 8192-byte line cap;
- the connect failure.

### The tests

`test_authd_cli`'s new `test_localcli_robustness`, six checks, each against
a forked fake daemon that accepts once and plays a script. Its child leaves
through `child_exit`.

| Case | Expected |
|---|---|
| a one-line reply | OK (the canary) |
| 600 bytes, never complete, into a 64-byte buffer with 16 guard bytes after it | RESPONSE; the buffer is NUL-terminated inside itself; the guard bytes untouched |
| a list closed before its END | RESPONSE, a truncation, not a list |
| no reply, against a 300 ms timeout | TIMEOUT, in 250–1500 ms |
| a request over the line cap | TOO_LONG; the fake daemon sees no connection at all |
| a socket path with no daemon | cannot-connect |

### The controls: campaign v82 (LC1–LC5), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| LC1 | the line cap is not enforced: the request is sent, truncated | KILLED(1 named) |
| LC2 | off by one: `recv` may fill the byte kept for the NUL, which is then written one past the buffer | KILLED(1 named): the guard bytes |
| LC3 | a reply closed before it is complete is returned as OK | KILLED(1 named) |
| LC4 | a timeout reported as an I/O error | KILLED(1 named) |
| LC5 | every connect failure reported as a timeout | KILLED(1 named) |

**One check is defence in depth, and the campaign says so by leaving it
out.** `localcli_call` also stops explicitly when the reply reaches the
buffer's size. But `recv`'s length already leaves room for the NUL, so the
stop never decides anything. A hand control removed it: all 175 checks
still passed, and the file was restored byte-exactly. The campaign therefore
mutates the length (LC2) instead, where the real off-by-one would live.

### One thing the triage did not find

`keyfile.c`'s `publish` was listed uncovered at line 105. That region is
the I/O-failure arm of its `link()`. The no-clobber refusal on the same
line is covered by `test_authd_keyfile`'s existing-path check, so it is
not a gap.

### The counts

359 mutations in 52 campaigns, 398 anchors; all 16 stated counts restated.
v82 is in nightly.yml's matrix.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `eae2cbff93db8316` | 57/57 |
  | `build-bench-p` | `aedc9f11378c93d0` | 53/53 |
  | ASan | `a0c13396a93d0f78` | 57/57, instrumentation in all 43 |
  | UBSan | `608864e473f9d6a5` | 57/57; one runtime error, the planted canary |
  | fuzz | `09b53056ab413883` | 36/36, and `test_authd_cli`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_cli` has 175 checks.
- **The gcc 16 check** (V4-49's lesson): `test_authd_cli.c` compiles
  cleanly at `-O0` and `-O2`.
- **Gates:**
  - anchors (398; 16 counts agreeing);
  - the claim map;
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-53 — the mutations only Linux can kill, listed, so a local campaign can end clean (loop iteration 28: fixes and cleanup)

### The problem

Three mutations are killed only by `authd_e2e`'s privileged leg, which needs
Linux's `setpriv` and root or passwordless sudo:
- v65 RU1 (the peer check against a real second user);
- v75 KC5 (the key file's owner);
- v79 PF6 (the passphrase file's owner).

CI's and the nightly's Linux jobs run that leg. Off Linux each of the three
scored `SURVIVED(BAD)`, so its campaign exited 1 on every local run. V4-42
and V4-48 explained the red survivor by hand, as predicted. A red result
that is always expected teaches the reader to ignore red.

### The change

- **`tools/mutations/linux_only_kills.txt`:** `campaign ID reason`, one line
  for each of the three, with the reason only Linux can tell.
- **`tools/run_mutations_v2.sh`:** off Linux, a listed mutation that survives
  is scored `SURVIVED(EXPECTED off Linux: linux_only_kills.txt; the nightly
  must kill it)`, and the campaign's exit stays 0. On Linux the list is
  never consulted, so a listed survivor there is still `SURVIVED(BAD)`. A
  listed mutation that is killed is scored `KILLED` everywhere.
- **`tools/audit/check_mutation_anchors.py`:** both lists the runner reads
  beside the campaigns are checked: this one and `compile_kills_allowed.txt`
  (F79). Each entry must have a reason and must name a mutation of that
  campaign's spec. A stale exception is otherwise one nothing would notice.
- **`tools/README.md`, `docs/review/REPRODUCE.md`:** what the list is. Neither
  states how many entries it has, since an ungated count drifts (F120); both
  point at the file.

### The controls (local, macOS ASan)

| Control | Expected | Seen |
|---|---|---|
| KC5 alone, listed | `SURVIVED(EXPECTED off Linux)`, exit 0 | as expected; restored clean, residue none |
| KC5 alone, its line removed | `SURVIVED(BAD: [a device key owned by another user])`, exit 1 | as expected; restored clean, residue none |
| a stale entry `v75 KC9` | the anchors gate refuses it | `ALLOWLIST linux_only_kills.txt:17: v75 KC9 is not a mutation of that campaign`, exit 1 |
| a compile-kill entry with no ID or reason | the anchors gate refuses it | `ALLOWLIST compile_kills_allowed.txt:12: needs 'campaign ID reason'`, exit 1 |

The list was restored from a copy after each control, and it was compared
byte for byte (`cmp`). The gate was green again afterwards: 398 anchors,
359 mutations, 52 campaigns.

**What a local run cannot show:** that the list changes nothing on Linux.
The platform guard comes before the list is read. The nightly is the
evidence: final nightly 39610024274 (V4-45..49) killed all three, v65 RU1,
v75 KC5 and v79 PF6, each `KILLED(1 named)`. This step's bring-up nightly
must do the same with the runner change in place.

### Verification

- Gates: anchors (398; 16 counts agreeing; both lists valid), the claim map,
  `doc_test_counts`, `git diff --check`, `bash -n` on the runner.
- No source, test or spec file changes, so no campaign's anchors move.

## V4-54 — the event loop against peers that pipeline or never read, and F127 (loop iteration 29: coverage)

### The gap

A coverage run on V4-53's tree put `slot_writable` at 13 of 32 regions, and
no test had ever filled a socket the daemon writes to. So a reply written in
parts had never been checked, and neither had a peer that reads nothing.

The loop is half-duplex. Once a served frame's reply is queued, it neither
polls for input nor consumes it until that reply has gone out, and `conn_io`
holds one reply at a time. That is what bounds a peer that sends and never
reads. Nothing had driven it.

The same run put `handshake_initiator_finish` at 34 of 54 regions. Every
missed region there is a local allocation failure or a defensive
re-validation, and no peer can reach any of them. So that function was not
this step's.

### What the tests found: F127 (Low)

Written against the loop as it was, the new tests failed in two ways:

- **Two frames in one write: only the first was served** (served 1, 9 of 18
  bytes back). Frames were served only after a read. When the first reply
  had gone out, the second frame was already in the buffer, but it waited
  for the peer to send something more. A peer that pipelines and then waits
  for both replies waits until its idle deadline.
- **Two back-to-back maximum-size frames: neither was served.** Every read
  took a whole 4096-byte chunk. Pushed into a buffer with less room than
  that, it was refused as an overflow, and the connection was closed.

Every client in the repository is lock-step and never pipelines, and a peer
that does harms only itself. So F127 is Low with no security impact. F51
(V4-10a) was the same class of fault: a proxy that coalesces, or a peer
that writes ahead, is what real networks do.

### The fix

- **`serve_buffered`:** the frame-serving loop, moved out of `slot_readable`.
  It runs after a read, as before, and now also when a reply finishes going
  out (the POLLOUT dispatch), so whatever was pipelined behind the reply is
  served at once.
- **`conn_io_in_room`:** a read takes at most the input buffer's free space.
  Each pushed byte adds at most one byte to that buffer (a WebSocket's
  framing is consumed, never stored), so a bounded read cannot overflow in
  any mode.
- **No room at all** cannot happen while input is being polled: a full
  buffer holds a complete frame, which is served before input is polled
  again. If it ever does happen, it is refused exactly as an overflow was
  before.

### The tests (`test_authd_evloop`, 171 checks)

- **`test_pipelined`**, over loopback TCP:
  - two small frames in one write, then two maximum-size frames;
  - both must be served without the peer sending more, and both replies
    must come back byte for byte;
  - a probe in the harness proves the second small frame was already
    buffered when the first was served, so that check is not vacuous.
- **`test_backpressure`**, over a Unix socket. Loopback TCP autotunes: macOS
  gave a 4096-byte `SO_RCVBUF` 326,640 bytes and absorbed every reply. Unix
  socket buffers hold what they are set to.
  - The peer sends 64 frames of 10,000 bytes and reads nothing. It stops
    being served, stays unserved for 200 more turns, holds at most one
    unsent reply, and is still connected.
  - Then it reads. All 64 frames are served and the 640,256 bytes come back
    byte for byte. A reply was seen part-sent, so the resumed-write path
    ran.
  - A second peer stalls the same way. It is open one millisecond before its
    deadline and closed at it, with its reply still unsent.
- **The reply size is a measured choice.** On Linux (WSL 2, kernel 6.18) a
  4096-byte `SO_SNDBUF` becomes 8192, and a 6004-byte reply went out whole
  in 64 of 64 writes. So the part-sent check would have had nothing to see
  in CI. With 10,004-byte replies, every one of 64 needed more than one write
  on both systems. These figures come from a standalone probe of the same
  socket set-up: a poll-driven writer, and a reader taking 4096 bytes at a
  time.

**Shown against the old loop:** with only the three daemon files
(`evloop.c`, `conn_io.c`, `conn_io.h`) checked out at HEAD, the four
pipelining checks failed by name. The fixed files were then restored and
compared by hash. The backpressure checks pass on both versions, because
frames that large never leave two complete frames buffered. They pin the
half-duplex behaviour, and campaign v83 shows each one can fail.

### The controls: campaign v83 (BP1–BP6), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| BP1 | the half-duplex stop removed | KILLED (3 named) |
| BP2 | input polled while a reply waits | KILLED (4 named) |
| BP3 | a partial write counted as whole | KILLED (4 named) |
| BP4 | the deadline skipped while a reply is pending | KILLED (2 named) |
| BP5 | F127 undone: a pipelined frame waits for more input | KILLED (3 named) |
| BP6 | F127 undone: a read past the buffer's room | KILLED (3 named) |

Every source was restored clean, with no residue. That run used 6,000-byte
replies. After the change to 10,000, BP2–BP4, the mutants the backpressure
test kills, were run again. All three were KILLED again, with the same
counts (4, 4 and 2 named), restored clean, with no residue.

**`slot_writable` is still 13 of 32 regions after this step,** re-measured
on the final tree. A partial write is not a region of its own: these tests
drive it, and BP3's kill shows it, but the count does not move. The
uncovered regions are three:
- **the nothing-pending guard.** Unreachable from the loop: POLLOUT is
  requested only while a reply is pending.
- **EAGAIN after POLLOUT.** Unreachable in practice: `poll` reports a
  socket writable only when there is room, and the probe saw 0 of them on
  either system.
- **any other write error,** such as a peer that resets mid-reply.
  Reachable, and still untested. Whether the poll loop's POLLERR branch
  would close such a slot first differs by platform. So a mutation there
  could be a kill on one system and a survivor on the other, which is what
  the V4-50..53 control nightly found v82 LC1 to be. It is left for a step
  that can show both.

### The counts

365 mutations in 53 campaigns, 404 anchors; all 16 stated counts restated.
v83 is in nightly.yml's matrix, and tools/README.md's campaign list names
it. The register is 127 findings, F0–F127.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `3d009d6164c59b24` | 57/57 |
  | `build-bench-p` | `6519982c6a31111d` | 53/53 |
  | ASan | `5ee08ea4c35ab599` | 57/57, instrumentation in all 43 |
  | UBSan | `f8c048e8466005b8` | 57/57; one runtime error, the planted canary |
  | fuzz | `1ee6c3035f23a605` | 36/36, and `test_authd_evloop`, `backend_symbols` and `doc_test_counts` 3/3 |

  `test_authd_evloop` has 171 checks and runs in about 3 s.
- **Coverage re-measured on the final tree:** `apps/authd/` 82.41% of lines
  and 88.49% of regions (82.44% and 88.48% before; the files grew).
- **The gcc 16 check** (V4-49's lesson), as a full compile at `-O0` and `-O2`:
  `test_authd_evloop.c`, `evloop.c` and `conn_io.c` are clean.
  `-fsyntax-only` was tried first and is not enough: it skips the middle end,
  where `-Wformat-truncation` runs.
- **Gates:**
  - anchors (404; 16 counts agreeing; both allowlists valid);
  - the claim map (127 findings);
  - the spec checks (vocabularies and constants);
  - the audit table's separators;
  - `git diff --check`;
  - nightly.yml's matrix against the spec files (53 and 53).

## V4-55 — campaign v82's LC1 re-authored as a memory-safe mutant, and both sides of the line cap tested (loop iteration 30: F128)

### What the control nightly found

The V4-50..53 control nightly (39646314151) was red on v79, as intended:
PF6's rotted expectation scored `SURVIVED(BAD)` on Linux although
`linux_only_kills.txt` lists PF6. That is the evidence V4-53 asked for: on
Linux the list changes nothing.

It was also red on v82, which nobody intended. LC1 scored `SURVIVED(BAD)`.
The run's `mutations-v82` artifact holds `LC1.test`, which shows ASan
aborting the test:

```
ERROR: AddressSanitizer: stack-buffer-overflow ... in send
  #1 net_write_all apps/net_io.c:331
  #2 localcli_call apps/authd/localcli.c:121
  #3 test_localcli_robustness tests/test_authd_cli.c:840
```

LC1 removed `localcli_call`'s line-cap check outright. The test's request was
8197 bytes, and the client builds it in an 8194-byte buffer
(`AUTHD_LINE_MAX + 2`), so the mutant sent 8197 bytes out of 8194.

- **On macOS** the 8192-byte Unix socket short-wrote. ASan checks only the
  bytes actually sent, so it saw nothing. The call then timed out, and the
  named check failed: KILLED(1 named) in V4-52.
- **On Linux** the socket took everything. ASan aborted inside `send`, before
  the named check could print.

**F128 (Info).** The mutant was caught on both systems. What was wrong was
the campaign's claim that this check is what catches it.

### The change

- **LC1 is the cap applied one byte late**, `(size_t)rn > AUTHD_LINE_MAX + 1u`.
  A request one byte over the cap, 8193 bytes, fits the 8194-byte buffer with
  its NUL. So the mutant is memory-safe by construction, and the named check
  decides on every system.
- **The test's over-cap request is exactly one byte over:** "PING ", 8187
  bytes of arguments and the LF. A check states the length, so the request
  cannot drift away from the boundary unnoticed.
- **A new case sends exactly 8192 bytes,** which spec 8 allows. It must not be
  refused: the fake daemon must see the client connect.
- **New LC6,** the cap one byte early (`>=`), is killed by that at-cap case.
  Until now nothing tested the cap's other side.

`test_authd_cli` has 178 checks (175 before).

### Why the test had to change, not only the mutation

A hand control ran V4-54's `test_authd_cli.c` against the re-authored LC1. It
passed with 175 checks and exit 0: an 8197-byte request is refused by a cap
one byte late as well, so the old test could not see that mutant. Both files
were restored and their hashes checked; the new test then passed (178).

### The controls: campaign v82 (LC1–LC6), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| LC1 | the line cap one byte late (re-authored) | KILLED (1 named): the over-cap check; no ASan report in its log |
| LC2 | `recv` may fill the NUL's byte | KILLED (1 named) |
| LC3 | a truncated list accepted | KILLED (1 named) |
| LC4 | a timeout called an I/O error | KILLED (1 named) |
| LC5 | every connect failure a timeout | KILLED (1 named) |
| LC6 | the line cap one byte early (new) | KILLED (1 named): the at-cap check |

Every source was restored clean, with no residue. The Linux verdicts come from
this group's next nightly. LC1 must be a named kill there: the mutant now
sends only bytes inside its buffer.

### The counts

366 mutations in 53 campaigns, 405 anchors; all 16 stated counts restated.
tools/README.md's campaign list says LC1–LC6. The register is 128 findings,
F0–F128.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `927c34930d81b278` | 57/57 |
  | `build-bench-p` | `b86675a1ea28429f` | 53/53 |
  | ASan | `ca3a08cb23f93d6b` | 57/57, instrumentation in all 43 |
  | UBSan | `4a79053bf88e9ba6` | 57/57; one runtime error, the planted canary |
  | fuzz | `588001abf096f6c0` | 36/36, and `test_authd_cli`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`:
  `test_authd_cli.c` is clean.
- **Gates:**
  - anchors (405; 16 counts agreeing);
  - the claim map (128 findings);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-56 — a peer that vanishes with a reply unsent is closed at once, F129 (loop iteration 31: fixes and cleanup)

### How it was found

V4-54 left one reachable region of `slot_writable` untested: a write error,
such as a peer that disappears mid-reply. Before writing a test for it, a
probe asked what `poll` reports for a writer whose peer has gone, with data
still unsent.

On macOS, a Unix socket and a loopback TCP socket both report POLLHUP alone:
no POLLOUT, no POLLERR. The next write is EPIPE. The Linux half of the probe
did not run, because the msi laptop did not answer.

The loop wrote only on POLLOUT. It closed on POLLHUP only when nothing was
pending, so that a peer that half-closes still gets its reply. So a peer that
vanished with a reply unsent kept its slot, and `poll` returned at once on
every turn, until the slot's idle deadline.

A test against the real loop showed it: **200 turns in 0 ms** against a 10 ms
poll timeout, and the slot still held. **F129 (Low):** bounded by the
deadline, CPU only, other slots still served.

### Linux, from CI rather than the probe

A scratch branch, `v4-56-ctl` (run 39687407344), carried the new test with
only the fix reverted. It failed exactly this check, "200 turns in 0 ms", on
all three macOS jobs, and passed it on every Linux job. So Linux reports such
a socket with POLLOUT or POLLERR, and the old loop already closed it. The
deployment platform was never affected. The branch was deleted.

### The fix

A hang-up with a reply pending is a write attempt. A peer that has gone
answers EPIPE, and the slot closes. A peer that only half-closed can still be
written to, and gets its reply. The test ignores SIGPIPE, as `mldsa-authd`
does (`authd_main.c`).

### The tests (`test_backpressure`, now 180 checks in `test_authd_evloop`)

- **4. The vanished peer.** It stalls with a reply unsent and then closes. Its
  slot must be freed within 3 turns, not by the deadline.
- **5. The half-closing peer.** It sends one frame, shuts down its sending
  side, and must get the whole reply.

Hand controls on macOS, each file restored and compared by hash:
- **the old loop:** check 4 fails ("200 turns in 0 ms"), and 5 passes;
- **closing on every hang-up instead:** check 5 fails. That fix would also
  have ended the spin, so check 5 is what rules it out.

### No mutation, on purpose

The fix's mutation (BP7, the hang-up condition removed) would be killed on
macOS and survive on Linux. The nightly runs v83 on Linux, so it would be red
there for a reason that is not a defect: F128's lesson.

The guard is the test itself. It runs on CI's three macOS jobs on every push,
and the scratch branch showed them turning red when the fix is reverted.

### Cleanup (this iteration's other half)

- The scratch branch was deleted.
- Local `main` was fast-forwarded to `origin/main` (`fd44fe7`).
- The remote holds only `main`, `nightly-bringup` and the branches in flight.
- `~/.cache/mldsa-tmp` (466 MB) was left alone. It holds the libsodium builds
  the trees depend on, and the raw campaign logs behind these records.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `2fe5237f97c7821f` | 57/57 |
  | `build-bench-p` | `15876964bfff161d` | 53/53 |
  | ASan | `5b685961b7252895` | 57/57, instrumentation in all 43 |
  | UBSan | `aea70ae443ccab85` | 57/57; one runtime error, the planted canary |
  | fuzz | `fd9d6b67e6cb849f` | 36/36, and `test_authd_evloop`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`: `evloop.c` and
  `test_authd_evloop.c` are clean.
- **Gates:**
  - anchors (405; unchanged, since no campaign moved);
  - the claim map (129 findings);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-50 to V4-56 — CI on the branches and the nightly bring-up

**One bring-up for seven steps.** V4-51, V4-52, V4-54 and V4-55 add or
change campaigns: v81, v82, v83, and v82's LC1 and LC6. The two control
nightlies ran on V4-50..53 and then on V4-50..55, each with one v79
expectation rotted. The final nightly runs every campaign against the final
tree, V4-56 included.

### CI on the branches

| Step | Head | Run | Result |
|---|---|---|---|
| V4-50 | `88e0b44` | 39610818141 | 14/14 |
| V4-51 | `e9648b9` | 39619270709 | 14/14 |
| V4-52 | `8735ec5` | 39635433752 | 14/14 |
| V4-53 | `47748ce` | 39643818929 | 14/14 |
| V4-54 | `7786de9` | 39670776071 | 14/14 |
| V4-55 | `4b78a30` | 39686403056 | 14/14 |
| V4-56 | `9eb3d23` | 39697644974 | run concluded success; see below |

**V4-56's run concluded `success` with one job record that never closed.**
13 jobs reported success. The fourteenth, `Release + install + hardening
(Linux, clang)`, kept the status `in_progress` with no conclusion. Every one
of its 11 steps reported success, and its log ends normally: the suite
53/53, the install tree, hardening, and one optimized backend.
That is a GitHub record, not a failure. It is stated here rather than counted
as a pass.

### The first control nightly: two campaigns red, one of them not planned

- **How it was built.** `62472ad` is `b692854` with V4-50..53 cherry-picked
  (its parent's tree equals V4-53's `47748ce`), plus v79 PF6's expectation
  rotted. PF6 is in `linux_only_kills.txt`. spec_v79's sha256 before was
  `c6d7717df274f731`.
- **Run 39646314151** was red on two campaigns, 65/67:
  - **v79, as planned.** PF6 scored **SURVIVED(BAD)**, naming the rotted text,
    on Linux, although the list names it. So the list changes nothing on
    Linux, which is the evidence V4-53 asked for.
  - **v82, not planned.** LC1's mutant over-read the client's line buffer, and
    ASan aborted the test before the named check printed. That is F128,
    fixed in V4-55.
- Across 52 campaign jobs there were 359 rows: 357 killed, and these 2
  survived. v81's first Linux run killed SU1–SU3.

### The second control nightly: red on exactly v79

- **How it was built.** `7d44d51` is `62472ad` with V4-54 and V4-55
  cherry-picked: V4-55's tree (`4b78a30`), plus the same rot.
- **Run 39686433565** was red on exactly `mutations · v79`, 67/68:
  - **366 rows in 53 campaigns:** 365 killed and 1 survived, the control.
  - **v82 on Linux:** LC1–LC6 all killed by name. F128's fix holds there.
  - **v83's first Linux run:** BP1–BP6 all killed by name.
  - **The Linux-only kills:** v65 RU1, v75 KC5 and v79's other six mutants
    were killed.
  - **Fuzz:** all 12 jobs green.

**V4-56 joins this landing without a control of its own.** It adds no
campaign. Its test runs on CI's macOS jobs, which V4-56's scratch branch
showed turning red when the fix is reverted. v83, the campaign its change
touches, was re-run locally on its tree: BP1–BP6 all killed (3, 5, 5, 4, 3
and 5 named). The final nightly is the first on its tree.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-57 — a failed start no longer deletes socket paths it never created, F130 (the owner's go; defensive review)

### How it was found

After V4-56, the defensive review read the daemon's start-up failure path.
`listener_failed:` calls `listener_close(&fd, path)` for all three Unix
sockets, whichever listener actually failed. `listener_close` unlinked `path`
even when `fd` was -1.

Reproduced against the built daemon before anything was changed:

1. **A regular file at `admin_socket`'s path.** The daemon refused it,
   correctly (`admin socket ...: path`), and then deleted it. A configuration
   typo that named a real file would destroy that file; it could be the
   store.
2. **A second daemon on the same configuration while the first runs.** The
   second failed at its TCP bind (`loopback listener: bind`) and unlinked all
   three of the first daemon's sockets. The first stayed up and logged
   nothing, but `list-users` over its admin socket went from `OK count=0` to
   `cannot-connect`: the site, the proxy and the operator were all cut off
   until it was restarted.

The e2e leg written for the refused file planted it, checked that the other
sockets were cleaned up, and then removed it itself with `rm -f`. So it could
never see the daemon delete it first.

Only someone who can run the daemon with its configuration can trigger this,
so it is not remotely exploitable. But a debugging session or an overlapping
restart is enough. **Medium**, like F51's availability failure. Per the
loop's rules it waited for the owner, who said go.

### The fix

`listener_close` does nothing at all, path included, unless it holds a
listener (`*fd >= 0`). Nothing is lost by that: a listener that fails after
`bind()` already unlinks its own path inside `listener_open_unix`. And
`store_open` writes nothing to an existing store, so a second instance does
not disturb the first one's audit chain either.

### The tests

- **`authd_e2e`:**
  - The planted file at the admin path must survive, byte for byte.
  - New leg: a second daemon on the running daemon's own configuration must
    fail, leave its three sockets in place, and leave its admin socket
    answering.
  - On Linux the second bind fails the same way: the loopback listener sets
    `SO_REUSEADDR` only, never `SO_REUSEPORT`.
- **`test_authd_ws` (156 checks):** `listener_close` with nothing held leaves
  a file at the path alone. The canary: a held listener is closed and its
  socket unlinked.

**Shown against the old code:** with `listener.c` and `listener.h` checked
out from V4-56, the unit check failed by name. `authd_e2e` failed at "a
second daemon's failed start removed the running daemon's p.sock (F130)"; it
stops at its first failure, so the planted-file check, further on, did not
run. The fixed files were restored and checked by hash.

### The control: campaign v80 LP6, local, macOS ASan

LP6 undoes the fix: the early return never taken, so an unheld path is
unlinked again.

| ID | Mutation | Verdict |
|---|---|---|
| LP1–LP5 | V4-49's listener-path mutants | all KILLED (2, 4, 2, 3 and 2 named) |
| LP6 | the early return never taken: an unheld path unlinked | KILLED (1 named): "listener_close with no listener held leaves the file at the path alone (F130)" |

Every source was restored clean, with no residue. On Linux, `authd_e2e`'s
second-daemon leg also catches LP6; v80's spec names `test_authd_ws` only.

### The counts

367 mutations in 53 campaigns, 406 anchors; all 16 stated counts restated.
tools/README.md says v80 LP1–LP6. The register is 130 findings, F0–F130.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `0e9ca24f16440127` | 57/57 |
  | `build-bench-p` | `7e66c1eb191ca8a5` | 53/53 |
  | ASan | `579580adc52abc7e` | 57/57, instrumentation in all 43 |
  | UBSan | `79e1f06bd2826649` | 57/57; one runtime error, the planted canary |
  | fuzz | `6d73652afe730f62` | 36/36, and `test_authd_ws`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`: `listener.c` and
  `test_authd_ws.c` are clean. `test_authd_ws.c` now includes `<errno.h>`
  itself: the canary reads `errno`, and glibc does not promise it through the
  headers the file had.
- **Gates:**
  - anchors (406; 16 counts agreeing);
  - the claim map (130 findings);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`;
  - `sh -n` on `authd_e2e.sh`.

## V4-58 — the reference site's sessions: a new id at each change of privilege, and a bounded table (F131, F132; the owner's go)

### The findings

The defensive review of 2026-10-21 found two defects in
`examples/site-node/server.mjs`. The runbook offers it as the site to deploy.
Both were reproduced locally, and both waited for the owner, who said go.

- **F131 (Medium), session fixation.** A session kept its id across a login,
  a signup and a recovery. Behind TLS, the cookie had no `__Host-` prefix.
- **F132 (Medium), no bound on the session table.** Every cookieless request
  added an entry, and none was ever removed.

### The fix

- **A new id at a login, a signup and a recovery.** `rotate()` drops the old
  id with everything it held, and issues a new one.
- **`__Host-sid` under `--secure`.** Only that exact cookie name is accepted
  there. Plain `sid` is kept for tests over http, since the prefix needs
  `Secure`.
- **A bounded table:**
  - idle sessions expire (30 minutes by default);
  - a logout removes its session and clears the cookie;
  - sessions with nobody logged in are capped (10,000 by default), least
    recently used evicted first;
  - logged-in sessions are never evicted.
  - The table is kept in least-recently-used order, so expired entries are
    dropped from its front for free.
- **Spec and runbook.** Spec §14 states these obligations (erratum 49,
  revision v1.14), and the runbook's rules for writing your own site grow
  from four to six.

### The test: `site_sessions` (24 checks)

It runs against the real daemon and the real wasm client:

- a session id issued before a login, a signup or a recovery holds nothing
  afterwards;
- the cookie's name and attributes, with and without `--secure`;
- logout removes the session and clears the cookie;
- 1,000 cookieless requests leave the table at its cap, with a logged-in
  session still valid;
- an idle session expires.

It registers only in trees built with the wasm module, so those tiers count
one more test: 56 with a WebAssembly tree, 58 with a browser.

**Against the old site,** the session-id and cookie checks fail by name.
**`browser_e2e`** passes in Edge with the fix (31 checks): signup, login,
recovery onto a fresh profile, and the recovered device's login.

### The controls: nine hand controls

The mutation runner proves each mutant reached the compiled binaries, so it
cannot mutate JavaScript. Each control below undid one part of the fix, ran
`site_sessions`, required a nonzero exit and the named check, and restored
the file, checked by sha256:

| ID | Undone | Verdict |
|---|---|---|
| HC1 | the new id at login | KILLED (9 named) |
| HC2 | the new id at signup | KILLED (2 named) |
| HC3 | the new id at recovery | KILLED (3 named) |
| HC4 | dropping the old id | KILLED (1 named) |
| HC5 | `__Host-sid` behind TLS | KILLED (2 named) |
| HC6 | the cap | KILLED (1 named) |
| HC7 | sparing logged-in sessions | KILLED (1 named) |
| HC8 | idle expiry | KILLED (1 named) |
| HC9 | removal at logout | KILLED (2 named) |

Step-up authentication before minting recovery codes was not added. That is
a design change beyond these findings, and it is offered to the owner.

### Verification

- **Every native tree rebuilt, proven current and run in full.** The
  fingerprints equal V4-57's, as they should: no C changed.

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `0e9ca24f16440127` | 58/58, `site_sessions` and `doc_test_counts` among them |
  | `build-bench-p` | `7e66c1eb191ca8a5` | 53/53 |
  | ASan | `579580adc52abc7e` | 58/58, instrumentation in all 43 |
  | UBSan | `79e1f06bd2826649` | 58/58; one runtime error, the planted canary |
  | fuzz | `6d73652afe730f62` | 36/36, and `test_authd_cli`, `backend_symbols` and `doc_test_counts` 3/3 |

- **Gates:**
  - anchors (406; unchanged);
  - the claim map (132 findings, 49 errata);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`;
  - `node --check` on the site and the test.

## V4-57 and V4-58 — CI on the branches and the nightly bring-up

**V4-50..56 landed first.** The final nightly 39708403120 passed 68/68, with
366/366 killed in 53 campaigns. The final-tree CI 39708422415 passed 14/14.
main went from `fd44fe7` to `2e30443`, 13 commits, whose tree equals the
tested revert's (`57bd54f`). main's CI 39724488410 passed 14/14. The branches
v4-50..v4-56 were then deleted, each checked as contained in main first.

### CI on the branches (14 jobs each, all green)

| Step | Head | Run |
|---|---|---|
| V4-57 | `e1261a5` | 39718693313 |
| V4-58 | `0b86a5d` | 39722865499 |

V4-57's run includes the Linux end-to-end legs. On Linux a second daemon on
the same configuration also fails at its TCP bind, and leaves the running
one reachable.

### The control nightly

- **How it was built.** `ad13755` is `57bd54f` with V4-57 and V4-58
  cherry-picked (V4-58's tree, `0b86a5d`), plus v80 LP6's expectation
  rotted. spec_v80's sha256 before was `4d9f7a250300f2b9`.
- **Run 39724503643** was red on exactly `mutations · v80`, 67/68:
  - LP6 **SURVIVED(BAD)**, naming the rotted text; LP1–LP5 were killed by
    name;
  - 367 rows in 53 campaigns: 366 killed and 1 survived, the control;
  - every fuzz job green.

The revert, whose tree equals this branch's final tree, follows. Its
nightly and main's landing are recorded with the next step.

## V4-59 — the store backup is 0600 from its first byte, F133 (F24's residue; loop iteration 34: fixes and cleanup, the owner's go)

### The finding

V4-9b fixed F24 by chmod-ing the backup 0600 after `VACUUM INTO`. But
`VACUUM INTO` creates its file under the process's umask, so until the copy
had finished, the copy of the credential database had the umask's mode, 0644
under 0022. A backup that failed after creating its file kept that mode.

The window was noted in V4-35 and parked for the owner. Under the shipped
systemd unit (`UMask=0077`) it never opened; it did wherever else the daemon
ran. Recorded now as **F133 (Low)**. The owner said fix it.

### The fix

`store_backup` creates the destination itself, before `VACUUM INTO` writes
into it:
- the file is created with mode 0600 and `O_CREAT|O_EXCL|O_NOFOLLOW`. SQLite
  accepts an existing empty file as `VACUUM INTO`'s destination;
- `O_EXCL` keeps the no-clobber rule that `VACUUM INTO` used to provide;
- the chmod after the copy stays;
- if the backup fails, the file is removed. `O_EXCL` made it, so it is this
  call's own to remove.

### The tests (`test_authd_store`, 289 checks)

- **The mode during the copy.** A test-only observer, compiled only under
  `MLDSA_STORE_FAULT_HOOK` and named `store_fault_arm_*` so
  `check_store_fault_hook.sh` proves it absent from shipped builds, reads the
  file between the copy and the chmod. Under a umask of 022 it must be 0600.
  A second check requires that the observer ran, so the first is not
  vacuous.
- **A refused second backup** leaves the first whole: the first still opens
  as a store.
- **A failed backup leaves no file.** The write-fault hook fails the
  `VACUUM INTO`.
- **A symlink at the path** is refused, and nothing is created at its
  target.

### The controls: campaign v84 (local, macOS ASan)

| ID | Mutation | Verdict |
|---|---|---|
| BK1 | the destination created 0644 | KILLED (2 named) |
| BK2 | no destination created first (the old behaviour) | KILLED (5 named) |
| BK4 | `O_EXCL` dropped: the failure path deletes the existing backup | KILLED (3 named) |
| BK5 | a failed backup's file kept | KILLED (2 named) |

Every source was restored clean, with no residue. BK3, `O_NOFOLLOW` dropped,
is not committed: `O_CREAT|O_EXCL` already refuses a symlink, so that mutant
would be equivalent.

**BK2 is the gap demonstration.** It is the code before this step, and five
named checks fail on it. The test cannot be run against the old code as it
stands: the old code has no observer to link against.

### A step rotting another step's campaign, caught before the nightly

v49b's B1, from V4-9b, removed the chmod, and `authd_e2e` saw a non-0600
backup. With the file now created 0600 first, removing the chmod alone
changes nothing: B1 would have survived in the nightly. B1 is re-authored as
"the backup keeps the umask's mode": the creation mode 0666 and the chmod
removed. Run alone on macOS ASan, it was KILLED (1 named), "the backup is not
0600", restored clean.

### The counts

371 mutations in 54 campaigns, 411 anchors; all 16 stated counts restated.
v84 is in nightly.yml's matrix, and tools/README.md's campaign list names it.
The register is 133 findings, F0–F133.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `b7f185dcd3391709` | 58/58 |
  | `build-bench-p` | `3db092661705b510` | 53/53 |
  | ASan | `f7950740aa47f5ee` | 58/58, instrumentation in all 43 |
  | UBSan | `e27d1f9a9fbf8f8b` | 58/58; one runtime error, the planted canary |
  | fuzz | `deca59ad3d19f9b2` | 36/36, and `test_authd_store`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`: `store.c` and
  `test_authd_store.c` are clean.
- **Gates:**
  - anchors (411; 16 counts agreeing);
  - the claim map (133 findings);
  - the spec checks;
  - the audit table's separators, after F133's escaped `|`s (the F105 trap);
  - `git diff --check`;
  - nightly.yml's matrix against the spec files.

## V4-60 — REVOKE-TOKENS user= handle= is scoped to the user, F123 (loop iteration 35; the owner's go)

### The decision

F123 had waited since V4-40 for the owner to say what `REVOKE-TOKENS user=
handle=` means. The daemon validated `user=`, then deleted every token on
`handle=` whoever it belonged to.

The owner approved the fix the register proposed: the delete is scoped to
both. A handle that belongs to another user revokes nothing and answers
`OK count=0`. There is no new error code, so §8's vocabulary is unchanged,
following the owner's preference in F48. Erratum 50 adds one sentence to §8.

### The change

`store_delete_tokens_for_handle` now takes the user as well, and deletes
`WHERE handle=?1 AND user_id=?2`. The local API passes `user=` through. The
function has no other production caller.

### The tests

- **`test_authd_store` (291 checks).** Another user with this handle deletes
  nothing, and the token still verifies. The handle's own user deletes it,
  with the count reported.
- **`test_authd_localapi` (303 checks), new `test_revoke_tokens_scope`.**
  Over the site socket: `REVOKE-TOKENS user=u2 handle=<u1's>` answers
  `OK count=0` and u1's token still verifies. The same request with `user=u1`
  answers `OK count=1` (the canary), and the token is gone.

This is also F122's item 3, the last of its five untested security checks,
so F122 is closed. F5 stays open only for the unmeasured wasm build.

### The controls: campaign v85 (RT1–RT2), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| RT1 | the user condition neutralised (the behaviour before V4-60) | KILLED (8 named, across both tests) |
| RT2 | the handle bound where the user belongs | KILLED (8 named, across both tests) |

Every source was restored clean, with no residue. RT1 is the gap
demonstration. The new tests cannot be built against the old code, whose
function took no user.

**Three problems in the campaign's own spec, fixed before it ran:**
- **The test regex.** First written with `|`, which splits a spec line and
  left both lines unnamed; then with `{4,}`, which CMake's regex dialect does
  not support, so `ctest -R` matched nothing. It is now
  `^test_authd_[sl][a-z][a-z][a-z][a-z][a-z]*$`, which `ctest -N` shows
  selecting exactly `test_authd_store` and `test_authd_localapi`.
- **RT2's anchor.** The bind line alone occurs five times in `store.c`. The
  gate called it ROTTED; an earlier grep for chosen words had hidden that.
  RT2 now anchors on the block from this function's `DELETE` through its
  second bind, which occurs once.
- **The first run was stopped in its preflight** when RT2's anchor was found.
  No mutation had been applied. Afterwards there was no runner process and
  no `MUTATION` marker in any source.

### The counts

373 mutations in 55 campaigns, 413 anchors; all 16 stated counts restated.
v85 is in nightly.yml's matrix, and tools/README.md's campaign list names it.
The register is unchanged at 133 findings, with F122 and F123 now closed.
§20 lists 50 errata.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `522b887acb309040` | 58/58 |
  | `build-bench-p` | `6f4b7c465ef1e18c` | 53/53 |
  | ASan | `62a7787249550bd1` | 58/58, instrumentation in all 43 |
  | UBSan | `727c4867bae8be24` | 58/58; one runtime error, the planted canary |
  | fuzz | `f6e12b6fc1e92bad` | 36/36, and `test_authd_localapi`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`: `store.c`,
  `localapi.c`, `test_authd_store.c` and `test_authd_localapi.c` are clean.
- **Gates:**
  - anchors (413; 16 counts agreeing; no rotted anchor);
  - the claim map (133 findings, 50 errata);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`.

## V4-61 — the daemon's start-up diagnostics agree, F126 (loop iteration 36; the owner's go)

### The decisions

F126 had waited since V4-51 for the owner: three start-up diagnostics
disagreed with each other. The owner said fix it, and the choices are:

- **(a) Exit codes.** A file the configuration names that cannot be used as
  configured exits **3**, a configuration error. That covers the server key
  and its passphrase file alike: missing, with unsafe modes, malformed, or
  not opened by the passphrase. An internal failure (`*_ERR_CRYPTO`, an
  allocation) exits **1**. Before, a refused passphrase file exited 3 and a
  refused server key 1, though the operator fixes both the same way. Spec
  §13 says so now (erratum 51), and so does the runbook's table.
- **(b) One refusal, one name.** The passphrase reader's permissions refusal
  is `unsafe-permissions`, the key-file reader's name. It was
  `permissions (mode must be 0600)`. The status names are not enumerated in
  the spec, so no vocabulary changes.
- **(c) A damaged store is not a broken audit chain.** A stored value of the
  wrong shape is the new `STORE_ERR_DAMAGED`, named `store-corrupt`. That
  covers `store_id`, `decoy_pk`, a recovery hash and a public key.
  `STORE_ERR_CORRUPT` keeps the meaning `store.h` always gave it, the audit
  chain's verification. The audit-chain lines did not move, so the
  constant-time inventory and v59's GB10 anchor, which quote them, are
  untouched. The new value is appended to the enum, so no existing value
  changes.

### The tests

- **`authd_e2e`.** The start-up legs now pin each refusal's exit code: 3
  for the group-readable passphrase file, 3 for the group-readable server
  key, 3 for the wrong passphrase, and 1 for a store that is not a database.
  The passphrase leg expects `unsafe-permissions`.
- **`test_authd_store` (292 checks).** The two damaged-meta cases expect
  `STORE_ERR_DAMAGED`. A new check pins both names: `store-corrupt` for a
  damaged value, and `audit-chain-corrupt` for the chain alone.
- **The texts that quote these checks moved with them:** v77's SD4 and SD5
  expectations, and the claim map's two citations.

### The controls: campaign v86 (DG1–DG5), local, macOS ASan

| ID | Mutation | Verdict |
|---|---|---|
| DG1 | a refused passphrase file exits 1 | KILLED (1 named), `authd_e2e` |
| DG2 | a refused server key exits 1 (the behaviour before V4-61) | KILLED (1 named), `authd_e2e` |
| DG3 | the passphrase reader's old name | KILLED (1 named), `authd_e2e` |
| DG4 | a damaged store value named `audit-chain-corrupt` | KILLED (2 named), `test_authd_store` |
| DG5 | a short `store_id` reported as the audit chain's status | KILLED (2 named), `test_authd_store` |

Every source was restored clean, with no residue. DG1–DG3 are killed by
`authd_e2e`'s start-up legs, which run on macOS too, so this local run covers
all five.

### The counts

378 mutations in 56 campaigns, 418 anchors; all 16 stated counts restated.
v86 is in nightly.yml's matrix, which after the rebase onto V4-60 lists v85
and v86 both, and tools/README.md's campaign list names it. The register is
unchanged at 133 findings, with F126 fixed. §20 lists 51 errata.

### Verification

- **Every native tree rebuilt, proven current and run in full:**

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `41fe7e30c6adec64` | 58/58 |
  | `build-bench-p` | `79a2d7a2d52eed3b` | 53/53 |
  | ASan | `162314732ed398a6` | 58/58, instrumentation in all 43 |
  | UBSan | `ed98793378a73ded` | 58/58; one runtime error, the planted canary |
  | fuzz | `d58caa0246d37a18` | 36/36, and `test_authd_store`, `backend_symbols` and `doc_test_counts` 3/3 |

- **The gcc 16 check**, as a full compile at `-O0` and `-O2`: `authd_main.c`,
  `authd_secret.c`, `store.c` and `test_authd_store.c` are clean. Adding an
  enum value raised no `-Wswitch` anywhere.
- **Gates:**
  - anchors (418; 16 counts agreeing);
  - the claim map (133 findings, 51 errata);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`;
  - `sh -n` on `authd_e2e.sh`.

## V4-62 — new recovery codes need a login, not only a session (loop iteration 37; the owner's decision)

### The decision

V4-58 left one question for the owner: should minting recovery codes on the
reference site take more than a logged-in session? A session cookie is a
weaker credential than what a login proves, the device key and the
passphrase. Recovery codes can enroll a new device. The owner decided: **it
should require login.**

### The change

- **The site.** `POST /api/recovery-codes` takes the code of a fresh login.
  The site `EXCHANGE`s it against the state it put in the session, and
  mints the codes only if the login is the session's own user's. A request
  without a code is `401 login required`; another user's login is `403`. The
  session keeps the token it had, and the new login's token is logged out at
  once.
- **The account page.** The button logs in again with this device's key and
  the passphrase field (the one rotation already uses), then sends that
  code. The field's label now says it is for both.
- **Spec and runbook.** §14 states the rule (erratum 52, revision v1.17).
  The runbook's rules for your own site grow to seven.

### The tests

- **`site_sessions` (28 checks):**
  - a logged-in session alone gets `401`;
  - a login by another user gets `403`;
  - the session's own fresh login mints five codes (the canary);
  - a code replayed after it minted once is refused.
- **`browser_e2e` in Edge:** with a wrong passphrase the account page mints
  nothing and the list stays empty; with the right one it mints five codes,
  and the rest of the recovery flow, onto a fresh profile, still passes.

### The controls: hand controls (the site is JavaScript)

| ID | Undone | Verdict |
|---|---|---|
| HC10 | the whole login requirement (the route before V4-62) | KILLED (4 named) |
| HC11 | the same-user comparison | KILLED (1 named) |

Each `server.mjs` was restored and checked by sha256. V4-58's nine controls
were re-run against the changed test: all still KILLED.

**Not pinned, and why:**
- **The state reset** (`s.state = null`): the daemon already makes a login
  code single-use, so a replay fails without it.
- **The logout of the new login's token:** the site never stores the token
  or sends it anywhere, so no test can see it either way.

### Verification

- **Every native tree rebuilt, proven current and run in full.** The
  fingerprints equal V4-61's, as they should: no C changed.

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `41fe7e30c6adec64` | 58/58, `site_sessions` and `browser_e2e` among them |
  | `build-bench-p` | `79a2d7a2d52eed3b` | 53/53 |
  | ASan | `162314732ed398a6` | 58/58, instrumentation in all 43 |
  | UBSan | `ed98793378a73ded` | 58/58; one runtime error, the planted canary |
  | fuzz | `d58caa0246d37a18` | 36/36, and 3/3 |

- **Gates:**
  - the claim map (133 findings, 52 errata);
  - anchors (418);
  - the spec checks;
  - the audit table's separators;
  - `git diff --check`;
  - `node --check` on the site, the account page and both tests.

## V4-63 — browser_e2e's teardown is bounded, F134 (loop iteration 38: fixes)

### The failure

V4-61's CI (39820109257) failed one job, the wasm client's. `browser_e2e`
printed every check as PASS, then never printed its summary, and CTest
killed it at its 600 s limit. The four runs before it took 14.5–16.4 s.
The job was re-run to see whether the failure repeats.

### The cause, read from the code

`tests/browser/cdp.mjs`'s `close()` has two unbounded waits:

- **An answer to `Browser.close`.** No handler failed pending requests when
  the DevTools socket closed. A browser that dropped the socket before
  answering left the wait open for ever.
- **The process's exit, judged by `exitCode` alone.** A process killed by a
  signal keeps a null `exitCode`, and its `exit` event has already fired, so
  the wait could never end.

The fixture's exit in `browser_e2e`'s `finally` was unbounded as well.
**F134 (Info):** a false failure, never a false pass.

### The fix

- **`cdp.mjs`:**
  - a closing DevTools socket fails every pending request;
  - `send` refuses a socket that is not open;
  - `close()` gives `Browser.close` 5 s and the exit 10 s, then sends
    SIGKILL and waits;
  - "exited" means `exitCode` or `signalCode`.
- **`browser_e2e.mjs`:** the fixture gets 3 s after SIGTERM, then SIGKILL,
  as in `wasm_interop`.

### The check, and what it shows

A third browser is launched, killed with SIGKILL, and closed. With the fix,
`close()` returns in 20 ms, and the whole test takes about 16 s.

- **Against the old helper** (`cdp.mjs` checked out from V4-62), the check
  fails at its 20 s guard. The test then exits instead of hanging.
- **Hand control:** with `signalCode` dropped from "exited", the check fails
  again at 20 s.

Both times the file was restored, checked by sha256. `phone_timing_tool`,
the other user of the helper, passes.

**What the check does not show:** which of the two waits hung in CI. A
browser that drops its socket without answering cannot be produced on
demand. That path is closed by the socket-close handler and the 5 s bound,
from reading the code.

### Verification

- **Every native tree rebuilt, proven current and run in full.** The
  fingerprints equal V4-61's: no C changed.

  | Tree | Fingerprint | Result |
  |---|---|---|
  | `build-p` | `41fe7e30c6adec64` | 58/58, `browser_e2e` (16 s) and `phone_timing_tool` among them |
  | `build-bench-p` | `79a2d7a2d52eed3b` | 53/53 |
  | ASan | `162314732ed398a6` | 58/58, instrumentation in all 43 |
  | UBSan | `ed98793378a73ded` | 58/58; one runtime error, the planted canary |
  | fuzz | `d58caa0246d37a18` | 36/36, and 3/3 |

- **V4-61's failed job, re-run unchanged** (39820109257, attempt 2): 14/14.
  The hang did not repeat; it was intermittent, as a teardown race would be.
- **Gates:**
  - the claim map (134 findings);
  - anchors;
  - the audit table's separators;
  - `git diff --check`;
  - `node --check` on both files.
