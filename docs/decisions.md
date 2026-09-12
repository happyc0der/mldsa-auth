# Protocol Decisions (through v1.0.0; v2 in progress)

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
  "regenerate it with keygen".
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
