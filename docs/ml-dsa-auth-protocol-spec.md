# ML-DSA Mutual Authentication Protocol — Engineering Spec

Paste this document to Claude Code as the project brief. It is organized as sequential build steps; complete and verify each before moving to the next. Items marked **[DECISION NEEDED]** require your input before implementation.

---

## 1. Objective

Implement a mutual-authentication handshake and encrypted session protocol in C, for two peers to establish identity and a secure channel over an untrusted transport. Identity is proven via **ML-DSA-65** (FIPS 204) digital signatures. Confidentiality and forward secrecy come from **X25519 ECDH + HKDF + ChaCha20-Poly1305**. This is a hybrid classical/post-quantum design intended for production use.

## 2. Scope

**In scope (v1):** two-party mutual authentication, session encryption, rekeying, trust-on-first-use (TOFU) key pinning, reference client/server, test suite, benchmarks.

**Out of scope (v1):** certificate authority / PKI, key revocation, multi-party sessions, non-C bindings, group messaging. These are noted as follow-up work in Section 9.

## 3. Dependencies

| Library | Version | Purpose |
|---|---|---|
| liboqs | ≥ 0.16.0 | ML-DSA-65 signing/verification |
| libsodium | latest stable | X25519, HKDF, ChaCha20-Poly1305 AEAD, secure memory |
| CMake | ≥ 3.20 | Build system |

Build liboqs with `-DOQS_MINIMAL_BUILD=SIG_ml_dsa_65` to minimize binary size and attack surface — do not link the full algorithm set. Pin exact dependency versions in the build config; do not float on `main`/`latest` branches.

## 4. Security Requirements

These apply to every line of code touching key material, without exception.

1. **No custom cryptographic primitives.** All signing, key exchange, hashing, and AEAD operations go through liboqs or libsodium. No hand-rolled implementations anywhere.
2. **Secret memory handling.** All private keys, shared secrets, and session keys are allocated with `sodium_malloc` and wiped with `sodium_memzero` on every exit path, including error returns.
3. **Constant-time comparisons.** Any comparison involving secret-derived data (MACs, tags, keys) uses `sodium_memcmp`. Never `memcmp` or `strcmp` on secret material.
4. **Transcript-bound signatures.** Each handshake signature covers the full message transcript up to that point, not just a single nonce, to prevent substitution and downgrade attacks.
5. **Replay protection.** Every session enforces strictly increasing sequence numbers; every handshake enforces single-use session IDs and nonces within a bounded replay window.
6. **Strict input validation.** All wire-format lengths are validated against exact expected sizes (ML-DSA-65 pubkey 1952 B, signature ≤3309 B, X25519 keys 32 B) before parsing. Malformed input is rejected before any cryptographic operation runs.
7. **No silent key rotation.** Re-registration of an existing `client_id` with a different public key is rejected and logged, never silently accepted.
8. **Build hardening.** Compile with `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`. All tests must pass clean under AddressSanitizer and UndefinedBehaviorSanitizer.
9. **No secret-dependent control flow** in any code written for this project. Underlying libraries handle constant-time signing/verification internally; the glue code must not reintroduce timing leaks.

## 5. Performance Requirements

1. Full mutual handshake (2 signatures + 2 verifications + ECDH + key derivation): target **< 15 ms** on a modern x86_64 core. Report actual measured numbers; do not estimate.
2. Signature generation and verification are benchmarked individually as well as end-to-end, so regressions are traceable to a specific operation.
3. Use AVX2-optimized liboqs backends when available, selected at build time — no runtime branching in hot paths.
4. Steady-state message throughput (ChaCha20-Poly1305) benchmarked at 64 B, 1 KB, and 64 KB payloads.
5. Zero heap allocation in the per-message encrypt/decrypt path after session establishment; buffers are pre-allocated at session setup.

## 6. Protocol Specification

### 6.1 Roles
Two symmetric peers, each holding a persistent ML-DSA-65 identity keypair and a `client_id`. Either peer may initiate. `client_id` is an **opaque byte string, 1-64 bytes** — not validated or interpreted as UTF-8 anywhere in v1 (see 6.3.1). UTF-8 validation and Unicode canonicalization of `client_id` are explicitly out of scope for v1; a future version may add them without changing the wire-level length bound.

### 6.2 Registration (out of band, once per peer)
Each peer generates its ML-DSA-65 keypair locally and shares its public key with the counterparty over a channel already trusted by some other means (manual verification, existing TLS session, etc.). No CA is implemented in v1 — this is a known, documented limitation (Section 9).

### 6.3 Handshake

```
A                                                                  B
|--- ClientHello(A_id, A_ephemeral_x25519_pub,
|                session_id, nonce_A) ------------------------->  |
|<-- ServerHello(B_id, B_ephemeral_x25519_pub, nonce_B,
|                session_id_echo, sig_B) -------------------------  |
|--- ClientAuth(handshake_id, sig_A) ----------------------------->  |
```

- `session_id`: 16 random bytes, generated by the initiator.
- `session_id_echo` (in `ServerHello`) **MUST** equal `ClientHello.session_id`. This is a normative requirement on the protocol, but it is enforced in two places with two different tools: the wire-format decoder (6.3.4) accepts any structurally well-formed 16-byte value with no opinion on whether it matches anything; the handshake state machine (Section 8 Step 4) is what actually compares it against the `session_id` the initiator sent and rejects the handshake on mismatch.
- Each side verifies the inbound signature against the pinned public key for the claimed `client_id` (TOFU keystore, 6.2). Handshake fails closed on any of: signature invalid, `client_id` unknown, field length mismatch, `session_id_echo` mismatch, transcript mismatch. This verification/rejection logic lives entirely in Step 4 (6.3.5) — not in the wire-format layer.
- Shared secret: `X25519(own_ephemeral_sk, peer_ephemeral_pub)`.
- Session keys: `HKDF-SHA256(shared_secret, salt=session_id, info="mldsa-auth-v1" || A_id || B_id || direction)` — independent keys for each direction (`c2s`, `s2c`); never reuse one key bidirectionally.

#### 6.3.1 Wire Format

All multi-byte integers are big-endian (the same convention Section 6.4 uses for the session layer).

```
ClientHello:
  message_type    : 1 byte   (0x01)
  a_id_len        : 1 byte   (1-64)
  a_id            : a_id_len bytes            (opaque, not UTF-8-validated)
  a_ephemeral_pub  : 32 bytes (X25519)
  session_id      : 16 bytes
  nonce_a         : 32 bytes

ServerHello, unsigned prefix ("ServerHello_unsigned" — this exact byte
range is what sig_B is computed over directly, see 6.3.2; it is also a
literal prefix of the full transmitted ServerHello below, not a separate
encoding):
  message_type    : 1 byte   (0x02)
  b_id_len        : 1 byte   (1-64)
  b_id            : b_id_len bytes
  b_ephemeral_pub  : 32 bytes (X25519)
  nonce_b         : 32 bytes
  session_id_echo : 16 bytes

ServerHello, full (as transmitted) = ServerHello_unsigned || the following:
  sig_b_len       : 2 bytes  (big-endian; 1-3309)
  sig_b           : sig_b_len bytes

ClientAuth:
  message_type    : 1 byte   (0x03)
  handshake_id    : 16 bytes (6.3.3)
  sig_a_len       : 2 bytes  (big-endian; 1-3309)
  sig_a           : sig_a_len bytes
```

The 3309-byte bound matches ML-DSA-65's signature length (Security Req 4.6) — ML-DSA-65 signatures are fixed-length in practice, but the length prefix is retained for structural defensiveness rather than treating that as an implicit protocol guarantee.

#### 6.3.2 Signature Coverage

Each signature covers a **domain-separated SHA-256 digest** of the relevant transcript — not the raw transcript bytes, and not a bare (non-domain-separated) hash:

```
sig_B = MLDSA_Sign(skB,
          SHA-256("mldsa-auth/v1/server-auth" || 0x00 ||
                  encode(ClientHello) || encode(ServerHello_unsigned)))

sig_A = MLDSA_Sign(skA,
          SHA-256("mldsa-auth/v1/client-auth" || 0x00 ||
                  encode(ClientHello) || encode(ServerHello)))
```

`sig_B` covers `ServerHello`'s own unsigned fields (`B_id`, `B_ephemeral_pub`, `nonce_B`, `session_id_echo`) directly — not only `ClientHello`. A construction that signed only `ClientHello` would not authenticate anything the responder itself contributes: an attacker modifying those fields in transit would leave `sig_B` unaffected, and while `ClientAuth`'s later signature does bind the (already-tampered) `ServerHello` bytes, that only proves the client saw the tampered version, not that B ever chose it. `sig_A` covers the complete transcript up to and including the now-signed `ServerHello`.

The three domain-separation labels below are literal ASCII byte strings, each hashed as a prefix followed by a single `0x00` separator, then the relevant message bytes:

- `"mldsa-auth/v1/server-auth"`
- `"mldsa-auth/v1/client-auth"`
- `"mldsa-auth/v1/handshake-id"` (6.3.3)

This is standard cryptographic domain separation — distinct, label-prefixed hash inputs stop a signature produced for one message type or protocol version from being replayable as a signature for another. **It is not a claim that SHA-256 collisions are impossible.** Two domain-separated inputs are, by construction, always distinct byte strings; two different SHA-256 *outputs* for distinct inputs is what collision-resistance provides, not a mathematical guarantee.

#### 6.3.3 `handshake_id`

```
handshake_id = SHA-256("mldsa-auth/v1/handshake-id" || 0x00 ||
                       encode(ClientHello) || encode(ServerHello))[0:16]
```

The full 32-byte digest is always computed first; only the finished digest is truncated to 16 bytes — never a separately-constructed short hash.

`handshake_id` is a **lookup/demultiplexing hint carried in `ClientAuth`, not an authentication mechanism by itself.** It lets the responder locate which pending handshake a given `ClientAuth` belongs to among possibly-many in flight. The responder **MUST** recompute `handshake_id` from its own stored transcript (the `ClientHello`/`ServerHello` it actually sent/received for that pending handshake) and **MUST still verify `sig_A`** against that stored transcript before accepting anything. A wrong or adversarially-chosen `handshake_id` can only cause a lookup miss, or — in the event of a collision with some unrelated pending handshake — select a candidate whose own `sig_A` verification then fails; it cannot make any signature valid for a handshake it was not produced for, because acceptance never depends on trusting `handshake_id` itself.

#### 6.3.4 Decoder Strictness

Wire-format decoding (Security Req 4.6) enforces, before any payload byte past the point of failure is parsed:

- **Exact message-type match per message** — a `ClientHello` decoder accepts only `0x01`, a `ServerHello` decoder only `0x02`, a `ClientAuth` decoder only `0x03`. This is a real per-message-type parser boundary, not a generic "reject unknown type byte" filter: a well-formed message of one type handed to another type's decoder must fail.
- **Every declared length field validated against both its own bound** (id: 1-64 bytes; signature: 1-3309 bytes) **and the actual remaining buffer size**, before the corresponding payload bytes are read.
- **Full-buffer consumption**: a decode succeeds only if it consumes exactly the number of bytes it was given — trailing bytes after an otherwise-valid message are rejected, never silently ignored.

#### 6.3.5 Division of Responsibility (Wire Format vs. Handshake State Machine)

The wire-format/serialization layer (6.3.1-6.3.4) validates **structure only**. The following are **not** performed at decode time and are the handshake state machine's (Section 8 Step 4) responsibility:

- Peer identity/public-key lookup (TOFU keystore, 6.2).
- Comparing `ServerHello.session_id_echo` against the initiator's actual `ClientHello.session_id`.
- `handshake_id`-based pending-handshake lookup.
- Reconstructing the transcript from stored message bytes and verifying `sig_B`/`sig_A` against it.
- Pending-session lifecycle: creation, expiry, and single-use/replay enforcement (Security Req 4.5).

A structurally well-formed message that fails any of the above is rejected by Step 4, not by the wire-format decoders — the decoders will accept it as valid wire data regardless.

### 6.4 Session
- Wire format per message: `[8-byte big-endian sequence number][ChaCha20-Poly1305 ciphertext + tag]`.
- Sequence number doubles as AEAD nonce material (zero-padded to 12 bytes). Any message with a sequence number ≤ last accepted is rejected — no reordering tolerance in v1.
- Rekey (re-run handshake with fresh ephemeral keys) after 2³² messages or 1 hour of session age, whichever comes first.

## 7. Module Structure

```
mldsa-auth/
├── CMakeLists.txt
├── src/
│   ├── crypto/
│   │   ├── mldsa_wrap.{c,h}      # liboqs ML-DSA wrapper
│   │   ├── kex.{c,h}             # X25519 + HKDF
│   │   └── aead.{c,h}            # ChaCha20-Poly1305 session encrypt/decrypt
│   ├── protocol/
│   │   ├── handshake.{c,h}       # handshake state machine
│   │   ├── session.{c,h}         # sequence tracking, rekey, send/recv
│   │   ├── transcript.{c,h}      # wire-format serialization + transcript hashing
│   │   └── keystore.{c,h}        # TOFU public key pinning store
│   └── util/
│       ├── secure_mem.{c,h}      # sodium_malloc/memzero helpers
│       └── varint.{c,h}          # length-prefixed encode/decode
├── apps/
│   ├── auth_server.c             # reference TCP server
│   └── auth_client.c             # reference TCP client
├── tests/
│   ├── test_handshake.c          # happy path + adversarial cases
│   ├── test_session.c            # encrypt/decrypt, replay rejection, rekey
│   ├── test_vectors.c            # known-answer tests against liboqs KATs
│   └── fuzz/fuzz_handshake_parser.c
├── bench/bench_handshake.c
└── README.md
```

## 8. Build Steps

Execute in order. Do not proceed to the next step until the current one's exit criteria are met.

**Step 1 — Scaffold.** CMake project, dependency fetching (pinned versions), empty module stubs, clean local build.
*Exit criteria: `cmake --build .` succeeds with zero warnings.*

**Step 2 — Crypto wrappers.** Implement `mldsa_wrap`, `kex`, `aead` in isolation. Unit test each against liboqs's own published known-answer test vectors.
*Exit criteria: all KAT tests pass; no test invents its own reference values.*

**Step 3 — Wire format.** Deterministic serialization for all handshake messages. Round-trip encode/decode tests, including malformed/truncated input.
*Exit criteria: fuzz-style malformed-input tests reject cleanly with no crashes.*

**Step 4 — Handshake state machine.** In-process test harness driving two `handshake_ctx` instances directly (no sockets).
*Exit criteria: happy path succeeds; tampered signature, wrong client_id, replayed nonce, and transcript-substitution all fail closed.*

**Step 5 — Session layer.** Sequence numbers, AEAD, rekey trigger.
*Exit criteria: replay/reorder rejected; rekey fires at both thresholds; no heap allocation in the hot path (verify with a heap-tracking tool).*

**Step 6 — Reference apps.** TCP client/server wiring the above together.
*Exit criteria: manual end-to-end run between two processes succeeds.*

**Step 7 — Adversarial testing + fuzzing.** Fuzz harness on the wire-format parser.
*Exit criteria: 10 minutes of libFuzzer/AFL++ with zero crashes.*

**Step 8 — Benchmarking.** Measure handshake latency (per-primitive and end-to-end) and throughput at 64 B / 1 KB / 64 KB.
*Exit criteria: results committed to `bench/results.md` with real measured numbers; any miss against the 15 ms target is explained with a profiling breakdown.*

**Step 9 — Documentation.** README covering build instructions, demo usage, exact dependency versions, and an explicit statement of what this protocol does and does not protect against.

## 9. Known Limitations (Document, Do Not Silently Fix)

- TOFU trust model only — no CA, no revocation. A compromised first contact is not detectable by this protocol.
- No protection against endpoint compromise (key exfiltration from a live process).
- No multi-party or group session support.
- Key exchange is classical X25519, not post-quantum — see Section 10.

## 10. Open Decision

**[RESOLVED, before Step 2]** Key exchange is classical X25519 only in v1. A fully post-quantum variant would add ML-KEM-768 as a hybrid alongside X25519 (not a replacement — hybrid is the current best practice, since it stays secure if either the classical or PQ assumption fails), but that hybrid KEX is **deferred to a v2 milestone** — `liboqs` in v1 is built with `OQS_MINIMAL_BUILD=SIG_ml_dsa_65` only, no KEM algorithms. See [decisions.md](decisions.md) for the full rationale and the rest of the protocol decisions made through Step 3.
