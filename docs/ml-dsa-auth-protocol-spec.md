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
- **Responder identity binding (initiator).** The initiator **MUST** reject a `ServerHello` whose `B_id` is not the peer identity it intended to contact, **before** looking up any key. Without this check, a `ServerHello` from a *different* identity that is also pinned — and that signs correctly with its own key — would pass every other check, and the initiator would authenticate a peer it never dialed.
- Shared secret: `X25519(own_ephemeral_sk, peer_ephemeral_pub)`. Implementations **MUST** check the X25519 primitive's result and treat a rejected (e.g. low-order) peer key as a fatal handshake failure.
- Session keys — see 6.3.7 for the normative, byte-exact key schedule. Independent keys for each direction (`c2s`, `s2c`); a key is never reused bidirectionally.

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

`handshake_id` is a **lookup/demultiplexing hint carried in `ClientAuth`, not an authentication mechanism by itself.** It lets the responder locate which pending handshake a given `ClientAuth` belongs to among possibly-many in flight. The responder **MUST** derive the expected `handshake_id` — and the `TH_client_auth` digest `sig_A` is verified against — from **the exact wire bytes of the `ClientHello` and `ServerHello` it actually received and sent** for that pending handshake: never from values carried in the `ClientAuth`, and never by re-serializing decoded structures. It **MAY** compute both once, when it creates the `ServerHello` (at which point it holds both exact byte strings), and retain only the two digests rather than the message bytes; the v1 implementation does exactly that. It **MUST** compare the retained `handshake_id` against `ClientAuth.handshake_id` in constant time, and **MUST still verify `sig_A`** against the retained `TH_client_auth` before accepting anything. A wrong or adversarially-chosen `handshake_id` can only cause a lookup miss, or — in the event of a collision with some unrelated pending handshake — select a candidate whose own `sig_A` verification then fails; it cannot make any signature valid for a handshake it was not produced for, because acceptance never depends on trusting `handshake_id` itself.

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

#### 6.3.6 Concurrency (v1)

The v1 reference implementation is an **in-process, single-threaded** state machine.

- The handshake context, the keystore, the responder's pending-handshake store, and the session object (6.4) are **not thread-safe** in v1. Every call on a given session must be serialized by the caller.
- Where this specification or the implementation describes an operation as **atomic** — in particular the responder's commit of a verified `ClientAuth` (`consume_success`) — it means **logically indivisible only when every call into a given pending store is serialized by the caller.** It is a statement about the store's own state transitions under serialized access, not a hardware or memory-model guarantee.
- A transport or server integration **MUST** either (1) confine each pending store, and every responder context associated with it, to a single thread/event loop; or (2) apply a synchronization strategy under which lookup, the expiry check, signature-result handling, and the single-use commit behave as **one critical section** per store. Under option 2 the ML-DSA verification computation itself need not be held inside the critical section, provided the entry's state is re-validated under the lock before the result is recorded.

No locking of any kind is implemented in v1.

#### 6.3.7 Key Schedule (normative)

Each direction's 32-byte session key is:

```
session_key = HKDF-SHA256( IKM  = X25519 shared secret,
                           salt = session_id            -- exactly 16 bytes,
                           info = kdf_info,
                           L    = 32 )

kdf_info =  "mldsa-auth/v1/kdf"   17 bytes, literal ASCII, no NUL
         || 0x00                   1-byte separator
         || A_id_len               1 byte, 1..64
         || A_id                   A_id_len bytes, opaque
         || B_id_len               1 byte, 1..64
         || B_id                   B_id_len bytes, opaque
         || direction              1 byte: 0x43 ('C') for c2s, 0x53 ('S') for s2c
```

- **`A_id` is always the initiator's identity and `B_id` always the responder's**, regardless of which peer is computing — both peers build byte-identical `kdf_info`.
- `A_id_len`/`B_id_len` are the same 1-byte lengths the wire format already carries (6.3.1). No other `direction` value is valid; implementations **MUST** reject any other byte.
- `kdf_info` is 23 bytes minimum and 149 bytes maximum. It is built from explicit lengths throughout: no C-string handling, no `strlen`, no implicit NUL terminator.
- **Injectivity rationale.** Each variable-length identity is preceded by its own length byte, and the label is fixed-length, so any `kdf_info` byte string corresponds to at most one `(A_id, B_id, direction)` triple. An earlier revision of this section specified plain concatenation of a fixed label, `A_id`, `B_id` and the direction byte, with no length prefixes — which is **not** injective: `A_id="ab", B_id="c"` and `A_id="a", B_id="bc"` produced identical bytes. Both identities are also bound into the signed transcripts (6.3.2), which constrains practical exploitation of that ambiguity, but a KDF's context input must be unambiguous on its own merits rather than by relying on a separate layer happening to cover the same fields. That earlier encoding was never used to derive keys in any implementation; this construction replaces it.

### 6.4 Session

An ESTABLISHED handshake's two directional keys (6.3.7) protect application data as a sequence of records, each sealed with ChaCha20-Poly1305 (IETF variant: 12-byte nonce, 16-byte tag).

#### 6.4.1 Record Format

```
record = record_type   1 byte   0x04
      || seq           8 bytes  big-endian; per-direction counter, starting at 0
      || ciphertext    pt_len bytes
      || tag           16 bytes
```

- `0 ≤ pt_len ≤ 65 536`, so a record is 25 to 65 561 bytes. The transport framing (Step 6) carries the record length; the record itself does not.
- `record_type` shares the message-type namespace with the handshake (`0x01`–`0x03`, 6.3.1). `0x04` is the only record type in v1; any other value is malformed.
- **v1 records are unpadded; record length reveals plaintext length plus the fixed 25-byte overhead. Padding is deferred to a future protocol version.**

#### 6.4.2 Nonce and Associated Data (normative)

```
nonce (12 bytes) = 0x00 0x00 0x00 0x00 || seq (8 bytes, big-endian)

ad (47 bytes)    = "mldsa-auth/v1/record"   20 bytes, literal ASCII, no NUL
                || 0x00                     1-byte separator
                || handshake_id             16 bytes (6.3.3)
                || direction                1 byte: 0x43 initiator->responder, 0x53 responder->initiator
                || record_type              1 byte (0x04)
                || seq                      8 bytes, big-endian
```

- Records from the initiator use the `c2s` key and direction `0x43`; records from the responder use the `s2c` key and direction `0x53`.
- **Nonce uniqueness.** Keys are per direction, `seq` never repeats within a direction (6.4.3), and a handshake's keys can seed exactly one session (6.4.4). So no `(key, nonce)` pair is ever used twice.
- **What the AD binds:**
  - the label binds the protocol version and the record-layer purpose;
  - `handshake_id` binds every record to the exact authenticated transcript;
  - `direction` stops reflection even if both directions ever shared a key;
  - `record_type || seq` authenticates every transmitted header byte.

#### 6.4.3 Sequence, Replay and Failure Policy

- A sender assigns `seq` values 0, 1, 2, … and never reuses one: `seq` is reserved before encryption.
- A receiver **MUST** accept a record only if its `seq` equals the next expected value exactly. A lower `seq` is a replay; a higher `seq` is a gap, meaning a record was deleted. There is no reordering or gap tolerance in v1. The transport is reliable and in-order, so a gap can only mean deletion or a bug.
- `seq` is checked on the header **before** any AEAD work. A forged header also fails authentication, because `seq` is in both the nonce and the AD.
- **Every receive failure is terminal for the whole session.** That covers a malformed record, replay, gap, authentication failure, and a peer that exceeds the hard record limit. The session's keys are zeroed immediately.
  - This gives an attacker who can inject into the transport nothing new, since that attacker can already reset the connection.
  - It limits every key to at most one failed verification.
- On authentication failure, the caller's plaintext buffer region is zeroed.
- API misuse, such as a buffer that is too small, changes no state and consumes no `seq`.

#### 6.4.4 Key Handoff and Initiator Confirmation

- A session is created from an ESTABLISHED handshake context, and creating it **consumes** that context: its keys are wiped. One handshake can therefore never seed two sessions, which would reuse nonces.
- A responder session is peer-confirmed from creation. `sig_A` has been verified, and the single-use entry has been consumed.
- An initiator session starts **unconfirmed**. It becomes confirmed on its first successfully authenticated record from the responder, and never otherwise.
  - A valid record under `s2c` requires the shared secret. The responder commits its keys only after verifying `ClientAuth`. So such a record proves the responder accepted the handshake.
  - Irreversible actions **MUST** be gated on this confirmation, not on the session existing.
- The responder **SHOULD** send a record, which may be empty, immediately after creating its session. The initiator is then confirmed without waiting for application data.
- The initiator **MAY** send before it is confirmed: only the authenticated responder can read that data. What stays unconfirmed is whether the responder accepted the handshake.

#### 6.4.5 Rekey and Expiry Limits

| | Soft limit: rekey due | Hard limit: refuse and expire |
|---|---|---|
| Records per direction | 2³² | 2³³ |
| Session age | 3 600 000 ms (1 h) | 3 900 000 ms (65 min) |

- **Rekey** means running a new full handshake with fresh ephemeral keys. The soft limits signal that a rekey is due; the session keeps working. Either direction's record count, or the age, triggers it.
- At a hard limit the session refuses every further seal and open and is expired. Its keys are zeroed.
  - A receiver also rejects any record whose `seq` reaches the hard record limit, because a compliant sender never produces one.
- Age is measured on a monotonic clock from session creation. A clock that cannot be read, or that goes backwards, counts as expired (fails closed).
- The grace between soft and hard limits covers a rekey handshake (about 1.5 RTT plus about 2 ms of computation) with a wide margin. At a plausible peak of about 10⁷ records/s, the record grace of 2³² records lasts about 7 minutes, comparable to the 5-minute time grace.
- **These are conservative v1 protocol-policy limits, not a derived AEAD bound.** They are chosen to stay well below practical ChaCha20-Poly1305 key-usage bounds and to leave headroom for rekeying.
  - Nonce uniqueness (6.4.2) is necessary but not the only consideration. Aggregate data under one key, record size, and forgery bounds also matter.
  - At the hard limit one key protects at most 2³³ records of at most 2¹⁶ bytes each, which is 2⁴⁹ bytes per direction.
  - Forgery exposure is capped separately by 6.4.3: at most one failed verification per key.
- **These record and key-usage limits are v1 policy values tied to the 65 536-byte maximum plaintext, ChaCha20-Poly1305, a reliable in-order transport, and full-handshake rekeying. They MUST be revisited if any of those change.**
- Implementations may let a caller tighten these limits, but never loosen them. The reference implementation's tests rely on this, so exercising the thresholds needs no test hooks.

#### 6.4.6 Session Object Lifecycle

- A session object **MUST** be zero-initialized before first use. The zero state is EMPTY and owns no key material.
- Creating a session is valid **only** on an EMPTY object. On any other object the attempt fails and changes nothing, neither the object nor the handshake context. A live key block is therefore never overwritten or leaked.
- A FAILED or EXPIRED session keeps its already-zeroed key block until it is wiped. Wiping frees the key block and returns the object to EMPTY. Wiping is idempotent and safe on an EMPTY object.
- The steady-state record path performs no heap allocation. Its only memory is the session's one key block, allocated at creation and freed at wipe, plus caller-provided record buffers.

An earlier revision of this section gave only a three-bullet sketch:
- the record was sequence number plus ciphertext, with no type byte;
- the nonce was "zero-padded to 12 bytes", without saying on which side;
- it did not specify AD;
- "≤ last accepted is rejected" would have accepted gaps;
- the 2³²-message and 1-hour values were stated without saying whether they were triggers or hard stops.

That sketch was never implemented; 6.4.1–6.4.6 replace it.

### 6.5 Reference Transport (v1)

This section specifies how the reference applications (`apps/`, Step 6) carry the protocol over TCP. It is normative for those applications and adds nothing to the cryptographic protocol: 6.3 and 6.4 are unchanged, and the handshake messages and records are the exact bytes those sections define.

**TCP provides no authentication.** Peer addresses and ports are never used for any trust decision, and loopback is not treated as trusted. Identity comes only from the ML-DSA handshake against explicitly pinned keys.

#### 6.5.1 Framing

```
frame = length (4 bytes, big-endian, unsigned) || payload (length bytes)
```

- Every handshake message and every record travels in exactly one frame. There is no separate frame-type byte: the payload's first byte is already the message type (`0x01`–`0x03` handshake, `0x04` record), and each state expects exactly one type.
- **Per-state limits.** The reader checks the length on the 4 header bytes, before reading any payload byte. A length outside the bounds ends the connection. The largest possible frame is the largest record: 65 561 bytes.

| Reader state | Minimum | Maximum |
|---|---|---|
| server, awaiting ClientHello | 1 | 146 |
| client, awaiting ServerHello | 1 | 3 457 |
| server, awaiting ClientAuth | 1 | 3 328 |
| client, awaiting the confirmation record | 25 | 25 (the empty record) |
| session phase, both sides | 25 | 65 561 |

- The length is unauthenticated and needs no authentication. A wrong length shifts the payload boundaries, and then the strict full-consumption decoders (6.3.4) or the AEAD (6.4.3) fail, which is terminal.
- Implementations **MUST NOT** assume that one read returns one frame. They **MUST** loop over partial reads and writes, retry interrupted system calls, and bound every wait by an **absolute** deadline, so a peer that trickles bytes cannot extend it.

#### 6.5.2 Connection Flow and Policy

1. The client sends ClientHello; the server replies with ServerHello; the client sends ClientAuth. Both sides then create their sessions (6.4.4).
2. The server sends one **empty** record immediately. The client does not send application data until that record has authenticated (6.4.4).
3. **Timeouts:**
   - **Handshake:** 10 s by default, absolute from accept (server) or connect (client) until the session is established. On the client it runs until the confirmation record arrives.
   - **Idle:** 30 s by default for each session-phase frame.
   - The server's handshake timeout **MUST NOT** exceed the pending-handshake TTL (6.3.5).
4. **ClientAuth failure closes the connection.** The server wipes the handshake context, which cancels its pending entry, and closes.
   - The library still reports a signature failure below the N = 3 limit as retryable. That limit exists for transports where a forged message can arrive alongside the genuine one.
   - On a TCP stream bound to one connection, anyone who can inject bytes can already reset the connection. Waiting for a second ClientAuth would only turn a bad peer into a timeout.
5. **Any other failure also ends the connection:** a frame outside the bounds, a handshake or record error, a timeout, or EOF. The reference apps send no alert. Buffers that may have held plaintext are wiped when every connection ends.
6. The reference server listens on `127.0.0.1` only and handles one connection at a time. It owns its pending-handshake store for its whole lifetime, which is the confinement option of 6.3.6.

#### 6.5.3 Demo Application Protocol

Inside each record after the confirmation record, the plaintext is `op (1 byte) || body`:

| op | Direction | Meaning |
|---|---|---|
| `0x01` MSG | client → server | the server replies ECHO with the same body |
| `0x02` ECHO | server → client | the echoed body |
| `0x03` GOODBYE | either | authenticated close, answered by GOODBYE |

- A connection has closed in an orderly way **only** after GOODBYE has been exchanged. EOF without GOODBYE is reported as a failure (possible truncation), because a TCP close is unauthenticated.
- The confirmation record is the only empty record. Every later record must carry an op byte.
- This is application-level convention for the reference apps. It is not part of the cryptographic protocol, and it adds no record type.

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

> **How Step 7 meets this.** Five libFuzzer targets cover every attacker-controlled input: the handshake wire decoders and transcript helpers, the handshake state machine, `session_open`, the reference frame reader, and the demo key-file loaders.
> - The libFuzzer binaries are built in a separate `build-fuzz` directory with a libFuzzer-capable clang, under AddressSanitizer and UndefinedBehaviorSanitizer.
> - Each runs 600 seconds locally (`tests/fuzz/run_fuzz.sh local`) and must end with zero crashes and no artifacts.
> - Every configuration also runs a portable, deterministic (not coverage-guided) replay smoke in CTest.
> - Harnesses assert properties against independent reference models, not just the absence of crashes.
>
> A fuzzing run is not a proof of correctness. `tests/fuzz/README.md` lists the properties that remain covered only by deterministic tests.

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
