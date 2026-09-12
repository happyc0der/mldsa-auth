# ML-DSA Mutual Authentication Protocol — Engineering Spec, Version 2

**Version 2.** v1 is frozen at tag `v1.0.0` and is described by
[ml-dsa-auth-protocol-spec.md](ml-dsa-auth-protocol-spec.md), which is
never edited again. This document supersedes it for all new work.

v2 is **not wire-compatible with v1** and there is no negotiation between
them: see §0 and §2. Items marked **[DECISION NEEDED]** would require input
before implementation; there are none open in v2.

---

## 0. Changes from v1

| Area | v1 | v2 |
|---|---|---|
| Key exchange | X25519 only | **Hybrid X25519 + ML-KEM-768** (§6.3, §6.3.7) |
| Key schedule | HKDF over the X25519 secret | HKDF over `ss_x ‖ ss_k`, with the transcript hash bound into `info` (§6.3.7) |
| Records | Unpadded; length leaks plaintext length | **Padded** to a sender-chosen bucket; length leaks only the bucket (§6.4.1) |
| Domain labels | `mldsa-auth/v1/...` | All bumped to `mldsa-auth/v2/...` (§6.3.2, §6.3.3, §6.3.7, §6.4.2) |
| ClientHello | ≤ 146 bytes | ≤ **1 330** bytes (+1 184-byte ML-KEM encapsulation key) |
| ServerHello | ≤ 3 457 bytes | ≤ **4 545** bytes (+1 088-byte ML-KEM ciphertext) |
| ClientAuth | ≤ 3 328 bytes | ≤ 3 328 bytes (unchanged) |
| Max record plaintext | 65 536 bytes of content | 65 536 bytes of *padded inner*, so ≤ **65 534** bytes of content (§6.4.1) |
| liboqs build | `SIG_ml_dsa_65`, pinned by tag | `SIG_ml_dsa_65;KEM_ml_kem_768`, pinned by **commit SHA**, backend selected at **build time** (§3) |
| Demo key files | `MLDSASK2` | Unchanged — identity keys are ML-DSA-65 in both versions |

Also in the v2 milestone, outside the protocol itself: the fuzz corpus
scanner's public-key-prefix false positive is fixed, and a
`MLDSASK1` → `MLDSASK2` demo-key migration command is added.

**What v2 does not change:** identity signatures are ML-DSA-65 as before,
the three-message handshake shape, the message-type bytes (`0x01`–`0x04`),
the TOFU pinning model, the record header and AD layout apart from the
label, the sequence/replay policy, the rekey and expiry limits, and the
transport framing.

## 1. Objective

Implement a mutual-authentication handshake and encrypted session protocol
in C, for two peers to establish identity and a secure channel over an
untrusted transport. Identity is proven via **ML-DSA-65** (FIPS 204) digital
signatures. Confidentiality and forward secrecy come from a **hybrid
X25519 + ML-KEM-768 key exchange**, HKDF-SHA256 and ChaCha20-Poly1305.

The hybrid is a combination, never a replacement: the session key depends on
**both** shared secrets, so it remains secure as long as *either* the
classical (X25519) or the post-quantum (ML-KEM) assumption holds. Unlike
v1, recorded v2 traffic is therefore not exposed to a future quantum
adversary ("harvest now, decrypt later").

## 2. Scope

**In scope (v2):** two-party mutual authentication, hybrid post-quantum key
exchange, session encryption with length padding, rekeying, trust-on-first-use
(TOFU) key pinning, reference client/server, test suite, benchmarks.

**Out of scope (v2):** certificate authority / PKI, key revocation,
multi-party sessions, non-C bindings, group messaging, multi-connection
handshake routing, transport rate limiting, thread safety. These are noted
as follow-up work or integrator obligations in Section 9.

### 2.1 Compatibility and maintenance (normative)

- **Clean break, no negotiation.** A v2 implementation speaks only v2. There
  is no version field and nothing to negotiate, so there is no downgrade
  surface. The separation is enforced by construction: every domain label
  differs, and the `ClientHello`/`ServerHello` layouts differ in length, so
  a v1 message fails a v2 decoder's strict length and full-consumption
  checks (§6.3.4), and a v2 message fails a v1 decoder's.
- **v1 is frozen at the `v1.0.0` tag — upgrade or fork.** This repository
  does not maintain a patchable v1 branch. v1's key-schedule, wire-format
  and handshake functions are deleted from `src/` when v2 replaces them.
  The reasoning: v1 is documented as not production-ready, so no deployed
  base depends on it; a v1 fix would still force both peers to upgrade,
  because the break is at the wire level; and maintaining a second protocol
  track would double this project's per-change verification cost (fresh
  sanitizer builds, fuzz budgets, mutation campaigns). Anyone who needs a
  patched v1 can branch from the tag; no such branch is promised here.
- Peers are upgraded together. Because trust is explicit pinning (§6.2),
  there is no discovery step in which a version mismatch could be
  negotiated away — a v1 peer and a v2 peer simply fail to handshake.

## 3. Dependencies

| Library | Version | Purpose |
|---|---|---|
| liboqs | 0.16.0, pinned by commit SHA | ML-DSA-65 signing/verification; ML-KEM-768 KEM |
| libsodium | 1.0.22, pinned by tarball SHA-256 | X25519, HKDF, ChaCha20-Poly1305 AEAD, secure memory |
| CMake | ≥ 3.20 | Build system |

- Build liboqs with `-DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"` —
  exactly one signature algorithm and one KEM, no other family — to keep
  binary size and algorithm attack surface to what v2 uses.
- **Pin by commit, not by tag.** `GIT_TAG` is set to the resolved commit
  SHA (`5a1a854b0dc9f2141bdc771c555ee60c37950183` for 0.16.0), so a
  re-pointed upstream tag cannot change what this project builds. The tag
  name is retained in a comment for human readability. libsodium is already
  pinned byte-exactly by `URL_HASH`.
- **Backend selection at build time** (Security Req 4.10): liboqs is built
  with `OQS_DIST_BUILD=OFF` and a single optimization target, so no
  CPU-feature branch is taken per signing or KEM call. The target is a
  project option defaulting to `native`. **A `native` build is tied to the
  build machine's CPU family**; builds for distribution must select
  `generic`, which on x86_64 gives up the AVX2 backend. This is done for
  requirement conformance, not for speed: the runtime-dispatch branch it
  removes was measured at 0.6–3.0%, inside run-to-run noise.

## 4. Security Requirements

These apply to every line of code touching key material, without exception.

1. **No custom cryptographic primitives.** All signing, key exchange, KEM,
   hashing, and AEAD operations go through liboqs or libsodium. No
   hand-rolled implementations anywhere — including the hybrid combiner,
   which is HKDF over a concatenation, not a bespoke construction.
2. **Secret memory handling.** All private keys, shared secrets, KEM
   decapsulation keys, and session keys are allocated with `sodium_malloc`
   and wiped with `sodium_memzero` on every exit path, including error
   returns.
3. **Constant-time comparisons.** Any comparison involving secret-derived
   data (MACs, tags, keys) uses `sodium_memcmp`. Never `memcmp` or `strcmp`
   on secret material.
4. **Transcript-bound signatures.** Each handshake signature covers the full
   message transcript up to that point — including both key-exchange
   contributions — not just a single nonce, to prevent substitution and
   downgrade attacks.
5. **Replay protection.** Every session enforces strictly increasing
   sequence numbers; every handshake enforces single-use session IDs and
   nonces within a bounded replay window.
6. **Strict input validation.** All wire-format lengths are validated
   against exact expected sizes (ML-DSA-65 pubkey 1952 B, signature
   ≤ 3309 B, X25519 keys 32 B, ML-KEM-768 encapsulation key 1184 B,
   ciphertext 1088 B) before parsing. Malformed input is rejected before any
   cryptographic operation runs.
7. **No silent key rotation.** Re-registration of an existing `client_id`
   with a different public key is rejected and logged, never silently
   accepted.
8. **Build hardening.** Compile with `-Wall -Wextra -Werror
   -fstack-protector-strong -D_FORTIFY_SOURCE=2`. All tests must pass clean
   under AddressSanitizer and UndefinedBehaviorSanitizer.
9. **No secret-dependent control flow** in any code written for this
   project. Underlying libraries handle constant-time signing, verification
   and decapsulation internally; the glue code must not reintroduce timing
   leaks.
10. **Build-time algorithm backend selection.** No runtime CPU-feature
    branching in signing, KEM or AEAD hot paths (§3).
11. **ML-KEM decapsulation is never a validation signal.** ML-KEM-768
    decapsulation cannot fail: on a malformed or tampered ciphertext it
    returns a pseudorandom secret (implicit rejection). Implementations
    **MUST NOT** treat its return value as authentication of the
    ciphertext, and **MUST NOT** branch on the decapsulated bytes. A
    tampered ciphertext is detected only as a key disagreement, which the
    record layer reports as an authentication failure (§6.3.3, §6.4.4).
12. **The responder's retained KEM secret is wiped on every path.** The
    responder holds `ss_k` between sending `ServerHello` and verifying
    `ClientAuth` (§6.3). It **MUST** be held in `sodium_malloc` memory and
    wiped on every failure, cancellation and teardown path, exactly like the
    ephemeral X25519 scalar.
13. **Padding is verified, not skipped.** A receiver **MUST** reject a
    record whose declared content length exceeds the padded inner plaintext,
    and **MUST** reject any nonzero padding byte (§6.4.1). Padding bytes are
    not secret, but accepting arbitrary trailing bytes would create a
    covert channel inside an authenticated record.

## 5. Performance Requirements

1. Full mutual handshake (2 signatures + 2 verifications + X25519 +
   ML-KEM-768 + key derivation): target **< 15 ms per handshake on the
   measurement platform**, reported with the platform named. The reference
   measurement platform is an Apple M4 Pro (arm64), Release build; v1
   measured **0.372 ms** median there. v2 is *expected* to land near
   0.45 ms — ML-KEM-768 keygen, encapsulation and decapsulation are each
   tens of microseconds — but that is an expectation until measured, and
   **only measured numbers are reported** (§8, V2-7).
2. Signature generation and verification, and KEM keygen, encapsulation and
   decapsulation, are benchmarked individually as well as end-to-end, so
   regressions are traceable to a specific operation.
3. Optimized liboqs backends are selected at build time, with no runtime
   branching in hot paths (§3, Security Req 4.10).
4. Steady-state message throughput (ChaCha20-Poly1305) benchmarked at 64 B,
   1 KiB, and 64 KiB payloads, for pad buckets 1 (no padding) and 256, so
   padding's cost is visible rather than folded into one number.
5. Zero heap allocation in the per-message encrypt/decrypt path after
   session establishment, padding included; buffers are pre-allocated at
   session setup.

## 6. Protocol Specification

### 6.1 Roles

Two symmetric peers, each holding a persistent ML-DSA-65 identity keypair
and a `client_id`. Either peer may initiate. `client_id` is an **opaque byte
string, 1-64 bytes** — not validated or interpreted as UTF-8 anywhere in v2
(see 6.3.1). UTF-8 validation and Unicode canonicalization of `client_id`
are explicitly out of scope; a future version may add them without changing
the wire-level length bound.

Note that the roles are not symmetric with respect to the KEM: the
**initiator** generates the ephemeral ML-KEM keypair and decapsulates; the
**responder** encapsulates. This follows from the message order — the
encapsulation key must be on the wire before the ciphertext can be produced.

### 6.2 Registration (out of band, once per peer)

Each peer generates its ML-DSA-65 keypair locally and shares its public key
with the counterparty over a channel already trusted by some other means
(manual verification, existing TLS session, etc.). No CA is implemented —
this is a known, documented limitation (Section 9). Only the long-term
identity key is registered; all key-exchange material is ephemeral and
per-handshake.

### 6.3 Handshake

```
A                                                                  B
|--- ClientHello(A_id, A_ephemeral_x25519_pub, A_mlkem_ek,
|                session_id, nonce_A) ------------------------->  |
|<-- ServerHello(B_id, B_ephemeral_x25519_pub, mlkem_ct, nonce_B,
|                session_id_echo, sig_B) -------------------------  |
|--- ClientAuth(handshake_id, sig_A) ----------------------------->  |
```

- `session_id`: 16 random bytes, generated by the initiator.
- `session_id_echo` (in `ServerHello`) **MUST** equal
  `ClientHello.session_id`. This is a normative requirement on the protocol,
  but it is enforced in two places with two different tools: the wire-format
  decoder (6.3.4) accepts any structurally well-formed 16-byte value with no
  opinion on whether it matches anything; the handshake state machine
  (Section 8, V2-5) is what actually compares it against the `session_id`
  the initiator sent and rejects the handshake on mismatch.
- Each side verifies the inbound signature against the pinned public key for
  the claimed `client_id` (TOFU keystore, 6.2). Handshake fails closed on
  any of: signature invalid, `client_id` unknown, field length mismatch,
  `session_id_echo` mismatch, transcript mismatch. This
  verification/rejection logic lives entirely in the state machine (6.3.5) —
  not in the wire-format layer.
- **Responder identity binding (initiator).** The initiator **MUST** reject
  a `ServerHello` whose `B_id` is not the peer identity it intended to
  contact, **before** looking up any key. Without this check, a
  `ServerHello` from a *different* identity that is also pinned — and that
  signs correctly with its own key — would pass every other check, and the
  initiator would authenticate a peer it never dialed.
- **Classical shared secret:** `ss_x = X25519(own_ephemeral_sk,
  peer_ephemeral_pub)`. Implementations **MUST** check the X25519
  primitive's result and treat a rejected (e.g. low-order) peer key as a
  fatal handshake failure. The initiator performs this check as a
  *validation probe* when it verifies `ServerHello`, before it signs
  `ClientAuth`, and discards the result; the value it actually uses is
  recomputed at `finish`.
- **Post-quantum shared secret:** the initiator generates an ephemeral
  ML-KEM-768 keypair `(ek, dk)` for each handshake — encapsulation key
  1 184 bytes (sent on the wire), decapsulation key **2 400 bytes** (secret,
  never transmitted, held in secure memory until `finish`) — and sends `ek`.
  Both shared secrets are 32 bytes. The
  responder computes `(ct, ss_k) = ML-KEM-768.Encaps(ek)` when it creates
  `ServerHello`, sends `ct`, and **retains `ss_k`** until it verifies
  `ClientAuth`. The initiator computes `ss_k = ML-KEM-768.Decaps(ct, dk)` at
  `finish`.
  - `Decaps` never fails (Security Req 4.11): a tampered `ct` yields a
    different `ss_k`, both sides complete the handshake, and the
    disagreement surfaces as the initiator's first record failing to
    authenticate. This is the designed failure mode, and it is exactly the
    confirmation property of 6.4.4.
  - `ek` and `ct` are both covered by the signatures (6.3.2), so a
    *substituted* KEM contribution from an active attacker is rejected
    outright; only an attacker able to forge an ML-DSA signature could
    reach the key-disagreement path.
  - `dk` (initiator) and `ss_k` (responder) are per-handshake secrets held
    in secure memory and wiped on every path (Security Req 4.12).
- Session keys — see 6.3.7 for the normative, byte-exact key schedule.
  Independent keys for each direction (`c2s`, `s2c`); a key is never reused
  bidirectionally.

#### 6.3.1 Wire Format

All multi-byte integers are big-endian (the same convention Section 6.4 uses
for the session layer).

```
ClientHello:
  message_type    : 1 byte    (0x01)
  a_id_len        : 1 byte    (1-64)
  a_id            : a_id_len bytes            (opaque, not UTF-8-validated)
  a_ephemeral_pub : 32 bytes  (X25519)
  a_mlkem_ek      : 1184 bytes (ML-KEM-768 encapsulation key)
  session_id      : 16 bytes
  nonce_a         : 32 bytes

ServerHello, unsigned prefix ("ServerHello_unsigned" — this exact byte
range is what sig_B is computed over directly, see 6.3.2; it is also a
literal prefix of the full transmitted ServerHello below, not a separate
encoding):
  message_type    : 1 byte    (0x02)
  b_id_len        : 1 byte    (1-64)
  b_id            : b_id_len bytes
  b_ephemeral_pub : 32 bytes  (X25519)
  mlkem_ct        : 1088 bytes (ML-KEM-768 ciphertext)
  nonce_b         : 32 bytes
  session_id_echo : 16 bytes

ServerHello, full (as transmitted) = ServerHello_unsigned || the following:
  sig_b_len       : 2 bytes   (big-endian; 1-3309)
  sig_b           : sig_b_len bytes

ClientAuth:
  message_type    : 1 byte    (0x03)
  handshake_id    : 16 bytes  (6.3.3)
  sig_a_len       : 2 bytes   (big-endian; 1-3309)
  sig_a           : sig_a_len bytes
```

Maximum encoded lengths (with a 64-byte identity):

| Message | Maximum | Composition |
|---|---|---|
| `ClientHello` | **1 330** | 1 + 1 + 64 + 32 + 1184 + 16 + 32 |
| `ServerHello_unsigned` | **1 234** | 1 + 1 + 64 + 32 + 1088 + 32 + 16 |
| `ServerHello` (full) | **4 545** | 1 234 + 2 + 3 309 |
| `ClientAuth` | **3 328** | 1 + 16 + 2 + 3 309 |

The 3309-byte bound matches ML-DSA-65's signature length (Security Req 4.6)
— ML-DSA-65 signatures are fixed-length in practice, but the length prefix
is retained for structural defensiveness rather than treating that as an
implicit protocol guarantee. The ML-KEM-768 key and ciphertext lengths are
**fixed** and carry no length prefix: a wrong length is a decode failure.

#### 6.3.2 Signature Coverage

Each signature covers a **domain-separated SHA-256 digest** of the relevant
transcript — not the raw transcript bytes, and not a bare
(non-domain-separated) hash:

```
sig_B = MLDSA_Sign(skB,
          SHA-256("mldsa-auth/v2/server-auth" || 0x00 ||
                  encode(ClientHello) || encode(ServerHello_unsigned)))

sig_A = MLDSA_Sign(skA,
          SHA-256("mldsa-auth/v2/client-auth" || 0x00 ||
                  encode(ClientHello) || encode(ServerHello)))
```

`sig_B` covers `ServerHello`'s own unsigned fields (`B_id`,
`B_ephemeral_pub`, `mlkem_ct`, `nonce_B`, `session_id_echo`) directly — not
only `ClientHello`. A construction that signed only `ClientHello` would not
authenticate anything the responder itself contributes: an attacker
modifying those fields in transit would leave `sig_B` unaffected, and while
`ClientAuth`'s later signature does bind the (already-tampered)
`ServerHello` bytes, that only proves the client saw the tampered version,
not that B ever chose it. `sig_A` covers the complete transcript up to and
including the now-signed `ServerHello`.

**Both key-exchange contributions are signed.** `A_ephemeral_pub` and
`a_mlkem_ek` are inside `ClientHello`, which both signatures cover;
`b_ephemeral_pub` and `mlkem_ct` are inside `ServerHello_unsigned`, which
both cover as well. An active attacker therefore cannot substitute either
half of the hybrid without breaking ML-DSA-65.

The domain-separation labels below are literal ASCII byte strings, each
hashed as a prefix followed by a single `0x00` separator, then the relevant
message bytes:

- `"mldsa-auth/v2/server-auth"`
- `"mldsa-auth/v2/client-auth"`
- `"mldsa-auth/v2/handshake-id"` (6.3.3)

This is standard cryptographic domain separation — distinct, label-prefixed
hash inputs stop a signature produced for one message type or protocol
version from being replayable as a signature for another. The `/v2/` labels
also make every v2 signature unusable in a v1 context and vice versa,
independently of the length differences in 6.3.1. **It is not a claim that
SHA-256 collisions are impossible.** Two domain-separated inputs are, by
construction, always distinct byte strings; two different SHA-256 *outputs*
for distinct inputs is what collision-resistance provides, not a
mathematical guarantee.

#### 6.3.3 `handshake_id`

```
handshake_id = SHA-256("mldsa-auth/v2/handshake-id" || 0x00 ||
                       encode(ClientHello) || encode(ServerHello))[0:16]
```

The full 32-byte digest is always computed first; only the finished digest
is truncated to 16 bytes — never a separately-constructed short hash.

`handshake_id` is a **lookup/demultiplexing hint carried in `ClientAuth`,
not an authentication mechanism by itself.** It lets the responder locate
which pending handshake a given `ClientAuth` belongs to among possibly-many
in flight. The responder **MUST** derive the expected `handshake_id` — and
the `TH_client_auth` digest `sig_A` is verified against — from **the exact
wire bytes of the `ClientHello` and `ServerHello` it actually received and
sent** for that pending handshake: never from values carried in the
`ClientAuth`, and never by re-serializing decoded structures. It **MAY**
compute both once, when it creates the `ServerHello` (at which point it
holds both exact byte strings), and retain only the two digests rather than
the message bytes; the reference implementation does exactly that. It
**MUST** compare the retained `handshake_id` against
`ClientAuth.handshake_id` in constant time, and **MUST still verify `sig_A`**
against the retained `TH_client_auth` before accepting anything. A wrong or
adversarially-chosen `handshake_id` can only cause a lookup miss, or — in
the event of a collision with some unrelated pending handshake — select a
candidate whose own `sig_A` verification then fails; it cannot make any
signature valid for a handshake it was not produced for, because acceptance
never depends on trusting `handshake_id` itself.

In v2 `TH_client_auth` has a second role: it is bound into the key schedule
(6.3.7), which is what makes the hybrid combiner resistant to mixing key
material across transcripts.

#### 6.3.4 Decoder Strictness

Wire-format decoding (Security Req 4.6) enforces, before any payload byte
past the point of failure is parsed:

- **Exact message-type match per message** — a `ClientHello` decoder accepts
  only `0x01`, a `ServerHello` decoder only `0x02`, a `ClientAuth` decoder
  only `0x03`. This is a real per-message-type parser boundary, not a
  generic "reject unknown type byte" filter: a well-formed message of one
  type handed to another type's decoder must fail.
- **Every declared length field validated against both its own bound** (id:
  1-64 bytes; signature: 1-3309 bytes) **and the actual remaining buffer
  size**, before the corresponding payload bytes are read. Fixed-length
  fields (X25519 keys, ML-KEM key and ciphertext, nonces, ids' contents)
  are validated by exact remaining-length checks.
- **Full-buffer consumption**: a decode succeeds only if it consumes exactly
  the number of bytes it was given — trailing bytes after an otherwise-valid
  message are rejected, never silently ignored.
- **A v1 message MUST fail a v2 decoder.** This is not a special case in the
  code; it follows from the two rules above, because v1's `ClientHello` and
  `ServerHello` are shorter than v2's by exactly the ML-KEM field and
  therefore fail the remaining-length check, and a v1 message padded to a
  v2 length fails full consumption or the signature check. This is the
  entire mechanism behind "no negotiation" (§2.1).

#### 6.3.5 Division of Responsibility (Wire Format vs. Handshake State Machine)

The wire-format/serialization layer (6.3.1-6.3.4) validates **structure
only**. The following are **not** performed at decode time and are the
handshake state machine's (Section 8, V2-5) responsibility:

- Peer identity/public-key lookup (TOFU keystore, 6.2).
- Comparing `ServerHello.session_id_echo` against the initiator's actual
  `ClientHello.session_id`.
- `handshake_id`-based pending-handshake lookup.
- Reconstructing the transcript from stored message bytes and verifying
  `sig_B`/`sig_A` against it.
- Performing X25519 and ML-KEM operations, and deriving keys.
- Pending-session lifecycle: creation, expiry, and single-use/replay
  enforcement (Security Req 4.5).

A structurally well-formed message that fails any of the above is rejected
by the state machine, not by the wire-format decoders — the decoders will
accept it as valid wire data regardless.

#### 6.3.6 Concurrency (v2)

The reference implementation is an **in-process, single-threaded** state
machine.

- The handshake context, the keystore, the responder's pending-handshake
  store, and the session object (6.4) are **not thread-safe**. Every call on
  a given session must be serialized by the caller.
- Where this specification or the implementation describes an operation as
  **atomic** — in particular the responder's commit of a verified
  `ClientAuth` (`consume_success`) — it means **logically indivisible only
  when every call into a given pending store is serialized by the caller.**
  It is a statement about the store's own state transitions under serialized
  access, not a hardware or memory-model guarantee.
- A transport or server integration **MUST** either (1) confine each pending
  store, and every responder context associated with it, to a single
  thread/event loop; or (2) apply a synchronization strategy under which
  lookup, the expiry check, signature-result handling, and the single-use
  commit behave as **one critical section** per store. Under option 2 the
  ML-DSA verification computation itself need not be held inside the
  critical section, provided the entry's state is re-validated under the
  lock before the result is recorded.
- **v2 adds one piece of cross-message secret state**: the responder's
  retained `ss_k` (6.3), which lives in its handshake context from
  `ServerHello` until `ClientAuth` is verified or the context is torn down.
  It is subject to the same confinement rule as the rest of the context, and
  to the wiping rule of Security Req 4.12.

No locking of any kind is implemented.

#### 6.3.7 Key Schedule (normative)

Each direction's 32-byte session key is:

```
ss_x = X25519(own_ephemeral_sk, peer_ephemeral_pub)   32 bytes
ss_k = ML-KEM-768 shared secret                       32 bytes
       (responder: Encaps(ek); initiator: Decaps(ct, dk))

session_key = HKDF-SHA256( IKM  = ss_x || ss_k        -- 64 bytes, this order,
                           salt = session_id          -- exactly 16 bytes,
                           info = kdf_info,
                           L    = 32 )

kdf_info =  "mldsa-auth/v2/kdf"   17 bytes, literal ASCII, no NUL
         || 0x00                   1-byte separator
         || A_id_len               1 byte, 1..64
         || A_id                   A_id_len bytes, opaque
         || B_id_len               1 byte, 1..64
         || B_id                   B_id_len bytes, opaque
         || TH_client_auth         32 bytes (6.3.3: the digest sig_A covers)
         || direction              1 byte: 0x43 ('C') for c2s, 0x53 ('S') for s2c
```

- **The hybrid combiner is the concatenation `ss_x || ss_k` as HKDF input
  keying material, in that fixed order.** HKDF-SHA256's extract step is the
  combiner; no separate construction is defined, and neither secret is ever
  used alone. If either assumption (ECDH or ML-KEM) survives, the extracted
  pseudorandom key is unpredictable.
- **`TH_client_auth` is bound into `info`.** That digest covers both
  identities, both nonces, `session_id`, both X25519 ephemeral keys, `ek`
  and `ct` (6.3.2). Binding it means a session key is valid only for the
  exact transcript that produced it, so key material cannot be transplanted
  between handshakes, and a KEM ciphertext captured from one handshake is
  useless in another even if an attacker could induce the same `(ss_x,
  ss_k)` pair. Both peers hold this digest at derivation time: the initiator
  computes it when it verifies `ServerHello`; the responder retains it in
  its pending-handshake entry.
- **`A_id` is always the initiator's identity and `B_id` always the
  responder's**, regardless of which peer is computing — both peers build
  byte-identical `kdf_info`.
- `A_id_len`/`B_id_len` are the same 1-byte lengths the wire format already
  carries (6.3.1). No other `direction` value is valid; implementations
  **MUST** reject any other byte.
- `kdf_info` is **55 bytes minimum and 181 bytes maximum**. It is built from
  explicit lengths throughout: no C-string handling, no `strlen`, no
  implicit NUL terminator.
- **Injectivity rationale.** Each variable-length identity is preceded by
  its own length byte, and the label, transcript digest and direction byte
  are all fixed-length, so any `kdf_info` byte string corresponds to at most
  one `(A_id, B_id, TH_client_auth, direction)` tuple. Adding a fixed-length
  field at a fixed position preserves the v1 injectivity argument unchanged.
- **Both secrets must be present.** An implementation that derived from
  `ss_x` alone would interoperate with itself perfectly and silently lose
  all post-quantum protection. Conformance therefore requires byte-exact
  test vectors for the derived key, computed independently of the
  implementation under test — a round-trip test between two instances of the
  same code cannot detect this class of bug.

### 6.4 Session

An ESTABLISHED handshake's two directional keys (6.3.7) protect application
data as a sequence of records, each sealed with ChaCha20-Poly1305 (IETF
variant: 12-byte nonce, 16-byte tag).

#### 6.4.1 Record Format

```
inner = content_len   2 bytes  big-endian; 0..65 534
     || content       content_len bytes
     || padding       zero or more 0x00 bytes

record = record_type  1 byte   0x04
      || seq          8 bytes  big-endian; per-direction counter, starting at 0
      || ciphertext   inner_len bytes   (AEAD-encrypted `inner`)
      || tag          16 bytes
```

- The AEAD plaintext is `inner`, not the application content: **padding is
  inside the authenticated, encrypted region**, so an attacker cannot
  observe or alter it.
- `2 ≤ inner_len ≤ 65 536`, so a record is **27 to 65 561 bytes**. The
  transport framing (6.5.1) carries the record length; the record itself
  does not.
- `0 ≤ content_len ≤ 65 534`, which is `65 536 − 2`: the largest content
  whose 2-byte prefix still fits the AEAD plaintext bound. Record and frame
  maxima are therefore unchanged from v1.
- **Sender padding policy.** A sender chooses a bucket from
  `{1, 16, 64, 256, 1024, 4096}` at session creation (the reference
  implementation defaults to 256; `1` means no padding) and sets
  `inner_len = roundup(2 + content_len, bucket)`, capped at 65 536. Every
  bucket is a power of two dividing 65 536, so the cap is never exceeded by
  rounding.
- **Receiver rules (normative).** A receiver knows nothing about the
  sender's bucket and **MUST NOT** require any particular `inner_len`. It
  **MUST**, after successful AEAD decryption:
  1. reject `inner_len < 2` as malformed;
  2. read `content_len` and reject `content_len > inner_len − 2` as
     malformed;
  3. reject the record if **any** byte after `content` is nonzero
     (Security Req 4.13).
  Each of these failures is terminal for the session, like every other
  receive failure (6.4.3).
- `record_type` shares the message-type namespace with the handshake
  (`0x01`–`0x03`, 6.3.1). `0x04` is the only record type in v2; any other
  value is malformed.
- **What padding does and does not hide.** It coarsens an observer's view of
  content length to the bucket: with bucket 256, a 1-byte and a 200-byte
  message are indistinguishable by length. It does **nothing** about message
  timing, message counts, direction, or the total volume of a session, and a
  content length above the largest bucket is still revealed to within one
  bucket. Padding is a mitigation, not a solution, for traffic analysis
  (Section 9).

#### 6.4.2 Nonce and Associated Data (normative)

```
nonce (12 bytes) = 0x00 0x00 0x00 0x00 || seq (8 bytes, big-endian)

ad (47 bytes)    = "mldsa-auth/v2/record"   20 bytes, literal ASCII, no NUL
                || 0x00                     1-byte separator
                || handshake_id             16 bytes (6.3.3)
                || direction                1 byte: 0x43 initiator->responder, 0x53 responder->initiator
                || record_type              1 byte (0x04)
                || seq                      8 bytes, big-endian
```

- Records from the initiator use the `c2s` key and direction `0x43`; records
  from the responder use the `s2c` key and direction `0x53`.
- **Nonce uniqueness.** Keys are per direction, `seq` never repeats within a
  direction (6.4.3), and a handshake's keys can seed exactly one session
  (6.4.4). So no `(key, nonce)` pair is ever used twice.
- **What the AD binds:**
  - the label binds the protocol version and the record-layer purpose;
  - `handshake_id` binds every record to the exact authenticated transcript;
  - `direction` stops reflection even if both directions ever shared a key;
  - `record_type || seq` authenticates every transmitted header byte.
- The AD does **not** cover `content_len` or the padding: both are inside
  the AEAD plaintext, which the tag already authenticates.

#### 6.4.3 Sequence, Replay and Failure Policy

- A sender assigns `seq` values 0, 1, 2, … and never reuses one: `seq` is
  reserved before encryption.
- A receiver **MUST** accept a record only if its `seq` equals the next
  expected value exactly. A lower `seq` is a replay; a higher `seq` is a
  gap, meaning a record was deleted. There is no reordering or gap
  tolerance. The transport is reliable and in-order, so a gap can only mean
  deletion or a bug.
- `seq` is checked on the header **before** any AEAD work. A forged header
  also fails authentication, because `seq` is in both the nonce and the AD.
- **Every receive failure is terminal for the whole session.** That covers a
  malformed record, replay, gap, authentication failure, a malformed inner
  plaintext or nonzero padding (6.4.1), and a peer that exceeds the hard
  record limit. The session's keys are zeroed immediately.
  - This gives an attacker who can inject into the transport nothing new,
    since that attacker can already reset the connection.
  - It limits every key to at most one failed verification.
- On authentication failure, the caller's plaintext buffer region is zeroed.
- API misuse, such as a buffer that is too small, changes no state and
  consumes no `seq`.

#### 6.4.4 Key Handoff and Initiator Confirmation

- A session is created from an ESTABLISHED handshake context, and creating
  it **consumes** that context: its keys are wiped. One handshake can
  therefore never seed two sessions, which would reuse nonces.
- A responder session is peer-confirmed from creation. `sig_A` has been
  verified, and the single-use entry has been consumed.
- An initiator session starts **unconfirmed**. It becomes confirmed on its
  first successfully authenticated record from the responder, and never
  otherwise.
  - A valid record under `s2c` requires both shared secrets. The responder
    commits its keys only after verifying `ClientAuth`. So such a record
    proves the responder accepted the handshake **and** that both sides
    derived the same hybrid key — which is also the only signal that a
    tampered `mlkem_ct` produces (6.3, Security Req 4.11).
  - Irreversible actions **MUST** be gated on this confirmation, not on the
    session existing.
- The responder **SHOULD** send a record, which may carry empty content,
  immediately after creating its session. The initiator is then confirmed
  without waiting for application data.
- The initiator **MAY** send before it is confirmed: only the authenticated
  responder can read that data. What stays unconfirmed is whether the
  responder accepted the handshake.

#### 6.4.5 Rekey and Expiry Limits

| | Soft limit: rekey due | Hard limit: refuse and expire |
|---|---|---|
| Records per direction | 2³² | 2³³ |
| Session age | 3 600 000 ms (1 h) | 3 900 000 ms (65 min) |

- **Rekey** means running a new full handshake with fresh ephemeral keys —
  in v2 that includes a fresh ML-KEM keypair and encapsulation. The soft
  limits signal that a rekey is due; the session keeps working. Either
  direction's record count, or the age, triggers it.
- At a hard limit the session refuses every further seal and open and is
  expired. Its keys are zeroed.
  - A receiver also rejects any record whose `seq` reaches the hard record
    limit, because a compliant sender never produces one.
- Age is measured on a monotonic clock from session creation. A clock that
  cannot be read, or that goes backwards, counts as expired (fails closed).
- The grace between soft and hard limits covers a rekey handshake with a
  wide margin. At a plausible peak of about 10⁷ records/s, the record grace
  of 2³² records lasts about 7 minutes, comparable to the 5-minute time
  grace.
- **These are conservative protocol-policy limits, not a derived AEAD
  bound.** They are chosen to stay well below practical ChaCha20-Poly1305
  key-usage bounds and to leave headroom for rekeying.
  - Nonce uniqueness (6.4.2) is necessary but not the only consideration.
    Aggregate data under one key, record size, and forgery bounds also
    matter.
  - At the hard limit one key protects at most 2³³ records of at most 2¹⁶
    bytes each, which is 2⁴⁹ bytes per direction.
  - Forgery exposure is capped separately by 6.4.3: at most one failed
    verification per key.
- **Limit review for v2 (normative note).** v1 required these values to be
  revisited if the maximum plaintext, the AEAD, the transport or the rekey
  policy changed. v2 changes none of them: the AEAD plaintext bound is still
  65 536 bytes (padding moved the *content* bound to 65 534 but not the
  record bound), the AEAD is unchanged, the transport is unchanged, and
  rekeying is still a full handshake. **The v1 limits therefore carry over
  unchanged**, and this review is the record of that decision. Padding
  *increases* the average bytes per record, which moves the aggregate-data
  figure closer to the bound for small messages; at 2⁴⁹ bytes per direction
  the headroom is large enough that no change is warranted.
- Implementations may let a caller tighten these limits, but never loosen
  them. The reference implementation's tests rely on this, so exercising the
  thresholds needs no test hooks.

#### 6.4.6 Session Object Lifecycle

- A session object **MUST** be zero-initialized before first use. The zero
  state is EMPTY and owns no key material.
- Creating a session is valid **only** on an EMPTY object. On any other
  object the attempt fails and changes nothing, neither the object nor the
  handshake context. A live key block is therefore never overwritten or
  leaked.
- A FAILED or EXPIRED session keeps its already-zeroed key block until it is
  wiped. Wiping frees the key block and returns the object to EMPTY. Wiping
  is idempotent and safe on an EMPTY object.
- The steady-state record path performs no heap allocation, padding
  included: the padded inner plaintext is assembled in the caller's output
  buffer, which is already sized for the record. Its only memory is the
  session's one key block, allocated at creation and freed at wipe, plus
  caller-provided record buffers.
- The **pad bucket** is a creation-time parameter alongside the rekey and
  expiry limits, and follows the same tighten-only rule in the sense that it
  may be set at creation and never changed for the life of the session. It
  is a sender-side policy and is never negotiated.

### 6.5 Reference Transport (v2)

This section specifies how the reference applications (`apps/`) carry the
protocol over TCP. It is normative for those applications and adds nothing
to the cryptographic protocol: 6.3 and 6.4 are unchanged, and the handshake
messages and records are the exact bytes those sections define.

**TCP provides no authentication.** Peer addresses and ports are never used
for any trust decision, and loopback is not treated as trusted. Identity
comes only from the ML-DSA handshake against explicitly pinned keys.

#### 6.5.1 Framing

```
frame = length (4 bytes, big-endian, unsigned) || payload (length bytes)
```

- Every handshake message and every record travels in exactly one frame.
  There is no separate frame-type byte: the payload's first byte is already
  the message type (`0x01`–`0x03` handshake, `0x04` record), and each state
  expects exactly one type.
- **Per-state limits.** The reader checks the length on the 4 header bytes,
  before reading any payload byte. A length outside the bounds ends the
  connection. The largest possible frame is the largest record: 65 561
  bytes.

| Reader state | Minimum | Maximum |
|---|---|---|
| server, awaiting ClientHello | 1 | 1 330 |
| client, awaiting ServerHello | 1 | 4 545 |
| server, awaiting ClientAuth | 1 | 3 328 |
| client, awaiting the confirmation record | 27 | 4 121 |
| session phase, both sides | 27 | 65 561 |

- The confirmation record carries **empty content**, but its length depends
  on the responder's pad bucket, which the client does not know. Its bound
  is therefore a range: 27 bytes (bucket 1: a 2-byte inner) to 4 121 bytes
  (bucket 4096: a 4 096-byte inner plus 25 bytes of record overhead). The
  client still requires the decrypted content to be **exactly empty**
  (6.4.4); that check moved from the frame length to the plaintext, where
  padding cannot confuse it.
- The length is unauthenticated and needs no authentication. A wrong length
  shifts the payload boundaries, and then the strict full-consumption
  decoders (6.3.4) or the AEAD (6.4.3) fail, which is terminal.
- Implementations **MUST NOT** assume that one read returns one frame. They
  **MUST** loop over partial reads and writes, retry interrupted system
  calls, and bound every wait by an **absolute** deadline, so a peer that
  trickles bytes cannot extend it.

#### 6.5.2 Connection Flow and Policy

1. The client sends ClientHello; the server replies with ServerHello; the
   client sends ClientAuth. Both sides then create their sessions (6.4.4).
2. The server sends one record with empty content immediately. The client
   does not send application data until that record has authenticated
   (6.4.4).
3. **Timeouts:**
   - **Handshake:** 10 s by default, absolute from accept (server) or
     connect (client) until the session is established. On the client it
     runs until the confirmation record arrives.
   - **Idle:** 30 s by default for each session-phase frame.
   - The server's handshake timeout **MUST NOT** exceed the
     pending-handshake TTL (6.3.5).
4. **ClientAuth failure closes the connection.** The server wipes the
   handshake context — which cancels its pending entry and wipes the
   retained `ss_k` (Security Req 4.12) — and closes.
   - The library still reports a signature failure below the N = 3 limit as
     retryable. That limit exists for transports where a forged message can
     arrive alongside the genuine one.
   - On a TCP stream bound to one connection, anyone who can inject bytes
     can already reset the connection. Waiting for a second ClientAuth would
     only turn a bad peer into a timeout.
5. **Any other failure also ends the connection:** a frame outside the
   bounds, a handshake or record error, a timeout, or EOF. The reference
   apps send no alert. Buffers that may have held plaintext are wiped when
   every connection ends.
6. The reference server listens on `127.0.0.1` only and handles one
   connection at a time. It owns its pending-handshake store for its whole
   lifetime, which is the confinement option of 6.3.6.

#### 6.5.3 Demo Application Protocol

Inside each record after the confirmation record, the content is
`op (1 byte) || body`:

| op | Direction | Meaning |
|---|---|---|
| `0x01` MSG | client → server | the server replies ECHO with the same body |
| `0x02` ECHO | server → client | the echoed body |
| `0x03` GOODBYE | either | authenticated close, answered by GOODBYE |

- The maximum body is **65 533 bytes**: the 65 534-byte content bound
  (6.4.1) less the op byte.
- A connection has closed in an orderly way **only** after GOODBYE has been
  exchanged. EOF without GOODBYE is reported as a failure (possible
  truncation), because a TCP close is unauthenticated.
- The confirmation record is the only record with empty content. Every later
  record must carry an op byte.
- This is application-level convention for the reference apps. It is not
  part of the cryptographic protocol, and it adds no record type.

## 7. Module Structure

```
mldsa-auth/
├── CMakeLists.txt
├── src/
│   ├── crypto/
│   │   ├── mldsa_wrap.{c,h}      # liboqs ML-DSA-65 wrapper
│   │   ├── mlkem_wrap.{c,h}      # liboqs ML-KEM-768 wrapper (v2)
│   │   ├── kex.{c,h}             # X25519 + HKDF + hybrid key schedule
│   │   └── aead.{c,h}            # ChaCha20-Poly1305 session encrypt/decrypt
│   ├── protocol/
│   │   ├── handshake.{c,h}       # handshake state machine
│   │   ├── session.{c,h}         # sequence tracking, padding, rekey, send/recv
│   │   ├── transcript.{c,h}      # wire-format serialization + transcript hashing
│   │   └── keystore.{c,h}        # TOFU public key pinning store
│   └── util/
│       ├── secure_mem.{c,h}      # sodium_malloc/memzero helpers
│       └── wire_int.{c,h}        # fixed-width integer encode/decode
├── apps/
│   ├── net_io.{c,h}              # sockets, deadlines
│   ├── frame.{c,h}               # length-prefixed framing
│   ├── demo_app.{c,h}            # demo client/server logic
│   ├── demo_keys.{c,h}           # demo key files (MLDSASK2)
│   ├── auth_server.c             # reference TCP server
│   └── auth_client.c             # reference TCP client
├── tests/                        # deterministic suite + tests/fuzz/
├── bench/                        # benchmarks and measured results
└── README.md
```

## 8. Build Steps

Execute in order. Do not proceed to the next step until the current one's
exit criteria are met. Every step is planned, approved, implemented alone,
verified, committed once and reviewed before the next begins.

**V2-1 — Specification.** This document, plus the v1-freeze decision
recorded in `docs/decisions.md` and `README.md`.
*Exit criteria: every constant cross-checked against liboqs headers and the
v1 wire macros; the v1 spec byte-identical; the freeze stated in three
places.*

**V2-2 — Dependency configuration.** ML-KEM-768 enabled, liboqs pinned by
commit SHA, `OQS_DIST_BUILD=OFF` with a build-time optimization target.
*Exit criteria: the existing suite passes unchanged in normal, ASan and
UBSan builds; symbol inspection shows exactly the ML-DSA-65 and ML-KEM-768
families; the bench environment block reports build-time selection.*

**V2-3 — ML-KEM-768 wrapper.** `mlkem_wrap` with keygen, encapsulation and
decapsulation, in the shape of `mldsa_wrap`.
*Exit criteria: liboqs's own published KAT reproduced; round trip verified;
a tampered ciphertext yields a different secret and never an error;
benchmarks for all three operations.*

**V2-4 — Wire format and key schedule.** v2 messages, v2 labels, the hybrid
KDF.
*Exit criteria: round-trip and strict-decode tests including the new fields;
a v1 message is rejected; byte-exact KDF vectors computed from literal bytes
pass (a round trip between two copies of the implementation is not
sufficient).*

**V2-5 — Handshake.** Hybrid state machine: initiator KEM keypair,
responder encapsulation and retained `ss_k`, initiator decapsulation.
*Exit criteria: the v1 adversarial suite passes on v2; a tampered ciphertext
is detected as a record-layer authentication failure; every failure path
leaves `dk` and `ss_k` wiped.*

**V2-6 — Record padding.** Padded inner plaintext, receiver validation.
*Exit criteria: exact record lengths per bucket; bucket 1 reproduces
unpadded sizes; nonzero padding and an out-of-range content length are
terminal failures; the zero-allocation gates still pass.*

**V2-7 — Integration and measurement.** Transport limits, demo apps, fuzz
corpus and dictionaries, full re-benchmark, documentation.
*Exit criteria: end-to-end demo runs; fuzz targets clean at the full time
budget; `bench/results.md` re-measured with a v1→v2 comparison.*

**V2-8 — Fuzz scanner precision.** Restrict the secret-window rule to the
genuinely secret regions of an ML-DSA secret key.
*Exit criteria: public-mode seeds scan clean; real secret-key files and
secret-region bytes are still refused.*

**V2-9 — Legacy key migration.** `MLDSASK1` → `MLDSASK2` conversion command.
*Exit criteria: a migrated file loads and its digest matches an independent
computation; corrupted input is refused; the command states that the source
file's integrity cannot be verified.*

**V2-10 — Final review and release.** Static analysis, full-tree read,
documentation verified by execution.
*Exit criteria: no defects found or all found defects fixed; every
documented command runs verbatim; `v2.0.0` tagged and released.*

## 9. Known Limitations (Document, Do Not Silently Fix)

- TOFU trust model only — no CA, no revocation. A compromised first contact
  is not detectable by this protocol.
- No protection against endpoint compromise (key exfiltration from a live
  process).
- No multi-party or group session support.
- **Traffic analysis is only partially mitigated.** Record padding (6.4.1)
  coarsens length to a bucket; message timing, message counts, direction and
  total volume remain visible, and content larger than the largest bucket is
  still revealed to within one bucket.
- **No multi-connection handshake routing.** The pending store holds digests
  only and cannot route a `ClientAuth` to the context that created its
  `ServerHello`; an integration that multiplexes handshakes must do that
  itself (6.3.3).
- **No rate limiting.** A duplicate `ClientHello` deliberately creates a
  second pending entry, because rejecting repeats would let an off-path
  attacker deny service to honest clients. Capacity and TTL bound the
  damage; rate limiting is the integrator's responsibility.
- **No thread safety** (6.3.6). Serialization is the caller's obligation.
- Demo key files are unencrypted and protected only by file permissions, and
  their integrity digest is unkeyed: it detects corruption, not tampering.
  Production key storage is out of scope.
- The reference server is loopback-only and has none of the hardening a
  public listener needs.

## 10. Decisions

**[RESOLVED in v2]** The v1 open decision — classical X25519 only, with
hybrid ML-KEM-768 deferred to a v2 milestone — is resolved by this document:
v2 uses hybrid X25519 + ML-KEM-768 (6.3, 6.3.7), and liboqs is built with
the ML-KEM-768 KEM enabled (§3).

The other decisions that shape v2 are recorded, with their reasoning, in
[decisions.md](decisions.md):

- **Clean break with no negotiation**, and **v1 frozen at `v1.0.0`**
  (upgrade-or-fork) — §2.1.
- **A separate v2 specification document**, leaving the v1 spec frozen, so
  every v1 tag still points at a specification that describes it.
- **Scope of v2**: hybrid key exchange, record padding, and four narrow
  backlog items (fuzz-scanner precision, dependency commit pin, build-time
  backend selection, legacy key migration).

No decisions are open.
