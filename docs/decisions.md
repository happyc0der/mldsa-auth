# Protocol Decisions (through Step 4)

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
