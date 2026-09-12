# mldsa-auth

Mutual authentication and an encrypted session protocol in C11: **ML-DSA-65**
(FIPS 204) identity signatures over an **X25519** key exchange, with
**HKDF-SHA256** key derivation and a **ChaCha20-Poly1305** record layer. Ships
with a reference TCP client and server, a deterministic test suite, libFuzzer
targets, and measured benchmarks.

The engineering specification is
[docs/ml-dsa-auth-protocol-spec.md](docs/ml-dsa-auth-protocol-spec.md) — the
canonical, versioned copy lives here, beside the implementation it specifies.
Every design decision and its rationale is recorded in
[docs/decisions.md](docs/decisions.md).

**Status: v1 feature-complete** (spec Steps 3–9). Wire format, handshake state
machine, record layer, reference transport, fuzzing, benchmarks and this
documentation are all done and verified.

> **Not production-ready.** The trust model is manual key pinning with no CA
> or revocation, the reference server is loopback-only, demo key files are
> unencrypted, and the library is single-threaded by design. Read
> [What this protects against](#what-this-protects-against-and-what-it-does-not)
> before using any of it for anything real.

## Build

Requirements: **CMake ≥ 3.20**, a **C11** compiler (tested with Apple clang 21
and Homebrew LLVM clang 23), `git`, and `make`. Dependencies are fetched and
built from source on first configure, which needs a network connection and a
few minutes.

```sh
cmake -S . -B build
cmake --build build -j8
```

Two constraints that will otherwise cost you an afternoon:

- **The project path must not contain spaces** — not the source directory and
  not the build directory. libsodium's Autotools/libtool build breaks on
  whitespace in its own paths, unpatchably. See
  [cmake/Dependencies.cmake](cmake/Dependencies.cmake).
- **The default build type is `Debug`**, which leaves the vendored liboqs
  unoptimized: signing is ~5.8× slower than Release. Use
  `-DCMAKE_BUILD_TYPE=Release` for anything where speed matters, and never
  benchmark a Debug build.

### Build configurations

| Configuration | Configure with | Purpose |
|---|---|---|
| Default (Debug) | `cmake -S . -B build` | Development and the test suite |
| Release | `-DCMAKE_BUILD_TYPE=Release` | Benchmarks, anything timed |
| AddressSanitizer | `-DENABLE_ASAN=ON` | Memory-safety runs of the whole suite |
| UndefinedBehaviorSanitizer | `-DENABLE_UBSAN=ON` | UB runs of the whole suite |
| libFuzzer | `-DMLDSA_FUZZ=ON` + a libFuzzer-capable clang | Coverage-guided fuzzing |

Project sources are compiled with `-Wall -Wextra -Werror
-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` (spec §4 req 8). Those
flags apply to this project's own targets only, never to the vendored
dependencies.

Apple clang does not ship the libFuzzer runtime, so the fuzz build needs a
different compiler and its own build directory:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DMLDSA_FUZZ=ON
cmake --build build-fuzz -j8
```

## Tests

```sh
ctest --test-dir build --output-on-failure
```

15 tests. `fuzz_libfuzzer` reports *Skipped* unless the tree was configured
with `-DMLDSA_FUZZ=ON`; everything else runs in every configuration.

| Test | Covers |
|---|---|
| `test_vectors` | Known-answer tests for ML-DSA-65, HKDF-SHA256 and ChaCha20-Poly1305, transcribed from RFCs and liboqs's own KAT file |
| `test_handshake` | Wire format plus the handshake state machine: happy path, tampered signatures, wrong ids, replay, transcript substitution, the pending ledger |
| `test_session` | Record format, exact nonce/AD layout, contiguous sequence policy, terminal receive failures, initiator key confirmation, rekey and expiry limits, key handoff |
| `test_session_alloc` | Zero allocation in the steady-state send/receive path, proved with a counting allocator |
| `session_no_alloc_scan` | Structural proof that `session.c` cannot allocate — a portable second gate on the same property |
| `test_net` | Reference transport over real loopback TCP: framing, socket I/O, fault injection, timeouts, and demo key files |
| `demo_e2e` | The full client/server demo end to end, including a check that no key material reaches any log |
| `fuzz_replay_*` (5) | Deterministic replay of every seed and committed regression for each fuzz target — no libFuzzer required |
| `fuzz_no_committed_secrets` | Repository gate: no ML-DSA secret-key material in any committed corpus, regression or dictionary file |
| `fuzz_libfuzzer` | Short coverage-guided run per target (skipped without `-DMLDSA_FUZZ=ON`) |
| `bench_smoke` | Every benchmark binary at tiny iteration counts, so bench code cannot rot |

Sanitizer runs use their own build directories:

```sh
cmake -S . -B build-asan -DENABLE_ASAN=ON
cmake --build build-asan -j8
ctest --test-dir build-asan --output-on-failure
```

Coverage-guided fuzzing and benchmarks have their own guides —
[tests/fuzz/README.md](tests/fuzz/README.md) and
[bench/README.md](bench/README.md):

```sh
tests/fuzz/run_fuzz.sh smoke build-fuzz
tests/fuzz/run_fuzz.sh local build-fuzz

cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j8
bench/run_bench.sh build-bench 3
```

`smoke` runs 60 s per target and `local` 600 s — the spec's Step 7 exit
criterion. Benchmarks need their own Release build directory, which is why
they do not reuse `build`.

## Demo

> **DEMO ONLY.** The key files below are an unencrypted demo format protected
> only by file permissions — not production key management. The server listens
> on `127.0.0.1` only. Keep generated keys in the git-ignored `demo-data/`
> directory and never commit them.

```sh
# 1. Generate one identity per side (the secret key file is created 0600).
./build/apps/auth_server keygen --id demo-server --dir demo-data
./build/apps/auth_client keygen --id demo-client --dir demo-data

# 2. Terminal 1: serve one connection, pinning the client's public key.
./build/apps/auth_server serve --id demo-server --key demo-data/demo-server.sk \
    --pin demo-client=demo-data/demo-client.pub --once

# 3. Terminal 2: connect, pinning the server's public key.
./build/apps/auth_client connect --id demo-client --key demo-data/demo-client.sk \
    --peer demo-server=demo-data/demo-server.pub --message "hello" --message "again"
```

The client prints its progress through the handshake and each verified echo:

```
client: ClientHello sent to 'demo-server'
client: server 'demo-server' authenticated (ML-DSA-65 signature verified against the pinned key)
client: ClientAuth sent; waiting for the responder's confirmation record
client: responder confirmed (empty authenticated record received)
client: message 1: authenticated echo verified (5 bytes)
client: message 2: authenticated echo verified (5 bytes)
client: GOODBYE exchanged; closing
client: connection finished: status=ok stage=goodbye messages=2
```

**Trust is explicit.** Each side names its peer and the file holding that
peer's public key (`--pin ID=FILE` on the server, `--peer ID=FILE` on the
client), and the id inside the file must match the id on the command line.
There is no discovery, no CA and no fallback: an unpinned peer cannot connect.

The initiator sends nothing until the responder's first authenticated record
verifies, each message comes back as an authenticated echo, and the connection
ends with an authenticated GOODBYE so truncation is distinguishable from an
orderly close. Nothing secret or decrypted is logged. Framing, limits and
timeouts are specified in spec §6.5.

**Key files.** `<id>.pub` is `"MLDSAPK1" || id_len || id || public_key`.
`<id>.sk` is `"MLDSASK2" || id_len || id || public_key || secret_key ||
SHA-256(label || 0x00 || id_len || id || public_key || secret_key)`, created
`0600` and published atomically. The digest is checked in constant time before
the key is used, so a corrupted or truncated key file is rejected at load
time — but it is **unkeyed**: it detects corruption, not tampering. Legacy
`MLDSASK1` files (Step 6) are rejected; regenerate them with `keygen`.

## Dependencies

Both are fetched from upstream at pinned versions and built from source. No
system packages are used, so a clean checkout builds identical bits.

| Dependency | Version | Pin mechanism |
|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | **0.16.0** | `FetchContent` at `GIT_TAG 0.16.0`; resolved commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` recorded in `cmake/Dependencies.cmake` |
| [libsodium](https://github.com/jedisct1/libsodium) | **1.0.22** | Release tarball pinned byte-exact by `URL_HASH` SHA-256 `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`; resolved commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda` |

liboqs is built with `OQS_MINIMAL_BUILD=SIG_ml_dsa_65`: exactly one signature
algorithm and no KEM is compiled in, so the library's algorithm surface is
only what v1 uses. libsodium is built via its own Autotools tooling from the
maintainer's release tarball, outside the build tree (see the path constraint
above).

The libsodium pin is byte-exact. The liboqs pin is by **tag**, with the
resolved commit recorded in a comment rather than enforced by the build — see
[Deferred work](#deferred-work).

## Performance

Measured, not estimated. Full tables, method and caveats:
[bench/results.md](bench/results.md).

| | |
|---|---|
| Full mutual handshake, in process | **0.372 ms** median (spec §5.1 target: < 15 ms) |
| Same handshake over TCP loopback with framing | 0.494 ms median |
| Record layer, 64 KiB payloads | 722 MiB/s sealing, 721 MiB/s opening |
| Record layer, 64 B payloads | 4.19 M records/s (239 ns per record) |

Two signatures and two verifications are 81% of the handshake; parsing,
encoding and transcript hashing together are under 2%. This is a
signature-bound protocol.

Measured on an Apple M4 Pro (arm64), Release build, median of three runs. The
spec's target names "a modern x86_64 core" and no x86_64 hardware was
available, so these are real measurements on a different architecture rather
than a literal verification of that requirement.

## What this protects against, and what it does not

### Protects against

- **Impersonation of either peer.** Both sides sign a transcript with
  ML-DSA-65 and verify it against an explicitly pinned public key. A peer
  whose key is not pinned cannot authenticate.
- **Transcript substitution and downgrade.** Each signature covers the full
  preceding transcript, so mixing messages from different handshakes, or
  altering any negotiated field, invalidates it.
- **Handshake replay.** A responder's pending entry is single-use and
  TTL-bounded, so a captured ClientAuth cannot establish a second session.
- **Record replay and reordering.** Sequence numbers must be exactly
  contiguous; a repeat, a gap or a reorder is a terminal error, not a
  warning.
- **Tampering with session data.** Every record is authenticated with
  ChaCha20-Poly1305 under per-direction keys, with the handshake identity and
  direction bound into the associated data.
- **Silent truncation.** The demo protocol ends with an authenticated
  GOODBYE, so a dropped connection is distinguishable from a clean close.
- **Key-file corruption.** Demo secret keys carry an integrity digest checked
  before use.

### Does not protect against

| | Consequence |
|---|---|
| **No CA, no revocation** (trust on first use) | A key compromised or substituted before you pinned it is undetectable by this protocol. Revoking a key means redistributing pins out of band. |
| **Endpoint compromise** | Anything that can read the process's memory or its key files has the identity. There is no hardware backing and no attestation. |
| **Classical key exchange** | X25519 is not post-quantum, so recorded session traffic is exposed to a future quantum adversary ("harvest now, decrypt later"). *Identity authentication is* post-quantum; confidentiality is not. Hybrid ML-KEM-768 is a v2 item. |
| **Traffic analysis** | v1 records are unpadded: record length reveals plaintext length plus a fixed 25-byte overhead, and timing and message counts are fully visible. |
| **Denial of service** | A duplicate ClientHello deliberately creates a second pending entry — rejecting repeats would let an off-path attacker deny service to honest clients. Capacity and TTL bound the damage; rate limiting is the integrator's responsibility. |
| **Concurrent use** | Contexts, the keystore and the pending ledger are not thread-safe. A server must confine each store to one thread or serialize access itself. |
| **Multi-party or group sessions** | Two parties only. |
| **Production key storage** | Demo key files are unencrypted, protected only by file permissions, and their integrity digest is unkeyed — it detects corruption, not tampering. Real deployments need an HSM, OS keychain, or encryption at rest. |
| **Hostile networks, in the reference server** | It binds `127.0.0.1` only and has none of the rate limiting, concurrency model or operational hardening a public listener needs. |

Neither fuzzing nor benchmarking establishes correctness. What each does and
does not prove is set out in [tests/fuzz/README.md](tests/fuzz/README.md) and
[bench/README.md](bench/README.md).

## Deferred work

Known-incomplete engineering, each recorded with its reasoning in
[docs/decisions.md](docs/decisions.md). None of these is a defect in what
ships; each is a decision to stop somewhere.

- **Multi-connection routing** — the pending ledger stores digests only and
  cannot route a ClientAuth to the context that created its ServerHello. The
  reference transport sidesteps this by handling one handshake per
  connection; a multiplexing server must route for itself.
  (§ *Pending-handshake store is a digest-only ledger*)
- **Transport rate limiting** — the deferred mitigation for duplicate
  ClientHellos. (§ *Duplicate ClientHello is accepted — an availability
  trade-off*)
- **Record padding** — deferred to a future protocol version; until then
  record length leaks plaintext length. (spec §6.4)
- **Hybrid X25519 + ML-KEM-768** — deferred to a v2 milestone.
  (§ *Key exchange: X25519 only in v1*)
- **AEAD limit review** — the two-tier rekey and hard limits are conservative
  policy values, not derived bounds, and must be revisited if the maximum
  plaintext size, the AEAD, the transport or the rekey policy changes.
  (§ *Two-tier limits*)
- **liboqs pin hardening** — pinned by tag with the resolved commit recorded
  in a comment; enforcing the SHA directly was left as a separate decision.
  ([cmake/Dependencies.cmake](cmake/Dependencies.cmake))
- **Backend selection at build time** — spec §5 req 3 asks for no runtime
  branching, but liboqs is built with `OQS_DIST_BUILD=ON` and picks its
  ML-DSA backend with a CPU-feature check per call. Step 8 measured the cost
  at 0.6–3.0%, inside run-to-run noise, so the default stands.
  (§ *Req 3 (build-time backend selection): measured, deviation kept*)
- **Fuzz scanner precision** — the secret scanner's 16-byte window rule also
  matches public-key prefixes, so it would refuse a legitimate public-mode
  fuzz regression. It over-rejects, never under-rejects.
  (§ *OPEN issue: the secret scanner's 16-byte window rule also matches
  public-key prefixes*)
- **Legacy key migration** — `MLDSASK1` files are rejected rather than
  migrated, because migrating would mean trusting an unverifiable file.
  Regenerate demo keys instead. (§ *Legacy files and the public-key format*)

## Repository layout

| Path | Contents |
|---|---|
| `src/crypto/` | Thin wrappers over liboqs and libsodium: ML-DSA, X25519, HKDF, AEAD |
| `src/protocol/` | Wire format and transcripts, handshake state machine, pending ledger, keystore, session record layer |
| `src/util/` | Secure memory, integer encoding |
| `apps/` | Reference transport (socket I/O, framing, demo key files) and the `auth_client` / `auth_server` binaries |
| `tests/` | Deterministic test suite; `tests/fuzz/` holds the fuzz targets, corpora and regressions |
| `bench/` | Benchmarks and measured results |
| `docs/` | The specification and the decision log |
| `cmake/` | Pinned dependency definitions |

Where to read next: the [specification](docs/ml-dsa-auth-protocol-spec.md) for
what the protocol is, the [decision log](docs/decisions.md) for why it is that
way, [tests/fuzz/README.md](tests/fuzz/README.md) for the adversarial testing
model, and [bench/results.md](bench/results.md) for measured performance.
