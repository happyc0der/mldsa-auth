# mldsa-auth

[![CI](https://github.com/happyc0der/mldsa-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/happyc0der/mldsa-auth/actions/workflows/ci.yml)

Mutual authentication and an encrypted session protocol in C11: **ML-DSA-65**
(FIPS 204) identity signatures over a **hybrid X25519 + ML-KEM-768**
(FIPS 203) key exchange, with **HKDF-SHA256** key derivation and a padded
**ChaCha20-Poly1305** record layer. Ships with a reference TCP client and
server, a deterministic test suite, libFuzzer targets, and measured
benchmarks.

The engineering specifications live here, beside the implementation they
specify: [v1](docs/ml-dsa-auth-protocol-spec.md) (frozen) and
[v2](docs/ml-dsa-auth-protocol-spec-v2.md) (current). Every design decision
and its rationale is recorded in [docs/decisions.md](docs/decisions.md).

**Status: `v2.0.0`.** Every normative element of the v2 specification is
implemented and verified — hybrid X25519 + ML-KEM-768 key exchange, the v2
wire format and labels, the hybrid key schedule, the hybrid handshake, and
padded records. The release tree was verified end to end rather than
step by step: normal, ASan and UBSan suites (15/15 each, instrumentation and
build-currency proven before each result), 56 mutations re-run across seven
campaigns, the full fuzz corpus, clang-tidy, scan-build and `-Weverything`.
What that verification does and does not establish is recorded in
[docs/decisions.md](docs/decisions.md) under *V2-10*.

> **v1 is frozen at the [`v1.0.0`](https://github.com/happyc0der/mldsa-auth/releases/tag/v1.0.0)
> tag and receives no patches — upgrade or fork.** v2 is a deliberate clean
> break with no version negotiation, and it deletes v1's key-schedule, wire
> and handshake code rather than maintaining two protocol tracks. v2 adds a
> **hybrid X25519 + ML-KEM-768 key exchange** (so session confidentiality
> becomes post-quantum, not just identity authentication) and **record
> padding**. It is specified in
> [docs/ml-dsa-auth-protocol-spec-v2.md](docs/ml-dsa-auth-protocol-spec-v2.md);
> the reasoning for the break and the freeze is in
> [docs/decisions.md](docs/decisions.md). `main` now speaks v2 only; a v2
> peer and a v1 peer cannot interoperate, by design.

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
| Portable binaries | `-DMLDSA_OQS_OPT_TARGET=generic` | Anything you distribute (see below) |

Project sources are compiled with `-Wall -Wextra -Werror
-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` (spec §4 req 8). Those
flags apply to this project's own targets only, never to the vendored
dependencies.

**`MLDSA_OQS_OPT_TARGET` decides portability.** It defaults to `auto`,
which tunes liboqs for the building machine's CPU (`-mcpu=native` /
`-march=native`) — fast, but the binary may fault on an older CPU of the same
family. Build anything you ship with `generic`, the portable baseline; on
x86_64 that gives up liboqs's AVX2 backends. Any other value is passed to the
compiler as a CPU name, and an unrecognised one fails the build rather than
silently degrading.

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
| `test_vectors` | Known-answer tests for ML-DSA-65, **ML-KEM-768**, HKDF-SHA256 and ChaCha20-Poly1305, transcribed from RFCs and liboqs's own KAT files, plus ML-KEM implicit rejection and FIPS 203 input validation |
| `test_handshake` | Wire format plus the handshake state machine: happy path, tampered signatures, wrong ids, replay, transcript substitution, the pending ledger, and the v2 additions — ML-KEM field layout at literal offsets, v1 messages rejected, byte-exact hybrid-KDF vectors, and hand-built-peer oracles that pin the hybrid keys independently |
| `test_session` | Record format, exact nonce/AD layout, contiguous sequence policy, terminal receive failures, initiator key confirmation, rekey and expiry limits, key handoff, the KEM-disagreement failure mode end to end, padded-inner sizes and receiver rules at every bucket, and the `pt_cap` sizing rule |
| `test_session_alloc` | Zero allocation in the steady-state send/receive path, proved with a counting allocator |
| `session_no_alloc_scan` | Structural proof that `session.c` cannot allocate — a portable second gate on the same property |
| `test_net` | Reference transport over real loopback TCP: framing, socket I/O, fault injection, timeouts, demo key files, asymmetric pad buckets on the wire (27/281/4121-byte confirmation records), and legacy-key migration |
| `demo_e2e` | The full client/server demo end to end — three times: default padding, mismatched `--pad-bucket` policies, and a migrated legacy key authenticating against the original pin — including a check that no key material reaches any log |
| `fuzz_replay_*` (5) | Deterministic replay of every seed and committed regression for each fuzz target — no libFuzzer required |
| `fuzz_no_committed_secrets` | Repository gate: no ML-DSA secret-key material in any committed corpus, regression or dictionary file — and the scanner proves its own rules on sixteen built-in controls before every scan |
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

### Continuous integration

The badge above is [`.github/workflows/ci.yml`](.github/workflows/ci.yml),
and it means exactly this, on every push and pull request: the 15-test suite
in debug, ASan and UBSan builds on `ubuntu-latest` (x86_64) and
`macos-latest` (arm64), plus a gcc build on Linux; every suite run preceded
**in the same step** by `tools/check_build_current.sh` and, for the sanitizer
jobs, `tools/check_sanitizer_link.sh`; and on Linux only — Apple clang ships
no libFuzzer runtime — the fuzz-labelled tests, `run_fuzz.sh smoke` (60 s per
target, any crash or artifact fails the job) and the repository secret scan.
The macOS jobs build liboqs with `-DMLDSA_OQS_OPT_TARGET=generic`, because
`-mcpu=native` on GitHub's arm64 runner enables no crypto extensions and
liboqs's ARMv8 SHA-2 will not compile there; a macOS tick therefore vouches
for the portable target, not the default one. The 600 s fuzz budgets and the
56-mutation suite are not run per push. Each of these gates has been shown to
turn the badge red when broken — the four controls and what each one
produced are in [docs/decisions.md](docs/decisions.md) under *V3-3*.

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

**Record padding.** Both binaries accept `--pad-bucket 1|16|64|256|1024|4096`,
which sets *that peer's* sending policy only (default 256; 1 means no
padding). Nothing is negotiated and the receiver is not told: it accepts any
bucket the sender chose, so the two sides may differ.

```sh
# Server pads every record it sends to a multiple of 4096; client sends unpadded.
./build/apps/auth_server serve --id demo-server --key demo-data/demo-server.sk \
    --pin demo-client=demo-data/demo-client.pub --once --pad-bucket 4096
./build/apps/auth_client connect --id demo-client --key demo-data/demo-client.sk \
    --peer demo-server=demo-data/demo-server.pub --message "hello" --pad-bucket 1
```

Each side logs the bucket it is using (`record padding: bucket 4096`).

> **Sizing your receive buffer.** Because the *sender* picks the bucket, an
> "empty" record is not a small record: with `--pad-bucket 4096` the empty
> confirmation is 4121 bytes on the wire. Size the `pt_cap` you pass to
> `session_open()` from the largest **record** you are willing to accept —
> `SESSION_OPEN_CAP_FOR(SESSION_MAX_RECORD_BYTES)` (65536) in the session
> phase, `SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX)` (4096) for the
> confirmation — never from the content length you expect. Sizing it from the
> content is the one way to get this contract wrong, and it is not
> hypothetical: it is the mistake V2-6 made in `tests/test_net.c`, where a
> one-byte buffer for an empty message caused every failure in that file.

**Migrating a legacy key.** A Step 6 `MLDSASK1` file has no integrity digest,
so the loaders refuse it. `migrate-key` converts one — into a **new** file,
never in place, never overwriting:

```sh
./build/apps/auth_server migrate-key --id demo-server \
    --in demo-data/old-demo-server.sk --out demo-data/demo-server-v2.sk
```

The identity is preserved, so peers' existing pins keep working. What the
command cannot do is verify the source: a legacy file carries no digest, and
the only available check is a sign/verify self-test that Step 7 measured
accepting a corrupted `t0` component in 11 of 20 cases. It therefore prints,
on every success, that **the digest in the new file certifies the key bytes as
they are now, not as `keygen` wrote them**. If the identity matters, regenerate
it and re-pin instead.

**Key files.** `<id>.pub` is `"MLDSAPK1" || id_len || id || public_key`.
`<id>.sk` is `"MLDSASK2" || id_len || id || public_key || secret_key ||
SHA-256(label || 0x00 || id_len || id || public_key || secret_key)`, created
`0600` and published atomically. The digest is checked in constant time before
the key is used, so a corrupted or truncated key file is rejected at load
time — but it is **unkeyed**: it detects corruption, not tampering. Legacy
`MLDSASK1` files (Step 6) are rejected by the loaders; regenerate them with
`keygen`, or convert one with `migrate-key` (below) when the identity's public
key is already pinned by peers.

## Dependencies

Both are fetched from upstream at pinned versions and built from source. No
system packages are used, so a clean checkout builds identical bits.

| Dependency | Version | Pin mechanism |
|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | **0.16.0** | Fetched at `GIT_TAG 0.16.0`, then **verified against commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`** — at population and again at every configure (`cmake/VerifyLiboqsCommit.cmake`) |
| [libsodium](https://github.com/jedisct1/libsodium) | **1.0.22** | Release tarball pinned byte-exact by `URL_HASH` SHA-256 `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`; resolved commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda` |

liboqs is built with `OQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"`:
exactly one signature algorithm and one KEM, so the library's algorithm
surface is only what the protocol uses. The backend is selected at build
time (`OQS_DIST_BUILD=OFF`), so no CPU-feature branch is taken per
cryptographic call. libsodium is built via its own Autotools tooling from the
maintainer's release tarball, outside the build tree (see the path constraint
above).

**Both pins are exact and neither trusts a mutable ref.** libsodium is
pinned by the SHA-256 of its release tarball. liboqs is *fetched* by tag —
CMake forbids a shallow clone of a bare commit — and then *verified* against
the pinned commit, twice: once when the source is first populated, before
liboqs's own CMake runs, and again on every configure, which also covers
`-DFETCHCONTENT_SOURCE_DIR_LIBOQS=<dir>`. Either mismatch aborts the build
naming both hashes.

## Performance

Measured, not estimated. Full tables, method and caveats:
[bench/results.md](bench/results.md).

| | |
|---|---|
| Full hybrid mutual handshake, in process | **0.450 ms** median (spec-v2 §5.1 target: < 15 ms) |
| Same handshake over TCP loopback with framing | 0.598 ms median |
| Record layer, 64 KiB payloads, default bucket | 736 MiB/s sealing, 723 MiB/s opening |
| Record layer, 64 B payloads | 301 ns to seal unpadded, 480 ns at the default bucket 256 |

Two ML-DSA signatures and two verifications still dominate: the four phases
containing them are 342 µs of the 450 µs median (76%). The hybrid costs
+86 µs against v1: 33 µs of it is ML-KEM itself (keygen 14.2 µs, encaps
8.7 µs, decaps 10.3 µs) and the rest is hashing and signing the 2.3 kB the
two new fields add to the transcript. Encoding and decoding all six messages
costs 258 ns together. **This is still a signature-bound protocol.**

Padding is a sender-side choice with a measurable price on small messages: a
64-byte round trip costs 605 ns unpadded and 1.29 µs at the default bucket,
and nothing at 64 KiB, where there is nothing left to pad.

Measured on an Apple M4 Pro (arm64), Release build, median of three runs. The
spec's target names "a modern x86_64 core" and no x86_64 hardware was
available, so these are real measurements on a different architecture rather
than a literal verification of that requirement.

## What this protects against, and what it does not

### Protects against

- **Impersonation of either peer.** Both sides sign a transcript with
  ML-DSA-65 and verify it against an explicitly pinned public key. A peer
  whose key is not pinned cannot authenticate.
- **Harvest-now-decrypt-later.** Session keys are derived from an X25519 and
  an ML-KEM-768 shared secret *together*, both ephemeral and both bound to the
  transcript, so traffic recorded today stays confidential against a future
  quantum adversary as long as either half holds.
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
| **A break of *both* key-exchange halves** | Session keys come from X25519 **and** ML-KEM-768 together, so confidentiality survives the failure of either one. It does not survive the failure of both, and the post-quantum half rests on ML-KEM-768's own security — newer and less studied than X25519's. The hybrid is there precisely because that assumption might not hold. |
| **Traffic analysis** | Partially mitigated. v2 records are padded to a sender-chosen bucket (default 256 bytes), so record length reveals content length only to within that bucket. Timing, message counts, direction and total session volume remain fully visible. |
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
- **Traffic-analysis resistance beyond padding** — v2 pads record lengths,
  but message timing, counts and direction are unprotected; no cover traffic
  and no constant-rate sending. (spec-v2 §6.4.1, §9)

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
| `tools/` | Verification scripts (mutation campaigns, sanitizer-link checking); not part of the build |

## License

Copyright (C) 2026 happyc0der.

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU General Public License, version 3**, as published by
the Free Software Foundation. It is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE)
for the full text.

The dependencies are fetched and built from source, not vendored here, and
both are GPL-compatible: [liboqs](https://github.com/open-quantum-safe/liboqs)
is MIT and [libsodium](https://github.com/jedisct1/libsodium) is ISC. A binary
built from this repository combines all three, and the combined work is
covered by the GPL.

Where to read next: the [specification](docs/ml-dsa-auth-protocol-spec.md) for
what the protocol is, the [decision log](docs/decisions.md) for why it is that
way, [tests/fuzz/README.md](tests/fuzz/README.md) for the adversarial testing
model, and [bench/results.md](bench/results.md) for measured performance.
