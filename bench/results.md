# Benchmark results (Step 8)

Measured 2026-09-12. Reproduce with [README.md](README.md); the raw logs and
CSVs are regenerated into `build-bench/bench-results/` and are not committed.

## Headline

| | |
|---|---|
| **Full mutual handshake, in process** | **0.372 ms median** (min 0.299 ms, p99 1.064 ms) |
| **Spec §5.1 target** | < 15 ms on a modern x86_64 core |
| **Result** | **PASS with ~40× margin** — on arm64; see *Platform caveat* |
| Same handshake over TCP loopback + framing | 0.494 ms median (transport adds ~0.122 ms) |
| Record layer, 64 KiB payloads | 722 MiB/s sealing, 721 MiB/s opening |
| Record layer, 64 B payloads | 4.19 M records/s sealed (239 ns each) |

**Platform caveat.** The spec's target names "a modern x86_64 core". No
x86_64 hardware was available; everything here was measured on an Apple M4
Pro (arm64). This is therefore a real measurement on a different
architecture, **not a literal verification of Req 5.1**. The margin is large
enough (40×) that the conclusion is unlikely to depend on the architecture,
but that is an expectation, not a measurement. The spec is deliberately left
unchanged.

## Environment

| | |
|---|---|
| Machine | Apple M4 Pro, 10 performance + 4 efficiency cores |
| OS | Darwin 25.5.0 arm64 |
| Compiler | Apple clang 21.0.0 (clang-2100.1.1.101) |
| Build | `-DCMAKE_BUILD_TYPE=Release` → `-O3 -DNDEBUG -Wall -Wextra -Werror -fstack-protector-strong` |
| liboqs | 0.16.0, ML-DSA-65 **NEON-optimized (aarch64)**, selected at **run time** (`OQS_DIST_BUILD=ON`) — *changed in V2-2, see the note at the end* |
| libsodium | 1.0.22 |
| Scheduling | `QOS_CLASS_USER_INTERACTIVE` granted (performance cores) |
| Clock | `CLOCK_MONOTONIC_RAW`, measured resolution **41.0 ns** |
| Socket buffers (loopback row) | 262144 B granted per direction (required ≥ 13844 B) |

The executing ML-DSA backend is not inferred from the build configuration:
the harness calls the same `OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)`
predicate that liboqs itself branches on, so the recorded backend is the one
that ran.

## Method

Three repetitions of each suite; every figure below is the **median of the
three run medians**. Run-to-run spread was ≤ 4% for most rows, ≤ 8% for
ML-DSA rows, and is called out where it is larger.

- Operations faster than the clock are timed in batches of *k* iterations
  (`sample / k`), with *k* calibrated to ~20 µs per batch. Rows marked
  `k = 1` are timed one call at a time.
- Stateful operations (each handshake phase, `session_open`) rebuild their
  state in a prepare step **outside** the timed region.
- One warmup batch is discarded before sampling.
- Median is the headline; min is the least noise-contaminated estimate of
  true cost; p99 exposes scheduling noise and genuine algorithmic variance.

## Handshake breakdown

The profiling breakdown the exit criterion asks for, produced whether or not
the target is met.

| Phase | Median | Min | p99 | k |
|---|---|---|---|---|
| initiator: create ClientHello | 14.62 µs | 13.29 µs | 37.96 µs | 1 |
| responder: accept ClientHello | ~42 ns † | — | 166 ns | 1 |
| responder: create ServerHello (**sign**) | 94.58 µs | 65.50 µs | 259.54 µs | 1 |
| initiator: verify ServerHello (**verify**) | 72.79 µs | 67.58 µs | 274.54 µs | 1 |
| initiator: create ClientAuth (**sign**) | 64.83 µs | 38.62 µs | 247.21 µs | 1 |
| responder: verify ClientAuth (**verify**) | 68.83 µs | 62.33 µs | 425.29 µs | 1 |
| initiator: finish (X25519 + KDF) | 38.25 µs | 32.71 µs | 299.04 µs | 1 |
| responder: finish | 3.50 µs | 2.21 µs | 19.67 µs | 1 |
| **sum of phases** | **357.5 µs** | | | |
| **end-to-end, in process** | **371.9 µs** | 299.1 µs | 1.064 ms | 1 |

† At 42 ns this row sits at the clock's 41 ns resolution — it is a bounds
check plus a copy, with no cryptography — so read it as "below what this
harness can resolve", not as a precise figure.

**Cross-check:** the phases account for 96.1% of the end-to-end median; the
14.5 µs gap is per-sample bookkeeping outside the individual phase calls.
A large discrepancy here would mean the harness was measuring something
other than it claims.

**Where the time goes.** Two signatures (159 µs) and two verifications
(142 µs) are 81% of the handshake. X25519 accounts for most of the rest:
~14.6 µs for the initiator's ephemeral keypair and ~38 µs in `finish`
(shared secret plus both key derivations). Parsing, encoding and transcript
hashing together are under 2%. **This is a signature-bound protocol**: any
future latency work belongs in ML-DSA, not in the glue.

| Transport | Median | Min | p99 |
|---|---|---|---|
| end-to-end, in process | 371.9 µs | 299.1 µs | 1.064 ms |
| end-to-end, TCP loopback + framing | 493.8 µs | 373.2 µs | 9.319 ms |

Framing plus loopback syscalls add ~122 µs (33%). The p99 of 9.3 ms reflects
scheduler wakeups on a single-process, alternating request/response
connection, not protocol work. `loopback connect + accept` was measured at
107.6 µs median but with 330% run-to-run spread — socket setup is too noisy
here to report as a stable number.

## Per-primitive costs

| Operation | Median | Min | p99 | k |
|---|---|---|---|---|
| `mldsa_keypair_generate` | 41.42 µs | 38.75 µs | 106.38 µs | 1 |
| `mldsa_sign` (32 B message) | 64.54 µs | 37.83 µs | 235.38 µs | 1 |
| `mldsa_verify` (32 B message) | 32.17 µs | 30.62 µs | 37.75 µs | 1 |
| `kex_keypair_generate` (X25519) | 15.54 µs | 14.50 µs | 39.67 µs | 1 |
| `kex_shared_secret` (X25519) | 18.10 µs | 17.19 µs | 73.52 µs | 2 |
| `kex_build_kdf_info` | 4.9 ns | 4.7 ns | 6.3 ns | 4054 |
| `kex_derive_session_key` (HKDF) | 1.07 µs | 1.02 µs | 1.34 µs | 19 |
| `transcript_hash_server_auth` | 494.0 ns | 475.6 ns | 612.8 ns | 40 |
| `transcript_hash_client_auth` | 6.42 µs | 6.17 µs | 7.73 µs | 4 |
| `transcript_handshake_id` | 6.43 µs | 6.19 µs | 8.07 µs | 4 |
| `encode_client_hello` | 4.4 ns | 4.2 ns | 15.2 ns | 2601 |
| `decode_client_hello` | 5.6 ns | 5.2 ns | 13.7 ns | 73 |
| `encode_server_hello` | 33.7 ns | 31.3 ns | 113.3 ns | 575 |
| `decode_server_hello` | 69.6 ns | 66.8 ns | 106.1 ns | 295 |
| `encode_client_auth` | 29.9 ns | 28.9 ns | 44.9 ns | 672 |
| `decode_client_auth` | 60.4 ns | 58.2 ns | 87.2 ns | 332 |
| `demo_keys_load_identity` (MLDSASK2) | 130.58 µs | 100.42 µs | 308.75 µs | 1 |

**`mldsa_sign` is the widest distribution in the system**: median 64.5 µs,
min 37.8 µs, mean 78.3 µs, p99 235.4 µs. That is ML-DSA's rejection
sampling, not measurement noise — signing retries until the candidate
signature passes its norm checks, so the iteration count varies per call.
Latency budgets should use the mean or a high percentile, not the median.
Verification has no such loop and is correspondingly tight (30.6–37.8 µs).

`transcript_hash_client_auth` and `transcript_handshake_id` cost ~6.4 µs
against 494 ns for `transcript_hash_server_auth` because they hash the full
ServerHello including its 3309-byte signature, rather than the unsigned
prefix.

`demo_keys_load_identity` at 130.6 µs is dominated by the loader's
sign/verify self-test (~97 µs); the Step 7.1 integrity digest hashes ~6 KB
and is a small part of it. It runs once at startup in the demo apps.

## Record layer throughput

Plaintext bytes per second; each record carries 25 bytes of overhead
(9-byte header + 16-byte tag).

| Payload | Operation | Median | Throughput | Records/s |
|---|---|---|---|---|
| 64 B | `session_seal` | 238.8 ns | 255.5 MiB/s | 4.19 M |
| 64 B | `session_open` | 238.3 ns | 256.1 MiB/s | 4.20 M |
| 64 B | seal + open | 477.7 ns | 127.8 MiB/s † | 2.09 M |
| 1 KiB | `session_seal` | 1.49 µs | 655.2 MiB/s | 671 k |
| 1 KiB | `session_open` | 1.50 µs | 650.5 MiB/s | 667 k |
| 1 KiB | seal + open | 3.01 µs | 324.2 MiB/s † | 332 k |
| 64 KiB | `session_seal` | 86.62 µs | 721.5 MiB/s | 11.5 k |
| 64 KiB | `session_open` | 86.71 µs | 720.8 MiB/s | 11.5 k |
| 64 KiB | seal + open | 172.92 µs | 361.4 MiB/s † | 5.8 k |

† The round-trip rows count each plaintext byte once while doing both
operations, so they are "one message delivered", not a halved throughput.

**Record-layer overhead is negligible.** At 64 KiB, `session_seal` (86.62 µs)
is within 0.2% of raw `aead_encrypt` (86.50 µs). At 64 B the protocol adds
29 ns over raw AEAD (239 ns vs 210 ns) for associated-data construction,
sequence handling and limit checks. Small records are dominated by
per-record cost: 64 B payloads move 255 MiB/s against 722 MiB/s at 64 KiB.

## Build-time vs run-time backend selection (spec Req 3)

Req 3 asks for the optimized backend to be "selected at build time — no
runtime branching in hot paths". The default build has `OQS_DIST_BUILD=ON`:
both the reference and aarch64 backends are compiled in and each
`sign`/`verify` call takes a CPU-feature branch. A comparison build
(`OQS_DIST_BUILD=OFF`, `OQS_OPT_TARGET=native`) fixes the choice at compile
time.

| Operation | Runtime dispatch (default) | Build-time selection | Delta |
|---|---|---|---|
| `mldsa_sign` | 64.54 µs | 62.62 µs | −3.0% |
| `mldsa_verify` | 32.17 µs | 31.25 µs | −2.9% |
| `mldsa_keypair_generate` | 41.42 µs | 40.58 µs | −2.0% |
| handshake, in process | 371.9 µs | 369.8 µs | −0.6% |

**The deviation costs nothing measurable.** The differences are 0.6–3.0%,
smaller than the 7–8% run-to-run spread of the ML-DSA rows themselves, so
they are not distinguishable from noise in this data. Both builds run the
same NEON backend; the branch is one CPU-feature test per call against tens
of microseconds of lattice arithmetic.

Changing the default is therefore **not justified on performance grounds**,
and it would cost portability: a `native`, non-dist build produces binaries
tied to the build machine's CPU. The Req 3 deviation is documented in
`docs/decisions.md`; revisiting it is a separate, narrow decision.

## Build type

The project's default build type is `Debug`, and liboqs inherits it.

| Operation | Debug | Release | Ratio |
|---|---|---|---|
| `mldsa_keypair_generate` | 225.3 µs | 41.4 µs | 5.4× |
| `mldsa_sign` | 375.9 µs | 64.5 µs | 5.8× |
| `mldsa_verify` | 191.5 µs | 32.2 µs | 5.9× |
| handshake, in process | 1.481 ms | 0.372 ms | 4.0× |

A Debug handshake still meets the 15 ms target, but every Debug figure
describes an unoptimized ML-DSA. libsodium is unaffected (it is an
ExternalProject built with its own Autotools defaults), so a Debug run
misleadingly pairs slow signatures with normal-speed AEAD. **Benchmark only
Release builds.**

## What these numbers do not establish

- **Not correctness.** Speed says nothing about whether the protocol is
  right; that is what `tests/` and `tests/fuzz/` are for.
- **Not a network result.** The loopback figure includes framing and
  syscalls, and excludes latency, loss, MTU and congestion.
- **Not multi-machine.** One machine, one OS, one compiler, no contention,
  no thermal pressure beyond a minute-long run.
- **Not the spec's stated platform.** arm64 measured against an
  x86_64-worded target.

---

## Re-measured after V2-2 (2026-09-12)

V2-2 turned off liboqs's runtime backend dispatch (`OQS_DIST_BUILD=OFF`,
`OQS_OPT_TARGET=auto`) and enabled ML-KEM-768. The environment block now
reads *"NEON-optimized (aarch64), selected at build time (OQS_DIST_BUILD=OFF:
no per-call branch)"*. Three repetitions on the reconfigured `build-bench`:

| | V2-2 | Step 8 (runtime dispatch) | Step 8 (comparison build) |
|---|---|---|---|
| Handshake, in process | **0.364 ms** | 0.372 ms | 0.370 ms |
| `session_seal`, 64 KiB | 727 MiB/s | 722 MiB/s | — |
| `session_open`, 64 KiB | 727 MiB/s | 721 MiB/s | — |
| `mldsa_sign` | 63.4 µs | 64.5 µs | 62.6 µs |
| `mldsa_verify` | 31.5 µs | 32.2 µs | 31.3 µs |

As Step 8's comparison predicted, removing the per-call CPU-feature branch
is **not a measurable speed-up**: the differences are inside the 7–8%
run-to-run spread of the ML-DSA rows. The change was made for Security
Req 4.10 conformance, not performance.

These numbers still describe **v1 protocol code**; ML-KEM-768 is compiled in
but not yet called by any code path. The full v1→v2 comparison, including
the hybrid handshake and padding, is measured in V2-7.

## ML-KEM-768 primitives (V2-3)

Measured on the V2-2 configuration (3 repetitions, medians of run medians).
The environment block now carries an `ml-kem backend` line alongside
`ml-dsa backend`; both read "NEON-optimized (aarch64), selected at build
time".

| Operation | Median | Min | p99 |
|---|---|---|---|
| `mlkem_keypair_generate` | 14.62 µs | 12.54 µs | 35.96 µs |
| `mlkem_encaps` | 8.96 µs | 8.64 µs | 12.26 µs |
| `mlkem_decaps` | 10.42 µs | 10.12 µs | 14.48 µs |

For scale, on the same run: `mldsa_sign` 63.0 µs, `mldsa_verify`
30.9 µs, X25519 keypair 14.8 µs, X25519 shared secret
17.6 µs. **All three ML-KEM operations together cost 34.0 µs** —
about a sixth of one ML-DSA signature, and roughly what one X25519 keypair
plus one shared secret costs. Every ML-KEM row is also far tighter than
`mldsa_sign`, which has no rejection-sampling loop to vary.

**No protocol path calls these yet.** The handshake becomes hybrid in V2-5;
the measured v1 → v2 handshake comparison is V2-7's. On these figures the
hybrid handshake should gain roughly 34 µs (one keypair + one encaps
+ one decaps, split across the two peers), which would put it near 0.40 ms
against the 15 ms target — an arithmetic expectation, not a measurement.
