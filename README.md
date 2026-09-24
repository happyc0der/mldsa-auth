# mldsa-auth

[![CI](https://github.com/happyc0der/mldsa-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/happyc0der/mldsa-auth/actions/workflows/ci.yml) [![Nightly](https://github.com/happyc0der/mldsa-auth/actions/workflows/nightly.yml/badge.svg)](https://github.com/happyc0der/mldsa-auth/actions/workflows/nightly.yml)

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

**Status: `v2.0.0` is current.** Every normative element of the v2
specification is implemented and verified — hybrid X25519 + ML-KEM-768 key
exchange, the v2 wire format and labels, the hybrid key schedule, the hybrid
handshake, and padded records. The release tree was verified end to end rather
than step by step: normal, ASan and UBSan suites (15/15 each, instrumentation
and build-currency proven before each result), 56 mutations re-run across seven
campaigns, the full fuzz corpus, clang-tidy, scan-build and `-Weverything`.
What that verification does and does not establish is recorded in
[docs/decisions.md](docs/decisions.md) under *V2-10*.

Since `v2.0.0` the repository has grown a second artefact: **`mldsa-authd`**, a
daemon that turns the protocol into a login system — a device authenticates
with the post-quantum handshake and receives a single-use login code, which a
site exchanges over a local Unix socket for an opaque session token. Devices can
be enrolled, revoked, and **rotate their keys** while keeping their identity.
It has its own specification ([docs/mldsa-authd-spec.md](docs/mldsa-authd-spec.md)),
its own store, its own CLIs, and nothing in it changes a byte on the wire. Browsers reach it as a **WebSocket** behind a TLS
proxy, which states the client's address in a PROXY v2 preamble the daemon
rate-limits on. It is **installable but not deployed** — a distinction worth keeping.
What exists and is proven: an `install()` target, probed link hardening gated
on the install tree by `check_hardening.sh --require`, a systemd unit checked
by systemd's own analysers rather than by review, an offline dependency cache
that still enforces every pin (proven by a build with the network switched
off), a daemon that warns when its locked-memory limit is too small to keep
secrets off disk, and [deploy/RUNBOOK.md](deploy/RUNBOOK.md) — a numbered
checklist from an empty VPS to a first login. What does not exist is a running
deployment: nobody has executed that checklist against a real host, and until
someone does, the runbook is where the remaining risk lives. See
*The authentication daemon* below for what works today and what does not.

Since `v2.0.0` the verification has been **automated rather than changed**: the
library, the reference apps and the build are byte-identical to the `v2.0.0`
tag, and what was a one-off retrospective now runs on every push and every
night (see *How this is verified*). That work carries its own `v3-step*` tags
and deliberately **no version bump** — a new number would advertise a change
to the code that does not exist.

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
-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2` (spec §4 req 8), and linked
with `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` and PIE where the toolchain
accepts them. Both sets apply to this project's own targets only, never to the
vendored dependencies — which is why they are set per target rather than
globally.

The link flags are **probed, not assumed**: `check_linker_flag()` and
`check_pie_supported()` decide, so a toolchain that rejects one simply does not
get it (macOS `ld` rejects `-z` outright). What is actually present is read back
out of the built binaries by
[`tools/audit/check_hardening.sh`](tools/audit/check_hardening.sh), which reads
Mach-O and ELF rather than the build files:

```sh
tools/audit/check_hardening.sh build-release --require
```

On Mach-O it reports RELRO and BIND_NOW as `n/a` — they are ELF concepts — so
`--require` there gates three properties, not five. **Run it on Linux if you
want it to mean something.**

### Installing, and building something you would deploy

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
      -DMLDSA_OQS_OPT_TARGET=x86-64-v3
cmake --build build-release -j8
cmake --install build-release --prefix /usr/local --component mldsa-authd
```

That installs `mldsa-authd`, `authd_admin` and `authd_client`, plus the service
unit and the example configs under `share/mldsa-authd/` — six files, and
nothing else. `x86-64-v3` is the x86_64 choice; on arm64 name an arm64 CPU
(`-DMLDSA_OQS_OPT_TARGET=neoverse-n1`, say). What matters is that it is
*named*: the `auto` default tunes for the building machine and the binary may
fault on an older CPU of the same family. **Pass `--component`**: liboqs is vendored with FetchContent and
brings its own install rules, so a bare `cmake --install` would additionally
drop a pin-locked, `-march`-tuned `liboqs.a` and its headers into your prefix,
where another build on that host could find and link it. Name the CPU target —
never ship the `auto` default, for the reason below. [`deploy/RUNBOOK.md`](deploy/RUNBOOK.md)
is the rest: users, directories, credentials, the proxy, the backup drill.

**Offline or air-gapped?** Fetch the three dependencies once on a networked
machine and carry the cache across; every hash and commit pin is still
enforced, and an offline configure checks the liboqs pin **three** times rather
than two:

```sh
sh deploy/fetch-deps.sh /opt/mldsa-deps       # networked machine, once
chown -R "$(id -un)" /opt/mldsa-deps          # git will not read another user's repo
cmake -S . -B build-release -DMLDSA_DEPS_CACHE=/opt/mldsa-deps ...
```

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

35 tests. `fuzz_libfuzzer` reports *Skipped* unless the tree was configured
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
| `test_authd_cli` | The two command-line tools driven in-process: `init` refusing an existing store and leaving it byte-identical, the sealed key opening with the passphrase **as written to the file**, spec §12's per-role Argon2id parameters read back out of the header, `rewrap` refusing a wrong passphrase and refusing to work in place, a `.pub` whose embedded id differs from `--handle`, both binaries' `--check-config` reporting the same status name, and the one list-framing table measured against a live daemon's actual replies |
| `authd_e2e` | Milestone A with the shipped binaries as real processes, in the **deployed** proxy configuration (`proxy_protocol = v2`): `init` → daemon → `keygen` → `enroll-operator` → `login` → the Node site handler exchanging and verifying → the admin queries. Also that no plaintext secret key is written anywhere (Req 10), that a login refuses a ServerHello not signed by the pinned key, that a listener failure runs its cleanup epilogue, that `audit-verify` accepts the real chain and rejects one with a single tampered row while blaming the key rather than the chain for a wrong passphrase, and that no passphrase or login code reaches a log. Since V4-13a it also drives the client's **rotation recovery** against the real daemon: a stale `.ek.next` beside a live `.ek` (logs in, reports it, deletes nothing), neither file authenticating (refuses, both files byte-identical), and an interrupted rename (the next login completes it) |
| `test_authd_keyfile` | The `MLDSAEK1` key-at-rest envelope: seal/open round trip, header-as-AAD, KDF parameter bounds on both sides, a tamper sweep over every header field, `O_NOFOLLOW`, and the KEK out-parameter (filled on success, identical on re-derive, zeroed on failure). Since V4-13a the **buffer** forms too — parity with the file forms in both directions (same key, same KEK), `keyfile_write_sealed` refusing anything that is not a well-formed envelope and never overwriting — and `MLDSAPK1` in memory: `bob` vs `bobby` and `bob` vs `bot`, one trailing byte, parity with the file loader |
| `test_authd_store` | The daemon's SQLite store: schema-enforced invariants (one active key per handle, a public key unique forever), the three-join active lookup, Req 7 re-enrollment refusal, rotation atomicity proven by injecting a fault mid-rotation and reopening, audit-chain MAC verification with tamper and truncation detection, token/login-code lifetimes and the login-CSRF state binding, and backup/restore |
| `test_authd_evloop` | The daemon's transport skeleton: strict `key = value` config parsing (unknown/duplicate/out-of-range/missing all refused, and a failed parse applies nothing), frame reassembly at every split point of a two-frame stream, the fixed slot pool and its refusal at capacity, deadline enforcement with a lower bound on both sides, graceful drain, slot wiping on release, log hygiene with a present canary, and the locked-memory check driven under a genuinely lowered `RLIMIT_MEMLOCK` — both sides of the boundary from literals, with a present canary proving the sufficient case is reachable, so "the limit is too small" cannot pass by always being true |
| `test_authd_conn` | The daemon's connection state machine, driven with the daemon in-process and the real library initiator over loopback: a full login (first record `LOGIN_CODE`, 43 bytes of content in a 281-byte record, expiry within Req 5's 60 s), the login code stored only as SHA-256 and bound to user/handle/handshake/state, single-use, the uniform responder (unknown handle and known-handle-wrong-key indistinguishable, with a canary proving the decoy still yields a verifiable ServerHello), revocation taking effect at the next handshake, `BYE` closing cleanly while `ROTATE` is refused `ERROR(0x02)`, and wipe-on-close |
| `test_authd_ws` | The WebSocket carrier and the proxy in front of it: RFC 6455's accept KAT and the FIPS 180-1 vectors for the vendored SHA-1, the upgrade's refusals enumerated, an unmasked client frame failing the connection, the same login run over both transports with the URL `state` bound into the login code (Req 5), the PROXY v2 preamble parsed and split at **every** offset, `LOCAL` and `AF_UNIX` carrying no client address, a peer outside the proxy's uid allowlist refused at accept with a canary that an allowed one is served, and the rate limiter's boundaries driven by an injected clock — including that a refused connection cost no `ServerHello` signature |
| `test_authd_localapi` | The local socket protocol (spec §8): the line grammar and its 8192-byte cap, the two dispatch tables (an administrative command is *absent* from the site table, and its refusal is byte-identical to a nonsense command's), `EXCHANGE` with the login-CSRF state binding and single use, `VERIFY` with the idle-window slide and its lower bound, `LOGOUT` counts, enrollment including Req 7 refusal and idempotence, the periodic sweep, revocation closing live sessions (Req 9), and log hygiene — the peer's uid/pid present, the token and code absent |
| `test_client_core` | The client core (V4-13a) — the code `authd_client` runs and the browser build will. Against the **in-process daemon over raw and WebSocket**: a login whose code the site socket `EXCHANGE`s for a token; a ServerHello not signed by the pinned key refused with not one byte of ClientAuth written (spec §4); a rotation the daemon acknowledges, after which only the new key logs in; the injected clock governing the session. Against a **fake server**, for what the daemon never sends: `BYE` or `ERROR` as the first record, a `ROTATE_ACK` naming another key, a same-length other handle or a prefix of the handle. And the secret key's lifetime (freed when ClientAuth is built and on refusal), frame header vs size, every envelope header byte flipped, and the browser's Argon2id parameters |
| `test_client_core_kat` | A deterministic generator (test only) with liboqs routed to it through the core; one device lifetime; the SHA-256 of 11 artefacts must match `tests/golden/client_core_kat.txt` and two in-process runs must match each other. The golden is the contract the wasm build (V4-13b) must reproduce. Links the client libraries only — no daemon |
| `client_links_no_sqlite` | `authd_client` contains no `sqlite3_` and no `store_` symbol, read from the linked binary; the daemon is the canary that must contain both. `client_links_no_sqlite_control` runs the same check on the daemon and is expected to fail |
| `site_node_handler` | The Node reference handler in `examples/site-node/` against a **real daemon** (a genuine handshake, a real login code): exchange, verify, logout, list-devices, the state binding, and that administrative commands are unreachable from the site socket |
| `fuzz_replay_*` (12) | Deterministic replay of every seed and committed regression for each fuzz target — no libFuzzer required |
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

The **Nightly** badge is [`.github/workflows/nightly.yml`](.github/workflows/nightly.yml):
at 03:17 UTC every day, and on demand, **all 192** must-kill mutations in
[`tools/mutations/`](tools/mutations/) run as one campaign per step against a
fresh Linux ASan tree — gated by a job that first checks every campaign's
anchor still matches its source exactly once, because a rotted anchor aborts
the runner and finding that out after three hours of mutation runs costs three
hours — and all twelve fuzz targets run for 600 s with any crash kept as a
downloadable artifact. Every committed campaign is in a matrix, and that is
now checked rather than remembered: a job asserts that each
`tools/mutations/spec_*.txt` appears in one, and that no matrix names a
campaign that does not exist. Eight campaigns had previously been committed
with their step and then run nowhere until someone recalled the bring-up, which
is not a habit worth trusting. It is not part of the push gate. GitHub
disables scheduled workflows after 60 days without a commit, so a badge that
has stopped updating is not a badge that is passing — check the date on it.

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

## The authentication daemon (milestone A)

The daemon (`mldsa-authd`) turns the protocol into a login system: a device
authenticates with a post-quantum handshake and receives a single-use **login
code**, which the site exchanges over a local Unix socket for an opaque
**session token**. The token never reaches browser JavaScript, and the site
never holds a device's secret. It is specified in
[docs/mldsa-authd-spec.md](docs/mldsa-authd-spec.md).

Milestone A is operators with a command-line client. Browsers are milestone B.

```sh
# 0. Build, and work somewhere with a short path: a Unix socket path must fit
#    sun_path (104 bytes on macOS, 108 on Linux), which is far shorter than the
#    255 bytes the configuration file allows.
cmake -S . -B build && cmake --build build -j
REPO=$PWD
mkdir -p /tmp/authd-demo && cd /tmp/authd-demo
```

```sh
# 1. Create the server identity, the store and the passphrase, in one command.
#    The passphrase is 32 random bytes that init generates; move it into a
#    systemd credential and delete the plaintext copy before going live.
"$REPO/build/apps/authd/authd_admin" init \
    --dir /tmp/authd-demo/data --server-id authd \
    --passphrase-file /tmp/authd-demo/data/pass
```

```sh
# 2. Configure and start the daemon. listen_unix carries the protocol; the two
#    local sockets carry the site API (0660) and the admin API (0600).
cat > /tmp/authd-demo/authd.conf <<EOF
store_path = /tmp/authd-demo/data/store.sqlite3
key_path = /tmp/authd-demo/data/server.ek
key_passphrase_file = /tmp/authd-demo/data/pass
server_id = authd
listen_unix = /tmp/authd-demo/p.sock
site_socket = /tmp/authd-demo/s.sock
admin_socket = /tmp/authd-demo/a.sock
site_uids = $(id -u)
admin_uids = $(id -u)
EOF
"$REPO/build/apps/authd/authd_admin" --check-config --config /tmp/authd-demo/authd.conf
"$REPO/build/apps/authd/mldsa-authd" --config /tmp/authd-demo/authd.conf &
```

```sh
# 3. On the operator's own machine: generate a device key. The secret never
#    leaves it. keygen prints the device handle on stdout.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /tmp/authd-demo/opass
chmod 600 /tmp/authd-demo/opass
"$REPO/build/apps/authd/authd_client" keygen \
    --dir /tmp/authd-demo/dev --passphrase-file /tmp/authd-demo/opass
```

```sh
# 4. The operator sends <handle>.pub to an administrator, who enrolls it.
#    Replace HANDLE with what keygen printed. --handle is the authority: a
#    .pub whose embedded id disagrees is refused.
HANDLE=$(ls /tmp/authd-demo/dev | sed -n 's/\.ek$//p')
"$REPO/build/apps/authd/authd_admin" enroll-operator \
    --socket /tmp/authd-demo/a.sock --user alice --handle "$HANDLE" \
    --pub "/tmp/authd-demo/dev/$HANDLE.pub" --label "work laptop"
```

```sh
# 5. Log in. This is a real hybrid X25519 + ML-KEM-768 handshake with an
#    ML-DSA-65 identity on both sides. It prints a 43-character base64url
#    login code, valid for 60 seconds and usable once.
"$REPO/build/apps/authd/authd_client" login \
    --handle "$HANDLE" --key "/tmp/authd-demo/dev/$HANDLE.ek" \
    --passphrase-file /tmp/authd-demo/opass \
    --server-id authd --server-pub /tmp/authd-demo/data/server.pub \
    --unix /tmp/authd-demo/p.sock
```

The site takes that code and exchanges it for a token over `site.sock`, using
the reference handler in [examples/site-node/](examples/site-node/):

```sh
cat > /tmp/authd-demo/site.mjs <<EOF
import { Authd, exchange, verify } from '$REPO/examples/site-node/authd.mjs';
const authd = await new Authd('/tmp/authd-demo/s.sock').connect();
const session = await exchange(authd, process.argv[2], '');  // state: V4-10
console.log(await verify(authd, session.token));
authd.close();
EOF
node /tmp/authd-demo/site.mjs "<the code from step 5>"
```

```sh
# 6. Administrative queries, and shutdown.
"$REPO/build/apps/authd/authd_admin" list-users    --socket /tmp/authd-demo/a.sock
"$REPO/build/apps/authd/authd_admin" list-devices  --socket /tmp/authd-demo/a.sock --user alice
"$REPO/build/apps/authd/authd_admin" audit-tail    --socket /tmp/authd-demo/a.sock --n 10
"$REPO/build/apps/authd/authd_admin" backup        --socket /tmp/authd-demo/a.sock --path /tmp/authd-demo/backup.sqlite3
kill %1
```

```sh
# 7. Replace this device's key, keeping its identity. The new key is sealed to
#    <key>.next BEFORE anything is sent and renamed over <key> only when the
#    daemon acknowledges, so an interrupted rotation is always recoverable --
#    the next login asks the daemon which key is live and finishes the job.
"$REPO/build/apps/authd/authd_client" rotate \
    --handle "$HANDLE" --key "/tmp/authd-demo/dev/$HANDLE.ek" \
    --passphrase-file /tmp/authd-demo/opass \
    --server-id authd --server-pub /tmp/authd-demo/data/server.pub \
    --unix /tmp/authd-demo/p.sock
```

Identifiers and labels are hex on the wire and are printed back as hex: they
are attacker-influenced strings, and a tool that decodes them for display is a
tool with a terminal-escape hazard. `xxd -r -p` decodes one when you want it.

**Passphrases are files, never a prompt and never `argv`** — argv and the
environment are readable by other processes on the same host. The file must be
mode 0600 and owned by you; anything else is a configuration error (exit 3).

### Losing the device

Rotation (above) needs a device that still works. For one that does not, the
site issues **recovery codes** — sixteen Crockford base32 characters, 80 bits,
stored only as Argon2id hashes and shown exactly once:

```js
import { Authd, recoveryIssue, recoveryUse, enroll } from './examples/site-node/authd.mjs';
const authd = await new Authd('/run/mldsa-authd/site.sock').connect();

const codes = await recoveryIssue(authd, 'bob', 10);   // show these ONCE
// ...later, the user has a new device and one code:
const { ticket } = await recoveryUse(authd, 'bob', typedCode, { revoke: 'all' });
await enroll(authd, { user: 'bob', handle: newHandle, pk: newPublicKey, ticket });
```

Three things are worth knowing before you build a page around it:

* **Pass the typed code through verbatim.** Do not upper-case it, strip its
  hyphens or correct its `O`/`0` and `l`/`1` — the daemon normalises, and what
  it hashes is its own canonical form. A site that normalises differently locks
  its users out of their own codes.
* **Issuing invalidates the previous generation.** That is what keeps the
  verification loop bounded, and the loop is not cheap: one code costs ~52 ms,
  so a worst-case `RECOVERY-USE` blocks the single-threaded daemon for ~0.8 s.
  Five wrong attempts lock recovery for an hour; put your own rate limit in
  front of it anyway.
* **An operator's recovery is not reachable from `site.sock`** — it answers
  `not-permitted`. Otherwise a compromised site process could mint an
  operator's codes and enroll itself as one, which is the escalation keeping
  `ENROLL-OPERATOR` off that socket exists to prevent.

`revoke: 'all'` also revokes every existing device of that user and closes
their live sessions — the right choice when the device was stolen rather than
mislaid.

Behind a proxy, a browser-shaped client reaches the daemon as a WebSocket and
the proxy states the client's address in a **PROXY protocol v2** preamble
(spec §7.2). The daemon checks the proxy's uid, refuses a connection whose
address is missing or unverifiable, and rate-limits on the address it was
given: 5 connections a minute with a burst of 10, 50 a second across the whole
daemon, 8 concurrent connections per address — all operator-settable, all
refusing with an HTTP 429 at the upgrade, before any signature is spent.
`tests/caddy_proxy.sh` performs a real login through a real Caddy to prove it,
and then removes `proxy_protocol` from the Caddyfile to prove the refusal.

**`proxy_protocol` defaults to `none`**, because there is no default that is
right for both "a proxy is in front" and "an operator's client is connected
directly" — a deployment must set it, and `--check-config` prints what it is.

The proxy configuration itself is [`deploy/Caddyfile.example`](deploy/Caddyfile.example),
and it is the file under test rather than an illustration of one:

```bash
sh tests/caddy_proxy.sh
```

builds the daemon and the CLIs inside a container, validates that Caddyfile,
starts a real Caddy with it, logs in through it, and then removes
`proxy_protocol` and requires the login to stop working. It needs Docker and
network access and is deliberately **not** a CTest — a suite gate that silently
depends on a container registry fails for reasons that have nothing to do with
the code.

### Getting it onto a host

The systemd unit, the hardening flags, the install target and the runbook all
exist now. What is packaged is [`deploy/`](deploy/): the unit, a commented
example config, `fetch-deps.sh` for an offline dependency cache, and
[`RUNBOOK.md`](deploy/RUNBOOK.md) — a numbered checklist from an empty VPS to a
first login, with a `LimitMEMLOCK` table and a "when it will not start" section
keyed to the daemon's own exit codes.

Two more container-backed proofs sit beside `caddy_proxy.sh`, neither a CTest
for the same reason:

```bash
sh tests/deploy_checks.sh                    # the unit, per systemd's own analysers
sh tests/offline_build.sh /opt/mldsa-deps    # a build with the network switched off
```

`deploy_checks.sh` gates the unit on `systemd-analyze` rather than on review —
and on its **output**, not its exit status, because `systemd-analyze verify`
exits 0 for an unknown directive; it also asserts an exposure score with a
control that moves it. `offline_build.sh` disconnects the container's network,
proves the disconnection by requiring DNS to fail, builds from the cache alone,
and then stages three ways the cache could be wrong — unreadable, one byte
changed, moved off the pinned commit — and requires each to be refused.

What does not exist is a running deployment. Nobody has executed that checklist
against a real host, so this is **installable, not deployed**, and the runbook
is where the remaining risk lives.


## Dependencies

Both are fetched from upstream at pinned versions and built from source. No
system packages are used, so a clean checkout builds identical bits.

| Dependency | Version | Pin mechanism |
|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | **0.16.0** | Fetched at `GIT_TAG 0.16.0`, then **verified against commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`** — at population and again at every configure (`cmake/VerifyLiboqsCommit.cmake`) |
| [libsodium](https://github.com/jedisct1/libsodium) | **1.0.22** | Release tarball pinned byte-exact by `URL_HASH` SHA-256 `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`; resolved commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda` |
| [SQLite](https://sqlite.org/) (amalgamation) | **3.53.4** | The daemon's store (V4-7). Amalgamation pinned byte-exact by `URL_HASH` **SHA3-256** `628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e` (2 946 650 B), the digest sqlite.org publishes; built in-tree with `SQLITE_THREADSAFE=0`, `SQLITE_OMIT_LOAD_EXTENSION`, `SQLITE_DQS=0` |

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

The first x86_64 measurements (V3-5) come from GitHub-hosted runners, which
are shared 4-vCPU VMs: the handshake medians **0.783 ms** on a Xeon Platinum
8370C and **1.022 ms** on an EPYC 7763 — 15–19× inside the 15 ms target, on
chips that differ 24% from each other, so they are published per model and
never averaged. An AVX2 backend is proven linked in the binary before any of
those numbers is recorded. What a shared VM does and does not establish is
spelled out in [bench/results.md](bench/results.md).

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
- **Transport rate limiting in the reference apps** — the deferred mitigation
  for duplicate ClientHellos. The *daemon* has one (spec §7.2/§7.3, keyed on
  the address a PROXY v2 preamble states); `auth_server` does not.
  (§ *Duplicate ClientHello is accepted — an availability trade-off*)
- **Traffic-analysis resistance beyond padding** — v2 pads record lengths,
  but message timing, counts and direction are unprotected; no cover traffic
  and no constant-rate sending. (spec-v2 §6.4.1, §9)

## How this is verified

Three standing rules, each added after it was violated at least once, and now
enforced by CI rather than by anyone remembering them:

1. **A mutation that fails to compile is a kill** — but only when the first
   compiler error names a project source file, so an unrelated build failure
   can never be laundered into one.
2. **A sanitizer result counts only if the instrumentation is linked**
   (`check_sanitizer_link.sh`): two trees were once configured with a
   misspelled flag that CMake accepted in silence.
3. **A suite result counts only if the build is current**
   (`check_build_current.sh`), proven **in the same command** as the suite:
   `ctest` never compiles, so a complete, correctly instrumented, freshly
   configured tree can still be testing yesterday's sources.

| Workflow | When | What it runs |
|---|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | every push and PR | the 15-test suite in debug/ASan/UBSan on Linux and macOS, a gcc build, fuzz smoke (60 s × 5) and the repository secret scan — ~5 min |
| [`nightly.yml`](.github/workflows/nightly.yml) | 03:17 UTC, or on demand | all twenty-three committed campaigns against fresh ASan trees — twenty-two on Linux, and v35 on macOS because its mutations live in macOS-only code — behind a mutation-anchors gate, plus 600 s on each of twelve fuzz targets with crash artifacts kept — ~80 min |
| [`bench.yml`](.github/workflows/bench.yml) | on demand only | Release build, proof that an optimized backend is linked, and the benchmarks — numbers, so never in a gate |

Every one of these gates has been shown to go **red** for the right reason by
deliberately breaking it, pushing the break alone and reverting it; what each
control produced is recorded in [docs/decisions.md](docs/decisions.md) under
*V3-3*, *V3-4* and *V3-5*. A green badge that has never been shown to fail
proves nothing, and a scheduled workflow GitHub has disabled after 60 days of
inactivity still shows its last green run — check the date, not the colour.

## Repository layout

| Path | Contents |
|---|---|
| `src/crypto/` | Thin wrappers over liboqs and libsodium: ML-DSA, X25519, HKDF, AEAD |
| `src/protocol/` | Wire format and transcripts, handshake state machine, pending ledger, keystore, session record layer |
| `src/util/` | Secure memory, integer encoding |
| `apps/` | Reference transport (socket I/O, framing, demo key files) and the `auth_client` / `auth_server` demo binaries; `apps/authd/` is the authentication daemon — its store, key envelope, local API and the `authd_admin` / `authd_client` tools |
| `tests/` | Deterministic test suite; `tests/fuzz/` holds the fuzz targets, corpora and regressions |
| `bench/` | Benchmarks and measured results |
| `docs/` | The specification and the decision log |
| `cmake/` | Pinned dependency definitions |
| `deploy/` | What a deployment needs and nothing else: the systemd unit, a commented example config, `fetch-deps.sh` for an offline dependency cache, and `RUNBOOK.md` — the numbered checklist from an empty VPS to a first login |
| `tools/` | The verification gates themselves — `run_mutations_v2.sh` plus the 192 committed mutations in `tools/mutations/`, and the checkers that must pass before a result is believed: `check_build_current.sh` (the binaries match the sources), `check_sanitizer_link.sh` (the instrumentation is really linked), `check_backend_symbols.sh` (one optimized backend is linked, no portable-C), and under `tools/audit/` the gates that check the documents against the code: `check_spec_constants.sh`, `check_spec_vocabularies.py`, `check_mutation_anchors.py` and `check_hardening.sh`. Not part of the build |

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
