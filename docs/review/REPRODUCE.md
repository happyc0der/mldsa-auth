# Reproducing every result

Every command below was run again for V4-38 (2026-10-20), as written, in a
fresh clone at a path without spaces, on macOS 27.0.1 (arm64, Apple clang;
Homebrew LLVM for fuzzing; Homebrew gcc 16; Docker for the two scripts that
need it), and each says what it printed then. They were first run for this
packet in V4-14b. The same gates run on Linux in CI and the nightly (see the
last section), which is where a reviewer without a Mac should look first.

## Before you start

- CMake ≥ 3.20, a C11 compiler, Python 3, `curl`. Everything else — liboqs,
  libsodium, SQLite — is fetched by the build and checked against the hashes
  in `cmake/Dependencies.cmake`.
- **libsodium is built under `$TMPDIR`**, because its libtool cannot build
  under a path with spaces. macOS cleans its default `$TMPDIR` on its own
  schedule and takes the installed library with it, so configure with a
  durable one (no spaces):

  ```bash
  export TMPDIR="$HOME/.cache/mldsa-tmp" && mkdir -p "$TMPDIR"
  ```

## The suite, three ways

```bash
cmake -S . -B build && cmake --build build -j8
tools/check_build_current.sh build && ctest --test-dir build
```

`OK: build is current`, then `100% tests passed out of 53` (56 with
`-DMLDSA_WASM_DIR` pointing at a wasm tree, 58 with a Chromium-family browser
found as well; V4-38's run printed two fewer of each, before V4-39 added
`backend_symbols` and V4-41 `doc_test_counts`); `ubsan_aborts` and
`fuzz_libfuzzer` report *Skipped* outside the trees they are for.

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON && cmake --build build-asan -j8
tools/check_build_current.sh build-asan && tools/check_sanitizer_link.sh build-asan asan && ctest --test-dir build-asan
cmake -S . -B build-ubsan -DCMAKE_BUILD_TYPE=Debug -DENABLE_UBSAN=ON && cmake --build build-ubsan -j8
tools/check_build_current.sh build-ubsan && tools/check_sanitizer_link.sh build-ubsan ubsan && ctest --test-dir build-ubsan
```

Each prints `OK: … is current`, `OK: asan|ubsan instrumentation present in all
… executable(s)` -- 43 in the ASan tree, 44 in the UBSan tree, which also
builds `ubsan_canary` -- and `100% tests passed out of 53`, or 58 when
configured as this packet's trees were, with `-DMLDSA_WASM_DIR` and a browser
found (the browser section below). Since V4-14c the UBSan build aborts on
undefined behaviour (audit F94); before it, a UB report printed and the test
still passed. Since V4-24b that is a CTest, `ubsan_aborts`: a planted signed
overflow must stop the process, and `build_flags` checks that every
translation unit was told `-fno-sanitize-recover`. To see it either way:

```bash
grep -c 'runtime error' build-ubsan/Testing/Temporary/LastTest.log     # printed 1: ubsan_aborts's planted overflow, and nothing else
```

`check_build_current.sh` rebuilds the project's own objects from scratch
(never the dependencies) and fails if anything on disk differs from what that
rebuild produces, so a suite result can never come from a stale binary.

A gcc 16 Release tree (the configuration no CI job uses):

```bash
cmake -S . -B build-gcc16 -DCMAKE_C_COMPILER=gcc-16 -DCMAKE_BUILD_TYPE=Release && cmake --build build-gcc16 -j8
ctest --test-dir build-gcc16                                           # 100% tests passed out of 53
```

## The browser client

With Emscripten **6.0.9** exactly (configure refuses any other version):

```bash
emcmake cmake -S . -B build-wasm -DCMAKE_BUILD_TYPE=Release && cmake --build build-wasm -j8
ctest --test-dir build-wasm                                            # 100% tests passed out of 3
cmake -S . -B build -DMLDSA_WASM_DIR="$PWD/build-wasm" && cmake --build build -j8
ctest --test-dir build -R '^(wasm_interop|web_flows|browser_e2e|phone_timing_tool)$'   # 100% tests passed out of 4
```

`wasm_module_gates` checks the module's exact export list; `test_client_core_kat`
checks that the wasm build reproduces the native known-answer golden byte for
byte; `browser_e2e` drives a real headless Chromium through enrollment, login,
the CSP and the storage rules, then scans both browser profiles on disk for
every key the browser held and for the passphrase (V4-27); `phone_timing_tool` runs `tools/phone_timing.mjs`
through a secure and a non-secure origin and checks that each timing row says
which it came from (V4-26, F119).

## Fuzzing

```bash
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DMLDSA_FUZZ=ON
cmake --build build-fuzz -j8 && ctest --test-dir build-fuzz -L fuzz    # 100% tests passed out of 36
tests/fuzz/run_fuzz.sh local build-fuzz authd_config                   # 600 s; crashes=0 artifacts=0 (123,075,142 runs)
```

Every target, at 600 s each: `tests/fuzz/run_fuzz.sh local build-fuzz`. Apple
clang ships no libFuzzer runtime, hence Homebrew LLVM.

## Mutation campaigns

371 committed mutations in 54 campaigns, each a defect the tests must catch
**by name**. One campaign, on an ASan tree -- v72's two mutations take about
twenty minutes; a larger one, such as v56's twenty, takes hours:

```bash
tools/run_mutations_v2.sh "$PWD" /tmp/mut tools/mutations/mutate_v72.py \
    tools/mutations/spec_v72.txt build-asan
```

It ends with `residue: none` and `final: all sources restored; all artifacts
identical to clean fingerprints`, and every row reads `KILLED(n named)`. A
compile failure counts only if `tools/mutations/compile_kills_allowed.txt`
lists it (one does: v24 M8). Since V4-14d every kill must be named (audit
F90): a spec line without an expected check is refused. The mutations only a
privileged Linux leg can kill are listed in `tools/mutations/linux_only_kills.txt`;
off Linux they read `SURVIVED(EXPECTED off Linux)` instead. Before editing sources,
check that every campaign still applies:

```bash
python3 tools/audit/check_mutation_anchors.py .                       # ALL ANCHORS OK (411 anchors checked; 371 mutations across 54 campaigns)
```

## The formal model

ProVerif 2.05, built from source (its opam package needs GTK); see
`formal/README.md`:

```bash
formal/run.sh path/to/proverif
```

**Not re-run locally**, in V4-14b or V4-38: ProVerif is not installed on the
machine that wrote this page. It runs in the nightly job `ProVerif model +
controls`, whose log in run 39447335408 (2026-10-20) reads: `ok base`, `ok leak_kem`,
`ok leak_dh`, `ok leak_c2s`, and `no longer provable` for each of `ctl_sigb`,
`ctl_kdf_nodh`, `ctl_kdf_nokem`, `ctl_rot_hsid` and `ctl_rot_sigold`.

## The documents, checked against the tree

```bash
bash tools/audit/check_spec_constants.sh .          # OK: every derived size appears in the specification
python3 tools/audit/check_spec_vocabularies.py .    # OK: ... log events and log fields match the daemon exactly
python3 tools/audit/check_claim_map.py .            # OK: every requirement is mapped, and everything the map cites exists
```

## Scripts outside CTest

```bash
sh tests/caddy_proxy.sh      # a real Caddy in Docker, a real login through it; 9 PASS lines, "PASS: CADDY: all checks" (also a CI job since V4-22b)
sh tests/deploy_checks.sh    # systemd's own analysers on the unit (Docker); exposure 1.7, "PASS: DEPLOY: all checks"
```

## The dependency advisories

The queries behind [ADVISORIES.md](ADVISORIES.md), repeatable as written:

```bash
curl -s -X POST https://api.osv.dev/v1/query -d '{"commit":"5a1a854b0dc9f2141bdc771c555ee60c37950183"}'   # liboqs 0.16.0
curl -s -X POST https://api.osv.dev/v1/query -d '{"commit":"77e1ce5d6dee871c49ef211222ba18ef0c486bda"}'   # libsodium 1.0.22
curl -s -X POST https://api.osv.dev/v1/query -d '{"commit":"b09c88c14082339b66c7b7158d609a771e64ca69"}'   # SQLite 3.53.4
curl -s -X POST https://api.osv.dev/v1/query -d '{"commit":"979a07af38c8fb1d344253f59736cbfa91bd0a66"}'   # SQLite 3.50.1: the control, returns CVE-2025-6965
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=liboqs"
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:sqlite:sqlite:3.53.4"
gh api repos/open-quantum-safe/liboqs/security-advisories
```

On 2026-10-20 (V4-38) the three pinned commits returned no vulnerabilities
and the control returned CVE-2025-6965. NVD returned 8 matches for liboqs and
1 for SQLite 3.53.4 (CVE-2022-31631, a PHP bug). GitHub returned 8 liboqs
advisories, one of them new since V4-14b (GHSA-xv6c-h66p-6mfq, in LMS, which
is not compiled). ADVISORIES.md accounts for every one.

## On Linux, without a Mac

- **CI** (`.github/workflows/ci.yml`, every push): the suite under debug, ASan
  and UBSan on Linux and macOS, gcc, Release with the hardening check, the
  offline build, fuzz smoke and the secret scan, the specification checks
  (since V4-34 the mutation anchors and the stated counts too), the wasm and
  headless-browser job, and `caddy proxy (Linux, Docker)`. 14 jobs; run
  39474140277 on main `71c8fc0`: 14/14.
- **Nightly** (`.github/workflows/nightly.yml`): every committed mutation
  campaign on fresh ASan trees, 600 s on each of twelve fuzz targets, the
  ProVerif model and its controls. Run 39447335408 on `71c8fc0`'s tree: 58/58,
  with 314 of 314 mutations killed by name (v74, V4-36's, joined after it).
