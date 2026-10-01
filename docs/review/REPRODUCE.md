# Reproducing every result

Every command below was run for this packet (V4-14b, 2026-09-27) on macOS 26
(arm64, Apple clang; Homebrew LLVM 23 for fuzzing; Homebrew gcc 16), and each
says what it printed. The same gates run on Linux in CI and the nightly (see
the last section), which is where a reviewer without a Mac should look first.

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

`OK: build is current`, then `100% tests passed out of 40` (42 with
`-DMLDSA_WASM_DIR` pointing at a wasm tree, 43 with a Chromium-family browser
found as well).

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON && cmake --build build-asan -j8
tools/check_build_current.sh build-asan && tools/check_sanitizer_link.sh build-asan asan && ctest --test-dir build-asan
cmake -S . -B build-ubsan -DCMAKE_BUILD_TYPE=Debug -DENABLE_UBSAN=ON && cmake --build build-ubsan -j8
tools/check_build_current.sh build-ubsan && tools/check_sanitizer_link.sh build-ubsan ubsan && ctest --test-dir build-ubsan
```

Each prints `OK: … is current`, `OK: asan|ubsan instrumentation present in all
… executable(s)`, and `100% tests passed out of 40` -- or 43, with 41
executables, when configured as this packet's trees were, with
`-DMLDSA_WASM_DIR` and a browser found (the browser section below). Since
V4-14c the UBSan build aborts on undefined behaviour (audit F94); before it, a
UB report printed and the test still passed. To see it either way:

```bash
grep -c 'runtime error' build-ubsan/Testing/Temporary/LastTest.log     # printed 0
```

`check_build_current.sh` rebuilds the project's own objects from scratch
(never the dependencies) and fails if anything on disk differs from what that
rebuild produces, so a suite result can never come from a stale binary.

A gcc 16 Release tree (the configuration no CI job uses):

```bash
cmake -S . -B build-gcc16 -DCMAKE_C_COMPILER=gcc-16 -DCMAKE_BUILD_TYPE=Release && cmake --build build-gcc16 -j8
ctest --test-dir build-gcc16                                           # 100% tests passed out of 40
```

## The browser client

With Emscripten **6.0.9** exactly (configure refuses any other version):

```bash
emcmake cmake -S . -B build-wasm -DCMAKE_BUILD_TYPE=Release && cmake --build build-wasm -j8
ctest --test-dir build-wasm                                            # 100% tests passed out of 3
cmake -S . -B build -DMLDSA_WASM_DIR="$PWD/build-wasm" && cmake --build build -j8
ctest --test-dir build -R '^(wasm_interop|web_flows|browser_e2e)$'
```

`wasm_module_gates` checks the module's exact export list; `test_client_core_kat`
checks that the wasm build reproduces the native known-answer golden byte for
byte; `browser_e2e` drives a real headless Chromium through enrollment, login,
the CSP and the storage rules.

## Fuzzing

```bash
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DMLDSA_FUZZ=ON
cmake --build build-fuzz -j8 && ctest --test-dir build-fuzz -L fuzz    # 100% tests passed out of 36
tests/fuzz/run_fuzz.sh local build-fuzz authd_config                   # 600 s; crashes=0 artifacts=0
```

Every target, at 600 s each: `tests/fuzz/run_fuzz.sh local build-fuzz`. Apple
clang ships no libFuzzer runtime, hence Homebrew LLVM.

## Mutation campaigns

275 committed mutations in 31 campaigns, each a defect the tests must catch
**by name**. One campaign, on an ASan tree:

```bash
tools/run_mutations_v2.sh "$PWD" /tmp/mut tools/mutations/mutate_v56.py \
    tools/mutations/spec_v56.txt build-asan
```

It ends with `residue: none` and `final: all sources restored; all artifacts
identical to clean fingerprints`, and every row reads `KILLED(n named)`. A
compile failure counts only if `tools/mutations/compile_kills_allowed.txt`
lists it (one does: v24 M8). Nine older mutations are killed without a named
check (audit F90). Before editing sources, check that every campaign still
applies:

```bash
python3 tools/audit/check_mutation_anchors.py .                       # ALL ANCHORS OK (307 anchors, 31 campaigns)
```

## The formal model

ProVerif 2.05, built from source (its opam package needs GTK); see
`formal/README.md`:

```bash
formal/run.sh path/to/proverif
```

**Not re-run locally for this packet** — ProVerif is not installed on the
machine that wrote it. It runs in the nightly job `ProVerif model +
controls`, whose last log (run 36345474231) reads: `ok base`, `ok leak_kem`,
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
sh tests/caddy_proxy.sh      # a real Caddy in Docker, a real login through it; 8 PASS lines, "all checks"
sh tests/deploy_checks.sh    # systemd's own analysers on the unit (Docker); exposure 1.7, "all checks"
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

## On Linux, without a Mac

- **CI** (`.github/workflows/ci.yml`, every push): the suite under debug, ASan
  and UBSan on Linux and macOS, gcc, Release with the hardening check, the
  offline build, fuzz smoke and the secret scan, the specification checks, and
  the wasm and headless-browser job. 13 jobs; run 36345474470 on `6f9269b`:
  13/13.
- **Nightly** (`.github/workflows/nightly.yml`): all 26 mutation campaigns on
  fresh ASan trees, 600 s on each of twelve fuzz targets, the ProVerif model
  and its controls. Run 36345474231 on `6f9269b`: 41/41, with 223 of 233
  mutations killed by name, 9 without a named check (F90) and 1 by the
  compiler (M8, allowlisted).
