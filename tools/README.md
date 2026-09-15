# Verification tooling

Standalone shell scripts, like `bench/run_bench.sh` and
`tests/fuzz/run_fuzz.sh`: nothing here is compiled, linked, or referenced by
any CMake target.

| Script | What it does |
|---|---|
| `run_mutations_v2.sh` | Runs a mutation campaign: applies one temporary defect at a time, forces a full rebuild, checks the defect reached the binaries, requires the named check to fail, then restores byte-exactly and re-runs the whole suite. |
| `check_sanitizer_link.sh` | Proves a build directory is genuinely instrumented — the `ENABLE_ASAN`/`ENABLE_UBSAN` cache entry is ON *and* every project executable carries the sanitizer runtime — before any sanitizer result is reported. |
| `check_build_current.sh` | Proves a build directory's binaries were compiled from the **current** working tree — it rebuilds and requires every project object and executable to be byte-identical afterwards — before any suite result from it is reported. |
| `check_backend_symbols.sh` | Proves **one** optimized ML-DSA/ML-KEM backend is linked and no portable-C one is (Security Req 4.10, Performance Req 3) — the claim is about the binary, so it is checked in the binary. Dual-architecture: `…_AARCH64_` and `…_X86_64_` symbol families, names taken from the pinned liboqs source. Three vacuous-pass guards: no executables, no binary linking the algorithm, and no optimized family present are each a FAILURE. Prints `BACKEND_FAMILY=` for `bench.yml`'s agreement check. |
| `mutations/` | The campaigns themselves: one `mutate_<step>.py` and one `spec_<step>.txt` per step (v23 K1–K5+K4b, v24 M1–M8, v25 N1–N8 minus N7, v26 Q1–Q9, v27 R1–R6, v28 X1–X10, v29 Y1–Y9, v33 S1+S2b — 57 must-kill). N7 (keys committed before `consume_success`) is deliberately absent: it survived in V2-5 and V2-10 and is recorded in `docs/decisions.md` as an *equivalent mutant* — `fail_ctx()` wipes the keys on every post-commit failure path, so no public-API test can distinguish the reordering. A documented survivor cannot be a pass criterion, so the nightly does not run it. Specs carry each mutation's *final* expectation string, the one that killed in its step's exit report. `.github/workflows/nightly.yml` runs every campaign nightly against a fresh Linux ASan tree. `spec_v35.txt` lists only U2/U3: U1 mutates an **x86_64-only** branch that does not compile on arm64, so it is applied by hand during `bench.yml`'s bring-up, where the agreement check kills it. **A step's campaign is committed with the step** — until V3-4 these files lived only in one agent's scratch directory, which made every "re-run" claim unreproducible by anyone else. |

Together they implement the three standing process rules recorded in
[`docs/decisions.md`](../docs/decisions.md) under **Process hardening after
V2-4**: a mutation that fails to compile is killed automatically; a sanitizer
build is not trusted until its instrumentation is proven linked; and a suite
result is not trusted until the build is proven current.

```sh
tools/run_mutations_v2.sh <repo> <scratch-dir> <mutate.py> <spec-file> [build-dir]
tools/check_sanitizer_link.sh <build-dir> asan|ubsan
tools/check_build_current.sh <build-dir>
```

The currency check is meant to run in the **same invocation** as the suite
whose result will be quoted, so the two are paired in the transcript:

```sh
tools/check_build_current.sh build-asan && ctest --test-dir build-asan --output-on-failure
```

On a stale tree it rebuilds, fails, and the `&&` stops the suite from running
at all — so a stale number cannot be produced. `ctest` never compiles, which
is how V2-9 came to report 15/15 from binaries built before its last edit.

## Platforms

All three run on **macOS and Linux**. Each script detects the platform with
`uname` and names the mechanism it used in its own output, so a transcript
records *what was compared*, not just the verdict:

| | macOS | Linux |
|---|---|---|
| hashing | `shasum -a 256` | `sha256sum` |
| executable code | `otool -X -t` | `objdump -d --section=.text` (or `llvm-objdump`) |
| executable discovery | `file` → Mach-O | `file` → ELF (`executable` or `pie executable`) |
| ASan linkage | `otool -L` / `nm -u` | `ldd` / `nm` |

The shim is duplicated in each script rather than sourced from a common file:
`tools/` is deliberately not an installable unit, and a shared file would make
it one.

Two guards exist because V3-1's mutations found them missing. A tree must have
**both** objects and executables — requiring merely "not both zero" let broken
executable discovery pass while silently comparing objects alone. And the text
tool is probed on a real binary before any comparison is trusted, because a
dump that silently produces nothing makes every executable compare equal.

The per-step mutation scripts and spec files these take as arguments are
written for one step's defects and are **not** committed; the runner itself
is step-agnostic, which is why it lives here.
