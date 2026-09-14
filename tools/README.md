# Verification tooling

Standalone shell scripts, like `bench/run_bench.sh` and
`tests/fuzz/run_fuzz.sh`: nothing here is compiled, linked, or referenced by
any CMake target.

| Script | What it does |
|---|---|
| `run_mutations_v2.sh` | Runs a mutation campaign: applies one temporary defect at a time, forces a full rebuild, checks the defect reached the binaries, requires the named check to fail, then restores byte-exactly and re-runs the whole suite. |
| `check_sanitizer_link.sh` | Proves a build directory is genuinely instrumented — the `ENABLE_ASAN`/`ENABLE_UBSAN` cache entry is ON *and* every project executable carries the sanitizer runtime — before any sanitizer result is reported. |
| `check_build_current.sh` | Proves a build directory's binaries were compiled from the **current** working tree — it rebuilds and requires every project object and executable to be byte-identical afterwards — before any suite result from it is reported. |

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

The per-step mutation scripts and spec files these take as arguments are
written for one step's defects and are **not** committed; the runner itself
is step-agnostic, which is why it lives here.
