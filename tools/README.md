# Verification tooling

Standalone shell scripts, like `bench/run_bench.sh` and
`tests/fuzz/run_fuzz.sh`: nothing here is compiled, linked, or referenced by
any CMake target.

| Script | What it does |
|---|---|
| `run_mutations_v2.sh` | Runs a mutation campaign: applies one temporary defect at a time, forces a full rebuild, checks the defect reached the binaries, requires the named check to fail, then restores byte-exactly and re-runs the whole suite. |
| `check_sanitizer_link.sh` | Proves a build directory is genuinely instrumented — the `ENABLE_ASAN`/`ENABLE_UBSAN` cache entry is ON *and* every project executable carries the sanitizer runtime — before any sanitizer result is reported. |

Together they implement the two standing process rules recorded in
[`docs/decisions.md`](../docs/decisions.md) under **Process hardening after
V2-4**: a mutation that fails to compile is killed automatically, and a
sanitizer build is not trusted until its instrumentation is proven linked.

```sh
tools/run_mutations_v2.sh <repo> <scratch-dir> <mutate.py> <spec-file> [build-dir]
tools/check_sanitizer_link.sh <build-dir> asan|ubsan
```

The per-step mutation scripts and spec files these take as arguments are
written for one step's defects and are **not** committed; the runner itself
is step-agnostic, which is why it lives here.
