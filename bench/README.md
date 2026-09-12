# Benchmarks (Step 8)

Measured results live in [results.md](results.md). This file is how to
reproduce them, and how to read them honestly.

## Reproduce

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j8
bench/run_bench.sh build-bench 3
```

Each repetition writes `build-bench/bench-results/run-N.txt` (table) and
`run-N.csv` (machine-readable). Every log starts with an environment block —
machine, compiler, build type and flags, dependency versions, the ML-DSA
backend that actually executed, the QoS class granted, and the clock chosen
with its measured resolution — so a number can never be read without knowing
how it was produced.

Individual suites:

```sh
./build-bench/bench/bench_primitives        # per-primitive costs
./build-bench/bench/bench_handshake         # phases, in-process and loopback handshake
./build-bench/bench/bench_session           # record layer at 64 B / 1 KiB / 64 KiB
```

`--csv` switches to CSV. `--smoke` runs tiny iteration counts for the CTest
`bench_smoke` gate; its numbers are meaningless by construction.

## Build type matters

**Use a Release build.** The project's default build type is `Debug`, and
liboqs is built inside the same CMake project, so a default build compiles
ML-DSA with no optimization. libsodium is different: it is an ExternalProject
using its own Autotools defaults, so it is optimized in every configuration.
A Debug bench run therefore reports a badly distorted picture — slow
signatures next to normally-fast AEAD. `results.md` quantifies the gap.

## Method

- **Clock.** Candidate monotonic clocks are measured at startup and the
  finest wins. On macOS that is `CLOCK_MONOTONIC_RAW` (~41 ns); plain
  `CLOCK_MONOTONIC` reports whole microseconds, which would quantize every
  unbatched row.
- **Batching.** Operations faster than the clock can resolve are timed in
  batches of *k* iterations, with the per-iteration cost derived as
  `sample / k`; *k* is calibrated so a batch lasts ~20 µs. Every row reports
  its *k*, so `batch 1` marks a row timed one call at a time.
- **Stateful operations** — each handshake phase, `session_open` on a fresh
  record — rebuild their state in a prepare step that runs **outside** the
  timed region.
- **Warmup.** One full batch is run and discarded before sampling.
- **Statistics.** Median is the headline; min is the least noise-contaminated
  estimate of true cost; p90/p99 expose scheduling noise and, for ML-DSA
  signing, genuine algorithmic variance.
- **Scheduling.** On Apple Silicon the process asks for
  `QOS_CLASS_USER_INTERACTIVE` so it runs on performance cores, and reports
  the class actually granted.

## What these numbers are not

- **Not correctness evidence.** A fast wrong implementation is still wrong.
  Correctness lives in `tests/` and `tests/fuzz/`.
- **Not a network measurement.** The loopback handshake crosses a real TCP
  connection on `127.0.0.1`: it includes framing and syscalls, and excludes
  every property of a real link — latency, loss, MTU, congestion.
- **Not portable.** One machine, one OS, one compiler. The spec's 15 ms
  target names an x86_64 core; these results are measured on arm64, which
  `results.md` states plainly rather than papering over.
- **Not a promise under load.** Single process, no contention, nothing else
  competing for the cores.
