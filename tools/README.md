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
| `check_store_fault_hook.sh` | Proves the store's fault-injection hook (`MLDSA_STORE_FAULT_HOOK`) is confined to the test build: **absent** from `libmldsa_authd.a` and every shipped executable, and **present** in `test_authd_store` — the second half matters, because an absence check that no longer matches the symbol name would pass vacuously forever. A build with no artifacts is a FAILURE, not a pass. |
| `audit/check_spec_vocabularies.py` | The specification's **names**, checked against the daemon in BOTH directions: §8's error codes, §15's log events and §15's log fields. A name the daemon can emit that the spec does not define is a failure, and so is a name the spec defines that nothing emits — the second is the one no test can see, because a defined-but-unemitted name is a promise to a reader rather than a bug in the software. Exact rather than heuristic: every call site passes a string literal, and a non-literal at any of them is itself reported, so the check cannot quietly cover less than it claims. `check_spec_constants.sh` does the same job for numbers; numbers never drifted, names did (`bad-handle` was documented for eight steps and never emitted once). |
| `audit/check_mutation_anchors.py` | Every campaign's anchor still matches its target file EXACTLY once, checked statically (the mutate scripts apply on import, so they are parsed, never imported) and with coverage asserted against `spec_v*.txt`, so a table shape it cannot read is reported rather than skipped. Run it BEFORE editing a source file and again after: a step rots other steps' anchors, which has happened twice (V4-9a rotted v47 S6/S8 and v48a D4; V4-9c rotted v47 S1) and both times something downstream found it. |
| `mutations/` | The campaigns themselves: one `mutate_<step>.py` and one `spec_<step>.txt` per step. **`tools/mutations/spec_*.txt` is the authority on the count: 192 must-kill mutations across 23 campaigns** (v23 K1–K5+K4b, v24 M1–M8, v25 N1–N8 minus N7, v26 Q1–Q9, v27 R1–R6, v28 X1–X10, v29 Y1–Y9, v33 S1+S2b, v35 U2+U3, v46 E2–E7, v47 S1–S7 (S8 retired), v48a D1–D6+D8, v48b C1–C7, v49a T1–T5+A1–A2+X1–X2+V1–V2, v49b, v49c W1–W15 (W6 retired), v49d G1–G15, v50a H1–H9, v50b J1–J13, v50c O1–O4, v51 Z1–Z5, v52 P1–P11, v53 F1–F12). Specs carry each mutation's *final* expectation string, the one that killed in its step's exit report.<br><br>**All twenty-three committed campaigns run nightly**: twenty-two architecture-independent ones on Linux against a fresh ASan tree, and v35 on macOS, because its mutations anchor inside `bench_common.c`'s `#if defined(__APPLE__)` branch and cannot even be applied on Linux — which is the point, since U2 is a defect that only ever appeared on a macOS VM. `spec_v35.txt` lists only U2/U3: U1 mutates an **x86_64-only** branch that does not compile on arm64, so it is applied by hand during `bench.yml`'s bring-up, where the agreement check kills it. **There are no exceptions left, and there is now a check instead of a habit.** `v50c` and `v51` joined in V4-11's nightly bring-up, and the same job that verifies the anchors now also asserts that every `tools/mutations/spec_*.txt` appears in a matrix and that no matrix names a campaign that does not exist. Eight campaigns — v48b, v49a–c, v49d, v50a, v50c, v51 — had each been committed with their step and then run nowhere until a bring-up was remembered; the anchors tool could never see it, because an unwired campaign's anchors match perfectly. The nightly verifies **all 192** committed mutations.<br><br>`check_mutation_anchors.py` GATES the campaign jobs (`needs:`) rather than running beside them: a rotted anchor aborts the runner, and learning that after three hours of mutation runs costs three hours to discover what five minutes knew.<br><br>**A step's campaign is committed with the step**, and a deferral gets a stated expiry: until V3-4 these files lived only in one agent's scratch directory, which made every "re-run" claim unreproducible by anyone else, and v48b, v49a–c, v49d and v50a each waited one step for a bring-up that was named when the deferral was made. V4-10b discharged the last of them.<br><br>Six mutations are deliberately absent as documented EQUIVALENT MUTANTS, because a documented survivor cannot be a pass criterion. **v48b's C8** (the decoy/no-user-id guard before a login code is issued) survives because a decoy pin has no secret key, so no sig_A over it can ever verify and the guarded state is unreachable through the daemon's own interface; the guard stays in the code. **v48a's D7** (`conn_io_push` no longer honours the sticky `failed` flag) survives because the offending frame header is still at offset 0 and is re-read and re-refused by `note_header()` either way. **N7** (keys committed before `consume_success`) survived in V2-5 and V2-10: `fail_ctx()` wipes the keys on every post-commit failure path, so no public-API test can distinguish the reordering. **v51's absent refusal** (the daemon REFUSES to start when RLIMIT_MEMLOCK is low) is not a mutation because it is not the behaviour and deliberately so: Linux's usual 8 MiB default is already short at the default 256 slots, so refusing would turn a widespread misconfiguration into an outage — a mutation asserting the opposite would be a mutation against the design, not against a defect. **v51's absent getrlimit failure** (a failed `getrlimit` treated as OK rather than UNKNOWN) is unreachable on Linux and macOS alike, so it would survive everywhere and teach that a survivor is normal. **v50b's absent PROXY guard** (widening `note_header`'s condition to name the PROXY stage) survives because the preamble is consumed strictly inside `WS_STAGE_UPGRADE`, which the existing condition already excludes — the two versions are indistinguishable, and the argument is written next to the guard. |

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
