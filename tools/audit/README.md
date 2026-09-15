# tools/audit — the V4-1 deployment audit, re-runnable

These are the mechanical half of `docs/v4/audit.md`. They exist as committed
scripts for the reason V3-4 established: **an uncommitted verification is an
unverifiable claim.** Each one is designed so that finding nothing is a
failure, not a pass, and each has a demonstrated failure mode recorded in the
audit.

| Script | What it proves | Failure mode demonstrated |
|---|---|---|
| `coverage.sh <build-cov> [out]` | Line, region and branch coverage of `src/` and `apps/`, from a **separate** instrumented tree (instrumented objects would poison the mutation runner's fingerprints and the currency checker's no-op-rebuild proof) | Excluding the session tests drops `session.c` branch coverage 95.99% → 76.28% |
| `check_hardening.sh <build> [--require]` | PIE / RELRO / BIND_NOW / non-executable stack / stack canaries, read **from the binary**, never from the build files. Executables discovered, never enumerated | `--require` fails on a tree lacking any property; refuses to pass when no executable is found |
| `constant_time_inventory.sh <repo>` | Every comparison in `src/` and `apps/` classified CT (`sodium_memcmp`/`sodium_is_zero`) vs plain. The audit's dispositions are the judgement; this is the evidence they were made against the real tree | Fails if it finds zero constant-time calls — i.e. if the grep itself broke |

Coverage is **not** a gate. The mutation campaigns are the gate; coverage maps
where a mutation could never be killed.

`check_hardening.sh` is written to become a gate: V4-11 runs it with
`--require` on the daemon binary once the hardening flags are added.
