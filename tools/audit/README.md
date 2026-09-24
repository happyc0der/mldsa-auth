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
| `check_spec_constants.sh <repo>` | Re-derives every size in `docs/mldsa-authd-spec.md` from `session.h`, `transcript.h`, `mldsa_wrap.h`, the envelope arithmetic and the per-role KDF constants, and diffs it against the document. A specification fails by lying, and prose does not compile | Changing one digit in the spec (8611 → 8610) fails the check; the restore is `cmp`-identical. Since V4-13a it also reads §12's Argon2id parameters **by role** out of the three places the tree defines them (server `authd_cli.c`, operator `cli_common.h`, browser `client_core.h`), scoped to the "Parameters by role" sentence because `ops=3` appears twice in it; the browser's `64 MiB` changed to `32` fails exactly that row |
| `constant_time_inventory.sh <repo>` | Every comparison in `src/` and `apps/` classified CT (`sodium_memcmp`/`sodium_is_zero`) vs plain. The audit's dispositions are the judgement; this is the evidence they were made against the real tree | Fails if it finds zero constant-time calls — i.e. if the grep itself broke |

Coverage is **not** a gate. The mutation campaigns are the gate; coverage maps
where a mutation could never be killed.

`check_hardening.sh` **is** a gate as of V4-11: it runs with `--require` over
the **install tree** — the three binaries that actually ship — in `ci.yml`'s
release job. Two things about that are worth keeping in mind. It reads the
binary, never the build files, so it cannot be satisfied by a flag that was
passed and silently dropped. And on Mach-O it reports RELRO and BIND_NOW as
`n/a`, because they are ELF concepts with no Mach-O equivalent, so a macOS
`--require` run gates three properties out of five: **it is a Linux gate**, and
a green run on macOS is not the same claim.
