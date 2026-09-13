# Fuzzing and adversarial robustness (Step 7)

Five targets cover every attacker-controlled input:

| Target | Code under test | Input |
|---|---|---|
| `fuzz_wire` | v2 wire decoders, transcript helpers | one candidate wire message |
| `fuzz_handshake` | v2 state machine (S0 ClientHello **and encapsulation**, S1 ServerHello, S2 up to 4 ClientAuth) | selector + 2-byte-length-prefixed messages |
| `fuzz_session` | v2 `session_open` on a valid session, padding included | selector (receiver, capacity, limits, clock, **inner mode**) + up to 8 records with 4-byte length prefixes |
| `fuzz_frame` | `frame_recv` on a socketpair stream | selector (reader state) + byte stream |
| `fuzz_keys` | Step 6 demo key-file loaders and the V2-9 legacy migration | selector (mode, expected id, migrate) + public-key file bytes or an identity-mode mutation program |

Each harness checks **properties, not just crashes**. An independent
reference model predicts the correct status, and any disagreement aborts,
even without a crash.

`fuzz_wire`'s model is written against v2 (spec-v2 §6.3.1–6.3.4): it
rebuilds the unsigned-prefix length from literal field sizes including the
1088-byte ML-KEM ciphertext, and the three transcript digests from literal
`mldsa-auth/v2/…` label bytes — never from the macros in
`src/protocol/transcript.h`, so a label or layout left at v1 fails the
oracle rather than agreeing with it.

`fuzz_handshake`'s S0 models FIPS 203 §7.2's modulus check itself — every
12-bit coefficient of the encapsulation key must be < 3329 — and requires
`create_server_hello` to succeed exactly when that model says the key is
well formed, so neither liboqs nor this project's wrapper is taken on
trust. Seeds pin the boundary at 3328 (must pass) and 3329 (must fail).
Every scenario also asserts that a terminal failure leaves no hybrid secret
behind, and that a *retryable* ClientAuth failure keeps `ss_kem` — the
handshake is still live and the next message needs it.

`fuzz_session`'s **inner mode** (selector bit 5) exists because the
receiver's padding rules sit *behind* the AEAD: a random record fails
authentication long before its inner plaintext is parsed, so those rules
would never be reached by fuzzing raw records. In inner mode the chunk **is**
the inner plaintext, and the harness seals it itself — with its own literal
`mldsa-auth/v2/record` label, nonce and AD — under the receiver's key at the
sequence number the receiver expects. Every such record is authentic by
construction, so the oracle predicts purely from the inner bytes: an inner
under 2 bytes, a `content_len` larger than the inner allows, or any nonzero
padding byte must be terminal, and anything else must yield exactly the
declared content with a zeroed tail. Seeds pin each boundary.

`fuzz_frame`'s confirmation state is a **range** (27..4121), not a fixed
length: the client cannot know the responder's pad bucket (spec-v2 §6.5.1).

**Dictionaries carry sizes, not labels.** Every token in `dict/` is a
length or a type byte that can actually appear in fuzzer-supplied input.
Domain-separation labels (`mldsa-auth/v2/...`) are deliberately absent: they
live in the associated data and the transcript hashes, neither of which is
attacker-supplied, so a label token could never help libFuzzer build a
better input. The lengths were refreshed for v2 in V2-7 — message maxima
1330/4545, the padded-record minimum 27, the default-bucket confirmation
281, the bucket-4096 confirmation 4121, and the 2-byte `content_len` values
that `fuzz_session`'s inner mode consumes directly.

**`fuzz_target_max_len` must exceed the largest message the target can
see** (`fuzz_wire`: 8192, above the 4545-byte v2 `ServerHello`), and
`run_fuzz.sh`'s `-max_len` matches it. The replay driver **fails** on a
seed larger than that maximum instead of truncating it, so a stale limit
left behind after a message grows is a loud error rather than a silently
shrunken corpus.

## Two drivers

- **`fuzz_<t>_replay`** is built in every configuration, with any compiler.
  CTest `fuzz_replay_<t>` runs, in the normal, ASan and UBSan builds:
  1. the empty input (passed as NULL with length 0);
  2. every seed;
  3. every committed regression;
  4. a fixed number of deterministic mutations.

  This is the **fallback**. It is **not coverage-guided**.
  - `fuzz_<t>_replay FILE...` reproduces inputs, with extra logging.
  - `--write-seeds DIR` writes the corpus seeds into a build directory.
- **`fuzz_<t>`** is the coverage-guided libFuzzer binary. It is built only with
  `-DMLDSA_FUZZ=ON` and a clang that ships the libFuzzer runtime; Apple Clang
  does not. Everywhere else CTest `fuzz_libfuzzer` reports **Skipped**.

```sh
brew install llvm            # keg-only: does not replace Apple Clang
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DMLDSA_FUZZ=ON
cmake --build build-fuzz -j
ctest --test-dir build-fuzz -L fuzz --output-on-failure   # 30 s libFuzzer smoke per target
tests/fuzz/run_fuzz.sh smoke build-fuzz                   # 60 s per target
tests/fuzz/run_fuzz.sh local build-fuzz                   # 600 s per target (spec §8 Step 7)
```

**Budgets:**
- CI smoke: F1 20 000, F2 300, F3 5 000, F4 5 000, F5 2 000 mutations (seconds in total).
- libFuzzer smoke: 30–60 s per target.
- Local run: 600 s per target, in parallel.

## Deterministic RNG (test only)

`fuzz_common.c` replaces libsodium's and liboqs's randomness with a
fixed-key ChaCha20 stream, through `randombytes_set_implementation` and
`OQS_randombytes_custom_algorithm`.

- **What it buys:** keys, nonces, signatures and `handshake_id` are identical on every run, so seeds stay valid, crashes reproduce, and oracles compare against genuine bytes regenerated at runtime.
- **Where it lives:** it is linked **only** into the fuzz executables, and each prints `DETERMINISTIC RNG - TEST ONLY` on start-up.

## Repository secret policy

> No ML-DSA secret key bytes, including deterministic fixture/test secret
> keys, are committed to corpus, regression, dictionary, artifact, or source
> files.

- **Seeds** are generated at runtime into ignored build directories; none are committed.
- **Identity mode never stores file bytes.** `fuzz_keys` identity-mode inputs are *mutation programs*, applied to a template the harness regenerates in memory from the fixed test RNG.
- **CTest `fuzz_no_committed_secrets`** scans `regressions/` and `dict/` with `fuzz_keys_replay --scan-secret-dirs`. The scan fails on any ML-DSA secret-key file layout — current `MLDSASK2` or legacy `MLDSASK1`, since both hold a secret key — or any 16-byte window of the **secret regions** of the fixture secret key. Bare `"MLDSASK1"`/`"MLDSASK2"` tokens in text are reported as "token only" and allowed.
  - **Which windows are secret (V2-8).** An ML-DSA-65 secret key is `rho | K | tr | s1 | s2 | t0`. `rho` **is** `pk[0..32)` and `tr` **is** `SHAKE256(pk, 64)`, so a window lying *entirely* inside either is computable by anyone holding the public key. Those 66 windows are excluded; the other **3951** — including the 45 that straddle a boundary and therefore hold secret bytes — are kept. A file containing the fixture *public* key now scans clean (it produced 17 violations per file before), so a minimized public-mode artifact is admissible through `add_regression.sh`.
  - **The exclusions are proven, not assumed.** Before every scan the tool checks `sk[0..32) == pk[0..32)` and `sk[64..128) == SHAKE256(pk, 64)` against the regenerated fixture. If either fails it prints `SCANNER ABORT` and refuses to scan anything — a packing this code no longer understands must not be allowed to decide what counts as secret.
  - **The scanner proves its own rules before it admits anything.** Sixteen built-in controls (`C1`–`C7`) run first, on in-memory buffers, and a single failure refuses the whole scan: a real `MLDSASK2` and a legacy `MLDSASK1` file are still caught by *both* rules with exactly 3951 window hits (`C1`, `C2`); public-key files are clean (`C3`); `rho`, `tr` and `rho || tr` are clean (`C4`); the windows one byte either side of each boundary behave exactly as the rule says (`C5`); 16 bytes of `K`, `s1` or `t0` embedded in text are caught (`C6`); prose naming the magic is token-only (`C7`).

**Migrate mode (V2-9).** Selector bit 3, in identity mode only, offers the
mutated file to `demo_keys_migrate_legacy()` instead of the loader. The model
is written separately from the loader's (size bounds → `MLDSASK2` magic ⇒
`NOT_LEGACY` → `MLDSASK1` magic → exact *legacy* size, 5993 + id_len, with no
digest → id), and every input additionally asserts that the source file is
byte-identical afterwards and that an output file exists **only** on success —
on success, one that loads through the normal loader and carries the input's
own keys under a digest this harness recomputes with its own label copy.

### Identity-mode mutation grammar v2 (`fuzz_keys`, selector bit 0 = 1)

The template is the Step 7.1 `MLDSASK2` file for the fixture identity `"alice"`:
`"MLDSASK2" || 5 || "alice" || pk (1952) || sk (4032) || digest (32)`, 6030 bytes. The harness computes the digest itself, with **its own copy** of the label (`sizeof(label) - 1` bytes, no NUL). The reference model recomputes the digest for every mutated file and predicts `integrity-check-failed` independently of `apps/demo_keys.c`.

```
program := count ops*      count = payload[0] % 9; empty payload = 0 ops
op      := opcode operands opcode = byte % 8; stops early when bytes run out
0 TRUNCATE  off16          L = off16 % (L+1)
1 SET_BYTE  off16 v8       buf[off16 % L] = v8           (no-op if L == 0)
2 FLIP_BIT  off16 b8       buf[off16 % L] ^= 1 << (b8 & 7)
3 OVERWRITE off16 n8 lit   n = n8 % 33, clipped; write at off16 % (L+1)
4 DUPLICATE src16 n16      append buf[src16 % L ..] (n16 % 257 bytes, clipped)
5 APPEND    n8 lit         n = n8 % 33, clipped; append
6 MAGIC     m8             first 8 bytes := {MLDSASK2, MLDSAPK1, MLDSASK1, 0x00*8}[m8 % 4]
7 ID_LEN    v8             buf[8] = v8 when L > 8
```

The capacity is 8192 bytes and the template is 6030 bytes. Every byte string is a valid, bounded program.

v2 (Step 7.1) changed only the MAGIC table: index 0 is now the valid `MLDSASK2` magic, and index 2 is the **legacy** `MLDSASK1` magic (expected status `unsupported-format-version`); it was the invalid `MLDSASK0`. No committed program uses MAGIC, so their meaning is unchanged.

## Crash-reproducer workflow

A crash counts as **fixed only when all of these hold:**
1. **Minimize it:** `build-fuzz/tests/fuzz/fuzz_<t> -minimize_crash=1 -runs=10000 <artifact>`. The replay driver also saves oracle failures as `crash-<t>-replay-*` in its working directory.
2. **Admit it:** `tests/fuzz/add_regression.sh <build> <t> <artifact> <short-name>`. The **secret scanner is the mandatory admission gate for every target**; F1–F4 and F5 public mode are designed not to consume secret-key formats, but they are scanned anyway. An artifact the scanner refuses stays untracked (build directory only), and its root cause gets a deterministic unit test instead.
3. **Show it fails first:** `fuzz_<t>_replay <regression>` must fail **before** the fix; record that in the fix's commit message.
4. **Fix it:** after the fix, `fuzz_replay_<t>` passes in the normal, ASan and UBSan builds. It replays every committed regression.
5. **Pin logic errors:** a logic-error root cause also gets a deterministic test in the matching `tests/test_*.c`.

### Committed regressions

- **`keys/sample-identity-truncate-*`:** a 5-byte program (TRUNCATE to 5996 bytes → `bad-format`). It makes every CI run regenerate the identity template at runtime.
- **`keys/t0-corruption-original-*`:** the Step 7 fuzz finding, as found (first committed as `t0-corruption-accepted-*`). The Step 6 `MLDSASK1` loader accepted a secret key with a corrupted t0 component: its one-shot self-test passed about 75% of the time, and about 32% of that key's signatures then failed to verify. Under grammar v2 its OVERWRITE lands at secret-key offset 2446, still inside t0.
- **`keys/t0-corruption-rejected-*`:** the exact recorded corruption, `70 3c 8d` at file offset 4608 (secret-key offset 2642).
- **Status: RESOLVED in Step 7.1** (`MLDSASK2` integrity digest; `docs/decisions.md`). Both t0 programs must replay as `integrity-check-failed`, and the model predicts that status by recomputing the digest.

## Fuzzing proves none of the following

"No crash in N minutes" is **not** evidence of correctness. These properties remain covered **only** by deterministic tests:

- **Cryptography:** KATs; byte-exact KDF info and nonce/AD layout; unforgeability. The "OK only for genuine bytes" oracles in F2/F3 detect acceptance bugs, not cryptanalytic weakness.
- **Timing and I/O:** timeouts, trickle, EINTR, real TCP fragmentation, peer close, SIGPIPE, FD_CLOEXEC, port files (test_net, demo_e2e).
- **Resource and lifecycle:** zero-allocation gates, wipe hygiene, exactly-once handoff, session lifecycle, default rekey/expiry values, clock failure (test_session, test_session_alloc).
- **Ledger time behavior:** TTL, capacity and cancel (test_handshake). F2 uses a fixed clock.
- **Key-file permissions:** ownership and symlinks (test_net T14).
- **Concurrency:** none (single-threaded by design).
