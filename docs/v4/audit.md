# Audit of v1–v3 for deployment (V4-1)

The owner intends to run this protocol as the login system for one website.
Everything in v1–v3 was built and verified as a **reference implementation**
whose own README says *"Not production-ready"*. This audit asks a different
question of the same code: **what stands between it and that deployment?**

Method: three passes — mechanical (re-runnable scripts under `tools/audit/`,
each with a demonstrated failure mode), a fresh full read, and an adversarial
pass per entry point — plus a disposition of the 31 debt items recorded across
v1–v3. Nothing is fixed here. Every finding gets a severity *for this
deployment*, evidence as `file:line`, and an owning step.

Scope of the surface: **3,603 lines** of library (`src/crypto` 748,
`src/protocol` 2,756, `src/util` 99), **2,370** of apps, 7,599 of tests, 3,168
of fuzz harness, 433 of tools. 29 commits since `v1.0.0`; v1's protocol code
was deleted from `main` in V2-4/V2-5, so v1 is audited through its frozen spec
and its decisions, not its code.

## Findings register

Severity is for *this* deployment (one website, operators then public users),
not in the abstract.

| # | Finding | Era | Sev | Evidence | Disposition | Step |
|---|---|---|---|---|---|---|
| **F0** | **Release + gcc does not build on Linux.** `-Werror=unused-result` on two `symlink()` calls. gcc does **not** honour a `(void)` cast on `warn_unused_result`; clang does. `_FORTIFY_SOURCE=2` is only defined when not sanitizing and only bites at `-O2`, so Debug/ASan/UBSan never see it. **CI builds Linux only in Debug/ASan/UBSan; the sole Release build is `bench.yml`, with clang.** The natural deployment build has never been attempted. | v2 | **High** | `tests/test_net.c:1849,1959`; `CMakeLists.txt:75-78`; `.github/workflows/ci.yml:35-43`; `bench.yml:53`; measured: `Release+gcc FAILS`, `Release+clang BUILDS`, gcc warns on `(void)symlink` / clang does not | fix (2 lines, check the return); add a Release row to CI | V4-5 / V4-11 |
| F1 | **Successful handshakes cap at capacity ÷ TTL.** A completed handshake leaves a CONSUMED tombstone reclaimed only at expiry; `cancel` refuses an unexpired tombstone. 16 per 30 s as the demo is configured; 256 per 30 s at the compile-time maximum. Replay protection working as designed, but it is a hard throughput ceiling. `handshake_pending_active_count` counts only ACTIVE entries, so it reports 0 while the store is full. | v2 | **High** (B) | `src/protocol/handshake.c` insert/sweep ~110-160, consume/cancel ~265-305; `handshake.h:73` | configure capacity = rate × TTL; caller-provided backing array | V4-8 / V4-12 |
| F2 | **Enrolled identities enumerate.** An unknown identity is closed with no ServerHello; a pinned one gets ~4.5 KB. One connection per guess, and the unknown path is also much cheaper (no keygen, encaps or signature). | v2 | **High** | `src/protocol/handshake.c:863-867`; `apps/demo_app.c:253-258` | decoy pin → uniform flow; random handles; rate limiting | V4-8 |
| F3 | `keystore_lookup` early-exits on a hit; a miss always scans 32 entries. Deliberately *not* how `find_slot` is written (constant-time, no early exit, comment at `handshake.c:74`). | v1 | Low | `src/protocol/keystore.c:19-26,82-88` vs `handshake.c:74-90` | superseded: the daemon's store replaces this path | V4-7 |
| F4 | **No PIE/RELRO/BIND_NOW/noexecstack in the project's own link options.** macOS supplies PIE, NX and canaries by default; RELRO and BIND_NOW are Linux concepts and are the deployment platform's. | v1 | **Med** | `CMakeLists.txt:62-78`; `src/CMakeLists.txt:24`, `apps/CMakeLists.txt:13,19,25` (sanitizer flags only); measured by `tools/audit/check_hardening.sh` | add to the daemon target; gate with `--require` | V4-11 |
| F5 | **Coverage had never been measured.** Now measured (below). | v1–v3 | Med | `tools/audit/coverage.sh` | gaps → tests | V4-5 |
| F6 | `mlock` is never called by this code; it relies on libsodium's `sodium_malloc`, which **ignores `mlock` failure silently**. Guard pages are attested only indirectly (mutation K4b SegFault). ~10 such blocks per handshake. | v1 | Med | `src/util/secure_mem.{h,c}`; `handshake.c:418,668,770,785,797,933,1089,1106`; `kex.c:15`; `mlkem_wrap.c:43` | spike S1; set `LimitMEMLOCK` | V4-2 / V4-11 |
| F7 | No `install()` target anywhere; static libs; default build type **Debug**; default `MLDSA_OQS_OPT_TARGET=auto` = `-march=native`, documented as crashing on an older CPU of the same family. | v1/v2 | **Med** | `src/CMakeLists.txt:1`; `apps/CMakeLists.txt:3`; `CMakeLists.txt:4-10,90-92` | install target; pin the target CPU; Release recipe | V4-11 |
| F8 | ~10 `sodium_malloc`/`free` pairs per handshake (mmap + guard pages each). The *session* steady state is allocation-free and gated; the handshake is not. | v2 | Low | call sites as F6; `session.h:66-73` | measure under load | V4-12 |
| F9 | Security Req 4.7 says re-registration with a different key is "rejected **and logged**". The library rejects (`KEYSTORE_ERR_KEY_MISMATCH`) and explicitly delegates the logging half to the caller — which no caller implements. | v1 | **Med** | `src/protocol/keystore.h:25-29,60-65`; `keystore.c:46-54`; `docs/decisions.md:180-187` | audit table entry on every ENROLL rejection | V4-9 |
| F10 | Loopback IPv4 only; `accept(fd, NULL, NULL)` so the peer address is never obtained; no IPv6 path exists. | v1 | **Med** | `apps/net_io.c:73-78,118-142,154` | Unix-socket listener + proxy-set address | V4-8 / V4-10 |
| F11 | No in-session rekey: `session_rekey_due()` means "run a new handshake", and the demo just closes. | v1 | Low | `session.h:253-255`; `demo_app.c:356-364` | accept; sessions here are seconds | — |
| F12 | **The build needs the network at configure time** (liboqs clone + libsodium tarball). `-DFETCHCONTENT_SOURCE_DIR_LIBOQS` covers liboqs only; no documented offline path for libsodium. | v2 | Med | `cmake/Dependencies.cmake:61-71,139-143`; `README.md:55-57` | cached-dependency recipe for the VPS | V4-11 |
| F13 | The tree must not live under a path containing spaces (libtool). The current working copy **violates this** (`…/PQ Authentication protocol/…`) and it will also bite the wasm spike. | v2 | Low | `cmake/Dependencies.cmake:108-125` | operational constraint; build elsewhere | V4-2 / V4-11 |
| F14 | Identities are logged (escaped). For operators that is an audit feature; for **public end users a handle in a log is PII**. | v2 | Med | `apps/demo_app.c:45-57,262,437`; `demo_app.h:30-33` | `log_identities`/`log_client_ip` policy | V4-8 |
| F15 | v1 spec §5.1's x86_64 target was never measured on x86_64; v1's code is gone, so it cannot be. | v1 | Info | `docs/decisions.md:650-657`; `bench/results.md:463-471` | stays open, recorded | — |
| **F17** | **Req 4.8 (build hardening) and Req 4.9 (no secret-dependent control flow) have no executable pin.** Nothing asserts the hardening flags are applied; nothing tests constant-time behaviour. The only matches are comments. 11 of 13 security requirements are pinned by tests or tools. | v1–v3 | Med | conformance matrix below | 4.8 → `check_hardening.sh --require`; 4.9 → recorded as unpinned, argued by code review | V4-11 / — |
| F18 | Plain `memcmp` on four attacker-influenced comparisons: the identity in a `.pub`/`.sk` file vs the expected id (×3) and the demo's echo comparison. All are local-file or plaintext-echo paths, not remote oracles. | v1/v2 | Low | `apps/demo_keys.c:310,396,513`; `apps/demo_app.c:506` | accept with rationale; the daemon does not use these paths | — |
| F19 | **`-Werror=format-truncation` under gcc at `-O2 -D_FORTIFY_SOURCE=2`** in the `path()` test helpers: `snprintf(out, cap, "%s/%s", g_dir, name)` where `g_dir` is the same size as the destination, so gcc cannot prove the result fits. **Two sites**, found by sweeping every project source under that configuration (the one-site figure first recorded here was a spot-check, not a sweep). clang does not diagnose it and CI builds gcc at `-O0`, so **no existing gate sees it** — the same latent-Release+gcc class as F0. `test_authd_conn.c` uses the same pattern but writes into a 512-byte buffer from a 256-byte `g_dir`, which gcc *can* prove, and is unaffected. Fix verified in a container: checking `snprintf`'s return (truncation is a fixture bug → abort) compiles clean. | v4 (V4-6, V4-7) | Low | `tests/test_authd_keyfile.c:34`, `tests/test_authd_store.c:64` | check the return and abort on truncation | V4-11 |
| F20 | **Three spec gaps in §8 found while implementing it**, recorded rather than resolved by editing the spec: (a) no error code is defined for a refused/unknown command — the implementation returns `not-permitted`; (b) `ENROLL` carries no `role=`, so the role of a newly created user is implied by which command was used, and an existing user is never re-roled (`role-mismatch`); (c) list responses have no size bound in the spec, but are built in one buffer and sent as one reply, so they are capped at `AUTHD_LIST_MAX` (24) with `ERR code=too-many` rather than truncated. | v4 (V4-9a) | Info | `docs/mldsa-authd-spec.md` §8; `apps/authd/localapi.c` | a spec errata step should adopt all three wordings; streaming lists if a deployment needs more than 24 | V4-9c / V4-11 |
| F21 | **`admin.sock` was mode 0660, but spec §8 says 0600.** `listener_open_unix` chmod'd every Unix socket 0660 unconditionally, so the administrative socket was group-reachable. The uid allowlist still refused such a peer, so nothing was exploitable — but the second layer is exactly what a second layer is for. | v4 (V4-8a) | Low | `apps/authd/listener.c:139-140` | **FIXED in V4-9b**: the mode is a parameter restricted to the two values §8 defines; mutation `S1`; asserted in `authd_e2e` because no functional behaviour changes | V4-9b |
| F22 | **A configuration failure exited 1, but spec §13 says 3.** `0 success, 1 operation failed, 2 usage error, 3 configuration error` is a contract an operator's start-up script depends on; nothing returned 3. | v4 (V4-8a) | Low | `apps/authd/authd_main.c:147,162` | **FIXED in V4-9b** in both binaries, including a bad passphrase file; mutation `C1`, which asserts *exactly* 3 — "non-zero" also matches a missing binary | V4-9b |
| F23 | **Two listener-failure paths leaked the decrypted server key.** They did `free(slots); return 1;` while `server_kp` held the ML-DSA secret in secure memory and `store`, `pending`, `conns` and `local_slots` were live — a Req 2 violation. The four sibling paths for the local sockets correctly `goto listener_failed`, whose epilogue wipes and frees everything, so this was an inconsistency rather than a missing epilogue. `evloop_add_listener`'s return was also discarded at two sites where the local equivalents check it. | v4 (V4-8a) | Med | `apps/authd/authd_main.c:292-296,302-307` | **FIXED in V4-9b**; mutation `R1`. The check is portable rather than LSan-based: macOS ASan has no leak detector, so the e2e observes the epilogue's *socket cleanup*, which is true exactly when it ran | V4-9b |
| F24 | **`store_backup` wrote the backup with the daemon's umask** — mode 0644 from an interactive shell. A backup is a byte-for-byte copy of the credential database: token hashes, the audit chain and every enrolled public key. Found by running the new `backup` command and looking at the file, not by reading the code. | v4 (V4-7) | Med | `apps/authd/store/store.c`, `VACUUM INTO` | **FIXED in V4-9b**: the destination is chmod'd 0600, like the store it copies; mutation `B1` | V4-9b |
| F25 | **§8 does not specify `ENROLL-OPERATOR`'s key set.** It says "everything above plus `ENROLL-OPERATOR`", and the implementation's `enroll_common` accepts only `via=site` — so operator enrollment, performed by the administrator, is audited as `detail="site"`. Confirmed by running `audit-tail` after a real enrollment. The spec is not edited to match the code. | v4 (V4-9b) | Info | `apps/authd/localapi.c` `enroll_common`; `docs/mldsa-authd-spec.md` §8 | A spec errata step should give `ENROLL-OPERATOR` its own key list and a `via=operator` value, which `store_enroll_device` already accepts | V4-9c / V4-11 |
| F26 | **§3.1's handle format is a client-side convention, not a daemon invariant.** `authd_client keygen` generates `"d1" + 32 hex` and `test_authd_cli` pins that, but `id_valid` accepts any 1..64 printable bytes, and the existing Node fixture enrolls the four-byte handle `d1aa`. Nothing enforces the format at the boundary. | v4 (V4-9b) | Info | `apps/authd/localapi.c` `id_valid`; `tests/authd_node_fixture.c` | Deliberate for now — handles are opaque to the daemon and the unguessability that matters comes from the generator. Worth stating in §3.1 rather than leaving a reader to assume a gate exists | V4-11 |
| F27 | **`bad-handle` and `ticket-invalid` appear in §8's error table but are never emitted.** A malformed handle currently returns `malformed`. Same family as F20. | v4 (V4-9a) | Info | `docs/mldsa-authd-spec.md` §8 vs `apps/authd/localapi.c` | Fold into the same spec errata as F20 | V4-9c / V4-11 |
| F28 | **`AUTHD_PATH_MAX` (255) is roughly 2.5× `sun_path`** (104 bytes on macOS, 108 on Linux). A configuration with a long socket path passed every byte-level check and `--check-config` reported "valid"; the daemon then failed to bind at start-up. | v4 (V4-8a) | Low | `apps/authd/authd_config.h:27`; `apps/authd/listener.c` | **MITIGATED in V4-9b**: `authd_config_check_paths()` rejects it, and is called by **both** binaries so there is one validator with two entry points | V4-9b |
| F29 | **`store_audit_verify()` is reachable from nothing.** The audit chain's whole purpose is tamper detection, and the function that walks it exists and is tested — but there is no §8 command and no §13 subcommand that runs it, so a deployed operator cannot check their own chain. §9.2 says the head MAC "is written to the system journal periodically"; nothing does that either. | v4 (V4-7) | Med | `apps/authd/store/store.h` `store_audit_verify`; `docs/mldsa-authd-spec.md` §9.2 | **Open.** An offline `authd_admin audit-verify` needs no §8 command and no protocol change, but it is not in §13's list, so it belongs to the same errata step rather than being invented here | V4-11 |


Not re-listed: **keys at rest are unencrypted** (`demo_keys.c:349-352`,
`demo_keys.h:28-30`) and **no trust lifecycle** (`keystore.h:55-77`: no
remove/replace/revoke/persistence) — these are not defects to fix but the
substance of V4-6, V4-7 and V4-9.

## Coverage — first measurement

`tools/audit/coverage.sh build-cov`, whole suite (15/15), 25 profiles, project
sources only. Control: excluding the session tests drops `session.c` branch
coverage 95.99% → 76.28%, so the measurement responds to what it measures.

| File | Regions | Lines | Branches |
|---|---|---|---|
| `src/protocol/session.c` | 98.70% | 100% | **95.99%** |
| `src/protocol/keystore.c` | 96.08% | 100% | 92.96% |
| `src/protocol/transcript.c` | 95.99% | 100% | 88.79% |
| `src/crypto/kex.c` | 90.58% | 100% | 80.15% |
| `src/protocol/handshake.c` | 89.40% | 100% | 80.90% |
| `src/crypto/mlkem_wrap.c` | 82.64% | 100% | 70.33% |
| `src/crypto/aead.c` | 85.92% | 100% | 68.89% |
| `src/crypto/mldsa_wrap.c` | 81.31% | 100% | **57.69%** |
| `src/util/secure_mem.c` | 82.35% | 100% | 77.78% |
| `src/util/wire_int.c` | 100% | 100% | 100% |
| `apps/demo_keys.c` | 86.73% | 100% | 75.10% |
| `apps/demo_app.c` | 87.70% | 100% | 72.77% |
| `apps/frame.c` | 85.06% | 83.33% | 77.14% |
| `apps/net_io.c` | 75.07% | 93.75% | 68.65% |
| `apps/auth_client.c` | 77.25% | 66.67% | 62.99% |
| `apps/auth_server.c` | 76.81% | 50.00% | **61.17%** |
| **TOTAL** | **87.77%** | **97.19%** | **77.29%** |

Reading: the **protocol core is the best-covered code and the apps layer the
worst** — and the apps layer is exactly what the daemon replaces, so the
weakest-covered code is on its way out. `mldsa_wrap.c`'s 57.69% branches is
the lowest in `src/`: those are liboqs failure paths (allocation and
`OQS_STATUS` errors) that tests cannot reach without fault injection. Coverage
is **not** adopted as a gate — the mutation campaigns are the gate — but an
uncovered branch is one no mutation could be killed in, so these are the
blind spots.

## Spec-v2 conformance matrix — §4 security requirements

Machine-checked: that each cited test exists (script). Read, not machine-checked:
that the cited test actually pins the requirement.

| Req | Statement | Pinned by |
|---|---|---|
| 4.1 | No custom primitives | `test_vectors` (liboqs/RFC KATs) |
| 4.2 | Secret memory handling | wipe assertions in `test_handshake`, `test_session`, `test_net`; `test_session_alloc` |
| 4.3 | Constant-time comparisons | `tools/audit/constant_time_inventory.sh` (48 sites: 11 CT, 37 plain, all plain ones dispositioned) |
| 4.4 | Transcript-bound signatures | `test_handshake` (substitution, tamper, W-series) |
| 4.5 | Replay protection | `test_session` (contiguous-seq policy), `test_handshake` (ledger) |
| 4.6 | Strict input validation | `test_handshake` truncation sweeps, `fuzz_wire`, `fuzz_handshake`, `fuzz_session` |
| 4.7 | No silent key rotation | `keystore` refusal tested; **the "and logged" half is unimplemented (F9)** |
| **4.8** | **Build hardening** | **nothing — F17.** `tools/audit/check_hardening.sh` is the first check |
| **4.9** | **No secret-dependent control flow** | **nothing — F17.** No timing test exists |
| 4.10 | Build-time backend selection | `tools/check_backend_symbols.sh` + `bench.yml` agreement check |
| 4.11 | Decaps never a validation signal | `test_vectors` (implicit rejection), `test_handshake` H3 |
| 4.12 | Responder KEM secret wiped on every path | `test_handshake` H6 wipe matrix |
| 4.13 | Padding verified, not skipped | `test_session` P4; `fuzz_session` inner model |

**11 of 13 pinned; 2 unpinned (4.8, 4.9).**

## Debt ledger disposition (A1–A31 from v1–v3)

Blocking this deployment, each owned by a step: A4 rate limiting (V4-10),
A6 CA/revocation (V4-7/V4-9), A7 key storage (V4-6), A8 non-loopback listener
and hardening (V4-10/V4-11), A12 Req 4.7 logging (V4-9).
Moot by architecture: A3 multi-connection routing (one handshake per
connection), A5 thread safety (single-threaded event loop by construction).
Accepted and recorded: A9 traffic analysis beyond padding, A10 two-party only,
A19 v1's x86_64 deviation, A26 endpoint compromise, A27 both-halves break,
A28/A29 what fuzzing and benchmarks do not establish, A31 path-with-spaces.
Resolved in v2/v3 and re-confirmed here: A1, A2, A15–A18, A23–A25.

## What this audit does not establish

It is still **single-agent review**: the same agent that wrote v1–v3 audited
them. That is why V4-14 produces a review packet for an external
cryptographic review, and why this document lists what was machine-checked
separately from what was read. No timing measurements were taken (Req 4.9);
no side-channel analysis beyond reading for secret-dependent branches; the
pinned dependency versions were not re-checked against advisories in this
pass.
