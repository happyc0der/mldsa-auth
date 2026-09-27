# Pinned dependencies against published advisories

Checked **2026-09-27 (23:07 UTC)** for the review packet (V4-14b). Until this
check, the V4-1 audit said plainly that nobody had ever compared the pinned
versions with published advisories. This page records **what was asked, of
whom, and what came back — including "nothing"** — so a reviewer can repeat it
and see what a clean answer is worth.

## What is pinned, and how

| Component | Version | Pinned by | Role |
|---|---|---|---|
| liboqs | 0.16.0 | git commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, verified twice at build time | ML-DSA-65, ML-KEM-768 (`OQS_MINIMAL_BUILD`: nothing else is compiled) |
| libsodium | 1.0.22 | tarball SHA-256 `adbdd8f1…3349` | X25519, ChaCha20-Poly1305, Argon2id, HKDF-SHA256, BLAKE2b, `secure_mem` |
| SQLite | 3.53.4 (`3530400`) | amalgamation SHA3-256 `628a44cf…934e` | the daemon's store |
| Emscripten | 6.0.9 | exact version refused otherwise at configure; emsdk commit `5eb0bde7` in CI | compiles the browser module |

Build and test tools that do not ship — Node 24.21.0, Chrome for Testing
154.0.8037.57, ProVerif 2.05, Caddy (installed by the operator) — are outside
this check.

## What was asked

1. **OSV.dev by source commit.** Each pinned release was resolved to its git
   commit and queried (`POST https://api.osv.dev/v1/query {"commit": …}`):
   liboqs `5a1a854b`, libsodium `77e1ce5d` (both the `1.0.22` and
   `1.0.22-RELEASE` tags point at it), SQLite `b09c88c1` (`version-3.53.4`),
   Emscripten `4e422385` (`6.0.9`).
2. **NVD.** Keyword search for `libsodium`, `liboqs` and `emscripten`, and
   `virtualMatchString=cpe:2.3:a:sqlite:sqlite:3.53.4`.
3. **The projects' own GitHub security advisories**
   (`repos/{owner}/{repo}/security-advisories`) for liboqs and libsodium.

**Controls.** A lookup that can only answer "nothing" is not evidence, so
each channel was also run against a version known to be affected:

- OSV by commit for SQLite `version-3.50.1` returns **CVE-2025-6965**, and NVD
  for `sqlite:3.50.1` returns it among five. Both channels work for SQLite.
- **OSV does not cover libsodium at all**: `1.0.18-RELEASE`, which predates
  CVE-2025-69277's fix, also returns nothing, and OSV lists no package under
  the name. libsodium's clean answer therefore rests on NVD and on reading the
  pinned source, not on OSV.

## What came back

**liboqs 0.16.0 — one advisory affects this version, in code this build does
not compile.**

- **GHSA-wh5q-mpc8-67wf** (2026-09-22, medium): a heap out-of-bounds read in
  LMS/HSS signature verification, patched in **0.17.0** — so 0.16.0 is in
  range. The build sets `OQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768"`,
  and the built `liboqs.a` holds **0** LMS/HSS symbols and **0** XMSS symbols,
  against 8 ML-DSA ones (the control that `nm` found the library at all).
  Recorded as audit finding **F91**: not exposed, and the pin should still
  move to 0.17.0 at the next dependency update, so that the claim does not
  rest on a build flag alone.
- Every other liboqs advisory is fixed at or before 0.16.0:
  - GHSA-2wxh-55qf-c7wg / CVE-2026-46344 and GHSA-wf7v-fhxj-73m2 /
    CVE-2026-44518: XMSS, fixed in 0.16.0, and not compiled.
  - GHSA-qq3m-rq9v-jfgm / CVE-2025-52473: HQC, fixed in 0.14.0.
  - GHSA-3rxw-4v8q-9gq5 / CVE-2025-48946: an HQC design flaw.
  - GHSA-gpf4-vrrw-r8v7 / CVE-2024-54137: HQC, fixed in 0.12.0.
  - GHSA-f2v9-5498-2vpp / CVE-2024-36405: Kyber reference timing, fixed in
    0.10.1.
  - CVE-2024-31510: ML-DSA-44 IPD AVX2 in v0.10.0. That is NVD-only, and
    names a component and version this build does not use.

**libsodium 1.0.22 — no advisory affects it.**

- CVE-2025-69277 (`crypto_core_ed25519_is_valid_point` accepted some points
  outside the main subgroup), fixed upstream by `ad3004e`. That commit is on
  `master`, which the 1.0.22 release tag diverges from, so ancestry settles
  nothing. Instead, **the pinned source was read**: `ge25519_is_on_main_subgroup`
  in 1.0.22's `ed25519_ref10.c` carries the fix's `Y == Z` check, and its
  regression vector `not_main_subgroup_p` is in the bundled test. The project
  does not call the function in any case.
- The other NVD matches for "libsodium" concern software that embeds or wraps
  it (Nim, Valve GameNetworkingSockets, WAL-G, two Perl modules, Parsec, Vim,
  Unbound), not libsodium itself. libsodium publishes no GitHub security
  advisories.

**SQLite 3.53.4 — none.** OSV by commit returns nothing. NVD's one CPE match,
CVE-2022-31631, is a PHP `PDO::quote()` bug filed under SQLite's product name,
not a defect in SQLite. The four SQLite CVEs NVD lists against 3.50.1 are
absent at 3.53.4.

**Emscripten 6.0.9 — none.** OSV by commit returns nothing. NVD's six matches
for "emscripten" are defects in software built with it or around it (stb_image,
WAVM, Binaryen misuse, a libheif wrapper, raylib, Wasmer), not in the compiler.

## What this does not establish

A clean answer means "no *published* advisory, in these three sources, on this
date". It says nothing about undisclosed defects, and the sources differ in
coverage — OSV's gap for libsodium is shown above. Rerun the queries before
relying on this page; the commands are in [REPRODUCE.md](REPRODUCE.md).
