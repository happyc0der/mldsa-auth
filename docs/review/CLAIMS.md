# Claim map: every security requirement, and what pins it

Two specifications state the security requirements this code must meet:

- **P1–P13**: the protocol's, [`ml-dsa-auth-protocol-spec-v2.md`](../ml-dsa-auth-protocol-spec-v2.md) §4.
- **D1–D14**: the deployment's, [`mldsa-authd-spec.md`](../mldsa-authd-spec.md) §5.

Each entry below lists the evidence that pins its requirement, strongest
first, then what that evidence does **not** establish. Read the second part
as carefully as the first: it is where this map is most useful to a reviewer.

**Evidence kinds.**

| Kind | Meaning |
|---|---|
| `check T "…"` | a named assertion in CTest `T`; the quoted text is what it prints |
| `mutation vNN ID` | a committed mutation (`tools/mutations/`) that this evidence kills; the nightly runs all 305 |
| `proverif "…"` | a query `formal/run.sh` requires ProVerif to prove, with controls that must make it fail |
| `fuzz name` | a libFuzzer target whose oracle asserts the property |
| `tool path` | a gate script |
| `ci job` | a CI job that runs the evidence |

**The map is checked.** `tools/audit/check_claim_map.py` fails if any
requirement in either specification lacks an entry here, if a heading's
title differs from its requirement's, or if anything cited no longer exists:
a check text not in its test, a mutation not in its campaign, a query
`formal/run.sh` does not expect. It runs in CI's specification job. It
cannot check the prose: "not established" is this document's judgement.

Findings cited as **F**nn are in the audit register,
[`docs/v4/audit.md`](../v4/audit.md). Several are open, and the open ones are
the most important thing on this page.

---

## The protocol (spec-v2 §4)

### P1 — No custom cryptographic primitives
- check `test_vectors` "mldsa65_kat: SHA-256(KAT record) matches liboqs's published single-vector hash"
- check `test_vectors` "mlkem768_kat: SHA-256(KAT record) matches liboqs's published single-vector hash"
- check `test_vectors` "hkdf_rfc5869: kex_hkdf_sha256 matches RFC 5869 Appendix A.1 Test Case 1"
- check `test_vectors` "chacha20poly1305_rfc8439: aead_encrypt matches RFC 8439's published ciphertext+tag"
- mutation `v24 M1` — the hybrid combiner's IKM uses ss_x twice and drops ss_k
- mutation `v53 F12` — liboqs no longer routed to libsodium's generator (only the client-core KAT golden sees it)
- tool `tests/web_no_crypto.mjs` — no JavaScript under `web/client` reaches WebCrypto, Node crypto, `getRandomValues` or `Math.random` (CTest `web_no_crypto`)
- check `no_hand_rolled_primitives` "no primitive's defining constant appears anywhere else in src/, apps/ or web/client/"
- check `no_hand_rolled_primitives` "sha1() is called by apps/authd/ws.c and by nothing else in src/ or apps/"
**Not established:** the gate looks for primitives by their defining constants; one written without any (a construction from generic operations, or constants computed at run time) would pass it. The tree holds one sanctioned primitive, a hand-written SHA-1 (`apps/authd/sha1.c`), used only for RFC 6455's accept value and pinned by FIPS 180-1 vectors; its scope is now checked, not asserted (audit F102). The gate was shown red by hand (a planted SHA-256 IV, the ChaCha sigma in JS, a stray `sha1()` call), not by a campaign.

### P2 — Secret memory handling
- check `test_session_alloc` "S23: session_wipe frees exactly one secure allocation and clears the key pointer"
- check `test_handshake` "v2-5 H5: no keys, secrets wiped"
- check `test_handshake` "v2-5 H7: a short ClientHello buffer rolls back BOTH keypairs, state stays NEW"
- check `test_client_core` "phish: the owned key is freed on refusal"
- mutation `v25 N4` — finish keeps the decapsulation key
- mutation `v53 F3` — the owned ML-DSA key is dropped, not freed, on success
- mutation `v23 K4b` — the freed decapsulation-key pointer is left dangling
- check `secure_mem_sites` "PASS: every listed secret is still allocated with secure_mem_alloc"
- mutation `v69 SM1` — the store's audit-MAC key is allocated with calloc and released with free
- mutation `v69 SM2` — the client's plaintext secret-key image at enrollment is allocated with malloc and released with free
**Not established:** most wipe checks observe a freed or NULL pointer (`sodium_free` zeroes), not the bytes. A structural scan of allocation covers `session.c` only (`session_no_alloc_scan`: no allocation in the steady state). Since V4-24b every `secure_mem_alloc` site in `src/` and `apps/` -- 35 of them -- is pinned both ways (`secure_mem_sites`), so a heap secret moved to ordinary memory fails by name; which buffers belong on that list rests on reading, done once in V4-24b; that every key in `src/` and `apps/` lives in `sodium_malloc` memory, and that stack copies are wiped on every error return, rests on code review.

### P3 — Constant-time comparisons
- tool `tools/audit/constant_time_inventory.sh` — lists every `sodium_memcmp`/`sodium_is_zero` site against every `memcmp`/`strcmp`/`strncmp` site in `src/` and `apps/`; fails only on finding no constant-time site
- mutation `v52 P8` — the identity `sodium_memcmp` in the pin lookup removed
- mutation `v53 F7` — the ROTATE_ACK fingerprint comparison bypassed
- mutation `v47 S6` — the login-code state-hash comparison disabled
- check `test_authd_conn` "conn: the pin lookup refuses an id that is not this connection's handle"
- check `test_client_core` "fake: a ROTATE_ACK naming a DIFFERENT key is refused"
- check `constant_time_sites` "every listed constant-time comparison is still a sodium_memcmp or sodium_is_zero call"
- mutation `v59 GB8` — the pin lookup's `sodium_memcmp` becomes `memcmp` (the mutation v49c and v52 declined, having no gate)
- mutation `v59 GB10` — the audit chain's MAC comparison becomes `memcmp`
**Not established:** the gate pins WHICH function compares, at 25 sites; it does not measure how long a comparison takes, and nothing does -- the constant-time property itself is libsodium's. The plain `memcmp`/`strcmp` sites stay a report (the inventory) with a judgement (audit F18); none of the 29 plain `memcmp` lines compares a secret (audit row 4.3, V4-15b).

### P4 — Transcript-bound signatures
- check `test_handshake` "v2-5 H4: another handshake's mlkem_ct spliced into a signed ServerHello -> SIGNATURE, FAILED"
- check `test_handshake` "v2-5 H4: ...and the reply fails sig_B at the initiator, whose transcript has its own ek"
- check `test_handshake` "transcript_hashes: transcript_hash_client_auth matches independent hand-built SHA-256(label||0x00||CH||SH)"
- mutation `v24 M5` — the TH_server_auth label left at v1
- mutation `v24 M3` — the transcript digest left out of the KDF info
- fuzz `wire` — each transcript helper equals a digest built independently with raw SHA-256 and literal labels
- ci `ProVerif model + controls` — injective agreement on (A, B, session_id, nonce_B, key); the `ctl_sigb` control makes it unprovable
- check `test_handshake` "v2-5 H1: the initiator completes against a hand-built responder"
- check `test_handshake` "v2-5 H2: the responder verifies the hand-built ClientAuth -> ESTABLISHED"
- mutation `v59 GB6` — TH_server_auth hashes the ClientHello without its nonce, in BOTH roles, so the library stays self-consistent
- mutation `v59 GB7` — TH_client_auth hashes the ServerHello without sig_B, in both roles
**Not established:** a self-consistent change to what is signed is caught only by checks that bring their own bytes -- the hand-built peers (H1, H2) and the client-core KAT golden, whose golden this same code produced; two fields are mutated, not every field. ProVerif works on an abstract model. Separation from v1 rests on the `/v2/` labels.

### P5 — Replay protection
- check `test_session` "S4: re-delivering an accepted record -> REPLAY, session FAILED"
- check `test_session` "S5: seq 1 before seq 0 (a gap) -> OUT_OF_ORDER, session FAILED"
- check `test_handshake` "step4 T9: replay (store layer) -> PENDING_ERR_CONSUMED"
- check `test_handshake` "step4 T11: ClientAuth after TTL -> EXPIRED, responder FAILED"
- check `test_session` "S12: a second session from the consumed initiator handshake -> UNEXPECTED_STATE"
- fuzz `session` — a reference model predicts every status (REPLAY below recv_seq, OUT_OF_ORDER above), the resulting state and recv_seq
- fuzz `handshake` — after every ClientAuth the ledger's slot state and failure count match the model, CONSUMED included
- check `test_session` "S4b: re-delivering an OLDER record (r0 after r0 and r1) -> REPLAY, session FAILED"
- check `test_session` "S5b: seq 2 before seq 0 (a gap of two) -> OUT_OF_ORDER, session FAILED"
- check `test_handshake` "step4 T34: record_failure on a CONSUMED tombstone -> CONSUMED, nothing counted, still a tombstone"
- check `test_handshake` "step4 T34: a second consume_success -> CONSUMED (a handshake commits once)"
- mutation `v59 GB1` — the REPLAY check narrowed to the previous record
- mutation `v59 GB2` — the OUT_OF_ORDER check narrowed to a gap of one
- mutation `v59 GB3` — failures counted against a CONSUMED tombstone
- mutation `v59 GB4` — a handshake commits twice
**Not established:** two of the ledger's five CONSUMED checks are reachable only through the store's API, not the protocol -- defence in depth -- and the CONSUMED-to-`HANDSHAKE_ERR_REPLAY` mapping is unreachable through the API: a replayed ClientAuth meets UNEXPECTED_STATE first (T9). v25 N7 remains a documented equivalent mutant. Single use is per `handshake_id` within the pending entry's TTL; there is no session-id or nonce cache beyond it.

### P6 — Strict input validation
- check `test_handshake` "v2-4 W1: CH/SH_unsigned/SH/CA maxima are 1330/1234/4545/3328 and the ML-KEM fields 1184/1088"
- check `test_handshake` "malformed: decode_server_hello rejects sig_len > MLDSA_SIGNATURE_MAX_BYTES"
- check `test_handshake` "malformed: decode_client_hello rejects valid message plus one trailing byte (strict mode)"
- mutation `v24 M6` — the ClientHello length check forgets the ML-KEM encapsulation key
- mutation `v26 Q6` — the minimum record length back to v1's 25
- mutation `v53 F1` — a frame's length header no longer compared to the bytes present
- fuzz `wire` — at most one decoder accepts, only its own type byte, with full consumption and encode(decode(x)) == x
- fuzz `frame` — on a bad length exactly the 4 header bytes are consumed, so no payload is read
**Not established:** an ML-KEM encapsulation key's validity is checked inside encapsulation, which is a cryptographic call; the 1952-byte ML-DSA public key is never on the handshake wire, and its size is enforced by the key-file, ROTATE and enrollment parsers instead.

### P7 — No silent key rotation
- check `test_authd_store` "a known handle presenting a different key is rejected (Req 7)"
- check `test_authd_store` "the rejected re-enrollment did not replace the active key"
- check `test_authd_localapi` "enroll: the same handle with a DIFFERENT key is refused (Req 7)"
- check `test_handshake` "step4 T16: same id, different key -> KEY_MISMATCH"
- check `test_handshake` "step4 T16: the pinned key was NOT replaced by the mismatching add"
- mutation `v49c W4` — the store no longer pins which key is being replaced
- tool `tools/audit/check_spec_vocabularies.py` — the `enroll-key-mismatch` events are emitted from literal call sites, checked against the spec both ways
- check `test_authd_localapi` "req7(site): the refusal is logged with both key fingerprints"
- check `test_authd_localapi` "req7(recovery): the refusal is logged with both key fingerprints"
- mutation `v58 GA11` — the daemon's pre-check comparison inverted: a different key passes as idempotent
- mutation `v58 GA10` — the logged `fp_old` is the presented key's fingerprint
**Not established:** "logged" means the §15 journal, not the audit chain -- a refused enrollment writes nothing to the store (erratum 45, a user decision), so the record of a Req 7 refusal is only as durable as the journal's sink. Until V4-15a three refusal paths logged nothing (audit F97, fixed).

### P8 — Build hardening
- tool `tools/audit/check_hardening.sh` — PIE, RELRO, BIND_NOW, a non-executable stack and a stack canary read from every binary; `--require` fails on any gap
- tool `tools/check_sanitizer_link.sh` — the ASan or UBSan runtime is linked into every executable
- ci `Release + install + hardening (Linux, ${{ matrix.cc }})` — runs `check_hardening.sh --require` on the installed tree
- ci `${{ matrix.os }}·${{ matrix.cc }}·${{ matrix.config }}` — ASan and UBSan on Linux and macOS, instrumentation proven, then the whole suite
- ci `mutations · ${{ matrix.campaign }}` — every campaign on a fresh, proven ASan tree
- check `authd_e2e` "PASS: E2E: no sanitizer report in any daemon or client log"
- tool `tests/check_build_flags.cmake` — the CTest `build_flags`: every project translation unit in `compile_commands.json` is told `-Wall -Wextra -Werror -fstack-protector-strong`, and `-D_FORTIFY_SOURCE=2` exactly outside the sanitizer and fuzz trees; the project's own archives import `__stack_chk_fail`; since V4-24b, each tree's sanitizer flags by its intent -- `-fsanitize=undefined` and `-fno-sanitize-recover=undefined` in a UBSan or fuzz tree, `-fsanitize=address` in an ASan or fuzz tree, none in any other
- check `ubsan_aborts` "PASS: ubsan_aborts: a planted signed overflow stops the process"
**Not established:** the flag gate reads what each translation unit was TOLD, not what the compiler did with it -- for UBSan alone, since V4-24b, `ubsan_aborts` also checks what was DONE, on one planted signed overflow; `check_hardening.sh`'s binary canary cannot fail for this project's code, because vendored archives satisfy it (audit F104). FORTIFY is inert without optimisation: on glibc a `-O0` build with `-D_FORTIFY_SOURCE=2` compiles under `-Werror` and imports no `__*_chk` (measured on Ubuntu 22.04, gcc 11.4, glibc 2.35), so CI's Linux debug jobs carry the define and none of its checks; only optimised builds (the Release job) get them. Until V4-14c the UBSan build did not stop on undefined behaviour, so a report printed and the test passed (audit F94, fixed: `-fno-sanitize-recover=undefined`, shown both ways on a planted overflow). No mutation covers that flag -- the campaigns mutate C sources only -- but since V4-24b it is pinned twice and shown by hand: with it removed from the UBSan branch, `build_flags` names every translation unit without it and `ubsan_aborts` sees the canary run on past the overflow; the same removal in the fuzz branch, `-fsanitize=address` removed, and a plain tree configured with `-fsanitize=undefined` each fail `build_flags` too (V4-24b's decisions entry).

### P9 — No secret-dependent control flow
- check `test_authd_conn` "decoy: known-wrong-key and unknown-handle reach the SAME client-side outcome"
- check `test_authd_conn` "decoy: the unknown handle still got a VERIFIABLE ServerHello (canary)"
- mutation `v52 P5` — the pin lookup branches on the decoy flag, so an unknown identity fails earlier and differently
- mutation `v48b C1` — an unknown identity gets no decoy and is refused outright
- tool `tools/audit/constant_time_inventory.sh` — a list of comparison sites, not a timing check
**Not established:** essentially unpinned. The audit (F17) records that this requirement has no executable pin and no timing test; the decoy evidence shows identical outcomes, not identical timing, and F37 records an accepted timing distinguisher in ROTATE rejection.

### P10 — Build-time algorithm backend selection
- tool `tools/check_backend_symbols.sh` — every executable links no portable-C ML-DSA-65/ML-KEM-768 and exactly one optimised family; fails on no executables, no backend, or no optimised family
- ci `Release + install + hardening (Linux, ${{ matrix.cc }})` — runs it as "One optimized backend, no portable-C" on a Release x86-64-v3 build
**Not established:** the check infers "no runtime branching" from `OQS_DIST_BUILD=OFF` and symbol names, not by looking for CPU-feature branches. It does not cover libsodium, whose ChaCha20 selects its implementation at `sodium_init` by CPU features (a one-time pointer choice, not a per-call branch, but a runtime selection all the same). It runs on Linux x86_64 only, and no mutation covers it.

### P11 — ML-KEM decapsulation is never a validation signal
- check `test_handshake` "v2-5 H3: the initiator's key does NOT match the encapsulator's -- the sides disagree, as designed"
- check `test_session` "S27: BOTH sides still reach ESTABLISHED -- decapsulation reports no error (Req 4.11)"
- check `test_session` "S27: the initiator's first record fails AUTH at the responder, terminally"
- check `test_vectors` "mlkem768_implicit_rejection: decaps of a tampered ciphertext SUCCEEDS (no error signal)"
- mutation `v25 N6` — decapsulation skipped; the initiator derives from a zero ss_k
- mutation `v23 K2` — the wrapper ignores the decapsulation status
- check `test_handshake` "P11: every value of the decapsulated secret's first byte -- the initiator completes, keyed by exactly what decapsulation returned"
- check `test_handshake` "P11: a decapsulated secret whose first two bytes are zero -- the initiator completes, keyed by exactly what decapsulation returned"
- mutation `v68 CG2` — the initiator fails a handshake whose decapsulated secret starts with two zero bytes
**Not established:** since V4-24a the decapsulated bytes are CHOSEN: for each of 289 initiator handshakes the test predicts implicit-rejection secrets (FIPS 203's J(z || c)) over candidate ciphertexts until one has a given property -- each value of its first byte, a zero at each position, two leading zeros -- confirms it by a real decapsulation, and needs the initiator to complete, keyed by HKDF over exactly that secret. That catches a branch which changes whether the handshake completes or what it derives, at the values the sweep reaches; a branch with no functional effect is a timing question, and nothing here measures timing. `handshake.c` does branch on the decapsulation wrapper's return code, which reports wrapper or argument errors, not ciphertext authenticity.

### P12 — The responder's retained KEM secret is wiped on every path
- check `test_handshake` "v2-5 H6: responder secrets wiped after UNKNOWN_IDENTITY"
- check `test_handshake` "v2-5 H6: responder secrets wiped after AUTH_FAILURE_LIMIT"
- check `test_handshake` "v2-5 H7: a short ServerHello buffer rolls back the ephemeral key AND ss_kem, nothing inserted"
- check `test_handshake` "v2-5 H2: ss_kem is wiped once the keys are derived"
- mutation `v25 N3` — terminal failures do not release ss_kem
- mutation `v25 N8` — a retryable failure releases it (the next ClientAuth then cannot complete)
- mutation `v48b C6` — a released daemon connection keeps its handshake
- fuzz `handshake` — ss_kem retained on success and wiped on failure; a terminal ClientAuth failure wipes the hybrid secret
**Not established:** "wiped" is observed as a NULL pointer after `secure_mem_free` (which zeroes), not by reading the bytes; on the daemon's cancellation path the test sees the ledger entry released, not ss_kem itself.

### P13 — Padding is verified, not skipped
- check `test_session` "v2-6 P4(b): the FIRST padding byte nonzero -> MALFORMED, FAILED, buffer zeroed"
- check `test_session` "v2-6 P4(c): the LAST padding byte nonzero -> MALFORMED, FAILED, buffer zeroed"
- check `test_session` "v2-6 P4(a): an authentic inner whose content_len exceeds it -> MALFORMED, FAILED, buffer zeroed"
- check `test_session` "v2-6 P4(d): content_len == inner_len - 2 (no padding) is legal"
- mutation `v26 Q1` — the receiver accepts nonzero padding
- mutation `v26 Q2` — content_len not bounded against the inner
- fuzz `session` — in inner mode, an inner under 2 bytes, content_len past the inner, or any nonzero padding byte is MALFORMED and terminal
- check `test_session` "v2-6 P4(g): EVERY middle padding byte (indices 13..62), one at a time, nonzero"
- mutation `v59 GB5` — only the first and the last padding byte checked
- check `test_session` "v2-6 P4(h): EVERY padding byte of every bucket's inners, one at a time, nonzero"
- check `test_session` "v2-6 P4(h): each bucket's inner opens while its padding is clean (the canary)"
- mutation `v64 TG5` — the padding check stops after the first 64 padding bytes, so only larger buckets' inners reach past it
**Not established:** since V4-22a every padding byte is set, one at a time, in 20 inners -- for each bucket from 16 to 4096, empty content, content one byte under and one byte over a bucket boundary, and the last one bucket on: 10,907 cases. They open on a white-box clone of a real receiver (`fuzz_session`'s technique), and the clean inner opening through each clone is the canary. Inner lengths no bucket produces and two bytes set at once rest on the fuzz model. Q2 is named only as `ASAN in sodium_is_zero`: its unbounded length wraps inside the padding check, and the process faults before any check can print (audit F90).

---

## The deployment (mldsa-authd §5)

### D1 — No new cryptographic primitives
- check `test_vectors` "mlkem768_kat: SHA-256(KAT record) matches liboqs's published single-vector hash"
- check `test_vectors` "mldsa65_kat: SHA-256(KAT record) matches liboqs's published single-vector hash"
- check `test_authd_keyfile` "flipping any header field or the ciphertext makes open fail"
- mutation `v23 K1` — the ML-KEM wrapper skips `OQS_KEM_encaps`
- mutation `v46 E3` — a failed XChaCha20-Poly1305 decrypt of the envelope is ignored
- fuzz `envelope` — an independent model of §12's MLDSAEK1 header rules predicts FORMAT/PARAMS/OK, and `keyfile_parse_header` must agree
- tool `tools/check_backend_symbols.sh` — one optimised liboqs backend linked, none portable
- check `liboqs_minimal` "no LMS, HSS, LM-OTS or XMSS symbol" — the linked `liboqs.a` holds ML-DSA and ML-KEM and no stateful-signature algorithm, so the advisories in F91 cannot reach it
- check `test_envelope_spec` "code->spec: raw XChaCha20-Poly1305 with AAD = bytes [0, 67) opens it to the exact MLDSASK2 image"
- check `test_envelope_spec` "spec->code: keyfile_open_buf opens the hand-built envelope, to the same identity"
- mutation `v60 GC1` — the envelope's associated data shortened to [0, 63), in seal AND open
- mutation `v60 GC2` — the KDF uses half the memlimit the header states, in both
- check `no_hand_rolled_primitives` "no primitive's defining constant appears anywhere else in src/, apps/ or web/client/"
**Not established:** the independent reader is this project's own test, written from §12 by the same author as `keyfile.c`; it shows the two readings agree with each other and with libsodium, not that §12 is the right design. The primitive gate finds primitives by their constants only (see P1).

### D2 — Secrets live in `secure_mem` and are wiped on every path
- check `test_authd_conn` "wipe: closing a connection clears its session, handle and identity"
- check `test_handshake` "v2-5 H5: no keys, secrets wiped"
- check `test_session_alloc` "S23: session_wipe frees exactly one secure allocation and clears the key pointer"
- check `authd_e2e` "E2E: a listener failure runs the cleanup epilogue that wipes the server key"
- mutation `v52 P9` — a slot's pinned key survives its connection
- mutation `v25 N3` — terminal handshake failures leak the responder's retained KEM secret
- mutation `v49b R1` — a listener failure leaks the decrypted server key
- fuzz `authd_conn` — after any close the connection record is free, its handle and user id zero and its session empty
- check `secure_mem_sites` "PASS: every secure_mem_alloc call in src/ and apps/ is on the list"
- mutation `v69 SM1` — the store's audit-MAC key is allocated with calloc and released with free
**Not established:** since V4-24b a gate lists every HEAP secret buffer and needs each to come from `secure_mem` (`secure_mem_sites`); which buffers are secret rests on reading, and a secret in a fixed-size array or on the stack is not an allocation, so it is not on the list. Several daemon secrets (the login code in a local struct, tokens, state hashes) live on the stack and are wiped with `sodium_memzero`, which no check observes; "every path" is tested on chosen failure paths, not exhaustively. Until V4-24b five local-API error returns left a decoded secret on the stack -- among them a valid login code, on a malformed `state` (audit F115, fixed, by reading: no check can read a dead stack frame).

### D3 — Constant-time comparison
- check `test_authd_conn` "conn: the pin lookup refuses a PREFIX of its handle"
- check `test_authd_conn` "conn: the pin lookup refuses an id that is not this connection's handle"
- check `test_authd_store` "a login code presented with the WRONG state is refused (login-CSRF binding)"
- mutation `v52 P8` — the identity `sodium_memcmp` in the pin lookup removed
- mutation `v47 S6` — the state-hash `sodium_memcmp` in the code's consumption disabled
- mutation `v53 F7` — the client's ROTATE_ACK fingerprint comparison bypassed
- tool `tools/audit/constant_time_inventory.sh` — every comparison site in `src/` and `apps/`, labelled constant-time or plain
- check `constant_time_sites` "every sodium_memcmp and sodium_is_zero call in src/ and apps/ is on the list"
- mutation `v59 GB8` — the pin lookup's `sodium_memcmp` becomes `memcmp`
- mutation `v59 GB9` — the login code's state comparison becomes `memcmp`
**Not established:** weaker than a measurement. Since V4-15b a swap to `memcmp` fails a named gate (GB8-GB10), but the gate pins which function compares, not how long it takes, and nothing measures timing. Token, login-code and ticket hashes are found by SQLite `WHERE ..._hash = ?` equality on an index, not compared with `sodium_memcmp`; since V4-14d the requirement names that as an accepted exception and argues it (erratum 43, audit F95) -- the timing concerns the SHA-256 of a 256-bit random secret, not the secret. The argument is this document's, not a measurement.

### D4 — Tokens, login codes, recovery codes and enrollment tickets are never stored in the clear
- check `test_authd_localapi` "recovery: the plaintext code is NOT in the store (Req 4)"
- check `test_authd_localapi` "recovery: the store holds an Argon2id hash (the present canary)"
- check `test_authd_conn` "login: the code is bound to the right user and handle"
- check `test_authd_localapi` "verify: a fresh token verifies"
- mutation `v48b C2` — the login code stored raw instead of as SHA-256
- mutation `v49a T1` — the token stored raw instead of as SHA-256
- tool `tools/audit/check_spec_constants.sh` — pins the recovery code's Argon2id parameters to §10.3
- check `test_authd_localapi` "exch: the plaintext login code is NOT in the store (Req 4)"
- check `test_authd_localapi` "exch: the plaintext token is NOT in the store (Req 4)"
- check `test_authd_localapi` "recovery: the plaintext ticket is NOT in the store (Req 4)"
- check `test_authd_localapi` "exch: the store holds the SHA-256 of the login code and of the token (the present canary)"
- mutation `v58 GA3` — half the login code parked in its row's `handshake_id` column, every round trip intact
- mutation `v58 GA4` — half the token parked the same way
- check `test_authd_localapi` "exch: neither plaintext is in a backup of the store (Req 4)"
- check `test_authd_localapi` "exch: a backup holds the same two SHA-256s (the present canary)"
- check `test_authd_localapi` "recovery: neither the ticket nor the code is in a backup of the store (Req 4)"
- check `test_authd_localapi` "recovery: a backup holds the ticket's SHA-256 and the code's Argon2id hash (the present canary)"
- mutation `v64 TG4` — the token's base64 parked in its row's `handshake_id` column, where the raw and lower-case hex scans cannot see it
- check `test_authd_localapi` "recovery: all three issued codes were extracted and are distinct (the canary)"
- mutation `v70 RK5` — every recovery code from the third on stored as itself instead of its Argon2id hash
- check `test_authd_localapi` "recovery: after the ticket is spent, the plaintext ticket is NOT in the store (Req 4)"
- check `test_authd_localapi` "recovery: after the ticket is spent, it is NOT in a backup of the store (Req 4)"
- check `test_authd_localapi` "recovery: the store read after the spend holds the recovered device's key (the present canary)"
- mutation `v72 TK1` — ENROLL via=recovery stores the raw ticket as the new device's label, every round trip intact
- mutation `v72 TK2` — RECOVERY-USE stores the raw ticket where its SHA-256 belongs
**Not established:** the scans read the database and its WAL at two moments, and a backup (`VACUUM INTO`) taken at each, for 16-byte windows of the raw secret, 32-character windows of its hex in either case, and 12-byte windows in standard and URL-safe base64 (since V4-22a, the journal scans' encodings). Other encodings, a secret split into pieces shorter than a window, and memory are not scanned, and the recovery codes -- since V4-24c every code issued, not only the first (F117) -- are looked for only in their canonical base32 form. Since V4-30 the ticket is scanned twice: when RECOVERY-USE issues it, and again once ENROLL has spent it. The second scan is the only one that sees campaign v72's TK1, a ticket kept as the new device's label with every round trip intact, which passed V4-29's checks. TK2 is the at-issue scan's first mutation kill.

### D5 — A login code is single-use, expires in ≤ 60 s, and is bound
- check `test_authd_conn` "login: the code expires in at most 60 s (Req 5)"
- check `test_authd_conn` "login: the code is single-use (Req 5)"
- check `test_authd_ws` "e2e: the code is REFUSED against a different state (Req 5, login-CSRF)"
- check `test_authd_localapi` "state: a WebSocket login's code is refused with the EMPTY state"
- mutation `v48b C3` — the code's lifetime becomes 3600 s
- mutation `v47 S7` — a consumed code is never marked used, so it replays
- mutation `v48b C4` — the state hash taken over zero bytes (killed only since V4-14a's WebSocket state test)
- proverif "event(siteLoggedIn(d,st_1)) ==> event(loginStart(d,st_1)) is true"
- check `test_authd_localapi` "expiry: at exactly 60 s the login code is refused at EXCHANGE as expired (Req 5)"
- check `test_authd_localapi` "expiry: one second earlier the same code exchanges -- the expired attempt did not spend it"
- mutation `v58 GA1` — the store's boundary moves from `now >= expires_at` to `now >`
- mutation `v58 GA2` — the STORED expiry an hour late while the wire still says 60 s
- check `authd_e2e` "PASS: E2E: the daemon's clock advances with the wall clock"
- mutation `v74 CK1` — the daemon's main loop stops updating `now_unix`, so no code or token ever expires
**Not established:** expiry is tested on the harness clock (`app.now_unix`), set rather than elapsed. Since V4-36 the real daemon's clock is watched too: `authd_e2e` exchanges two codes 2 s apart against the `mldsa-authd` process and needs their `issued` times 2 s apart and within 5 s of the wall clock (v74 CK1 freezes it and passed every check before), but no test waits out a real 60 s; the sweep that deletes expired rows reads the same column and is tested separately (it catches GA2 too). `handshake_id` is recorded with the code but never consulted when it is spent (the site cannot know it); since V4-14d the requirement says "recorded with", not "bound to" (erratum 44, audit F96). The ProVerif query is non-injective and has no time, and `formal/controls/state.pv` is no longer generated or run.

### D6 — Uniform responder flow
- check `test_authd_conn` "decoy: known-wrong-key and unknown-handle reach the SAME client-side outcome"
- check `test_authd_conn` "decoy: the unknown handle still got a VERIFIABLE ServerHello (canary)"
- check `test_authd_conn` "revoked: a revoked device is served the decoy, exactly like an unknown one"
- check `authd_e2e` "E2E: the superseded key gets no login code (no overlap window, spec 10.2)"
- mutation `v48b C1` — no decoy: an unknown identity is closed outright
- mutation `v52 P5` — the pin lookup refuses decoy connections, so an unknown identity fails earlier and differently
- mutation `v47 S3` — the active-key lookup drops the user-status join
- fuzz `authd_conn` — no input brings a decoy connection to SERVING
- check `test_authd_conn` "decoy: good, wrong-key, unknown, disabled, superseded and revoked all get a ServerHello of the"
- check `test_authd_conn` "decoy: a DISABLED user's device is served the decoy (Req 6)"
- check `test_authd_conn` "decoy: a SUPERSEDED key is refused on the known-handle path -- the new key is pinned, not the decoy"
**Not established:** the lengths are equal by construction -- one code path builds every ServerHello from fixed-size fields -- so no mutation isolates the length check; it pins the invariant. No test compares the bytes (fresh per handshake), the close, or timing, and ProVerif does not model the decoy.

### D7 — No silent key rotation
- check `test_authd_store` "a known handle presenting a different key is rejected (Req 7)"
- check `test_authd_store` "the rejected re-enrollment did not replace the active key"
- check `test_authd_localapi` "enroll: the same handle with a DIFFERENT key is refused (Req 7)"
- check `test_authd_localapi` "enroll: a fresh user with an already-enrolled handle is refused (Req 7)"
- mutation `v49c W4` — the store no longer pins which key is being replaced
- tool `tools/audit/check_spec_vocabularies.py` — the three `enroll-key-mismatch` events are emitted from literal call sites
- check `test_authd_localapi` "req7(disabled owner): the refusal is logged with both key fingerprints"
- check `test_authd_localapi` "req7(revoked handle): the refusal is logged with both key fingerprints"
- check `test_authd_localapi` "req7(recovery): the refusal did not spend the ticket -- it still enrolls a new device"
- check `test_authd_localapi` "req7(site): the refusal wrote nothing to the audit chain (erratum 45)"
- mutation `v58 GA12` — a store CONFLICT on a known handle answered `pk-in-use` in silence again (the pre-F97 shape)
- mutation `v58 GA10` — the logged `fp_old` is the presented key's fingerprint
- check `test_authd_store` "owner: another user naming the handle and its key is refused, not idempotent"
- check `test_authd_store` "owner: u2's ticket naming u1's handle and key is refused, not idempotent"
- check `test_authd_localapi` "owner(site): another user naming the handle and its key is refused as pk-in-use"
- check `test_authd_localapi` "owner(recovery): u2's ticket naming u1's handle and key is refused as pk-in-use"
- mutation `v62 AO4` — the store's ownership query matches every user (audit F48)
- mutation `v62 AO5` — the daemon's pre-check keeps `idempotent=1` when the handle is another user's
**Not established:** the log is the journal (erratum 45): the tamper-evident audit chain records no Req 7 refusal, by design. The four refusal paths are tested; a path added later would need its own check, since the daemon only explains a refusal the store has already made.

### D8 — Rotation requires proof of possession of both keys
- check `test_authd_conn` "rotate: a ROTATE whose sig_new is by the OLD key is REJECTED"
- check `test_authd_conn` "rotate: a ROTATE captured from one session is REJECTED on a second"
- check `test_authd_conn` "rotate: the digest matches the hand-built spec 6.3 vector for both labels"
- proverif "inj-event(rotated(d,po,pn,h)) ==> inj-event(rotateRequested(d,po,pn,h)) is true" — proven in `base` and under a leaked record key; the controls `ctl_rot_hsid` (handshake_id out of the signed tuple) and `ctl_rot_sigold` (sig_old unchecked) each make it unprovable. Nightly job `formal`.
- mutation `v49c W3` — sig_new verified against pk_old: no proof of possession of the incoming key
- mutation `v49c W5` — handshake_id dropped from the rotate digest: a captured ROTATE replays on another session
- mutation `v49c W2` — the domain label replaced by "x": the two signatures stop being separated
- fuzz `authmsg` — a decoded ROTATE re-encodes to exactly its input; reserved flag bits refused; a failed decode leaves no fields behind
- check `test_authd_conn` "rotate: a ROTATE whose ONLY defect is sig_old is REJECTED (possession of the outgoing key)"
- check `test_authd_conn` "rotate: the journal names sig_old as the check that refused it"
- mutation `v58 GA5` — sig_old's verdict ignored
- check `test_authd_conn` "rotate: a ROTATE whose sig_old is by the INCOMING key, over the right digest, is REJECTED"
- check `test_authd_conn` "rotate: a ROTATE whose sig_old is by a key enrolled nowhere, over the right digest, is REJECTED"
- check `test_authd_conn` "rotate: the journal names sig_old as refusing the INCOMING key"
- mutation `v64 TG3` — sig_old accepted under `pk_old` OR `pk_new`: an attacker holding only the incoming key could rotate to it
**Not established:** since V4-22a sig_old is isolated by three vectors -- the old key over the wrong digest, and the incoming key and a key enrolled nowhere over the right one -- not by every key; the journal is what says each refusal came from sig_old. W2 and W5 are killed only because the test builds the vector by hand and replays a ROTATE.

### D9 — Revocation is immediate
- check `test_authd_localapi` "revoke: the live session was CLOSED, not just the row updated (Req 9)"
- check `test_authd_conn` "revoked: after revocation the SAME key gets no login code"
- check `test_authd_store` "revoking a device deletes its tokens"
- check `test_authd_store` "a revoked device cannot rotate its key"
- mutation `v49a V1` — REVOKE-DEVICE closes no live session
- mutation `v47 S5` — a revoked device's tokens survive (`DELETE ... AND 0`)
- mutation `v49c W7` — revoked or disabled devices can still rotate
- fuzz `authd_conn` — a connection served the decoy (what a revoked device gets) must never be issued a login code
- check `test_authd_store` "filter: a revoked device does not resolve even while its key row is active"
- check `test_authd_localapi` "disable: the disabled user's live session was CLOSED, not just the row updated (Req 9)"
- check `test_authd_localapi` "disable: another user's live session is untouched"
- check `test_authd_localapi` "revoke-all: the lost device's live session was CLOSED, not just revoked in the store (Req 9)"
- check `test_authd_localapi` "revoke-all: revoke=none leaves the user's live session open"
- check `authd_e2e` "PASS: E2E: a disabled user is refused, and the same identity logs in again once re-enabled"
- check `authd_e2e` "PASS: E2E: a device revoked over site.sock is refused at its next login"
- mutation `v58 GA6` — the lookup's device clause becomes `d.status=d.status`
- mutation `v58 GA7` — live sessions no longer matched by user
- mutation `v58 GA8` — DISABLE-USER closes no live session
- mutation `v58 GA9` — RECOVERY-USE `revoke=all` closes no live session
- check `test_authd_store` "keyfilter: a revoked key does not resolve even while its device and user are active"
- check `test_authd_store` "keyfilter: an active key resolves (the canary)"
- mutation `v64 TG1` — the lookup's key clause excludes only superseded keys
- check `authd_e2e` "PASS: E2E: RECOVERY-USE with revoke=all over site.sock refuses every device of the user at its next login"
- mutation `v64 TG2` — revoke=all's in-transaction device search matches nothing (v49d G14's shape, named against `authd_e2e`)
- check `wasm_interop` "revoke: the daemon closes the revoked device's live WebSocket, seen from the client's process (Req 9, D9)"
- check `wasm_interop` "revoke: the other device's live session stays open (the canary)"
- check `wasm_interop` "disable: the daemon closes the disabled user's live WebSocket, seen from the client's process (Req 9, D9)"
- check `wasm_interop` "revoke=all: the daemon closes BOTH of the user's live WebSockets, seen from the client's process (Req 9, D9)"
- check `wasm_interop` "revoke=none: the user's live session stays open (the canary)"
**Not established:** the device clause and, since V4-22a, the key clause are each shown to hold on their own only for a state an attacker with the database file creates (no API path revokes one without the other). `authd_e2e` drives `revoke=all` through the site's own library and checks that both of the user's devices are refused at their next login; that revoke=all closes their live sessions is checked in-process there, and since V4-33 from outside the daemon too. `wasm_interop`'s client, in Node, holds live WebSocket sessions against the separate daemon process. REVOKE-DEVICE (V4-32), DISABLE-USER and RECOVERY-USE with revoke=all (V4-33) each close exactly the sessions they name within 3 s. Another user's session, and revoke=none's, stay open. That runs only in trees with a wasm module, so the nightly's campaigns do not reach it. It was shown red by hand with v49a's V1 and v58's GA7, GA8 and GA9, and with a close that matched every session (V4-32's and V4-33's decisions entries). Raw-listener sessions are observed in-process only.

### D10 — Identity keys are encrypted at rest
- check `test_authd_cli` "keygen-server: no plaintext MLDSASK file was written anywhere (Req 10)"
- check `test_authd_cli` "client keygen: no plaintext MLDSASK file was written anywhere (Req 10)"
- check `authd_e2e` "PASS: E2E: no plaintext secret-key file exists anywhere under the work directory"
- check `test_authd_keyfile` "write_sealed refuses a plaintext MLDSASK2 image (FORMAT), writes nothing"
- mutation `v49b K1` — keygen also writes a plaintext secret-key image beside the sealed key
- mutation `v53 F10` — `keyfile_write_sealed` publishes a non-envelope
- mutation `v46 E3` — an AEAD decrypt failure is no longer refused
- fuzz `envelope` — `keyfile_parse_header` agrees with an independent model; a rejected open returns no secret key
- check `test_authd_cli` "keygen-server: no window of the server's secret key is in any file under its directory (Req 10)"
- check `test_authd_cli` "rewrap: no window of the secret key in either sealed file or anywhere else (Req 10)"
- check `test_authd_cli` "migrate-key: no window of the secret key outside its plaintext input (Req 10)"
- check `authd_e2e` "PASS: E2E: after every key operation, still no plaintext secret-key file anywhere under the work directory"
- mutation `v60 GC3` — the envelope stops encrypting; every round trip still works
- check `test_authd_cli` "rotate: no window of the old or the new secret key in any file under the device's or the daemon's directory (Req 10)"
- check `test_authd_cli` "rotate: a raw copy of the new key, planted beside it, IS found (the canary)"
- check `test_authd_cli` "interrupted rotation: after the login that completes it, no window of either key in any file (Req 10)"
- check `test_authd_cli` "stale rotate: no window of any of the three keys in any file (Req 10)"
- mutation `v70 RK1` — rotate keeps the old key's raw secret beside `.ek` once both ROTATE signatures are made
- mutation `v70 RK2` — rotate writes the new key's raw secret beside `.ek.next` once it has reopened it
- mutation `v70 RK3` — the login that completes an interrupted rotation keeps the superseded key's raw secret
- mutation `v70 RK4` — a rotation whose session cannot open keeps the new key's raw secret "for a retry"
- check `test_authd_cli` "rotate refused: no window of the old or the new secret key in any file (Req 10)"
- check `test_authd_cli` "rotate lost: no window of the old or the new secret key in any file (Req 10)"
- mutation `v73 RL1` — a rotation the daemon refuses keeps the new key's raw secret "for a retry"
- mutation `v73 RL2` — a rotation whose reply never arrives does the same
- check `browser_e2e` "a canary written into IndexedDB is found on disk, every window but at most two page splits'"
- check `browser_e2e` "no window of ${what} is anywhere in the profile"
- check `browser_e2e` "planted in the profile in the clear, is found by the same scan, every window"
- check `browser_e2e` "the passphrase is in no file of the profile, as UTF-8 or UTF-16"
- tool `tests/envelope_key_scan.c` — opens an envelope read back from the browser's IndexedDB with the test's passphrase and scans the browser's profile for the key's secret windows; it prints positions, never bytes
**Not established:** the window scans read files under the directories the CLI writes to, in raw bytes, for 16 contiguous SECRET bytes -- a window touching `rho` or `tr`, which the public key determines, is not looked for (F105) -- so fewer than 16 contiguous secret bytes would not be seen, nor would a deleted temp file, swap, a core dump or another encoding of the key. Since V4-24c the same scan covers rotation: `test_authd_cli` runs the CLI's own rotate and login against the in-process daemon and looks for every key the device held after an acknowledged rotation, after the login that completes an interrupted one, and after a rotation attempted from a key the daemon has superseded. Since V4-35 a CLI rotation whose session opens but whose reply is refused, or lost, is scanned too. The in-process daemon refuses a real ROTATE after the store's key has moved behind the session, or commits and is cut off before its ACK flushes; campaign v73 shows both scans catching a raw key that passed V4-34's suite; the e2e's real processes still have only its header scan, since the shell holds no plaintext key. The browser is scanned since V4-27:
- **What is scanned.** `browser_e2e` reads back every envelope its store held, as the test saw each appear: enrollment, a stale pending key, a lost-ACK rotation, the account page's rotation, and a recovered device in a second profile.
- **How.** It opens each one natively with the test's passphrase (`tests/envelope_key_scan.c`). It then scans the whole Chromium profile, about 15 MB in some 300 files, for the key's secret windows and for the passphrase as UTF-8 and UTF-16.
- **Why a clean result means something.** It counts only after a canary written into IndexedDB the same way is found whole, and after the key itself, planted in the profile in the clear, is found whole.
- **What that covers.** Headless Chromium at the moment of the scan, while its IndexedDB values sit in LevelDB's log. A later compaction (Snappy-compressed tables), memory, swap and other browsers are not scanned. Account recovery makes no key of its own: the replacement device's key is an ordinary keygen, covered by the client keygen scan, and nothing in the recovery flow handles a secret key -- that rests on reading.

### D11 — Every Unix-socket peer is authenticated by peer credentials
- check `test_authd_ws` "proxy-uid: a peer outside the allowlist is refused at accept, occupying no slot"
- check `test_authd_localapi` "tables: an ADMIN command on site.sock is refused (Req 11, by construction)"
- check `test_authd_localapi` "tables: an admin command and a nonsense command give the SAME answer"
- check `test_authd_localapi` "policy: an operator's recovery codes are NOT mintable from site.sock (Req 11)"
- check `authd_e2e` "PASS: E2E: admin.sock is 0600 (spec 8)"
- mutation `v50b J4` — protocol listeners lose their uid allowlist
- mutation `v49a A1` — the ADMIN table is served on site.sock
- mutation `v49b S1` — every socket is 0660, so admin.sock is reachable by its group
- check `test_authd_evloop` "cfg: a site socket without site_uids is refused (Req 11)"
- mutation `v57 HC1` — a site socket without `site_uids` accepted again
- check `authd_e2e` "PASS: E2E: site.sock and admin.sock refuse a uid outside their own lists at accept; the proxy socket still serves"
- mutation `v58 GA13` — `site.sock` registered with an empty allowlist in `authd_main.c`
- mutation `v58 GA14` — `admin.sock` registered with an empty allowlist in `authd_main.c`
- check `authd_e2e` "PASS: E2E: a real second user (nobody, uid"
- mutation `v65 RU1` — the allowlist scan compares the daemon's own uid, not the peer's; no test with one user can tell
- check `test_authd_ws` "modes: a socket mode other than spec 8's two is refused with LISTENER_ERR_ARG, and nothing is created"
- mutation `v68 CG1` — the refusal of a mode outside spec 8's two can never hold; 0666 opens a world-writable socket
**Not established:** since V4-22b a real second user connects -- `nobody`, holding the daemon's group, as spec 8's site user would -- and is served on the socket its uid is listed for and refused at accept on the two it is not, file access granted; a third connection without the group shows file permission stops it first and is not counted. That leg needs Linux's `setpriv` and root or passwordless sudo, so it runs in CI's Linux jobs and a root container, and is skipped on macOS; elsewhere only the uid+1 leg runs. `nobody` stands in for the site's user, and admin.sock is opened to it for the leg, since its 0600 would stop it before the check. An EMPTY allowlist still means "no check" to the listener; since V4-14c (audit F92, fixed) the configuration can no longer produce one for `site.sock`, or for a proxy-facing listener that believes PROXY v2. The proxy-facing listener without PROXY v2 -- the development shape -- may still run without one. The ProVerif model treats the site socket as a private channel: an assumption, not a proof.

### D12 — The client address used for rate limiting is obtained from a source the client cannot forge
- check `test_authd_ws` "proxy-loop: a preamble with no client address is closed, and nothing is said"
- check `test_authd_ws` "limiter: a connection with no client address is refused, not pooled"
- check `test_authd_ws` "proxy: a connection that sends no preamble is refused before any HTTP is parsed"
- check `authd_e2e` "PASS: E2E: a connection with no PROXY v2 preamble is refused (Req 12, fail closed)"
- mutation `v50b J3` — a preamble that establishes no client address is served anyway
- mutation `v50b J1` — only the first byte of the 12-byte PROXY v2 signature is compared
- mutation `v50b J11` — a refused no-address connection still gets its queued 101
- fuzz `ws` — a client address never appears before the PROXY preamble completes; a poisoned connection refuses every later push
- check `test_authd_evloop` "cfg: proxy_protocol = v2 without proxy_uids is refused (Req 11)"
- mutation `v57 HC2` — `proxy_protocol = v2` without `proxy_uids` accepted again
- ci `caddy proxy (Linux, Docker)` — a real login through Caddy over WebSocket with a PROXY v2 preamble, the client's address recorded, and refused once `proxy_protocol` is removed; the image and the Caddy tarball pinned by digest
**Not established:** the preamble is only as trustworthy as the peer that wrote it (D11); `proxy_protocol = v2` now requires `proxy_uids` (audit F92, fixed in V4-14c), but nothing checks that the uid named IS the proxy's. `proxy_protocol` defaults to `none` (audit F63): no address and no limiter at all. Since V4-22b the real-Caddy leg (`tests/caddy_proxy.sh`) runs in CI as a job of its own, on amd64 only, with the container image and the Caddy tarball pinned by digest; the packages it installs into that image are not pinned, and it is still not a CTest.

### D13 — Logging never contains
- check `test_authd_conn` "logscan: the login code never appears in the daemon's log"
- check `test_authd_localapi` "recovery: the enrollment TICKET never appears in the log (§15)"
- check `test_authd_localapi` "log: the issued token never appears in the log"
- check `test_authd_localapi` "recovery: the recovery CODE never appears in the log (§15)"
- check `authd_e2e` "PASS: E2E: no passphrase and no login code appears in any log"
- mutation `v49c W12` — the login code is logged through the `authd_log_fp` sink, by an explicit cast to `authd_fp_t` since V4-21
- mutation `v49d G12` — the recovery ticket is logged through `authd_log_fp`, by an explicit cast since V4-21
- tool `tools/audit/check_spec_vocabularies.py` — the field names the logger can emit equal §15's list, both ways, so a new field such as `sig=` fails
- check `test_authd_conn` "journal: no window of the server's, the device's or the rotated-to secret key"
- check `test_authd_conn` "journal: no window of either side's session keys, the X25519 private key or the ML-KEM shared secret"
- check `test_authd_conn` "journal: no window of either signature or of the ClientHello's nonce"
- mutation `v60 GC4` — the rotation's `fp_new` line prints the session send key, through an explicit cast since V4-21
- tool `tests/check_log_fp_type.cmake` — the CTest `log_fp_type`: with the build's own compiler at `-Werror`, an `authd_fp_t` passed to `authd_log_fp` compiles (the canary) and a bare 32-byte buffer does not (audit F41)
- check `test_authd_log` "fp: authd_fp_of_pk is the SHA-256 of the whole public key"
- mutation `v63 FT1` — `authd_log_fp`'s parameter widened to `const void *`, so a bare secret compiles again (audit F41)
- mutation `v63 FT2` — `authd_fp_of_pk` hashes one byte short of the public key
- check `test_authd_conn` "journal: no window of any raw frame of the connection"
- check `test_authd_conn` "journal: no window of any decrypted payload"
- check `test_authd_conn` "journal: no window of the ROTATE's own signatures"
- mutation `v68 CG3` — the decrypted ROTATE's first 32 bytes are logged
- mutation `v68 CG4` — every received record's first ciphertext bytes are logged
- mutation `v68 CG5` — the start of the ROTATE's sig_old is logged (audit F113)
- check `test_authd_localapi` "log: no window of the issued token in any form -- hex, base64, an escaped id= field (V4-29)"
- check `test_authd_localapi` "log: no window of the login code in any form -- hex, base64, an escaped id= field (V4-29)"
- check `test_authd_localapi` "recovery: no window of the enrollment TICKET in any form -- hex, base64, an escaped id= field (V4-29)"
- tool `tests/journal_scan.h` — the encodings every journal scan looks for, shared by `test_authd_conn` and `test_authd_localapi`: hex in either case, both base64 alphabets, and since V4-29 the escaped `id=` field `authd_log_slot_id` writes
- mutation `v71 EI1` — the login code is logged as the `id=` of `login-code-issued`
- mutation `v71 EI2` — the ClientHello's nonce is logged where its id was
- mutation `v71 EI3` — ROTATE logs `sig_new` where the handle was
- mutation `v71 EI4` — EXCHANGE logs the issued token as an `id=`, before wiping it
- mutation `v71 EI5` — RECOVERY-USE logs the enrollment ticket where the user was
**Not established:** the scan covers one connection's login, ROTATE and BYE, in hex and base64, for the secret keys' wholly secret windows and each signature's `c~ || z` (the hint after it is mostly zero padding, a match on which would be evidence of nothing) -- the ROTATE's `sig_old` and `sig_new` only since V4-24a, though this paragraph had said "each signature" before (audit F113). Since V4-24a it also covers every byte the connection put on the wire -- the three handshake messages and the four records -- and every payload a record carried, decrypted, in both directions; windows wholly inside the ROTATE_ACK's `fp_new`, which the journal records on purpose, are not looked for, and BYE's one-byte payload is below any window. `authd_log_slot_id` prints bytes as escaped printable text: since V4-29 every journal scan also looks there, matching each 16-character window of an `id=` field against the secret's own escaped image, and campaign v71 shows each of five secrets passed where an identifier belongs caught by name after passing V4-28's scans. An escaped window with fewer than two printable characters is not counted, and with `log_ids = hashed` the field is a keyed pseudonym, which no scan can relate to a secret. The local API's and recovery's paths are scanned for their own secrets only (codes, tokens, tickets, passphrase). "No option to enable any of them" rests on the logger's API shape. Since V4-21 that shape refuses a bare 32-byte buffer at compile time (`log_fp_type`), but a secret deliberately cast to `authd_fp_t` compiles, and only the journal scans catch it, as they catch W12, G12 and GC4. Until V4-22a this sentence still said the sink accepts any 32-byte secret (audit F109).

### D14 — Every store mutation is a single transaction
- check `test_authd_store` "a half-rotation is impossible: after reopen the old key is still active"
- check `test_authd_store` "rec: a half-consume is impossible: after reopen the code is still spendable"
- check `test_authd_localapi` "enroll: NEITHER refusal created a user -- a refused request changes nothing (F47)"
- mutation `v47 S1` — rotation without its transaction: an injected mid-rotation fault leaves no active key
- mutation `v49d G7` — on the injected fault the code spend commits without its ticket
- mutation `v49d G15` — user creation commits separately and survives a refused enrollment's rollback
- fuzz `localapi` — an ERR response never advances the audit chain (except RECOVERY-USE `invalid`, which must)
- tool `tools/check_store_fault_hook.sh` — the fault-injection hook is absent from the shipped library and binaries, present in the test
- check `test_authd_store` "revoke-all: after the fault BOTH devices are still active -- not one of two"
- mutation `v57 HC3` — each revoke=all revocation commits on its own again (the pre-F93 shape)
- check `test_authd_store` "fault(revoke): after the fault the device still resolves -- the revocation is all or nothing"
- check `test_authd_store` "fault(disable): after the fault the user is still active -- the disable is all or nothing"
- check `test_authd_store` "fault(enroll-user): after the fault no user was created (F47's half-state)"
- check `test_authd_store` "fault(enroll-device): the handle enrolls cleanly afterwards -- no device row was left behind"
- check `test_authd_store` "fault(ticket): the ticket still redeems -- the fault did not spend it"
- mutation `v58 GA15` — revocation commits before its last step
- mutation `v58 GA16` — the disable commits after the status write
- mutation `v58 GA17` — the enrollment commits the user before the device
- mutation `v58 GA18` — the enrollment commits the device row before its key
- mutation `v58 GA19` — the ticket's spend commits before the enrollment
- check `test_authd_store` "clock: the key-rotate row is stamped with the rotation's clock"
- check `test_authd_store` "clock: revoke=all's two device-revoke rows are stamped with the recovery's clock"
- mutation `v62 AO1` — the audit row reads the wall clock again, not its transaction's (audit F45)
- mutation `v62 AO2` — revoke=all stamps its revocations with the wall clock, not the recovery's
- check `test_authd_store` "sweep(rotate): a fault at each of its writes leaves the database exactly as it was"
- check `test_authd_store` "sweep(recovery-consume-revoke-all): a fault at each of its writes leaves the database exactly as it was"
- check `test_authd_store` "sweep(recovery-replace): a fault at each of its writes leaves the database exactly as it was"
- check `test_authd_store` "sweep(add-token): a fault at each of its writes leaves the database exactly as it was"
- mutation `v66 FW1` — recovery-replace commits after superseding the old codes; a fault on an insert leaves no usable code
- mutation `v66 FW2` — add-token's error path returns without rolling back; the open transaction fails the next write
- check `test_authd_store` "commit(recovery-consume-revoke-all): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write"
- check `test_authd_store` "commit(enroll-req7): a failed COMMIT leaves the database as it was, the write lock free and the handle able to write"
- mutation `v67 FC1` — a failed COMMIT is not rolled back (audit F112 restored): the handle stays inside the transaction and holds the write lock
- mutation `v67 FC2` — Req 7's refusal path commits around `tx_commit`, keeping F112 on that one path
**Not established:** since V4-22c every writing statement of every mutating primitive is failed in turn -- 23 cases, from one write to twelve (`revoke=all` over two devices) -- and after each, the committed database as another connection reads it is unchanged, and the same handle then completes the call; a transaction left open after a fault would fail that next attempt. The fault is a statement returning an I/O error, not a crash or a torn write; atomicity below the statement is SQLite's. Since V4-23 a failed COMMIT is rolled back (audit F112, fixed): a test hook fails the COMMIT of each of the 18 cases that run a transaction, leaving the transaction open as `SQLITE_BUSY` does, and the database must be unchanged, the write lock free for a second store, and the same handle able to complete the call. That models the BUSY outcome. Real I/O failures at COMMIT were injected once, by hand, through a failing VFS on SQLite 3.45.1 -- SQLite had already rolled each back -- and are not in CI, nor tried on CI's 3.53.4. `store_open`'s schema setup and `store_backup` are outside the sweep. The fault hooks' confinement to the test build is a CTest (`store_fault_hook`) since V4-15a -- before that the tool cited here ran nowhere (audit F99, fixed) -- and the new write hook's symbols fall under the same gate. RECOVERY-USE with `revoke=all` was not one transaction until V4-14c (audit F93, fixed): its revocations now commit with the code and the ticket.
