# Coverage of the project's own code (V4-40, audit F5)

Coverage is not a gate in this project; the mutation campaigns are. It is
measured because an uncovered region is one no mutation could ever be killed
in, so the figure maps where the campaigns are blind. Audit F5 recorded that
it had been measured once, in V4-1, before the daemon existed. This is the
first figure for `apps/authd/`.

## How it was measured

- **When and where:** 2026-10-20, on macOS 27.0.1 (arm64), with Apple clang
  21.0.0. The source was V4-39's head `df2172e` plus V4-40's changes, before
  they were committed.
- **The tree:** `build-cov-p`, configured with `-DMLDSA_COVERAGE=ON` and
  `-DMLDSA_WASM_DIR`, and with Edge found, so all 56 tests ran. It was
  proven current by `tools/check_build_current.sh` (`5b44c662708d4ac3`).
  `MLDSA_COVERAGE` instruments the project's 112 sources and none of the
  105 liboqs sources.
- **The run:** `tools/audit/coverage.sh build-cov-p <out>` ran the whole
  suite instrumented: 56/56 passed, writing 137 profiles. The fuzz replay
  drivers ran their seeds and regressions in the same pass.
- **Processes counted:** the profiles include every process a test starts
  that exits normally. The real daemon's `main` ran 6 times (`authd_e2e`,
  the fixtures).
- **Not measured:** the WebAssembly build. Code only the browser runs, such
  as `ccw_diag_stage`, shows as never called here.

## A measurement defect found first: forked children were not counted

A forked test child leaves with `_exit()`, which skips the hook the profile
runtime writes from. So everything a child ran counted as never run:
- the prompt that `test_client_prompt` drives under `forkpty`;
- the CLI that `test_authd_cli` runs pumped;
- the demo server and proxy of `test_net`.

Since V4-40 those children leave through `tests/child_exit.h`. In an
`MLDSA_COVERAGE` build it writes the profile first; in every other build it
is `_exit()` alone. Its effect:

| File | Lines before | Lines after |
|---|---|---|
| `apps/authd/cli_prompt.c` | 4.5% (8 of 177) | 67.2% (119 of 177) |
| `apps/authd/client_cli.c` | 71.0% | 75.7% |
| `apps/demo_app.c` | 73.1% | 76.8% |
| `apps/frame.c` | 77.1% | 80.0% |

The coverage tool had two defects of its own:
- its list of least-covered functions came out empty without saying so;
- its totals counted CMake's compiler-probe programs.

Both are fixed.

## The figures

| Area | Lines | Regions | Branches | Functions |
|---|---|---|---|---|
| `src/` (the protocol) | 83.67% (1655/1978) | 92.02% (2180/2369) | 73.37% (763/1040) | 100% (116/116) |
| `apps/authd/` (daemon, CLIs, client core) | 81.30% (7589/9335) | 87.51% (10017/11447) | 69.05% (4299/6226) | 97.45% (421/432) |
| `apps/` other (the v1/v2 demo apps) | 71.23% (1354/1901) | 84.19% (2092/2485) | 57.85% (744/1286) | 93.51% (72/77) |
| all | 80.20% (10598/13214) | 87.66% (14289/16301) | 67.89% (5806/8552) | 97.44% (609/625) |

Per file, `src/` and `apps/authd/`:

| File | Lines | Regions | Branches | Functions |
|---|---|---|---|---|
| `apps/authd/authd_admin.c` | 57.1% (3 missed) | 60.0% (2 missed) | 50.0% (1 missed) | 1/1 |
| `apps/authd/authd_cli.c` | 74.2% (182 missed) | 89.0% (102 missed) | 66.5% (159 missed) | 15/16 |
| `apps/authd/authd_config.c` | 88.3% (48 missed) | 94.3% (34 missed) | 83.0% (64 missed) | 14/14 |
| `apps/authd/authd_conn.c` | 80.5% (91 missed) | 85.4% (54 missed) | 64.7% (79 missed) | 20/21 |
| `apps/authd/authd_log.c` | 96.2% (8 missed) | 87.2% (34 missed) | 75.1% (43 missed) | 19/19 |
| `apps/authd/authd_main.c` | 67.0% (104 missed) | 73.6% (62 missed) | 58.8% (42 missed) | 4/5 |
| `apps/authd/authd_secret.c` | 56.6% (33 missed) | 75.7% (18 missed) | 55.4% (25 missed) | 3/3 |
| `apps/authd/authmsg.c` | 81.8% (55 missed) | 92.4% (31 missed) | 66.5% (65 missed) | 16/16 |
| `apps/authd/base32.c` | 87.3% (8 missed) | 94.9% (4 missed) | 84.1% (7 missed) | 3/3 |
| `apps/authd/cli_common.h` | 100.0% (0 missed) | 93.5% (2 missed) | 57.1% (3 missed) | 7/7 |
| `apps/authd/cli_prompt.c` | 67.2% (58 missed) | 74.2% (59 missed) | 46.6% (71 missed) | 3/5 |
| `apps/authd/client_cli.c` | 75.7% (150 missed) | 81.7% (118 missed) | 61.0% (129 missed) | 19/20 |
| `apps/authd/client_core.c` | 77.4% (106 missed) | 86.7% (73 missed) | 63.0% (108 missed) | 31/31 |
| `apps/authd/client_wasm.c` | 86.2% (26 missed) | 85.7% (32 missed) | 63.0% (37 missed) | 23/24 |
| `apps/authd/conn_io.c` | 84.3% (53 missed) | 81.8% (81 missed) | 73.7% (55 missed) | 25/26 |
| `apps/authd/evloop.c` | 90.2% (43 missed) | 88.7% (54 missed) | 74.7% (73 missed) | 17/17 |
| `apps/authd/keyfile.c` | 81.4% (53 missed) | 87.1% (58 missed) | 64.5% (81 missed) | 17/17 |
| `apps/authd/listener.c` | 64.2% (69 missed) | 80.9% (48 missed) | 58.1% (54 missed) | 7/8 |
| `apps/authd/localapi.c` | 86.7% (120 missed) | 90.6% (73 missed) | 80.2% (99 missed) | 35/35 |
| `apps/authd/localcli.c` | 67.8% (47 missed) | 71.7% (52 missed) | 54.6% (54 missed) | 5/5 |
| `apps/authd/memlock.c` | 92.5% (3 missed) | 94.7% (2 missed) | 88.5% (3 missed) | 4/4 |
| `apps/authd/passphrase.c` | 96.3% (8 missed) | 94.5% (21 missed) | 83.1% (41 missed) | 10/10 |
| `apps/authd/proxy_v2.c` | 85.4% (20 missed) | 87.2% (21 missed) | 72.3% (26 missed) | 8/9 |
| `apps/authd/ratelimit.c` | 86.9% (26 missed) | 88.8% (18 missed) | 75.0% (22 missed) | 16/16 |
| `apps/authd/recovery.c` | 79.7% (12 missed) | 87.9% (8 missed) | 60.7% (11 missed) | 4/4 |
| `apps/authd/sha1.c` | 94.1% (3 missed) | 96.4% (2 missed) | 95.5% (1 missed) | 3/3 |
| `apps/authd/store/store.c` | 81.1% (348 missed) | 89.5% (285 missed) | 65.5% (468 missed) | 75/75 |
| `apps/authd/tokens.c` | 82.8% (5 missed) | 89.7% (3 missed) | 64.3% (5 missed) | 3/3 |
| `apps/authd/ws.c` | 84.8% (64 missed) | 87.2% (79 missed) | 72.8% (101 missed) | 14/15 |
| `src/crypto/aead.c` | 68.9% (14 missed) | 85.9% (10 missed) | 44.4% (20 missed) | 2/2 |
| `src/crypto/kex.c` | 80.2% (26 missed) | 90.6% (18 missed) | 68.4% (24 missed) | 6/6 |
| `src/crypto/mldsa_wrap.c` | 57.7% (33 missed) | 81.3% (20 missed) | 50.0% (23 missed) | 4/4 |
| `src/crypto/mlkem_wrap.c` | 70.3% (27 missed) | 82.6% (21 missed) | 65.9% (15 missed) | 5/5 |
| `src/protocol/handshake.c` | 82.0% (167 missed) | 90.2% (90 missed) | 70.2% (127 missed) | 48/48 |
| `src/protocol/keystore.c` | 93.0% (5 missed) | 96.1% (4 missed) | 77.1% (11 missed) | 8/8 |
| `src/protocol/session.c` | 96.0% (11 missed) | 98.7% (5 missed) | 92.1% (15 missed) | 21/21 |
| `src/protocol/transcript.c` | 88.8% (36 missed) | 96.0% (18 missed) | 76.5% (38 missed) | 15/15 |
| `src/util/secure_mem.c` | 77.8% (4 missed) | 82.4% (3 missed) | 50.0% (4 missed) | 3/3 |
| `src/util/wire_int.c` | 100.0% (0 missed) | 100.0% (0 missed) | 100.0% (0 missed) | 4/4 |

## What is not covered

76 functions in `src/` and `apps/authd/` have under 80% region coverage
(`functions.txt` in the tool's output lists them, most missed first). Most
uncovered regions are of three kinds, none of which a normal test can reach:
- **Failure of a primitive or an allocation:** a `NULL` from guarded
  memory, or a failing `kex_shared_secret`, `mlkem_decaps` or
  `sqlite3_open_v2`. They need fault injection, which the store has (V4-22c)
  and the protocol layer does not.
- **`EINTR`, `EAGAIN` and short-I/O retries** in the event loop and the
  writers.
- **Name tables** (`*_status_name`): most cases are printed only on paths
  above.

### Five functions no test calls

| Function | Why |
|---|---|
| `conn_io_out_capacity` (`conn_io.c:78`) | dead: no caller anywhere |
| `authd_conn_stage_name` (`authd_conn.c:13`) | dead: no caller anywhere |
| `listener_accept` (`listener.c:250`) | dead: the event loop calls `listener_accept_ex`. Its `(uid_t)-1` sentinel passes an empty allowlist, which means no credential check: F92's shape, in code nothing reaches |
| `ccw_diag_stage` (`client_wasm.c:246`) | live: the browser client calls it, and the wasm build is not measured |
| `cli_prompt_status_name` (`cli_prompt.c`) | live: printed only on the prompt's error paths |

The three dead ones are audit **F121**, removed in V4-41.

### Security checks no test reaches

These are audit **F122**. Each is a check the code makes and no test drives
to its refusal, so a mutation deleting it would survive every campaign.
- **Key-file custody,** `keyfile.c:306` (`keyfile_open`) and `keyfile.c:348`
  (`keyfile_promote`). A key file not owned by the user, or with any
  group/other bit set, is refused with `KEYFILE_ERR_PERMISSIONS`. Neither
  refusal ever ran: the condition was evaluated 174 and 4 times, the
  refusal 0. The demo apps' loader has such tests (`test_net` T14); the
  daemon's and the client's key files had none. **Tested since V4-42**
  (campaign v75); the owner half only on Linux, where root can arrange it.
- **The CLI client's WebSocket frame reader,** `ws.c:503-545`
  (`ws_client_read_message`). It parses frames from the server. None of
  these ever refused anything:
  - the RSV bits;
  - a masked server frame;
  - the 64-bit length and its top bit;
  - control frames and an oversized control payload;
  - a non-binary or fragmented frame;
  - the bound of a frame's length against the caller's buffer, `ws.c:544`.

  Without that last one, a server's frame would be read past the buffer.
  The daemon's side of the same framing is fuzzed (`fuzz_ws`); this reader
  is not. **Tested since V4-43** (campaign v76), frame by frame; still not
  fuzzed.
- **`REVOKE-TOKENS handle=`,** `localapi.c:667-676`. Revoking the tokens of
  one device never ran; only the per-user form is tested.
- **`store_open`'s refusal of a damaged store,** `store.c:492-528`:
  - a schema version of the wrong length;
  - a store from a newer schema (`STORE_ERR_SCHEMA`);
  - a `store_id` or `decoy_pk` of the wrong length.

  **Tested since V4-45** (campaign v77).
- **The daemon's record path,** `authd_conn.c`:
  - a record over `AUTHD_MAX_RECORD`;
  - a BYE of the wrong length;
  - after a ROTATE with the drop-tokens flag, the dropping of the device's
    tokens (`dropped > 0`, line 534; first described here as closing live
    sessions, which it is not).

  **Tested since V4-46** (campaign v78). The oversized record is unreachable:
  the frame cap equals the record cap.

## Re-measured in V4-44, after V4-41 to V4-43

The same command on the same machine (`build-cov-p` `0ef7effc6e611498`,
57/57, 137 profiles), after:
- V4-41 removed F121's three dead functions;
- V4-42 tested key-file custody;
- V4-43 tested the CLI's frame reader.

| Area | Lines | Regions | Branches | Functions |
|---|---|---|---|---|
| `src/` | 83.67% (unchanged) | 92.02% | 73.37% | 100% |
| `apps/authd/` | 81.64% (7606/9316) | 88.11% (10045/11401) | 69.62% (4324/6211) | 98.14% (421/429) |
| all | 80.45% | 88.08% | 68.30% | 97.91% |

- **`ws_client_read_message`:** 75 of its 78 code regions now run, up from
  49. The three left are its null-argument guard and two I/O failures
  inside a 64-bit length and a control payload.
- **`keyfile_open` and `keyfile_promote`:** each gained its refusal region
  (70 of 82 and 27 of 31).
- **Functions under 80%:** 72, down from 76. Three of the four are gone with
  F121's dead code, and the frame reader is now above the line.

## After the re-measurement: the passphrase file (V4-48)

The re-measurement showed `authd_secret.c` at 56.6% of lines. It holds
`authd_secret_read`, which the daemon and both CLIs use to read a
passphrase file, and only its mode refusal had ever run. Since V4-48 every
refusal is driven, with campaign v79 showing each caught: a missing file, a
symlink, a directory, each group and other bit, an empty file, a file
holding only a newline, a file one byte over the limit, and another user's
file (Linux only).

## The listener's paths (V4-49)

`listener.c` read 64% of lines. Most of what was uncovered is the failure of
a system call (`socket`, `bind`, `listen`, `fcntl`). Lines 71 and 72,
`htons` and `htonl`, are the byte-swap macros' constant branch, which
llvm-cov attributes to the source line. Three checks had never run:
- the refusal of a socket path too long for `sun_path`;
- the not-a-socket refusal, named by no test;
- `listener_accept_ex`'s allowlist bound.

Since V4-49 each is driven, with a symlink at the path and a stale socket
besides; campaign v80 shows each caught.

## The local-API client (V4-52)

`localcli.c` read 67% of lines: `localcli_call`, the client `authd_admin`
uses, had never met a misbehaving daemon. None of these had run:
- a reply larger than the caller's buffer;
- a list the daemon closes before its END;
- a daemon that never answers;
- a request over spec 8's line cap;
- a socket with no daemon.

Since V4-52 each is driven against a forked fake daemon, the buffer case
with guard bytes after the buffer; campaign v82 shows each caught. The
explicit "reply larger than the buffer" break is defence in depth: `recv`'s
length already leaves room for the NUL, so removing the break alone changes
nothing. The campaign mutates the length instead.

The same triage found `keyfile.c`'s `publish` uncovered at line 105. That is
the I/O-failure arm of its `link()`. The no-clobber refusal on the same line
is covered (`test_authd_keyfile`, "refuses an existing path"), so it is not
a gap.

## What these figures do not establish

- **Covered is not checked.** A region a test runs can still be wrong with
  every test passing; the campaigns are what show checks can fail.
- **One machine, one compiler, native only.** The wasm module and Linux are
  not measured, and code under `#ifdef __linux__` (`setpriv` legs,
  `SO_PEERCRED`) shows as it builds on macOS.
- **Counted twice:** some store functions appear twice in the function list,
  because the fault-hook test compiles `store.c` a second time.
- **Not exactly repeatable.** A second full run matched these lines,
  regions, functions and the 76-function list exactly. It found one branch
  fewer in `apps/authd/` (4,298 against 4,299), a path that depends on
  timing (an event-loop retry), and its call counts differ for the same
  reason.
- **Not gated.** A later step that lowers these figures fails nothing. The
  figures are a dated measurement, re-run with the command above.
