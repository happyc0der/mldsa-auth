# --- WebAssembly (V4-13b) ----------------------------------------------------
# Under Emscripten only the tests that prove the wasm build computes what the
# native one does are built: test_vectors (V4-2 S6's 27 checks, now permanent)
# and the client core's KAT, against the SAME golden file native CTest uses.
# CTest runs them through Node (emcmake sets CMAKE_CROSSCOMPILING_EMULATOR);
# NODERAWFS gives them the real filesystem, so the golden and liboqs's KAT
# JSON are read from the tree exactly as natively -- no copies to drift.
if(EMSCRIPTEN)
  set(_mldsa_wasm_test_link ${MLDSA_WASM_LINK_FLAGS} -sNODERAWFS=1 -sEXIT_RUNTIME=1)

  add_executable(test_vectors test_vectors.c)
  target_link_libraries(test_vectors PRIVATE mldsa_core oqs-internal)
  target_compile_options(test_vectors PRIVATE ${MLDSA_HARDENING_FLAGS})
  target_compile_definitions(test_vectors PRIVATE ${MLDSA_HARDENING_DEFS}
      MLDSA_AUTH_LIBOQS_KATS_SIG_JSON="${liboqs_SOURCE_DIR}/tests/KATs/sig/kats.json"
      MLDSA_AUTH_LIBOQS_KATS_KEM_JSON="${liboqs_SOURCE_DIR}/tests/KATs/kem/kats.json")
  target_link_options(test_vectors PRIVATE ${_mldsa_wasm_test_link})
  add_test(NAME test_vectors COMMAND test_vectors)

  add_executable(test_client_core_kat test_client_core_kat.c)
  target_link_libraries(test_client_core_kat PRIVATE mldsa_client)
  target_compile_options(test_client_core_kat PRIVATE ${MLDSA_HARDENING_FLAGS})
  target_compile_definitions(test_client_core_kat PRIVATE ${MLDSA_HARDENING_DEFS})
  target_link_options(test_client_core_kat PRIVATE ${_mldsa_wasm_test_link})
  add_test(NAME test_client_core_kat
           COMMAND test_client_core_kat ${CMAKE_CURRENT_SOURCE_DIR}/golden/client_core_kat.txt)
  return()
endif()

add_executable(test_vectors test_vectors.c)
target_link_libraries(test_vectors PRIVATE mldsa_core)

# `oqs-internal` is a CMake target liboqs's OWN build defines -- this is
# not a target we created, and not an artifact of our OQS_MINIMAL_BUILD
# scoping. In liboqs 0.16.0's src/CMakeLists.txt (fetched source, not
# vendored/patched by us):
#
#   add_library(oqs kem/kem.c ... ${COMMON_OBJS})
#   # Internal library to be used only by test programs
#   add_library(oqs-internal STATIC ${INTERNAL_OBJS})
#
# rand_nist.c (the deterministic NIST-KAT RNG backend) is compiled only
# into INTERNAL_OBJS (src/common/CMakeLists.txt), never into COMMON_OBJS
# -- so it's absent from the public `oqs` library in every build
# configuration, not just this minimal one. liboqs's own comment above
# states the intent: internal-only, for test programs.
#
# If a future liboqs version bump renames/restructures this (check
# src/CMakeLists.txt for the `oqs-internal` target and where rand_nist.c
# ends up), update this line and re-verify OQS_randombytes_nist_kat /
# OQS_randombytes_nist_kat_init_256bit are still reachable from it.
#
# Needed ONLY here, for the KAT test's use of those two functions. NEVER
# link oqs-internal into mldsa_core -- production key generation must
# only ever use the real system RNG via the public `oqs` library.
target_link_libraries(test_vectors PRIVATE oqs-internal)
target_compile_options(test_vectors PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_vectors PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_vectors PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# Points the ML-DSA-65 KAT test at liboqs's own vendored KAT reference
# file, so the test reads liboqs's published hash live rather than
# copying it into our source (see tests/test_vectors.c). liboqs_SOURCE_DIR
# is set by FetchContent_MakeAvailable(liboqs) in cmake/Dependencies.cmake.
target_compile_definitions(test_vectors PRIVATE
    MLDSA_AUTH_LIBOQS_KATS_SIG_JSON="${liboqs_SOURCE_DIR}/tests/KATs/sig/kats.json"
    MLDSA_AUTH_LIBOQS_KATS_KEM_JSON="${liboqs_SOURCE_DIR}/tests/KATs/kem/kats.json"
)

add_test(NAME test_vectors COMMAND test_vectors)

add_executable(test_handshake test_handshake.c)
target_link_libraries(test_handshake PRIVATE mldsa_core)
target_compile_options(test_handshake PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_handshake PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_handshake PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

add_test(NAME test_handshake COMMAND test_handshake)

add_executable(test_session test_session.c)
target_link_libraries(test_session PRIVATE mldsa_core)
target_compile_options(test_session PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_session PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_session PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

add_test(NAME test_session COMMAND test_session)

# Zero-allocation Gate 1 (spec §8 Step 5). counting_secure_mem.c defines all
# three secure_mem_* symbols, so when this executable is linked against the
# STATIC mldsa_core archive the linker never pulls in the library's own
# secure_mem.o -- every secure allocation anywhere in mldsa_core is counted.
# The test proves the substitution is live (session init must count exactly
# one allocation), so it fails loudly rather than passing vacuously if
# mldsa_core ever stops being a static archive.
add_executable(test_session_alloc test_session_alloc.c counting_secure_mem.c)
target_link_libraries(test_session_alloc PRIVATE mldsa_core)
target_compile_options(test_session_alloc PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_session_alloc PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_session_alloc PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# Optional macOS developer diagnostic (libmalloc's malloc_logger hook). Not a
# stable public API: OFF by default, never required, never affects the exit
# status. The portable proofs are Gate 1 above and Gate 2 below.
option(MLDSA_MALLOC_DIAG "Run the optional macOS malloc_logger diagnostic in test_session_alloc" OFF)
if(MLDSA_MALLOC_DIAG)
  target_compile_definitions(test_session_alloc PRIVATE MLDSA_MALLOC_DIAG=1)
endif()

add_test(NAME test_session_alloc COMMAND test_session_alloc)

# Step 6 reference transport: framing, sockets, the demo client/server
# logic and demo key files over real loopback TCP (fork-based, no threads).
add_executable(test_net test_net.c)
target_link_libraries(test_net PRIVATE mldsa_demo)
target_compile_options(test_net PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_net PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_net PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

add_test(NAME test_net COMMAND test_net)

add_executable(test_authd_keyfile test_authd_keyfile.c)
target_link_libraries(test_authd_keyfile PRIVATE mldsa_authd)
target_compile_options(test_authd_keyfile PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_keyfile PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_authd_keyfile PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_keyfile COMMAND test_authd_keyfile)

# V4-7: the store. This target compiles store.c ITSELF with the fault hook so
# the atomicity of a rotation can be proven by injecting a failure mid-way; the
# shipped mldsa_authd carries the same source WITHOUT the hook, and a
# structural check keeps it that way. It therefore links mldsa_demo + sqlite3
# directly rather than mldsa_authd (which would duplicate store.o).
add_executable(test_authd_store test_authd_store.c ${PROJECT_SOURCE_DIR}/apps/authd/store/store.c)
target_include_directories(test_authd_store PRIVATE ${PROJECT_SOURCE_DIR}/apps/authd/store)
target_link_libraries(test_authd_store PRIVATE mldsa_demo sqlite3)
target_compile_definitions(test_authd_store PRIVATE ${MLDSA_HARDENING_DEFS} MLDSA_STORE_FAULT_HOOK=1)
target_compile_options(test_authd_store PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_link_options(test_authd_store PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_store COMMAND test_authd_store)

add_executable(test_authd_evloop test_authd_evloop.c)
target_link_libraries(test_authd_evloop PRIVATE mldsa_authd)
target_compile_options(test_authd_evloop PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_evloop PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_authd_evloop PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_evloop COMMAND test_authd_evloop)

# V4-8b: the connection state machine, driven with the daemon in-process so the
# test owns its clock and can read its counters and slot state directly.
add_executable(test_authd_conn test_authd_conn.c)
target_link_libraries(test_authd_conn PRIVATE mldsa_authd)
target_compile_options(test_authd_conn PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_conn PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_authd_conn PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_conn COMMAND test_authd_conn)

# V4-10a: the WebSocket carrier. Its own target rather than more cases in
# test_authd_conn, because the upgrade parser is the first attacker-facing TEXT
# parser in the tree and deserves a named place to fail.
add_executable(test_authd_ws test_authd_ws.c)
target_link_libraries(test_authd_ws PRIVATE mldsa_authd)
target_compile_options(test_authd_ws PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_ws PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_authd_ws PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_ws COMMAND test_authd_ws)

# V4-9a: the local socket protocol, tokens and revocation reaching live
# sessions. Shares tests/authd_harness.h with test_authd_conn so both drive
# the same in-process daemon.
add_executable(test_authd_cli test_authd_cli.c)
target_link_libraries(test_authd_cli PRIVATE mldsa_authd mldsa_client_cli)
target_compile_options(test_authd_cli PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_cli PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_authd_cli PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_cli COMMAND test_authd_cli)

# V4-13a: the client core, against the in-process daemon and a fake server.
# The TIMEOUT is a guard, not a budget (the test takes seconds): it flips every
# envelope header byte, and a mutant that removed the KDF bounds would send a
# flipped opslimit into Argon2id for hours instead of failing.
add_executable(test_client_core test_client_core.c)
target_link_libraries(test_client_core PRIVATE mldsa_authd)
target_compile_options(test_client_core PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_client_core PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_client_core PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_client_core COMMAND test_client_core)
set_tests_properties(test_client_core PROPERTIES TIMEOUT 300)

# V4-13b: the wasm export shim, natively, driven the way JavaScript drives it.
add_executable(test_client_wasm test_client_wasm.c)
target_link_libraries(test_client_wasm PRIVATE mldsa_client_wasm)
target_compile_options(test_client_wasm PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_client_wasm PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_client_wasm PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_client_wasm COMMAND test_client_wasm)

# The KAT links the CLIENT libraries only -- no daemon, no store, no sqlite --
# which is also the proof that the core stands on its own, as the wasm build
# (13b) will need it to. The golden is the contract that build must reproduce.
add_executable(test_client_core_kat test_client_core_kat.c)
target_link_libraries(test_client_core_kat PRIVATE mldsa_client)
target_compile_options(test_client_core_kat PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_client_core_kat PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_client_core_kat PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_client_core_kat
         COMMAND test_client_core_kat ${CMAKE_CURRENT_SOURCE_DIR}/golden/client_core_kat.txt)

# V4-13a: authd_client links no sqlite3 and no store. Checked on the linked
# binary by symbol, because a static library links whatever it is never asked
# for and "it built" proves nothing. The _control test runs the same script on
# the DAEMON, which must have both, and is expected to fail: a gate that could
# not fail would pass forever once the symbol names changed.
add_test(NAME client_links_no_sqlite
         COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/client_links_no_sqlite.sh
                 $<TARGET_FILE:authd_client_bin> $<TARGET_FILE:mldsa_authd_bin>)
add_test(NAME client_links_no_sqlite_control
         COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/client_links_no_sqlite.sh
                 $<TARGET_FILE:mldsa_authd_bin> $<TARGET_FILE:mldsa_authd_bin>)
set_tests_properties(client_links_no_sqlite_control PROPERTIES WILL_FAIL TRUE)

add_executable(test_authd_localapi test_authd_localapi.c)
target_link_libraries(test_authd_localapi PRIVATE mldsa_authd)
target_compile_options(test_authd_localapi PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_localapi PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(test_authd_localapi PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
add_test(NAME test_authd_localapi COMMAND test_authd_localapi)

# A real daemon for the Node reference handler to talk to. Not a CTest itself:
# it is spawned by examples/site-node/authd.test.mjs.
add_executable(authd_node_fixture authd_node_fixture.c)
target_link_libraries(authd_node_fixture PRIVATE mldsa_authd)
target_compile_options(authd_node_fixture PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_node_fixture PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(authd_node_fixture PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# The Node reference handler, against that daemon. Skips with a named reason if
# node is absent -- never passes vacuously.
find_program(MLDSA_NODE node)
if(MLDSA_NODE)
  add_test(NAME site_node_handler
    COMMAND ${MLDSA_NODE} --test ${CMAKE_CURRENT_SOURCE_DIR}/../examples/site-node/authd.test.mjs)
  set_tests_properties(site_node_handler PROPERTIES
    ENVIRONMENT "AUTHD_FIXTURE=$<TARGET_FILE:authd_node_fixture>")
endif()

# V4-13b: the wasm client logging in to the real daemon, from Node. The module
# is built in a SEPARATE Emscripten tree, so this test exists only when that
# tree is named: -DMLDSA_WASM_DIR=<build-wasm>. CI's wasm job always names it;
# a native-only tree simply does not have the test, rather than a test that
# silently skips.
add_executable(authd_wasm_fixture authd_wasm_fixture.c)
target_link_libraries(authd_wasm_fixture PRIVATE mldsa_authd)
target_compile_options(authd_wasm_fixture PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_wasm_fixture PRIVATE ${MLDSA_HARDENING_DEFS} _GNU_SOURCE=1)
target_link_options(authd_wasm_fixture PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
if(MLDSA_NODE)
  # Spec 14's "no cryptography in JavaScript", as a check on web/client/.
  add_test(NAME web_no_crypto COMMAND ${MLDSA_NODE} ${CMAKE_CURRENT_SOURCE_DIR}/web_no_crypto.mjs
                                      ${PROJECT_SOURCE_DIR}/web/client)
endif()
set(MLDSA_WASM_DIR "" CACHE PATH "An Emscripten build tree (web/mldsa_client.mjs) for the wasm interop test")
if(MLDSA_WASM_DIR)
  if(NOT MLDSA_NODE)
    message(FATAL_ERROR "MLDSA_WASM_DIR is set but node was not found: the wasm interop test needs it")
  endif()
  add_test(NAME wasm_interop
    COMMAND ${MLDSA_NODE} ${CMAKE_CURRENT_SOURCE_DIR}/wasm_interop.mjs
            $<TARGET_FILE:authd_wasm_fixture> ${MLDSA_WASM_DIR}/web/mldsa_client.mjs
            ${PROJECT_SOURCE_DIR}/web/client/authd-client.mjs)
  set_tests_properties(wasm_interop PROPERTIES TIMEOUT 180)
endif()

# Milestone A, automated: the shipped daemon and both CLIs as real processes.
# The node arguments are optional -- the script prints a named SKIP line for
# the EXCHANGE/VERIFY leg when node is absent, rather than failing or (worse)
# passing quietly.
add_test(NAME authd_e2e
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/authd_e2e.sh
          $<TARGET_FILE:authd_admin_bin> $<TARGET_FILE:authd_client_bin>
          $<TARGET_FILE:mldsa_authd_bin> "${MLDSA_NODE}"
          ${CMAKE_CURRENT_SOURCE_DIR}/e2e_site.mjs
          ${CMAKE_CURRENT_SOURCE_DIR}/e2e_recovery.mjs
)
set_tests_properties(authd_e2e PROPERTIES TIMEOUT 600)

# Step 6 exit criterion, automated: the real executables as two processes.
add_test(NAME demo_e2e
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/demo_e2e.sh $<TARGET_FILE:auth_server> $<TARGET_FILE:auth_client>
)

# Zero-allocation Gate 2: portable structural scan of session.c, with
# built-in negative controls (see the script header).
add_test(NAME session_no_alloc_scan
  COMMAND ${CMAKE_COMMAND}
    -DSESSION_C=${PROJECT_SOURCE_DIR}/src/protocol/session.c
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_session_no_alloc.cmake
)

# Step 7 fuzz targets (portable replay driver + libFuzzer binaries)
add_subdirectory(fuzz)
