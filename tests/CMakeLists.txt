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
target_link_options(test_vectors PRIVATE ${MLDSA_SANITIZE_FLAGS})

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
target_link_options(test_handshake PRIVATE ${MLDSA_SANITIZE_FLAGS})

add_test(NAME test_handshake COMMAND test_handshake)

add_executable(test_session test_session.c)
target_link_libraries(test_session PRIVATE mldsa_core)
target_compile_options(test_session PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_session PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_session PRIVATE ${MLDSA_SANITIZE_FLAGS})

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
target_link_options(test_session_alloc PRIVATE ${MLDSA_SANITIZE_FLAGS})

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
target_link_options(test_net PRIVATE ${MLDSA_SANITIZE_FLAGS})

add_test(NAME test_net COMMAND test_net)

add_executable(test_authd_keyfile test_authd_keyfile.c)
target_link_libraries(test_authd_keyfile PRIVATE mldsa_authd)
target_compile_options(test_authd_keyfile PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_authd_keyfile PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_authd_keyfile PRIVATE ${MLDSA_SANITIZE_FLAGS})
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
target_link_options(test_authd_store PRIVATE ${MLDSA_SANITIZE_FLAGS})
add_test(NAME test_authd_store COMMAND test_authd_store)

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
