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
)

add_test(NAME test_vectors COMMAND test_vectors)

add_executable(test_handshake test_handshake.c)
target_link_libraries(test_handshake PRIVATE mldsa_core)
target_compile_options(test_handshake PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(test_handshake PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(test_handshake PRIVATE ${MLDSA_SANITIZE_FLAGS})

add_test(NAME test_handshake COMMAND test_handshake)
