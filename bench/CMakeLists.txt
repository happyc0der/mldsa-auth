# Step 8 benchmarks (spec §5, §8 Step 8).
#
# These are MEASUREMENT targets: nothing in src/ or apps/ links against
# them, and they only call the same public APIs the tests use. They are
# built in every configuration so they cannot rot, but real numbers must
# come from a Release build -- the default build type is Debug, which
# leaves liboqs unoptimized (see bench/README.md).

add_library(mldsa_bench STATIC bench_common.c)
target_include_directories(mldsa_bench PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# libm: bench_common.c uses sqrt() for the standard deviation. macOS folds
# libm into libSystem so this is a no-op there; Linux needs it explicitly.
target_link_libraries(mldsa_bench PUBLIC mldsa_core $<$<NOT:$<PLATFORM_ID:Darwin>>:m>)
target_compile_options(mldsa_bench PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_bench PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_bench PUBLIC ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# Recorded in every bench run's environment block, so a result can never be
# read without knowing how it was compiled.
string(TOUPPER "${CMAKE_BUILD_TYPE}" _mldsa_bt_uc)
string(REPLACE ";" " " _mldsa_hardening_str "${MLDSA_HARDENING_FLAGS}")
string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_mldsa_bt_uc}} ${_mldsa_hardening_str}" _mldsa_flags_str)
target_compile_definitions(mldsa_bench PRIVATE
  BENCH_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
  BENCH_C_FLAGS="${_mldsa_flags_str}"
)

# bench_primitives and bench_handshake use the demo/reference layer
# (demo_keys, net_io, frame); bench_session needs only the protocol core.
foreach(_bench primitives handshake session)
  add_executable(bench_${_bench} bench_${_bench}.c)
  target_link_libraries(bench_${_bench} PRIVATE mldsa_bench)
  target_compile_options(bench_${_bench} PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
  target_compile_definitions(bench_${_bench} PRIVATE ${MLDSA_HARDENING_DEFS})
  target_link_options(bench_${_bench} PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})
endforeach()
target_link_libraries(bench_primitives PRIVATE mldsa_demo)
target_link_libraries(bench_handshake PRIVATE mldsa_demo)

# Bit-rot gate: runs every bench binary with tiny iteration counts in the
# normal, ASan and UBSan builds. It asserts only that the harness runs and
# the protocol behaves (handshakes complete, sealed records open back) --
# never a performance threshold, since sanitizer builds are far slower.
add_test(NAME bench_smoke
  COMMAND ${CMAKE_COMMAND}
    -DBENCH_PRIMITIVES=$<TARGET_FILE:bench_primitives>
    -DBENCH_HANDSHAKE=$<TARGET_FILE:bench_handshake>
    -DBENCH_SESSION=$<TARGET_FILE:bench_session>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/run_smoke.cmake
)
set_tests_properties(bench_smoke PROPERTIES TIMEOUT 300)
