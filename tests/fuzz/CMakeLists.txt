# Step 7 fuzz targets (tests/fuzz/README.md).
#
#   fuzz_<t>_replay  portable driver, built in EVERY configuration (any
#                    compiler): CI smoke = empty input + seeds + committed
#                    regressions + deterministic mutations. NOT coverage-guided.
#   fuzz_<t>         libFuzzer binary, only with -DMLDSA_FUZZ=ON and a
#                    libFuzzer-capable clang (separate build-fuzz directory).
#
# The deterministic test-only RNG in fuzz_common.c is linked ONLY into these
# executables.

set(FUZZ_TARGETS wire handshake session frame keys envelope authd_config authd_conn localapi authmsg)

# CI smoke budget (deterministic fallback mutations per target).
set(FUZZ_ITER_wire 20000)
set(FUZZ_ITER_handshake 300)
set(FUZZ_ITER_session 5000)
set(FUZZ_ITER_frame 5000)
set(FUZZ_ITER_keys 2000)
set(FUZZ_ITER_envelope 5000)
set(FUZZ_ITER_authd_config 20000)
set(FUZZ_ITER_authd_conn 300)
set(FUZZ_ITER_localapi 5000)
set(FUZZ_ITER_authmsg 20000)

# libFuzzer -max_len per target (the harnesses enforce the same bound).
set(FUZZ_MAXLEN_envelope 8192)
set(FUZZ_MAXLEN_authmsg 9216)
set(FUZZ_MAXLEN_authd_config 4096)
set(FUZZ_MAXLEN_authd_conn 16384)
set(FUZZ_MAXLEN_localapi 8192)
set(FUZZ_MAXLEN_wire 4096)
set(FUZZ_MAXLEN_handshake 16384)
set(FUZZ_MAXLEN_session 140000)
set(FUZZ_MAXLEN_frame 140000)
set(FUZZ_MAXLEN_keys 8192)

# Under UBSan, undefined behavior must FAIL the replay test, not just print.
set(FUZZ_REPLAY_EXTRA_FLAGS "")
if(ENABLE_UBSAN)
  list(APPEND FUZZ_REPLAY_EXTRA_FLAGS -fno-sanitize-recover=all)
endif()

set(FUZZ_DIR ${CMAKE_CURRENT_SOURCE_DIR})

foreach(t IN LISTS FUZZ_TARGETS)
  add_executable(fuzz_${t}_replay fuzz_replay_main.c fuzz_${t}.c fuzz_common.c)
  target_include_directories(fuzz_${t}_replay PRIVATE ${FUZZ_DIR})
  target_link_libraries(fuzz_${t}_replay PRIVATE mldsa_authd)
  target_compile_options(fuzz_${t}_replay PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS}
                                                  ${FUZZ_REPLAY_EXTRA_FLAGS})
  target_compile_definitions(fuzz_${t}_replay PRIVATE ${MLDSA_HARDENING_DEFS})
  target_link_options(fuzz_${t}_replay PRIVATE ${MLDSA_SANITIZE_FLAGS} ${FUZZ_REPLAY_EXTRA_FLAGS})

  add_test(NAME fuzz_replay_${t}
    COMMAND fuzz_${t}_replay --ci
            --dict ${FUZZ_DIR}/dict/${t}.dict
            --regressions ${FUZZ_DIR}/regressions/${t}
            --iterations ${FUZZ_ITER_${t}} --seed 1)

  if(MLDSA_FUZZ)
    add_executable(fuzz_${t} fuzz_${t}.c fuzz_common.c)
    target_include_directories(fuzz_${t} PRIVATE ${FUZZ_DIR})
    target_link_libraries(fuzz_${t} PRIVATE mldsa_authd)
    target_compile_options(fuzz_${t} PRIVATE ${MLDSA_HARDENING_FLAGS}
      -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)

    # Seeds are generated at runtime into the (ignored) build directory.
    set(corpus ${CMAKE_BINARY_DIR}/fuzz-corpus/${t})
    add_test(NAME fuzz_seed_${t}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${corpus}/ctest ${CMAKE_BINARY_DIR}/fuzz-artifacts/${t})
    add_test(NAME fuzz_seedgen_${t} COMMAND fuzz_${t}_replay --write-seeds ${corpus}/seeds)
    add_test(NAME fuzz_libfuzzer_smoke_${t}
      COMMAND fuzz_${t} ${corpus}/ctest ${corpus}/seeds
              -dict=${FUZZ_DIR}/dict/${t}.dict -max_len=${FUZZ_MAXLEN_${t}}
              -artifact_prefix=${CMAKE_BINARY_DIR}/fuzz-artifacts/${t}/
              -timeout=10 -rss_limit_mb=2048 -max_total_time=30 -print_final_stats=1)
    set_tests_properties(fuzz_seed_${t} PROPERTIES FIXTURES_SETUP fuzzdirs_${t} LABELS fuzz)
    set_tests_properties(fuzz_seedgen_${t} PROPERTIES FIXTURES_SETUP fuzzseeds_${t} FIXTURES_REQUIRED fuzzdirs_${t}
                         LABELS fuzz)
    set_tests_properties(fuzz_libfuzzer_smoke_${t} PROPERTIES FIXTURES_REQUIRED "fuzzdirs_${t};fuzzseeds_${t}"
                         LABELS fuzz
                         ENVIRONMENT "ASAN_OPTIONS=abort_on_error=1:detect_leaks=0;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")
  endif()
endforeach()

# Repository admission gate: committed fuzz inputs and dictionaries must never
# contain ML-DSA secret-key bytes (the fixture key is regenerated in memory).
add_test(NAME fuzz_no_committed_secrets
  COMMAND fuzz_keys_replay --scan-secret-dirs ${FUZZ_DIR}/regressions ${FUZZ_DIR}/dict)

if(NOT MLDSA_FUZZ)
  add_test(NAME fuzz_libfuzzer
    COMMAND sh -c "echo 'SKIP: libFuzzer targets not built in this configuration (configure a separate build dir with a libFuzzer-capable clang and -DMLDSA_FUZZ=ON; see tests/fuzz/README.md)'; exit 77")
  set_tests_properties(fuzz_libfuzzer PROPERTIES SKIP_RETURN_CODE 77)
endif()
