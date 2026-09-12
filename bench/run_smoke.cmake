# CTest bench_smoke driver: every bench binary at tiny iteration counts.
#
# This is a bit-rot and correctness gate, NOT a benchmark. It runs in the
# normal, ASan and UBSan builds, where absolute timings are meaningless, so
# it asserts only that each binary completes successfully -- the binaries
# themselves abort (BENCH_REQUIRE) on any protocol failure, a zero median,
# or socket buffers too small to run single-process.
foreach(_exe "${BENCH_PRIMITIVES}" "${BENCH_HANDSHAKE}" "${BENCH_SESSION}")
  message(STATUS "bench_smoke: ${_exe} --smoke")
  execute_process(COMMAND "${_exe}" --smoke RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "bench_smoke FAILED: ${_exe} exited ${_rc}\n${_out}\n${_err}")
  endif()
endforeach()
message(STATUS "bench_smoke: all bench binaries ran clean")
