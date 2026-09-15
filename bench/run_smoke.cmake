# CTest bench_smoke driver: every bench binary at tiny iteration counts.
#
# This is a bit-rot and correctness gate, NOT a benchmark. It runs in the
# normal, ASan and UBSan builds, where absolute timings are meaningless, so
# it asserts only that each binary completes successfully -- the binaries
# themselves abort (BENCH_REQUIRE) on any protocol failure, a zero median,
# or socket buffers too small to run single-process.
# The environment block is the only part of a published measurement that is
# prose rather than a number, so it is the only part with no natural oracle --
# and it is exactly what makes a figure reproducible ("0.45 ms" on what?).
# These assertions give it one, here rather than in a new test, so the suite
# stays at 15. V3-2.
set(_required_keys "os" "cpu" "compiler" "build type" "liboqs" "ml-dsa backend" "ml-kem backend" "clock")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND _required_keys "cpu scaling" "virtualization")
endif()

function(check_environment_block exe out)
  foreach(_key IN LISTS _required_keys)
    # TWO spaces: values are column-aligned, so a key is followed by several
    # spaces while a longer key sharing its prefix is followed by exactly one.
    # With a single space, "cpu scaling" satisfied the "cpu" requirement and a
    # deleted cpu line went unnoticed -- V3-2 mutation V1.
    if(NOT out MATCHES "\n  ${_key}  +([^\n]*)")
      message(FATAL_ERROR "bench_smoke FAILED: ${exe} environment block has no '${_key}' line\n${out}")
    endif()
    set(_value "${CMAKE_MATCH_1}")
    string(STRIP "${_value}" _value)
    if(_value STREQUAL "")
      message(FATAL_ERROR "bench_smoke FAILED: ${exe} reports '${_key}' with an empty value -- an unreadable fact must print unknown (<why>), never nothing")
    endif()
    # A value the binary could not read must SAY so, so a reader can tell a
    # measured fact from a missing one.
    if(_value MATCHES "^(unknown|\\(null\\))$")
      message(FATAL_ERROR "bench_smoke FAILED: ${exe} reports '${_key}' as a bare '${_value}' with no reason")
    endif()
  endforeach()
  # On Linux the cpu line must be derived from /proc/cpuinfo, not invented:
  # either it matches the model name read independently here, or it declares
  # itself unknown (arm64 has no model name field at all).
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    string(REGEX MATCH "\n  cpu  +([^\n]*)" _m "${out}")
    set(_cpu "${CMAKE_MATCH_1}")
    set(_model "")
    if(EXISTS "/proc/cpuinfo")
      file(STRINGS "/proc/cpuinfo" _lines REGEX "^model name")
      if(_lines)
        list(GET _lines 0 _first)
        string(REGEX REPLACE "^model name[ \t]*:[ \t]*" "" _model "${_first}")
      endif()
    endif()
    if(_model STREQUAL "")
      if(NOT _cpu MATCHES "unknown \\(")
        message(FATAL_ERROR "bench_smoke FAILED: ${exe} reports cpu '${_cpu}' but /proc/cpuinfo has no model name -- it must say unknown (<why>)")
      endif()
    elseif(NOT _cpu MATCHES "${_model}")
      message(FATAL_ERROR "bench_smoke FAILED: ${exe} reports cpu '${_cpu}' which does not contain /proc/cpuinfo's model name '${_model}'")
    endif()
  endif()
endfunction()

foreach(_exe "${BENCH_PRIMITIVES}" "${BENCH_HANDSHAKE}" "${BENCH_SESSION}")
  message(STATUS "bench_smoke: ${_exe} --smoke")
  execute_process(COMMAND "${_exe}" --smoke RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "bench_smoke FAILED: ${_exe} exited ${_rc}\n${_out}\n${_err}")
  endif()
  check_environment_block("${_exe}" "${_out}")
endforeach()
message(STATUS "bench_smoke: all bench binaries ran clean; environment blocks complete")
