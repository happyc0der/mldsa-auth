# The fingerprint sink takes a fingerprint and nothing else (V4-21, audit
# finding F41, CLAIMS D13). Run by CTest as
#
#   cmake -DCC=<C compiler> -DSOURCE_DIR=<repo> -DWORK=<scratch dir>
#         -P check_log_fp_type.cmake
#
# authd_log_fp is the logging API's one byte sink. Until V4-21 it took
# `const uint8_t fp[32]`, which C reads as a pointer, so a login code, a
# recovery ticket or half the session keys -- each 32 bytes -- type-checked
# and went to the journal in hex. It now takes `const authd_fp_t *`, a struct
# only authd_fp_of_pk makes, so that call is a compile error under -Werror.
# A compile error is a property no test binary can observe, so this gate
# compiles two probes with the build's own compiler:
#
#   canary  an authd_fp_t made by authd_fp_of_pk  -> must compile
#   defect  a bare 32-byte buffer                  -> must NOT compile
#
# The two share every line but the argument, so the canary rules out the
# defect failing for any other reason (a missing include, a renamed type).
# What the gate cannot see is a cast: `(const authd_fp_t *)secret` compiles,
# and is caught at run time by the log scans (v49c W12, v49d G12, v60 GC4).

cmake_minimum_required(VERSION 3.20)
foreach(_v CC SOURCE_DIR WORK)
  if(NOT DEFINED ${_v})
    message(FATAL_ERROR "usage: cmake -DCC=<compiler> -DSOURCE_DIR=<repo> -DWORK=<dir> -P check_log_fp_type.cmake")
  endif()
endforeach()

file(MAKE_DIRECTORY "${WORK}")
set(_failed 0)

function(probe name arg out_rc out_err)
  file(WRITE "${WORK}/${name}.c"
"#include \"authd_log.h\"
void probe(const uint8_t *pk, const uint8_t h[32]);
void probe(const uint8_t *pk, const uint8_t h[32])
{
    authd_fp_t f;
    authd_fp_of_pk(&f, pk);
    (void)h;
    authd_log_fp(AUTHD_LOG_INFO, \"probe\", ${arg});
}
")
  execute_process(
    COMMAND "${CC}" -std=c11 -Wall -Wextra -Werror -fsyntax-only
            "-I${SOURCE_DIR}/apps/authd" "${WORK}/${name}.c"
    RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_VARIABLE _err)
  set(${out_rc} "${_rc}" PARENT_SCOPE)
  set(${out_err} "${_err}" PARENT_SCOPE)
endfunction()

probe(fp_canary "&f" _rc_canary _err_canary)
if(_rc_canary EQUAL 0)
  message(STATUS "PASS: fp-type(canary): an authd_fp_t is accepted by authd_log_fp")
else()
  string(REPLACE "\n" " | " _e "${_err_canary}")
  message(STATUS "FAIL: fp-type(canary): an authd_fp_t is accepted by authd_log_fp -- ${_e}")
  set(_failed 1)
endif()

probe(fp_defect "h" _rc_defect _err_defect)
if(NOT _rc_defect EQUAL 0)
  message(STATUS "PASS: fp-type: a 32-byte buffer passed to authd_log_fp does not compile")
else()
  message(STATUS "FAIL: fp-type: a 32-byte buffer passed to authd_log_fp does not compile -- it COMPILED")
  set(_failed 1)
endif()

if(_failed)
  message(FATAL_ERROR "log_fp_type FAILED")
endif()
message(STATUS "All checks passed")
