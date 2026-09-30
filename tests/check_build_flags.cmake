# Build-flag evidence (V4-15c, CLAIMS P8). Run by CTest as
#
#   cmake -DCOMPILE_COMMANDS=<build>/compile_commands.json -DSOURCE_DIR=<repo>
#         -DEXPECT_FORTIFY=ON|OFF -DARCHIVES="<a.a>|<b.a>" -DNM=<nm>
#         -P check_build_flags.cmake
#
# tools/audit/check_hardening.sh reads the LINKED binaries, and there its
# canary line cannot fail for this project's code: vendored liboqs and sqlite
# import __stack_chk_fail themselves, whatever the project asks (audit F104,
# the class of F75). This gate checks two things that ARE the project's:
#
#   1. what the build was TOLD. Every project translation unit in
#      compile_commands.json carries -Wall -Wextra -Werror and
#      -fstack-protector-strong, and -D_FORTIFY_SOURCE=2 exactly when the tree
#      is neither a sanitizer nor a fuzz tree (CMakeLists.txt skips it there).
#   2. what the compiler DID with the canary flag: the project's own static
#      archives, which hold project objects only, import __stack_chk_fail.
#
# FORTIFY gets no binary check: glibc ignores it without optimisation, and the
# macOS SDK turns its checks on whatever the project asks, so a __*_chk
# import proves nothing about this project in either place. What the gate
# cannot see is what the compiler did with each flag it was told -- a flag
# that is present and silently ignored would pass here.

cmake_minimum_required(VERSION 3.20)
foreach(_v COMPILE_COMMANDS SOURCE_DIR EXPECT_FORTIFY ARCHIVES NM)
  if(NOT DEFINED ${_v})
    message(FATAL_ERROR "usage: cmake -DCOMPILE_COMMANDS=... -DSOURCE_DIR=... -DEXPECT_FORTIFY=ON|OFF -DARCHIVES=\"a|b\" -DNM=... -P check_build_flags.cmake")
  endif()
endforeach()

set(_failed 0)
function(gate_fail text)
  # Verbatim on one line: CMake re-wraps FATAL_ERROR text (see run_smoke.cmake).
  message(STATUS "FAIL: build_flags: ${text}")
  set(_failed 1 PARENT_SCOPE)
endfunction()

file(READ "${COMPILE_COMMANDS}" _json)
string(JSON _n ERROR_VARIABLE _err LENGTH "${_json}")
if(_err)
  message(STATUS "FAIL: build_flags: ${COMPILE_COMMANDS} is not a JSON array (${_err})")
  message(FATAL_ERROR "build_flags FAILED")
endif()

set(_project 0)
set(_required -Wall -Wextra -Werror -fstack-protector-strong)
math(EXPR _last "${_n} - 1")
foreach(_i RANGE 0 ${_last})
  string(JSON _file GET "${_json}" ${_i} file)
  string(JSON _cmd ERROR_VARIABLE _nocmd GET "${_json}" ${_i} command)
  if(_nocmd)
    # the "arguments" form: an array, joined with spaces
    string(JSON _na LENGTH "${_json}" ${_i} arguments)
    set(_cmd "")
    math(EXPR _al "${_na} - 1")
    foreach(_j RANGE 0 ${_al})
      string(JSON _a GET "${_json}" ${_i} arguments ${_j})
      string(APPEND _cmd " ${_a}")
    endforeach()
  endif()
  # A project TU is a file under the source tree's own directories, never a
  # vendored one (those live under the build tree's _deps).
  set(_is_project 0)
  foreach(_d src apps tests bench web)
    string(FIND "${_file}" "${SOURCE_DIR}/${_d}/" _at)
    if(_at EQUAL 0)
      set(_is_project 1)
    endif()
  endforeach()
  if(NOT _is_project)
    continue()
  endif()
  math(EXPR _project "${_project} + 1")
  set(_padded " ${_cmd} ")
  foreach(_flag ${_required})
    string(FIND "${_padded}" " ${_flag} " _has)
    if(_has EQUAL -1)
      gate_fail("${_file} is compiled without ${_flag}")
    endif()
  endforeach()
  string(FIND "${_padded}" " -D_FORTIFY_SOURCE=2 " _fort)
  if(EXPECT_FORTIFY AND _fort EQUAL -1)
    gate_fail("${_file} is compiled without -D_FORTIFY_SOURCE=2")
  elseif(NOT EXPECT_FORTIFY AND NOT _fort EQUAL -1)
    gate_fail("${_file} defines _FORTIFY_SOURCE in a sanitizer or fuzz tree, where it collides")
  endif()
endforeach()

if(_project EQUAL 0)
  gate_fail("no project translation unit found in ${COMPILE_COMMANDS} -- wrong SOURCE_DIR, or the scan broke")
endif()

string(REPLACE "|" ";" _archives "${ARCHIVES}")
set(_n_arch 0)
foreach(_a IN LISTS _archives)
  math(EXPR _n_arch "${_n_arch} + 1")
  execute_process(COMMAND "${NM}" "${_a}" OUTPUT_VARIABLE _syms ERROR_QUIET RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0 OR _syms STREQUAL "")
    gate_fail("nm could not read ${_a}")
  elseif(NOT _syms MATCHES "__stack_chk_fail")
    gate_fail("${_a} imports no __stack_chk_fail -- the project's own objects carry no stack canary")
  endif()
endforeach()

if(_failed)
  message(FATAL_ERROR "build_flags FAILED")
endif()
message(STATUS "PASS: every one of ${_project} project translation units is compiled with -Wall -Wextra -Werror -fstack-protector-strong")
if(EXPECT_FORTIFY)
  message(STATUS "PASS: and with -D_FORTIFY_SOURCE=2 (not a sanitizer or fuzz tree)")
else()
  message(STATUS "PASS: and without _FORTIFY_SOURCE, as a sanitizer or fuzz tree must be")
endif()
message(STATUS "PASS: the project's own ${_n_arch} archives import __stack_chk_fail")
message(STATUS "All checks passed")
