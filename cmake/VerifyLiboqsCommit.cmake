# Enforces the liboqs commit pin (V2-2).
#
# liboqs is fetched by TAG (GIT_TAG 0.16.0, shallow) because CMake forbids a
# shallow clone of a bare commit hash ("If GIT_SHALLOW is enabled then
# GIT_TAG works only with branch names and tags. A commit hash is not
# allowed." -- ExternalProject.cmake). A tag is mutable, so the tag is only
# the fetch hint: THIS script is what pins the dependency to a commit.
#
# It runs in two places (see cmake/Dependencies.cmake):
#   1. as the FetchContent PATCH_COMMAND, at population time -- BEFORE
#      liboqs's own CMakeLists is ever processed, so a re-pointed or
#      replaced tag never reaches configuration;
#   2. again at every configure, after FetchContent_MakeAvailable, so a
#      hand-edited _deps/liboqs-src is caught too.
#
# Usage: cmake -DSOURCE_DIR=<liboqs source dir> -DEXPECTED_SHA=<40 hex> \
#              -P cmake/VerifyLiboqsCommit.cmake
# Exits nonzero (FATAL_ERROR) on any mismatch or if the SHA cannot be read.

if(NOT DEFINED SOURCE_DIR OR NOT DEFINED EXPECTED_SHA)
  message(FATAL_ERROR "VerifyLiboqsCommit.cmake: SOURCE_DIR and EXPECTED_SHA are required")
endif()
# NB: CMake's regex engine has no bounded-repetition operator ({40} is
# matched literally), so the length is checked separately.
string(LENGTH "${EXPECTED_SHA}" _sha_len)
if(NOT _sha_len EQUAL 40 OR NOT EXPECTED_SHA MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "VerifyLiboqsCommit.cmake: EXPECTED_SHA must be a full 40-hex-digit commit id, got '${EXPECTED_SHA}' (length ${_sha_len})")
endif()

find_package(Git QUIET)
if(NOT Git_FOUND)
  message(FATAL_ERROR "VerifyLiboqsCommit.cmake: git is required to verify the liboqs commit pin")
endif()

execute_process(
  COMMAND "${GIT_EXECUTABLE}" -C "${SOURCE_DIR}" rev-parse HEAD
  OUTPUT_VARIABLE _actual_sha
  ERROR_VARIABLE _git_err
  RESULT_VARIABLE _git_rc
)
string(STRIP "${_actual_sha}" _actual_sha)

if(NOT _git_rc EQUAL 0)
  message(FATAL_ERROR
    "liboqs commit pin: cannot read HEAD of '${SOURCE_DIR}' (git exit ${_git_rc}): ${_git_err}\n"
    "Refusing to build an unverified dependency.")
endif()

if(NOT _actual_sha STREQUAL EXPECTED_SHA)
  message(FATAL_ERROR
    "liboqs commit pin MISMATCH:\n"
    "  checked out: ${_actual_sha}\n"
    "  pinned:      ${EXPECTED_SHA}\n"
    "The liboqs tag no longer resolves to the pinned commit, or the source tree was modified. "
    "Refusing to build an unverified dependency (cmake/Dependencies.cmake).")
endif()

message(STATUS "liboqs commit verified: ${_actual_sha}")
