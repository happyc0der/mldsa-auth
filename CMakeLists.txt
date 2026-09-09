cmake_minimum_required(VERSION 3.20)
project(mldsa-auth C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# --- Sanitizer toggles (used starting Step 4, scaffolded now) -------------
# Collected into a variable rather than applied globally via
# add_compile_options()/add_link_options(), for the same reason as the
# hardening flags below — only this project's own targets should be
# compiled/linked with sanitizer instrumentation, not the vendored
# liboqs/libsodium builds.
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)

set(MLDSA_SANITIZE_FLAGS "")
if(ENABLE_ASAN)
  list(APPEND MLDSA_SANITIZE_FLAGS -fsanitize=address)
endif()
if(ENABLE_UBSAN)
  list(APPEND MLDSA_SANITIZE_FLAGS -fsanitize=undefined)
endif()

# --- Build hardening (Security Requirement 4.8) ---------------------------
# Applied to this project's own targets only (src/, apps/, tests/) via
# MLDSA_HARDENING_FLAGS/MLDSA_HARDENING_DEFS below — NOT injected globally
# via add_compile_options(), because that would also apply to vendored
# third-party sources pulled in via add_subdirectory() (liboqs through
# FetchContent, notably) and hold code we don't own to warning-as-error
# standards it wasn't written against.
set(MLDSA_HARDENING_FLAGS
  -Wall
  -Wextra
  -Werror
  -fstack-protector-strong
)

# _FORTIFY_SOURCE is skipped under ASan/UBSan builds: Apple Clang (and GCC)
# auto-define _FORTIFY_SOURCE=0 whenever -fsanitize=address is active
# (fortification needs optimization the sanitizer build forgoes, and the two
# checks overlap), so our own -D_FORTIFY_SOURCE=2 collides with the
# compiler's own definition under -Werror,-Wmacro-redefined. Verified with a
# real -DENABLE_ASAN=ON build, not assumed.
set(MLDSA_HARDENING_DEFS "")
if(NOT ENABLE_ASAN AND NOT ENABLE_UBSAN)
  list(APPEND MLDSA_HARDENING_DEFS _FORTIFY_SOURCE=2)
endif()

# --- Dependencies (pinned versions; see cmake/Dependencies.cmake) ---------
include(cmake/Dependencies.cmake)

# --- Test discovery ---------------------------------------------------------
# Declared at the top level (not only in tests/CMakeLists.txt) so `ctest`
# can discover tests from the repo root once Step 2 adds them.
enable_testing()

add_subdirectory(src)
add_subdirectory(apps)
add_subdirectory(tests)
