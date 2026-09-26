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

# --- libFuzzer build (Step 7; separate build directory only) --------------
# Coverage-guided fuzz targets need a clang that ships the libFuzzer runtime
# (Apple Clang does not). Configure a SEPARATE build dir, e.g.
#   cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DMLDSA_FUZZ=ON
# The project's own libraries are then coverage-instrumented
# (fuzzer-no-link) and built with ASan + UBSan; the fuzz executables link
# the libFuzzer runtime (tests/fuzz/CMakeLists.txt).
option(MLDSA_FUZZ "Build libFuzzer targets (requires a libFuzzer-capable clang)" OFF)
if(MLDSA_FUZZ)
  include(CheckCSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
  set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
  check_c_source_compiles(
    "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n"
    MLDSA_HAVE_LIBFUZZER)
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LINK_OPTIONS)
  if(NOT MLDSA_HAVE_LIBFUZZER)
    message(FATAL_ERROR
      "MLDSA_FUZZ=ON requires a compiler with the libFuzzer runtime (-fsanitize=fuzzer must compile AND link). "
      "Apple Clang does not ship it; configure a separate build dir with e.g. "
      "-DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang")
  endif()
  list(APPEND MLDSA_SANITIZE_FLAGS -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined)
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

# --- Link-time hardening (V4-11, spec 16; audit finding F4) ---------------
# PIE, full RELRO and BIND_NOW, and a non-executable stack. Measured before
# this was added: a Linux Release build of the daemon already had PIE, partial
# RELRO, NX and canaries from the toolchain's own defaults -- the one property
# actually missing was BIND_NOW. The register said "no PIE/RELRO/BIND_NOW/
# noexecstack"; the binary said otherwise, and the binary is the authority
# (which is why tools/audit/check_hardening.sh reads ELF headers rather than
# build files).
#
# Every flag is PROBED, never assumed from the platform name. `-Wl,-z,...` is
# an ELF concept and Apple's ld rejects it outright ("ld: unknown options: -z"),
# so a guess of the form `if(APPLE)` would be both wrong in principle and
# fragile in practice -- a linker is a property of the toolchain, not of the
# operating system. A flag this toolchain will not take is simply absent, and
# check_hardening.sh then reports the property as `n/a` (Mach-O) rather than
# as a failure.
#
# NOTE for anyone reading a green `--require` on macOS: RELRO and BIND_NOW have
# no Mach-O equivalent, so that run proves three properties out of five. The
# gate that matters runs on Linux, in CI, against the install tree.
include(CheckLinkerFlag)
include(CheckPIESupported)

set(MLDSA_HARDENING_LINK_FLAGS "")
foreach(_mldsa_lflag "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack")
  string(MAKE_C_IDENTIFIER "MLDSA_HAVE${_mldsa_lflag}" _mldsa_lvar)
  check_linker_flag(C "${_mldsa_lflag}" ${_mldsa_lvar})
  if(${_mldsa_lvar})
    list(APPEND MLDSA_HARDENING_LINK_FLAGS "${_mldsa_lflag}")
  endif()
endforeach()

# PIE via CMake's own support check, which knows how to ask each toolchain and
# sets -fPIE/-pie correctly for executables (policy CMP0083).
check_pie_supported(OUTPUT_VARIABLE _mldsa_pie_why LANGUAGES C)
if(CMAKE_C_LINK_PIE_SUPPORTED)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
else()
  message(STATUS "PIE not supported by this toolchain: ${_mldsa_pie_why}")
endif()

# _FORTIFY_SOURCE is skipped under ASan/UBSan builds: Apple Clang (and GCC)
# auto-define _FORTIFY_SOURCE=0 whenever -fsanitize=address is active
# (fortification needs optimization the sanitizer build forgoes, and the two
# checks overlap), so our own -D_FORTIFY_SOURCE=2 collides with the
# compiler's own definition under -Werror,-Wmacro-redefined. Verified with a
# real -DENABLE_ASAN=ON build, not assumed.
set(MLDSA_HARDENING_DEFS "")
if(NOT ENABLE_ASAN AND NOT ENABLE_UBSAN AND NOT MLDSA_FUZZ)
  list(APPEND MLDSA_HARDENING_DEFS _FORTIFY_SOURCE=2)
endif()

# --- liboqs optimisation target (Security Req 4.10) -----------------------
# The algorithm backend is selected at COMPILE time (OQS_DIST_BUILD=OFF in
# cmake/Dependencies.cmake), so this choice is baked into the binary:
#   auto     tune for THIS machine's CPU (-mcpu=native / -march=native).
#            Fast, and NOT portable -- the binary may crash with an illegal
#            instruction on an older CPU of the same family.
#   generic  portable baseline (-march=armv8-a+crypto / -march=x86-64).
#            Use this for anything you distribute; on x86_64 it gives up
#            liboqs's AVX2 backends.
#   <cpu>    any CPU name your compiler accepts, passed through verbatim.
set(MLDSA_OQS_OPT_TARGET "auto" CACHE STRING
    "liboqs optimisation target: auto (this CPU, not portable), generic (portable), or a CPU name")
set_property(CACHE MLDSA_OQS_OPT_TARGET PROPERTY STRINGS auto generic)

# --- WebAssembly (V4-13b) --------------------------------------------------
# `emcmake cmake -S . -B build-wasm` builds the CLIENT only -- the core, the key
# formats, the WebSocket framing and client_core -- plus the tests that prove
# the wasm build computes what the native one does. No daemon, no store, no
# sqlite: a browser runs none of them.
#
# The Emscripten version is PINNED and checked, not assumed: the wasm build's
# claim is that it reproduces the native KAT byte-for-byte, and a compiler that
# moves under that claim moves the claim. 6.0.9 is what emsdk installs in CI
# (release f04ea239d533260dd1db760dd2d668d5f9a88d6b) and what V4-13b was built
# with. Change it deliberately, with the KAT re-run, or not at all.
if(EMSCRIPTEN)
  set(MLDSA_EMSCRIPTEN_VERSION "6.0.9")
  if(NOT EMSCRIPTEN_VERSION STREQUAL MLDSA_EMSCRIPTEN_VERSION)
    message(FATAL_ERROR
      "Emscripten ${EMSCRIPTEN_VERSION} found, ${MLDSA_EMSCRIPTEN_VERSION} required "
      "(MLDSA_EMSCRIPTEN_VERSION): the wasm build's KAT golden is only a contract "
      "for the compiler it was checked against")
  endif()
  if(ENABLE_ASAN OR ENABLE_UBSAN OR MLDSA_FUZZ)
    message(FATAL_ERROR "sanitizers and fuzzing are native-only; configure a separate native tree")
  endif()
  # wasm has no CPU to tune for: liboqs's portable C, as V4-2 S6 proved.
  set(MLDSA_OQS_OPT_TARGET "generic" CACHE STRING "" FORCE)
  # The one flag V4-2 S6 found indispensable: the 64 KiB default stack faults
  # at once on 4 KB keys and a ~3.9 KB handshake context.
  set(MLDSA_WASM_LINK_FLAGS -sSTACK_SIZE=8MB -sALLOW_MEMORY_GROWTH=1)
  # The link-hardening probe above PASSES under emcc -- wasm-ld only warns on
  # an unknown -z value -- so RELRO/BIND_NOW/noexecstack would reach every wasm
  # link as noise. They are ELF properties; a wasm module has none of them.
  set(MLDSA_HARDENING_LINK_FLAGS "")
  message(STATUS "WebAssembly build: Emscripten ${EMSCRIPTEN_VERSION} (pinned), client only")
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
if(NOT EMSCRIPTEN)
  add_subdirectory(bench)
else()
  add_subdirectory(web)
endif()
