# Pinned third-party dependencies.
#
# Per spec Section 3: "Pin exact dependency versions in the build config;
# do not float on main/latest branches." Both libraries are fetched from
# their upstream sources rather than resolved via find_package() against
# whatever happens to be installed on the host, so a clean checkout on any
# machine builds identical bits. Both pins are exact, and neither relies on
# a mutable ref: liboqs is verified against a commit SHA (below), libsodium
# against the SHA-256 of its release tarball.

include(FetchContent)

# --- liboqs 0.16.0 ----------------------------------------------------------
# GIT_TAG confirmed literal (no "v" prefix) against the upstream release page:
# https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
#
# THE PIN IS THE COMMIT; THE TAG IS ONLY THE FETCH HINT (V2-2).
# A git tag is mutable, so fetching "0.16.0" is not by itself a pin. The
# commit below is what this project is pinned to, and it is ENFORCED twice
# by cmake/VerifyLiboqsCommit.cmake (see that file for the full rationale):
#   1. as the PATCH_COMMAND, at population time, BEFORE liboqs's own
#      CMakeLists is processed;
#   2. again at configure time below, so a hand-edited _deps/liboqs-src is
#      also caught.
# Either check fails the configure with a FATAL_ERROR naming both hashes.
#
# The tag is kept as the fetch mechanism because CMake forbids a shallow
# clone of a bare commit: "If GIT_SHALLOW is enabled then GIT_TAG works only
# with branch names and tags. A commit hash is not allowed."
# (ExternalProject.cmake). Setting GIT_TAG to the SHA would force a
# full-history clone -- well above the ~160 MB shallow .git -- in every
# build directory, for no gain the verification below does not already give.
set(MLDSA_LIBOQS_COMMIT "5a1a854b0dc9f2141bdc771c555ee60c37950183")  # "0.16.0 release (#2491)", 2026-07-09

# OQS_MINIMAL_BUILD scopes the build to exactly one signature algorithm and
# one KEM (spec-v2 Section 3): ML-DSA-65 for identity, ML-KEM-768 for the
# hybrid key exchange. Everything else in liboqs stays out of the archive,
# keeping the algorithm surface -- and thus attack surface -- to what v2 uses.
set(OQS_MINIMAL_BUILD "SIG_ml_dsa_65;KEM_ml_kem_768" CACHE STRING "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# Security Req 4.10 / spec-v2 Section 3: the algorithm backend is chosen at
# COMPILE time, not by a CPU-feature branch on every sign/verify/encaps call.
#
# OQS_DIST_BUILD=ON (liboqs's default) compiles every backend and dispatches
# at run time via OQS_CPU_has_extension(). OFF makes the choice a #if in
# liboqs's own sig_ml_dsa_65.c / kem_ml_kem_768.c, so nothing references the
# portable-C entry points and the linker never pulls them into a binary.
# (liboqs still COMPILES the reference objects into the static archive
# unconditionally; "one backend" is a property of what gets linked, which is
# what the V2-2 verification measures.)
#
# MLDSA_OQS_OPT_TARGET (top-level CMakeLists) selects the target: "auto"
# tunes for the building machine's CPU and is NOT portable; "generic" is the
# portable baseline and is what distributable binaries must use.
set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
set(OQS_OPT_TARGET "${MLDSA_OQS_OPT_TARGET}" CACHE STRING "" FORCE)

# --- offline builds (V4-11, audit finding F12) ----------------------------
# MLDSA_DEPS_CACHE names a directory holding the three dependencies, populated
# once on a networked machine by deploy/fetch-deps.sh. It exists so a VPS can
# be built on without trusting the network at deploy time, and so a rebuild is
# reproducible from something you kept rather than from something a server
# still serves.
#
# EVERY PIN STAYS ENFORCED, and the shape of each source is chosen for that:
#
#   liboqs     a local CLONE used as GIT_REPOSITORY, not
#              FETCHCONTENT_SOURCE_DIR_LIBOQS. The override is the obvious
#              route and it is the wrong one: CMake's design makes it bypass
#              the population-time PATCH_COMMAND, so the commit would be
#              verified once instead of twice. V2-10's retrospective already
#              had to record that asymmetry; cloning from a local path keeps
#              both checks, because FetchContent clones from a path exactly as
#              it clones from a URL.
#   libsodium  the tarball, with URL pointed at the file. ExternalProject
#              checks URL_HASH for a local file exactly as for a remote one.
#   sqlite     the zip, likewise.
#
# So an offline build is not a weaker build -- which is the whole point, and
# the reason deploy/fetch-deps.sh verifies each artefact as it writes it and
# tests/offline_build.sh proves, in a container with the network switched off,
# that each way the cache could be wrong is refused: unreadable, one byte
# changed, or moved off the pinned commit.
set(MLDSA_DEPS_CACHE "" CACHE PATH
    "Directory of pre-fetched dependencies for an offline build (see deploy/fetch-deps.sh)")

set(_mldsa_oqs_repo "https://github.com/open-quantum-safe/liboqs.git")
if(MLDSA_DEPS_CACHE AND EXISTS "${MLDSA_DEPS_CACHE}/liboqs.git")
  set(_mldsa_oqs_repo "${MLDSA_DEPS_CACHE}/liboqs.git")
  message(STATUS "liboqs from the offline cache: ${_mldsa_oqs_repo}")

  # Prove the cached clone is usable BEFORE FetchContent tries it. Found by
  # the V4-11 container proof: a cache populated by one user and built by
  # another trips git's safe.directory rule, and the failure surfaces three
  # layers down as "Failed to clone repository" inside a generated
  # subbuild script -- with the actual cause (`detected dubious ownership`)
  # buried in a log nobody reads. Reading the pinned commit out of the cache
  # here is one command, and it answers both questions at once: whether git
  # will talk to this directory at all, and whether it holds the commit this
  # build is pinned to.
  #
  # This does not REPLACE either pin check. Both still run: the PATCH_COMMAND
  # at population time and the re-check after FetchContent_MakeAvailable
  # below, each against the populated tree rather than against the cache. An
  # offline build is checked three times, an online one twice.
  find_package(Git QUIET REQUIRED)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${_mldsa_oqs_repo}" rev-parse HEAD
    OUTPUT_VARIABLE _mldsa_cache_head
    ERROR_VARIABLE _mldsa_cache_err
    RESULT_VARIABLE _mldsa_cache_rc
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _mldsa_cache_rc EQUAL 0)
    string(STRIP "${_mldsa_cache_err}" _mldsa_cache_err)
    if(_mldsa_cache_err MATCHES "dubious ownership")
      message(FATAL_ERROR
        "the cached liboqs clone at ${_mldsa_oqs_repo} is not owned by the "
        "user running this build, so git refuses to read it:\n"
        "  ${_mldsa_cache_err}\n"
        "Fix the ownership rather than the exception -- the cache is a build "
        "input and should belong to whoever builds:\n"
        "  chown -R \"$(id -un)\" ${MLDSA_DEPS_CACHE}\n"
        "(see deploy/RUNBOOK.md, offline build)")
    endif()
    message(FATAL_ERROR
      "the cached liboqs clone at ${_mldsa_oqs_repo} is unusable:\n"
      "  ${_mldsa_cache_err}\n"
      "Re-populate it with deploy/fetch-deps.sh on a networked machine.")
  endif()
  if(NOT _mldsa_cache_head STREQUAL MLDSA_LIBOQS_COMMIT)
    message(FATAL_ERROR
      "the cached liboqs clone is at ${_mldsa_cache_head}, pinned commit is "
      "${MLDSA_LIBOQS_COMMIT}: refusing to build from an unverified cache. "
      "Re-populate it with deploy/fetch-deps.sh.")
  endif()
  message(STATUS "liboqs cache holds the pinned commit: ${_mldsa_cache_head}")
endif()

FetchContent_Declare(
  liboqs
  GIT_REPOSITORY ${_mldsa_oqs_repo}
  GIT_TAG        0.16.0
  GIT_SHALLOW    TRUE
  PATCH_COMMAND  ${CMAKE_COMMAND}
                   -DSOURCE_DIR=<SOURCE_DIR>
                   -DEXPECTED_SHA=${MLDSA_LIBOQS_COMMIT}
                   -P ${CMAKE_CURRENT_LIST_DIR}/VerifyLiboqsCommit.cmake
)
FetchContent_MakeAvailable(liboqs)
# Provides the `oqs` static library target.

# Check 2: re-verify on EVERY configure, not only on population. The
# PATCH_COMMAND runs once, when the source is first fetched; this catches a
# tree that was modified, re-checked-out or swapped afterwards. The script
# reads SOURCE_DIR/EXPECTED_SHA from the calling scope, so they are set and
# then unset around the include to avoid leaking two very generic names.
set(SOURCE_DIR "${liboqs_SOURCE_DIR}")
set(EXPECTED_SHA "${MLDSA_LIBOQS_COMMIT}")
include(${CMAKE_CURRENT_LIST_DIR}/VerifyLiboqsCommit.cmake)
unset(SOURCE_DIR)
unset(EXPECTED_SHA)

# --- libsodium 1.0.22 --------------------------------------------------------
# libsodium's maintained build path is Autotools, not CMake, so it is built
# out-of-band via ExternalProject_Add wrapping `./configure && make` and
# imported as a static library, rather than attempting a CMake port.
#
# Fetched from the maintainer's release *distribution tarball* (not a raw
# git/GitHub source archive) because that tarball ships a pre-generated
# `configure` script, avoiding an autoreconf/automake/libtool dependency on
# the build host entirely. URL_HASH pins the exact artifact bit-for-bit
# (byte-exact, stronger than a commit pin alone), on top of the version
# pin, per Section 3.
#
# Resolved commit for audit purposes: the `1.0.22-RELEASE` tag is a
# PGP-signed annotated tag (tag object bc5892beb87c388e123baa7c8f4862f30d9206a7)
# pointing to commit:
#   77e1ce5d6dee871c49ef211222ba18ef0c486bda
# (resolved via the GitHub API against jedisct1/libsodium, since this
# dependency is fetched as a tarball, not a git clone, so no local .git
# metadata exists to read the commit from directly). The URL_HASH above
# is the actual pin this build enforces; this comment is traceability
# for that tarball back to source history.
include(ExternalProject)

# libsodium is built via Autotools/libtool, which has a real, unpatchable bug
# handling paths that contain spaces: both its `configure` prelude check and
# `libtool --mode=install`'s own argument quoting break if any path involved
# — source dir, build dir, or --prefix — contains whitespace.
#
# STANDING CONSTRAINT: this project's own path must never contain spaces
# (CMAKE_BINARY_DIR included) — e.g. don't build under a directory named
# "PQ Authentication protocol". This isn't a one-off issue Step 1 patched
# around; it's an Autotools/libtool limitation that will resurface for any
# future Autotools-based dependency, not just libsodium.
#
# Workaround for *this* dependency: libsodium's source, build, AND install
# locations are placed under the system temp dir instead of CMAKE_BINARY_DIR
# (only libsodium needs this — liboqs's build is pure CMake and unaffected).
# The subdirectory name is suffixed with a hash of this build tree's own
# path so concurrent builds from different build directories (e.g. `build/`
# and `build-asan/`, or parallel CI workers) never share — and race on — the
# same libsodium build/install tree.
if(DEFINED ENV{TMPDIR})
  set(_mldsa_tmp "$ENV{TMPDIR}")
else()
  set(_mldsa_tmp "/tmp")
endif()
get_filename_component(_mldsa_build_abs "${CMAKE_BINARY_DIR}" ABSOLUTE)
string(MD5 _mldsa_build_hash "${_mldsa_build_abs}")
string(SUBSTRING "${_mldsa_build_hash}" 0 10 _mldsa_build_hash)
set(LIBSODIUM_BUILD_DIR "${_mldsa_tmp}/mldsa-auth-libsodium-1.0.22-${_mldsa_build_hash}-build")
set(LIBSODIUM_PREFIX "${_mldsa_tmp}/mldsa-auth-libsodium-1.0.22-${_mldsa_build_hash}-install")
set(LIBSODIUM_INCLUDE_DIR ${LIBSODIUM_PREFIX}/include)
set(LIBSODIUM_LIBRARY ${LIBSODIUM_PREFIX}/lib/libsodium.a)

set(_mldsa_sodium_url
    "https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz")
if(MLDSA_DEPS_CACHE AND EXISTS "${MLDSA_DEPS_CACHE}/libsodium-1.0.22.tar.gz")
  set(_mldsa_sodium_url "${MLDSA_DEPS_CACHE}/libsodium-1.0.22.tar.gz")
  message(STATUS "libsodium from the offline cache: ${_mldsa_sodium_url}")
endif()

# Native: ./configure && make. WebAssembly (V4-13b): the SAME tarball, the
# same hash, through Emscripten's wrappers, with the three options libsodium's
# own dist-build/emscripten.sh passes -- no stack protector (wasm has no
# guard-page canary support in libsodium's build), no assembly, no pthreads.
# libsodium detects Emscripten itself and draws randomness from the host's
# crypto.getRandomValues, which is the only generator a browser offers.
if(EMSCRIPTEN)
  set(_mldsa_sodium_configure emconfigure <SOURCE_DIR>/configure
      --prefix=${LIBSODIUM_PREFIX} --disable-shared --enable-static
      --disable-ssp --disable-asm --without-pthreads)
  set(_mldsa_sodium_make emmake make)
else()
  set(_mldsa_sodium_configure <SOURCE_DIR>/configure
      --prefix=${LIBSODIUM_PREFIX} --disable-shared --enable-static)
  set(_mldsa_sodium_make make)
endif()

ExternalProject_Add(
  libsodium_ext
  URL               ${_mldsa_sodium_url}
  URL_HASH          SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_DIR        ${LIBSODIUM_BUILD_DIR}
  UPDATE_COMMAND    ""
  CONFIGURE_COMMAND ${_mldsa_sodium_configure}
  BUILD_COMMAND     ${_mldsa_sodium_make} -j
  INSTALL_COMMAND   ${_mldsa_sodium_make} install
  BUILD_IN_SOURCE   TRUE
  BUILD_BYPRODUCTS  ${LIBSODIUM_LIBRARY}
)

file(MAKE_DIRECTORY ${LIBSODIUM_INCLUDE_DIR})

add_library(sodium STATIC IMPORTED GLOBAL)
set_target_properties(sodium PROPERTIES
  IMPORTED_LOCATION ${LIBSODIUM_LIBRARY}
  INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_INCLUDE_DIR}
)
add_dependencies(sodium libsodium_ext)

if(EMSCRIPTEN)
  # The store is the daemon's; a browser build has no use for sqlite.
  return()
endif()

# --- SQLite 3.53.4 (amalgamation) --------------------------------------------
# The daemon's store (V4-7). Pinned like the other dependencies: the exact
# amalgamation artifact is verified bit-for-bit by its published SHA3-256
# (sqlite.org's PRODUCT line: 2026/sqlite-amalgamation-3530400.zip, 2946650 B).
# URL_HASH runs the check at population time, before any of the source is used,
# so a substituted archive never reaches the compiler. The amalgamation is a
# single C file with no build system of its own -- no Autotools, so the
# path-with-spaces libtool bug that forces libsodium out to $TMPDIR does not
# apply here; it builds straight in the build tree as pure CMake.
set(MLDSA_SQLITE_SHA3 628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e)
set(_mldsa_sqlite_url "https://sqlite.org/2026/sqlite-amalgamation-3530400.zip")
if(MLDSA_DEPS_CACHE AND EXISTS "${MLDSA_DEPS_CACHE}/sqlite-amalgamation-3530400.zip")
  set(_mldsa_sqlite_url "${MLDSA_DEPS_CACHE}/sqlite-amalgamation-3530400.zip")
  message(STATUS "sqlite from the offline cache: ${_mldsa_sqlite_url}")
endif()

FetchContent_Declare(
  sqlite3_amalg
  URL      ${_mldsa_sqlite_url}
  URL_HASH SHA3_256=${MLDSA_SQLITE_SHA3}
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3_amalg)

# The zip carries a single top-level directory; find sqlite3.c/.h beneath the
# populated source dir rather than hardcoding the versioned folder name, so a
# future version bump touches only the URL and the hash above.
file(GLOB_RECURSE _mldsa_sqlite_c   "${sqlite3_amalg_SOURCE_DIR}/*/sqlite3.c" "${sqlite3_amalg_SOURCE_DIR}/sqlite3.c")
file(GLOB_RECURSE _mldsa_sqlite_hdr "${sqlite3_amalg_SOURCE_DIR}/*/sqlite3.h" "${sqlite3_amalg_SOURCE_DIR}/sqlite3.h")
list(GET _mldsa_sqlite_c 0 MLDSA_SQLITE_C)
list(GET _mldsa_sqlite_hdr 0 MLDSA_SQLITE_H)
get_filename_component(MLDSA_SQLITE_INCLUDE_DIR "${MLDSA_SQLITE_H}" DIRECTORY)
if(NOT MLDSA_SQLITE_C OR NOT EXISTS "${MLDSA_SQLITE_C}")
  message(FATAL_ERROR "sqlite3.c not found under ${sqlite3_amalg_SOURCE_DIR}")
endif()

# Build options (spec 9): no threading (the daemon is single event loop),
# no extension loading (no dlopen surface), no double-quoted string literals
# (DQS=0 makes a mistyped identifier an error, not a silent string), foreign
# keys on by default. Third-party code, so the project's -Wall -Wextra -Werror
# is NOT applied: it is compiled with warnings off and its own hardening only.
add_library(sqlite3 STATIC "${MLDSA_SQLITE_C}")
target_include_directories(sqlite3 PUBLIC "${MLDSA_SQLITE_INCLUDE_DIR}")
target_compile_definitions(sqlite3 PRIVATE
  SQLITE_THREADSAFE=0
  SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_DQS=0
  SQLITE_DEFAULT_MEMSTATUS=0
  SQLITE_DEFAULT_FOREIGN_KEYS=1
)
target_compile_options(sqlite3 PRIVATE -w)
set_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)
