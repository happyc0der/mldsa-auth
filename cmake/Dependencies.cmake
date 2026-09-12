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

FetchContent_Declare(
  liboqs
  GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
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

ExternalProject_Add(
  libsodium_ext
  URL               https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz
  URL_HASH          SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_DIR        ${LIBSODIUM_BUILD_DIR}
  UPDATE_COMMAND    ""
  CONFIGURE_COMMAND <SOURCE_DIR>/configure
                     --prefix=${LIBSODIUM_PREFIX}
                     --disable-shared
                     --enable-static
  BUILD_COMMAND     make -j
  INSTALL_COMMAND   make install
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
