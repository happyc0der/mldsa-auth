# Pinned third-party dependencies.
#
# Per spec Section 3: "Pin exact dependency versions in the build config;
# do not float on main/latest branches." Both libraries are fetched from
# their upstream source repos at fixed tags rather than resolved via
# find_package() against whatever happens to be installed on the host, so a
# clean checkout on any machine builds identical bits.

include(FetchContent)

# --- liboqs 0.16.0 ----------------------------------------------------------
# GIT_TAG confirmed literal (no "v" prefix) against the upstream release page:
# https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
#
# Resolved commit for audit purposes (tag 0.16.0 is a lightweight tag, so
# this *is* the exact commit GIT_TAG resolves to -- confirmed by reading
# `git rev-parse HEAD` inside the actually-fetched build/_deps/liboqs-src):
#   5a1a854b0dc9f2141bdc771c555ee60c37950183
#   "0.16.0 release (#2491)", 2026-07-09
# This comment records the resolved revision for auditability; it does not
# itself pin the build (GIT_TAG below is still what CMake resolves against
# on every fetch). See Step 3 checkpoint notes for whether tag-to-commit
# pinning should be enforced directly in CMake (GIT_TAG set to the SHA
# instead of the tag name) -- deliberately NOT done here without a
# separate, explicit decision, since GIT_TAG values are still the tags
# approved during Step 1.
#
# OQS_MINIMAL_BUILD scopes the build to exactly one signature algorithm
# (ML-DSA-65), per spec Section 3 / Section 10 decision (hybrid ML-KEM-768
# KEX deferred to v2 — no KEM algorithms are built in v1).
set(OQS_MINIMAL_BUILD "SIG_ml_dsa_65" CACHE STRING "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  liboqs
  GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
  GIT_TAG        0.16.0
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(liboqs)
# Provides the `oqs` static library target.

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
