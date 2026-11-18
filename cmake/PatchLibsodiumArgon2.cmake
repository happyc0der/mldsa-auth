# V4-305 (F531, F512): libsodium 1.0.22 frees Argon2id's working memory
# without clearing it -- ARGON2_DEFAULT_FLAGS is 0, so clear_memory() never
# runs -- and the envelope key can be recomputed from its last block: in the
# daemon for the second of the unseal (F512), in the browser module's heap,
# which never shrinks, for the page's lifetime (F531). This sets the default
# to ARGON2_FLAG_CLEAR_MEMORY, which libsodium's own code honours
# (argon2-core.c, free_instance). Run by ExternalProject's PATCH_COMMAND, in
# the extracted source, after URL_HASH has verified the archive. It refuses if
# the line it replaces is not there exactly once, so a libsodium bump that
# moves it fails the build rather than ship unpatched.
#
#   cmake -DSOURCE_DIR=<libsodium source> -P PatchLibsodiumArgon2.cmake
set(_f "${SOURCE_DIR}/src/libsodium/crypto_pwhash/argon2/argon2.h")
if(NOT EXISTS "${_f}")
  message(FATAL_ERROR "libsodium patch: ${_f} not found")
endif()
file(READ "${_f}" _s)
set(_old "#define ARGON2_DEFAULT_FLAGS (UINT32_C(0))")
set(_new "#define ARGON2_DEFAULT_FLAGS (ARGON2_FLAG_CLEAR_MEMORY) /* mldsa-auth V4-305, F531 */")
string(FIND "${_s}" "${_new}" _done)
if(NOT _done EQUAL -1)
  return()                       # already patched (a re-run of the step)
endif()
string(FIND "${_s}" "${_old}" _at)
if(_at EQUAL -1)
  message(FATAL_ERROR "libsodium patch: the ARGON2_DEFAULT_FLAGS line is not where V4-305 expects it in ${_f}")
endif()
string(REPLACE "${_old}" "${_new}" _s "${_s}")
file(WRITE "${_f}" "${_s}")
message(STATUS "libsodium: Argon2 clears its working memory (V4-305)")
