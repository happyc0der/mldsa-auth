# Where libsodium is unpacked, built and installed (V4-229, F315).
#
#   mldsa_sodium_dirs(<build dir> <TMPDIR or ""> <HOME or ""> <out build> <out prefix> <out error>)
#
# A function of its three inputs only, so tests/check_sodium_dirs.cmake can
# ask it about any host from any host.
#
# The archive installed here is linked into the daemon, so this directory is
# as trusted as the compiler. In order:
#
#   1. INSIDE THE BUILD TREE, whenever the tree's path has no whitespace.
#      Whoever can write there can already replace every object file.
#   2. Under TMPDIR, when the path has whitespace (libtool cannot build or
#      install under one) and the caller set TMPDIR. Named by a hash of the
#      build path, so two trees never share a directory. TMPDIR is then the
#      caller's choice and the caller's to keep private.
#   3. Under HOME/.cache/mldsa-auth, when TMPDIR is not set.
#   4. Refused otherwise.
#
# Never /tmp by default. It used to be: on a Linux host with no TMPDIR the
# prefix was /tmp/mldsa-auth-libsodium-1.0.22-<hash>-install for every tree,
# the runbook's included -- a name any local user can compute, in a directory
# any local user can create first, or re-create after /tmp is emptied, when
# the build's stamps still say libsodium is installed.
function(mldsa_sodium_dirs build_abs tmpdir home out_build out_prefix out_err)
  set(${out_err} "" PARENT_SCOPE)
  if(NOT build_abs MATCHES "[ \t\r\n]")
    set(${out_build} "${build_abs}/_deps/libsodium-1.0.22-build" PARENT_SCOPE)
    set(${out_prefix} "${build_abs}/_deps/libsodium-1.0.22-install" PARENT_SCOPE)
    return()
  endif()
  if(NOT tmpdir STREQUAL "")
    set(_root "${tmpdir}")
  elseif(NOT home STREQUAL "" AND NOT home MATCHES "[ \t\r\n]")
    set(_root "${home}/.cache/mldsa-auth")
  else()
    set(${out_build} "" PARENT_SCOPE)
    set(${out_prefix} "" PARENT_SCOPE)
    set(${out_err}
        "libsodium cannot be built under a path with whitespace (${build_abs}), and there is nowhere private to build it instead: TMPDIR is not set and HOME is unset or has whitespace too. Build in a directory whose path has no whitespace, or set TMPDIR to a directory only you can write to."
        PARENT_SCOPE)
    return()
  endif()
  string(MD5 _hash "${build_abs}")
  string(SUBSTRING "${_hash}" 0 10 _hash)
  set(${out_build} "${_root}/mldsa-auth-libsodium-1.0.22-${_hash}-build" PARENT_SCOPE)
  set(${out_prefix} "${_root}/mldsa-auth-libsodium-1.0.22-${_hash}-install" PARENT_SCOPE)
endfunction()
