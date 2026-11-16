# Where libsodium is built (V4-229, F315): cmake -DREPO=<repo> -P this file.
#
# libsodium's archive is linked into the daemon, so the directory it is
# installed to is as trusted as the compiler. It used to be
# /tmp/mldsa-auth-libsodium-1.0.22-<hash of the build path>-install on a
# Linux host with no TMPDIR: a name any local user can compute, in a
# directory any local user can create first or re-create after /tmp is
# emptied, and the build stamps then said the archive was already there.
include("${REPO}/cmake/SodiumDirs.cmake")
set(_fail 0)
macro(check cond text)
  if(${cond})
    message(STATUS "PASS: sodium-dirs: ${text}")
  else()
    message(STATUS "FAIL: sodium-dirs: ${text}")
    set(_fail 1)
  endif()
endmacro()

# The runbook's build, on Linux, with no TMPDIR in the environment.
mldsa_sodium_dirs("/opt/build/mldsa-auth/build-release" "" "/root" b p e)
string(FIND "${p}" "/opt/build/mldsa-auth/build-release/" at_p)
string(FIND "${b}" "/opt/build/mldsa-auth/build-release/" at_b)
set(inside FALSE)
if(at_p EQUAL 0 AND at_b EQUAL 0 AND e STREQUAL "")
  set(inside TRUE)
endif()
check(inside "a build tree whose path has no whitespace keeps libsodium inside itself (${p})")

# The same tree with TMPDIR set: still inside. TMPDIR is for the case below.
mldsa_sodium_dirs("/opt/build/mldsa-auth/build-release" "/tmp" "/root" b2 p2 e2)
set(same FALSE)
if(p2 STREQUAL p AND b2 STREQUAL b)
  set(same TRUE)
endif()
check(same "TMPDIR does not move it out of such a tree (${p2})")

# libtool cannot build under a path with whitespace. Then TMPDIR, as before.
mldsa_sodium_dirs("/Users/a/PQ Authentication protocol/build" "/Users/a/.cache/t" "/Users/a" b3 p3 e3)
string(FIND "${p3}" "/Users/a/.cache/t/mldsa-auth-libsodium-1.0.22-" at3)
set(tmp_ok FALSE)
if(at3 EQUAL 0 AND e3 STREQUAL "" AND NOT p3 MATCHES "[ \t]" AND NOT b3 MATCHES "[ \t]")
  set(tmp_ok TRUE)
endif()
check(tmp_ok "a tree under a path with whitespace builds it under TMPDIR (${p3})")

# Two such trees never share one.
mldsa_sodium_dirs("/Users/a/PQ Authentication protocol/build-asan" "/Users/a/.cache/t" "/Users/a" b4 p4 e4)
set(apart FALSE)
if(NOT p4 STREQUAL p3 AND NOT b4 STREQUAL b3)
  set(apart TRUE)
endif()
check(apart "two such trees get two directories")

# Whitespace and no TMPDIR: the user's own cache, never /tmp.
mldsa_sodium_dirs("/home/a/my tree/build" "" "/home/a" b5 p5 e5)
string(FIND "${p5}" "/home/a/.cache/mldsa-auth/" at5)
set(home_ok FALSE)
if(at5 EQUAL 0 AND e5 STREQUAL "" AND NOT p5 MATCHES "^/tmp/")
  set(home_ok TRUE)
endif()
check(home_ok "with whitespace and no TMPDIR it goes under the user's own cache, not /tmp (${p5})")

# Whitespace, no TMPDIR, no usable HOME: refused, with the two ways out named.
mldsa_sodium_dirs("/srv/my tree/build" "" "" b6 p6 e6)
set(refused FALSE)
if(NOT e6 STREQUAL "" AND e6 MATCHES "TMPDIR" AND e6 MATCHES "whitespace")
  set(refused TRUE)
endif()
check(refused "with whitespace, no TMPDIR and no HOME the configure is refused (${e6})")
mldsa_sodium_dirs("/srv/my tree/build" "" "/home/first last" b7 p7 e7)
set(refused2 FALSE)
if(NOT e7 STREQUAL "")
  set(refused2 TRUE)
endif()
check(refused2 "a HOME with whitespace is no way out either")

if(_fail)
  message(FATAL_ERROR "FAIL: sodium-dirs")
endif()
message(STATUS "PASS: sodium-dirs: all checks")
