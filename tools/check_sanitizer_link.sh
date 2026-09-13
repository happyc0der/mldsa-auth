#!/bin/bash
# Proves a build directory is ACTUALLY instrumented before its results are
# trusted (V2-4 hardening).
#
#   check_sanitizer_link.sh <build-dir> asan|ubsan
#
# Why this exists: V2-4's "fresh ASan/UBSan" trees were configured with
# -DMLDSA_SANITIZE=address. This project's options are ENABLE_ASAN /
# ENABLE_UBSAN. CMake accepts an unknown -D variable silently, so both trees
# were plain Debug builds and the sanitizer verification they produced was
# worthless. Nothing in the build output said so; only the linked binary
# does. Every executable is discovered, never enumerated.
set -u
BUILD="${1:?usage: check_sanitizer_link.sh <build-dir> asan|ubsan}"
KIND="${2:?usage: check_sanitizer_link.sh <build-dir> asan|ubsan}"

case "$KIND" in
  asan)  CACHE_VAR="ENABLE_ASAN" ;;
  ubsan) CACHE_VAR="ENABLE_UBSAN" ;;
  *) echo "FAIL: kind must be asan or ubsan"; exit 2 ;;
esac

# 1. the option must actually be ON in the cache (catches a typo'd -D flag,
#    which leaves the real option at its OFF default)
if ! grep -qE "^${CACHE_VAR}:BOOL=(ON|TRUE|1|YES)$" "$BUILD/CMakeCache.txt" 2>/dev/null; then
  echo "FAIL: $CACHE_VAR is not ON in $BUILD/CMakeCache.txt"
  grep -iE "^(ENABLE_ASAN|ENABLE_UBSAN|MLDSA_SANITIZE)" "$BUILD/CMakeCache.txt" 2>/dev/null | sed 's/^/      cache: /'
  exit 1
fi

# 2. every project executable must carry the instrumentation
# CMake's own compiler-probe binaries (CMakeFiles/<ver>/CompilerIdC/a.out,
# CMakeDetermineCompilerABI_C.bin) are built during configure, before any
# project flags apply, and are never instrumented. They are toolchain
# scratch, not project output, so they are excluded -- by path, so a real
# project binary can never be skipped by accident.
bins=$(find "$BUILD" -path "$BUILD/_deps" -prune -o -path '*/CMakeFiles/*' -prune -o \
         -type f -perm -u+x -print 2>/dev/null |
  while IFS= read -r f; do
    case "$(file -b "$f" 2>/dev/null)" in (*Mach-O*executable*) echo "$f" ;; esac
  done | sort)
[ -n "$bins" ] || { echo "FAIL: no Mach-O executables found under $BUILD (nothing was checked)"; exit 1; }

n=0; bad=0
while IFS= read -r b; do
  n=$((n + 1))
  case "$KIND" in
    asan)  otool -L "$b" 2>/dev/null | grep -q "libclang_rt.asan" ||
             nm -u "$b" 2>/dev/null | grep -q "__asan_" || { echo "  NOT INSTRUMENTED: $b"; bad=1; } ;;
    ubsan) [ "$(nm "$b" 2>/dev/null | grep -c '__ubsan')" -gt 0 ] || { echo "  NOT INSTRUMENTED: $b"; bad=1; } ;;
  esac
done <<< "$bins"

[ $bad -eq 0 ] && { echo "OK: $KIND instrumentation present in all $n executable(s) under $BUILD"; exit 0; }
echo "FAIL: $KIND instrumentation missing above; this build's results must NOT be reported"
exit 1
