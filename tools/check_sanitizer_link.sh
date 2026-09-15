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

# ---- platform shim (V3-1) ------------------------------------------------
# The gates must mean the same thing on both platforms, so each mechanism is
# named here rather than probed silently, and the script prints which one it
# used. Duplicated per script on purpose: tools/ is deliberately NOT an
# installable unit (docs/decisions.md), so nothing here may be sourced.
case "$(uname -s)" in
  Darwin)
    MLDSA_PLATFORM="macOS"
    MLDSA_TEXTTOOL="otool -X -t"
    sha256() { shasum -a 256 "$1"; }
    textdump() { otool -X -t "$1" 2>/dev/null; }
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*Mach-O*executable*) return 0 ;; esac; return 1; } ;;
  Linux)
    MLDSA_PLATFORM="Linux"
    if command -v objdump > /dev/null 2>&1; then MLDSA_TEXTTOOL="objdump -d --section=.text"
    elif command -v llvm-objdump > /dev/null 2>&1; then MLDSA_TEXTTOOL="llvm-objdump -d --section=.text"
    else MLDSA_TEXTTOOL="(none: whole-file fingerprint)"; fi
    sha256() { sha256sum "$1"; }
    textdump() {
      case "$MLDSA_TEXTTOOL" in
        "(none"*) cat "$1" ;;                      # no disassembler: hash the file itself
        *) $MLDSA_TEXTTOOL "$1" 2>/dev/null ;;
      esac
    }
    # ELF executables are ET_EXEC ("executable") or ET_DYN ("pie executable").
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*ELF*executable*|*ELF*pie*) return 0 ;; esac; return 1; } ;;
  *)
    echo "FAIL: unsupported platform $(uname -s)"; exit 2 ;;
esac

# Sanitizer runtimes differ by platform and by static/shared linkage.
if [ "$MLDSA_PLATFORM" = "macOS" ]; then
  linked_asan()  { otool -L "$1" 2>/dev/null | grep -q "libclang_rt.asan" || nm -u "$1" 2>/dev/null | grep -q "__asan_"; }
  linked_ubsan() { otool -L "$1" 2>/dev/null | grep -q "libclang_rt.ubsan"; }
else
  linked_asan()  { ldd "$1" 2>/dev/null | grep -qE "libasan|libclang_rt\.asan" || nm -u "$1" 2>/dev/null | grep -q "__asan_" || nm "$1" 2>/dev/null | grep -q "__asan_"; }
  linked_ubsan() { ldd "$1" 2>/dev/null | grep -qE "libubsan|libclang_rt\.ubsan"; }
fi

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
  while IFS= read -r f; do is_exe "$f" && echo "$f"; done | sort)
[ -n "$bins" ] || { echo "FAIL: no executables found under $BUILD (nothing was checked)"; exit 1; }

n=0; bad=0
while IFS= read -r b; do
  n=$((n + 1))
  case "$KIND" in
    # asan: clang links libclang_rt.asan (macOS) or libasan/libclang_rt (Linux,
    # gcc or clang); a static link shows only the symbols. Any one suffices.
    asan)  linked_asan "$b" || { echo "  NOT INSTRUMENTED: $b"; bad=1; } ;;
    ubsan) nm "$b" 2>/dev/null | grep -q '__ubsan' || linked_ubsan "$b" || { echo "  NOT INSTRUMENTED: $b"; bad=1; } ;;
  esac
done <<< "$bins"

[ $bad -eq 0 ] && { echo "OK: $KIND instrumentation present in all $n executable(s) under $BUILD [$MLDSA_PLATFORM]"; exit 0; }
echo "FAIL: $KIND instrumentation missing above; this build's results must NOT be reported"
exit 1
