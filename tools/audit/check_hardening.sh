#!/bin/bash
# V4-1 audit / V4-11 gate: report the hardening actually present in built
# binaries -- PIE, RELRO, BIND_NOW, non-executable stack, stack canaries.
#
#   check_hardening.sh <build-dir> [--require]
#
# Without --require this REPORTS (audit mode: the answer today is expected to
# be "mostly absent", which is finding F4). With --require it FAILS unless
# every discovered executable has the full set -- that is how V4-11 gates the
# daemon binary once the flags are added.
#
# The claim is about the BINARY, so it is read from the binary, never from the
# build files. Executables are discovered, never enumerated (the rule that
# check_backend_symbols.sh and check_sanitizer_link.sh follow).
#
# The CANARY column is informational for this project's own code: it reads the
# LINKED binary, and vendored liboqs and sqlite import __stack_chk_fail
# themselves, so it would say yes with the project's -fstack-protector-strong
# gone (audit F104, the class of F75 for BIND_NOW). The attributable check is
# tests/check_build_flags.cmake, which reads the project's own archives and
# what compile_commands.json says each translation unit was told.
set -u
BUILD="${1:?usage: check_hardening.sh <build-dir> [--require]}"
# V4-302, F518: without `file` no executable was recognised, and the check
# said "no executables found" rather than what was missing.
command -v file > /dev/null 2>&1 || { echo "FAIL: \`file\` is not installed (apt-get install file); nothing can be checked"; exit 1; }
REQUIRE=0; [ "${2:-}" = "--require" ] && REQUIRE=1

case "$(uname -s)" in
  Darwin) PLATFORM="macOS"
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*Mach-O*executable*) return 0;; esac; return 1; }
    # Mach-O: PIE is a header flag; the stack is non-executable unless
    # MH_ALLOW_STACK_EXECUTION; RELRO/BIND_NOW are ELF concepts with no
    # Mach-O equivalent, so they are reported as n/a rather than as failures.
    probe() {
      local f="$1" flags; flags=$(otool -hv "$f" 2>/dev/null | tail -1)
      case "$flags" in (*PIE*) P=yes;; (*) P=no;; esac
      case "$flags" in (*ALLOW_STACK_EXECUTION*) X=no;; (*) X=yes;; esac
      R="n/a"; N="n/a"
      if nm -u "$f" 2>/dev/null | grep -q "__stack_chk_fail"; then C=yes; else C=no; fi
    } ;;
  Linux) PLATFORM="Linux"
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*ELF*executable*|*ELF*pie*executable*) return 0;; esac; return 1; }
    # tests/gate_claims.sh puts a stand-in here to show a header that is not
    # there; a linker that leaves GNU_STACK out is not something to install.
    READELF="${MLDSA_HARDENING_READELF:-readelf}"
    probe() {
      local f="$1" hdr ph dyn
      hdr=$($READELF -h "$f" 2>/dev/null); ph=$($READELF -lW "$f" 2>/dev/null); dyn=$($READELF -dW "$f" 2>/dev/null)
      case "$hdr" in (*"DYN (Position-Independent Executable"*|*"DYN (Shared object"*) P=yes;; (*) P=no;; esac
      case "$ph"  in (*GNU_RELRO*) R=yes;; (*) R=no;; esac
      case "$dyn" in (*BIND_NOW*|*"NOW"*) N=yes;; (*) N=no;; esac
      # F358: no GNU_STACK header at all is not "non-executable": on x86_64
      # the kernel then makes the stack executable. It read as yes.
      case "$ph"  in (*"GNU_STACK"*RWE*) X=no;; (*"GNU_STACK"*) X=yes;; (*) X=no;; esac
      if $READELF -sW "$f" 2>/dev/null | grep -q "__stack_chk_fail"; then C=yes; else C=no; fi
    } ;;
  *) echo "FAIL: unsupported platform $(uname -s)"; exit 2 ;;
esac

echo "check_hardening: $BUILD [$PLATFORM]"
printf '  %-26s %-5s %-6s %-8s %-9s %s\n' BINARY PIE RELRO BIND_NOW NX-STACK CANARY
checked=0; missing=0
while IFS= read -r f; do
  is_exe "$f" || continue
  checked=$((checked+1)); probe "$f"
  printf '  %-26s %-5s %-6s %-8s %-9s %s\n' "$(basename "$f")" "$P" "$R" "$N" "$X" "$C"
  for v in "$P" "$R" "$N" "$X" "$C"; do [ "$v" = "no" ] && missing=$((missing+1)); done
# CMakeFiles/ holds CMake's own compiler-probe binaries, built with none of
# this project's flags; counting them would manufacture findings.
done < <(find "$BUILD" -path "$BUILD/_deps" -prune -o -path "*/CMakeFiles/*" -prune -o -type f -perm -u+x -print 2>/dev/null | sort)

echo "  ---"
echo "  executables checked: $checked; hardening properties absent: $missing"
[ "$checked" -eq 0 ] && { echo "  FAIL: no executables found in $BUILD (nothing was checked)"; exit 1; }
# The CPU target (V4-230, audit F321). Spec 16: "a named CPU target (never
# -march=native), and check_hardening.sh --require gates it" -- and this
# script did not look. The target is not in the binary in any form that can
# be read back, so it is read from the build tree's own record, where there
# is one: `auto` is the project's default and means this machine's CPU. An
# install tree has no record, and that is said, not passed over.
TARGET_BAD=0
if [ -f "$BUILD/CMakeCache.txt" ]; then
  TARGET=$(sed -n 's/^MLDSA_OQS_OPT_TARGET:[A-Z]*=//p' "$BUILD/CMakeCache.txt" | head -1)
  case "$TARGET" in
    "")   echo "  CPU target: this build tree's CMakeCache.txt does not record one"; TARGET_BAD=1 ;;
    auto) echo "  CPU target: auto -- built for THIS machine's CPU (-march=native / -mcpu=native)"; TARGET_BAD=1 ;;
    *)    echo "  CPU target: $TARGET (named)" ;;
  esac
else
  echo "  CPU target: not a build tree (no CMakeCache.txt), so not checked here"
fi
if [ "$REQUIRE" -eq 1 ]; then
  [ "$missing" -eq 0 ] || { echo "FAIL: $missing hardening property/properties absent"; exit 1; }
  [ "$TARGET_BAD" -eq 0 ] || { echo "FAIL: the CPU target is not a named one: configure with -DMLDSA_OQS_OPT_TARGET=generic, or a CPU name such as x86-64-v3"; exit 1; }
  echo "OK: every discovered executable carries the full hardening set [$PLATFORM]"
fi
exit 0
