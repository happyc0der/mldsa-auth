#!/bin/bash
# Proves ONE optimized ML-DSA/ML-KEM backend is LINKED, and no portable-C one
# is (spec-v2 Security Req 4.10, Performance Req 3).
#
#   check_backend_symbols.sh [--expect aarch64|x86_64|c] <build-dir>
#
# --expect (V4-39) names the ONE family every executable must link, and
# checks that no other family's symbols appear beside it. `c` is for an
# x86_64 build with MLDSA_OQS_OPT_TARGET=generic: spec-v2 section 3 requires
# that target for distribution, and on x86_64 it gives up the AVX2 backend,
# so portable C is then the one backend linked. Without --expect, the check
# is the original one: no portable-C symbol, and some optimised family.
#
# Why this exists: the project builds liboqs with OQS_DIST_BUILD=OFF, so the
# backend is chosen by a compile-time #if and the reference C implementation,
# though present in the static archive, is never pulled in by the linker.
# That is a claim about the BINARY, so it is checked in the binary. It has
# been checked by hand since V2-2 -- but the script lived in a scratch
# directory and knew only aarch64, so the x86_64 half of the claim had never
# been tested at all when V3-5 first ran it (the same shape as V3-4's finding
# about the mutation campaigns: an unversioned tool is an unverifiable claim).
#
# Every executable is DISCOVERED, never enumerated, so a binary added later
# cannot be silently skipped -- and three separate guards make a vacuous pass
# impossible: no executables found, no binary linking the algorithm at all,
# or no optimized family present are each a FAILURE, never a silent success.
set -u
EXPECT=
if [ "${1:-}" = "--expect" ]; then
  EXPECT="${2:-}"; shift 2 || { echo "usage: check_backend_symbols.sh [--expect aarch64|x86_64|c] <build-dir>"; exit 2; }
  case "$EXPECT" in aarch64|x86_64|c) ;; *) echo "FAIL: --expect takes aarch64, x86_64 or c, not '$EXPECT'"; exit 2 ;; esac
fi
BUILD="${1:?usage: check_backend_symbols.sh [--expect aarch64|x86_64|c] <build-dir>}"
# Without these two, every file would look like a non-executable and the
# run would end "no executables found" -- true, and the wrong reason.
for tool in nm file; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: '$tool' is not installed, so nothing can be checked"; exit 2; }
done

# ---- platform shim (V3-1) ------------------------------------------------
# Duplicated per script on purpose: tools/ is deliberately NOT an installable
# unit (docs/decisions.md), so nothing here may be sourced.
case "$(uname -s)" in
  Darwin)
    MLDSA_PLATFORM="macOS"
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*Mach-O*executable*) return 0 ;; esac; return 1; } ;;
  Linux)
    MLDSA_PLATFORM="Linux"
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*ELF*executable*|*ELF*pie*executable*) return 0 ;; esac; return 1; } ;;
  *)
    echo "FAIL: unsupported platform $(uname -s)"; exit 2 ;;
esac

# The symbol families, taken from the pinned liboqs source (mldsa-native and
# mlkem-native name every backend function this way), never guessed:
#   PQCP_MLDSA_NATIVE_MLDSA65_{C,AARCH64,X86_64}_*
#   PQCP_MLKEM_NATIVE_MLKEM768_{C,AARCH64,X86_64}_*
REF='PQCP_MLDSA_NATIVE_MLDSA65_C_|PQCP_MLKEM_NATIVE_MLKEM768_C_'
ARM='PQCP_MLDSA_NATIVE_MLDSA65_AARCH64_|PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_'
X86='PQCP_MLDSA_NATIVE_MLDSA65_X86_64_|PQCP_MLKEM_NATIVE_MLKEM768_X86_64_'

echo "check_backend_symbols: $BUILD [$MLDSA_PLATFORM, $(uname -m)]${EXPECT:+ expecting $EXPECT}"
fail=0; checked=0; linked=0; arm_total=0; x86_total=0; ref_total=0
while IFS= read -r f; do
  is_exe "$f" || continue
  checked=$((checked + 1))
  nref=$(nm "$f" 2>/dev/null | grep -cE "$REF")
  narm=$(nm "$f" 2>/dev/null | grep -cE "$ARM")
  nx86=$(nm "$f" 2>/dev/null | grep -cE "$X86")
  if [ -n "$EXPECT" ]; then
    # One family, named in advance: its symbols present, every other's absent.
    [ $((nref + narm + nx86)) -gt 0 ] || continue
    linked=$((linked + 1))
    arm_total=$((arm_total + narm)); x86_total=$((x86_total + nx86)); ref_total=$((ref_total + nref))
    case "$EXPECT" in
      aarch64) other=$((nref + nx86)) ;;
      x86_64)  other=$((nref + narm)) ;;
      c)       other=$((narm + nx86)) ;;
    esac
    # It links some backend (above), so with no other family's symbols every
    # one is the expected family's: "none of the expected family" needs no
    # test of its own, and V4-39's control D7 showed it could never decide.
    if [ "$other" -gt 0 ]; then
      printf "  FAIL %-26s aarch64=%-4s x86_64=%-4s portable-C=%-4s (want %s only)\n" "$(basename "$f")" "$narm" "$nx86" "$nref" "$EXPECT"
      fail=1
    else
      printf "  ok   %-26s aarch64=%-4s x86_64=%-4s portable-C=%s\n" "$(basename "$f")" "$narm" "$nx86" "$nref"
    fi
  elif [ "$nref" -gt 0 ]; then
    echo "  FAIL $(basename "$f"): $nref portable-C backend symbol(s) linked"
    fail=1
  elif [ "$narm" -gt 0 ] && [ "$nx86" -gt 0 ]; then
    # "Exactly one" was claimed here from the start but never checked
    # (V4-39): two families in one binary would have passed as x86_64.
    linked=$((linked + 1))
    echo "  FAIL $(basename "$f"): both optimized families are present (aarch64=$narm x86_64=$nx86)"
    fail=1
  elif [ "$narm" -gt 0 ] || [ "$nx86" -gt 0 ]; then
    linked=$((linked + 1))
    arm_total=$((arm_total + narm)); x86_total=$((x86_total + nx86))
    printf "  ok   %-26s aarch64=%-4s x86_64=%-4s portable-C=0\n" "$(basename "$f")" "$narm" "$nx86"
  fi
done < <(find "$BUILD" -type f -perm -u+x -not -path "*/_deps/*" -not -name "*.cmake" -not -name "*.sh")

echo "  ---"
echo "  executables scanned: $checked; linking a backend: $linked (aarch64 symbols $arm_total, x86_64 symbols $x86_total${EXPECT:+, portable-C symbols $ref_total})"
# Three vacuous-pass guards. Finding nothing is never a pass.
if [ "$checked" -eq 0 ]; then
  echo "  FAIL: no executables found in $BUILD (nothing was checked)"; fail=1
elif [ "$linked" -eq 0 ]; then
  echo "  FAIL: no executable linked an ML-DSA/ML-KEM backend at all (nothing was proven)"; fail=1
elif [ -z "$EXPECT" ] && [ "$arm_total" -eq 0 ] && [ "$x86_total" -eq 0 ] && [ "$fail" -eq 0 ]; then
  echo "  FAIL: no optimized backend family present (a pass would mean the portable C build)"; fail=1
elif [ -z "$EXPECT" ] && [ "$arm_total" -gt 0 ] && [ "$x86_total" -gt 0 ]; then
  echo "  FAIL: both optimized families are present, in different executables"; fail=1
fi

if [ "$fail" -eq 0 ] && [ -n "$EXPECT" ]; then
  echo "OK: exactly one backend ($EXPECT) is linked in all $linked executable(s); no other family's symbols [$MLDSA_PLATFORM]"
  echo "BACKEND_FAMILY=$EXPECT"
elif [ "$fail" -eq 0 ]; then
  if [ "$x86_total" -gt 0 ]; then FAMILY=x86_64; else FAMILY=aarch64; fi
  echo "OK: exactly one optimized backend ($FAMILY) is linked in all $linked executable(s); no portable-C symbols [$MLDSA_PLATFORM]"
  # Machine-readable for the bench workflow's agreement check.
  echo "BACKEND_FAMILY=$FAMILY"
fi
exit $fail
