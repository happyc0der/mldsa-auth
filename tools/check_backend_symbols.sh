#!/bin/bash
# Proves ONE optimized ML-DSA/ML-KEM backend is LINKED, and no portable-C one
# is (spec-v2 Security Req 4.10, Performance Req 3).
#
#   check_backend_symbols.sh <build-dir>
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
BUILD="${1:?usage: check_backend_symbols.sh <build-dir>}"

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

echo "check_backend_symbols: $BUILD [$MLDSA_PLATFORM, $(uname -m)]"
fail=0; checked=0; linked=0; arm_total=0; x86_total=0
while IFS= read -r f; do
  is_exe "$f" || continue
  checked=$((checked + 1))
  nref=$(nm "$f" 2>/dev/null | grep -cE "$REF")
  narm=$(nm "$f" 2>/dev/null | grep -cE "$ARM")
  nx86=$(nm "$f" 2>/dev/null | grep -cE "$X86")
  if [ "$nref" -gt 0 ]; then
    echo "  FAIL $(basename "$f"): $nref portable-C backend symbol(s) linked"
    fail=1
  elif [ "$narm" -gt 0 ] || [ "$nx86" -gt 0 ]; then
    linked=$((linked + 1))
    arm_total=$((arm_total + narm)); x86_total=$((x86_total + nx86))
    printf "  ok   %-26s aarch64=%-4s x86_64=%-4s portable-C=0\n" "$(basename "$f")" "$narm" "$nx86"
  fi
done < <(find "$BUILD" -type f -perm -u+x -not -path "*/_deps/*" -not -name "*.cmake" -not -name "*.sh")

echo "  ---"
echo "  executables scanned: $checked; linking a backend: $linked (aarch64 symbols $arm_total, x86_64 symbols $x86_total)"
# Three vacuous-pass guards. Finding nothing is never a pass.
if [ "$checked" -eq 0 ]; then
  echo "  FAIL: no executables found in $BUILD (nothing was checked)"; fail=1
elif [ "$linked" -eq 0 ]; then
  echo "  FAIL: no executable linked an ML-DSA/ML-KEM backend at all (nothing was proven)"; fail=1
elif [ "$arm_total" -eq 0 ] && [ "$x86_total" -eq 0 ]; then
  echo "  FAIL: no optimized backend family present (a pass would mean the portable C build)"; fail=1
fi

if [ "$fail" -eq 0 ]; then
  if [ "$x86_total" -gt 0 ]; then FAMILY=x86_64; else FAMILY=aarch64; fi
  echo "OK: exactly one optimized backend ($FAMILY) is linked in all $linked executable(s); no portable-C symbols [$MLDSA_PLATFORM]"
  # Machine-readable for the bench workflow's agreement check.
  echo "BACKEND_FAMILY=$FAMILY"
fi
exit $fail
