#!/bin/bash
# Proves a build directory's binaries were compiled from the CURRENT working
# tree, before any suite result from it is trusted (V2-10 hardening).
#
#   check_build_current.sh <build-dir>
#
# Use it in the SAME invocation as the suite whose result you will quote:
#
#   tools/check_build_current.sh build && ctest --test-dir build --output-on-failure
#
# Why this exists: V2-9's build-ubsan was a complete, correctly configured,
# fully linked, genuinely instrumented build -- of sources as they stood
# twelve minutes before a late edit. `ctest` never compiles, so it ran those
# stale binaries and reported 15/15. check_sanitizer_link.sh passed too,
# because the binaries really were instrumented: it proves instrumentation,
# never currency. Rebuilding had only ever happened as a SIDE EFFECT of other
# work -- a mutation campaign's forced rebuild, the README pass's `rm -rf` --
# and build-ubsan was missing from the one rm list that mattered. Nothing in
# any output said so.
#
# The proof is a no-op rebuild: rebuild, then show every project object and
# executable is byte-identical afterwards. A stale object cannot survive a
# rebuild unchanged. mtimes are deliberately NOT used -- `touch` and
# `git checkout` forge them, and they say nothing about content.
set -u
BUILD="${1:?usage: check_build_current.sh <build-dir>}"
[ -f "$BUILD/CMakeCache.txt" ] || { echo "FAIL: $BUILD is not a configured build directory"; exit 2; }

# ---- discovery (never a hardcoded list) ----------------------------------
# Objects: project objects live UNDER CMakeFiles/ (.../CMakeFiles/tgt.dir/x.c.o),
# so ONLY _deps is pruned here. Executables: pruned the way
# check_sanitizer_link.sh prunes them -- CMake's configure-time compiler
# probes are toolchain scratch, not project output.
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

objects() { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.o' -print 2>/dev/null | sort; }
executables() {
  find "$BUILD" -path "$BUILD/_deps" -prune -o -path '*/CMakeFiles/*' -prune -o \
       -type f -perm -u+x -print 2>/dev/null |
    while IFS= read -r f; do is_exe "$f" && echo "$f"; done | sort
}
h()  { sha256 "$1" | cut -c1-16; }
# Text section only: a relink can move LC_UUID / build-id without changing code.
ht() { textdump "$1" | sha256 /dev/stdin | cut -c1-16; }
snapshot() {
  while IFS= read -r o; do [ -f "$o" ] && echo "obj $o $(h "$o")"; done < <(objects)
  while IFS= read -r e; do [ -f "$e" ] && echo "bin $e $(ht "$e")"; done < <(executables)
}

nobj=$(objects | wc -l | tr -d ' ')
nbin=$(executables | wc -l | tr -d ' ')
# BOTH must be non-empty. Requiring only "not both zero" let a broken
# executable discovery (wrong platform branch, a future layout change) pass
# while silently comparing objects alone -- V3-1 mutation W1.
if [ "$nobj" -eq 0 ] || [ "$nbin" -eq 0 ]; then
  echo "FAIL: $BUILD has $nobj object(s) and $nbin executable(s) -- a tree whose suite results you intend to quote must have both (nothing was checked)"
  exit 1
fi

# A text dump that silently produces nothing makes every binary compare equal,
# so the gate would pass vacuously -- V3-1 mutation W4. Prove the tool works
# on a real binary before trusting any comparison built from it.
_probe=$(executables | head -1)
if [ -z "$(textdump "$_probe" 2>/dev/null | head -c 64)" ]; then
  echo "FAIL: cannot read the text section of $_probe using '$MLDSA_TEXTTOOL' on $MLDSA_PLATFORM (executable fingerprints would all be empty and compare equal)"
  exit 1
fi
before=$(snapshot)

# BSD mktemp accepts a bare -t prefix; GNU mktemp demands XXXXXX in the
# template. This form is correct on both.
log=$(mktemp "${TMPDIR:-/tmp}/mldsa-check-current.XXXXXX")
if ! cmake --build "$BUILD" -j8 > "$log" 2>&1; then
  echo "FAIL: $BUILD does not build from the current working tree"
  grep -m 3 -E "error:" "$log" | sed 's/^/      /'
  rm -f "$log"
  exit 1
fi
rm -f "$log"
after=$(snapshot)

if [ "$before" = "$after" ]; then
  fp=$(echo "$after" | shasum -a 256 | cut -c1-16)
  echo "OK: $BUILD is current with the working tree ($nobj object(s), $nbin executable(s); a rebuild changed nothing; fingerprint $fp) [$MLDSA_PLATFORM, text via $MLDSA_TEXTTOOL]"
  exit 0
fi

echo "FAIL: $BUILD was STALE -- rebuilding from the current tree changed:"
diff <(echo "$before") <(echo "$after") | awk '/^[<>]/ {print $3}' | sort -u | sed 's/^/      /'
echo
echo "Any suite result obtained from $BUILD before this rebuild is VOID. Re-run it now."
exit 1
