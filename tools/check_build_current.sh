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
# The proof is a FROM-SCRATCH rebuild of the project's own artefacts: delete
# every project object, archive and executable (never _deps), rebuild, and
# show the results byte-identical to what was there. mtimes are deliberately
# NOT trusted -- `touch` and `git checkout` forge them, and they say nothing
# about content.
#
# It used to be a no-op rebuild ("a stale object cannot survive a rebuild
# unchanged"), which is only true if the build tool SEES the change. V4-13b
# found where it does not: macOS's /usr/bin/make is GNU make 3.81, which
# compares timestamps to the second, so a source restored in the same second
# as the previous link leaves a stale module that make calls up to date -- and
# the no-op rebuild then agreed with it. Deleting the artefacts takes the
# timestamps out of the question; the campaign runner has always done this
# (run_mutations_v2.sh forced_build) and was never fooled.
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
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*Mach-O*executable*|*WebAssembly*) return 0 ;; esac; return 1; } ;;
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
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*ELF*executable*|*ELF*pie*|*WebAssembly*) return 0 ;; esac; return 1; } ;;
  *)
    echo "FAIL: unsupported platform $(uname -s)"; exit 2 ;;
esac

objects() { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.o' -print 2>/dev/null | sort; }
archives() { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.a' -print 2>/dev/null | sort; }
executables() {
  find "$BUILD" -path "$BUILD/_deps" -prune -o -path '*/CMakeFiles/*' -prune -o \
       -type f -perm -u+x -print 2>/dev/null |
    while IFS= read -r f; do is_exe "$f" && echo "$f"; done | sort
}
h()  { sha256 "$1" | cut -c1-16; }
# WebAssembly (V4-13b): an Emscripten tree's executables are .wasm modules on
# either host. otool/objdump cannot read them, and a wasm module carries no
# UUID or build-id for a relink to move, so the WHOLE module is the
# fingerprint. (The .js glue beside each module is generated from link flags
# and the module; a changed flag changes the module too.)
is_wasm() { case "$(file -b "$1" 2>/dev/null)" in (*WebAssembly*) return 0 ;; esac; return 1; }
# Text section only: a relink can move LC_UUID / build-id without changing code.
ht() { if is_wasm "$1"; then h "$1"; else textdump "$1" | sha256 /dev/stdin | cut -c1-16; fi; }
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
if ! is_wasm "$_probe" && [ -z "$(textdump "$_probe" 2>/dev/null | head -c 64)" ]; then
  echo "FAIL: cannot read the text section of $_probe using '$MLDSA_TEXTTOOL' on $MLDSA_PLATFORM (executable fingerprints would all be empty and compare equal)"
  exit 1
fi
before=$(snapshot)

# BSD mktemp accepts a bare -t prefix; GNU mktemp demands XXXXXX in the
# template. This form is correct on both.
log=$(mktemp "${TMPDIR:-/tmp}/mldsa-check-current.XXXXXX")
# From scratch: the project's own artefacts only (_deps is pruned by every
# finder above, so liboqs is not rebuilt; libsodium lives outside the tree).
{ objects; archives; executables; } | while IFS= read -r f; do rm -f "$f"; done
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
  echo "OK: $BUILD is current with the working tree ($nobj object(s), $nbin executable(s); a from-scratch rebuild reproduced every one; fingerprint $fp) [$MLDSA_PLATFORM, text via $MLDSA_TEXTTOOL]"
  exit 0
fi

echo "FAIL: $BUILD was STALE -- rebuilding from the current tree changed:"
diff <(echo "$before") <(echo "$after") | awk '/^[<>]/ {print $3}' | sort -u | sed 's/^/      /'
echo
echo "Any suite result obtained from $BUILD before this rebuild is VOID. Re-run it now."
exit 1
