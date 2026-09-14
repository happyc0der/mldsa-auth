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
objects() { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.o' -print 2>/dev/null | sort; }
executables() {
  find "$BUILD" -path "$BUILD/_deps" -prune -o -path '*/CMakeFiles/*' -prune -o \
       -type f -perm -u+x -print 2>/dev/null |
    while IFS= read -r f; do
      case "$(file -b "$f" 2>/dev/null)" in (*Mach-O*executable*) echo "$f" ;; esac
    done | sort
}
h()  { shasum -a 256 "$1" | cut -c1-16; }
# Text section only: a relink can move LC_UUID without changing any code.
ht() { otool -X -t "$1" | shasum -a 256 | cut -c1-16; }
snapshot() {
  while IFS= read -r o; do [ -f "$o" ] && echo "obj $o $(h "$o")"; done < <(objects)
  while IFS= read -r e; do [ -f "$e" ] && echo "bin $e $(ht "$e")"; done < <(executables)
}

nobj=$(objects | wc -l | tr -d ' ')
nbin=$(executables | wc -l | tr -d ' ')
if [ "$nobj" -eq 0 ] && [ "$nbin" -eq 0 ]; then
  echo "FAIL: no project objects or executables under $BUILD (nothing was checked)"
  exit 1
fi
before=$(snapshot)

log=$(mktemp -t mldsa-check-current)
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
  echo "OK: $BUILD is current with the working tree ($nobj object(s), $nbin executable(s); a rebuild changed nothing; fingerprint $fp)"
  exit 0
fi

echo "FAIL: $BUILD was STALE -- rebuilding from the current tree changed:"
diff <(echo "$before") <(echo "$after") | awk '/^[<>]/ {print $3}' | sort -u | sed 's/^/      /'
echo
echo "Any suite result obtained from $BUILD before this rebuild is VOID. Re-run it now."
exit 1
