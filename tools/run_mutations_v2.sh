#!/bin/bash
# Generalized mutation runner for the v2 steps (V2-3 onward).
#
# Nothing here is step-specific: the mutation ids, the test to run and the
# expected failure text all come from a spec file, and every source file
# and build artifact is DISCOVERED, never enumerated. That is deliberate --
# two earlier runners hardcoded their artifact lists, and both times a
# mutation in a file outside the list left a stale object linked into a
# "clean" rebuild, so the clean-suite check silently ran mutated code.
#
#   run_mutations_v2.sh <repo> <scratch> <mutate.py> <spec-file> [build-dir]
#
# spec file: one line per mutation, ID|ctest-regex|;-separated FAIL texts
#            (empty FAIL texts = "must fail somehow", e.g. a crash).
#
# A mutation that does not COMPILE is KILLED automatically (V2-4 hardening):
# a static assert or type error catches the defect earlier than any test, so
# it is the strongest outcome, not a reason to abandon the run. It is
# credited only when the first compiler error names a project source file,
# and it goes through the same restore/rebuild/clean-suite epilogue as every
# other verdict. Before this, such a mutation aborted the campaign and had
# to be driven by hand -- which is precisely how a half-built tree left
# stale objects behind and a "restored" tree reported 12 failures.
#
# Run the campaign against a SANITIZER build directory when a mutation's
# effect is memory-unsafety rather than a wrong answer: V2-4's M6 (a decoder
# length check missing a field) passes every functional oracle in a plain
# build and is caught only by ASan.
set -u
REPO="$1"; SCRATCH="$2"; MUTATE="$3"; SPEC="$4"; BUILD="${5:-build}"
SNAP="$SCRATCH/snapshot_v2"; LOG="$SCRATCH/mutation_v2-logs"
rm -rf "$SNAP" "$LOG"; mkdir -p "$SNAP" "$LOG"
cd "$REPO" || exit 2

# ---- discovery (never a hardcoded list) ---------------------------------
# ---- platform shim (V3-1) ------------------------------------------------
# Duplicated per script on purpose: tools/ is deliberately NOT an installable
# unit (docs/decisions.md), so nothing here may be sourced.
case "$(uname -s)" in
  Darwin)
    MLDSA_PLATFORM="macOS"; MLDSA_TEXTTOOL="otool -X -t"
    sha256() { shasum -a 256 "$1"; }
    textdump() { otool -X -t "$1" 2>/dev/null; }
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*Mach-O*executable*) return 0 ;; esac; return 1; } ;;
  Linux)
    MLDSA_PLATFORM="Linux"
    if command -v objdump > /dev/null 2>&1; then MLDSA_TEXTTOOL="objdump -d --section=.text"
    elif command -v llvm-objdump > /dev/null 2>&1; then MLDSA_TEXTTOOL="llvm-objdump -d --section=.text"
    else MLDSA_TEXTTOOL="(none: whole-file fingerprint)"; fi
    sha256() { sha256sum "$1"; }
    textdump() { case "$MLDSA_TEXTTOOL" in ("(none"*) cat "$1" ;; (*) $MLDSA_TEXTTOOL "$1" 2>/dev/null ;; esac; }
    is_exe() { case "$(file -b "$1" 2>/dev/null)" in (*ELF*executable*|*ELF*pie*) return 0 ;; esac; return 1; } ;;
  *) echo "FATAL: unsupported platform $(uname -s)"; exit 2 ;;
esac

sources()     { find src apps tests bench -type f \( -name '*.c' -o -name '*.h' \) | sort; }
objects()     { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.o' -print 2>/dev/null | sort; }
archives()    { find "$BUILD" -path "$BUILD/_deps" -prune -o -name '*.a' -print 2>/dev/null | sort; }
executables() {
  find "$BUILD" -path "$BUILD/_deps" -prune -o -type f -perm -u+x -print 2>/dev/null |
    while IFS= read -r f; do is_exe "$f" && echo "$f"; done | sort
}

# ---- snapshot / restore: the whole source region, not a chosen subset ----
if grep -rl "MUTATION" $(sources) >/dev/null 2>&1; then
  echo "FATAL: refusing to snapshot -- MUTATION marker already present in: $(grep -rl MUTATION $(sources) | tr '\n' ' ')"
  exit 3
fi
while IFS= read -r f; do mkdir -p "$SNAP/$(dirname "$f")"; cp "$f" "$SNAP/$f"; done < <(sources)
SNAP_COUNT=$(find "$SNAP" -type f | wc -l | tr -d ' ')

restore() {
  local bad=0
  while IFS= read -r f; do
    cp "$SNAP/$f" "$f"
    cmp -s "$SNAP/$f" "$f" || { echo "  restore mismatch: $f"; bad=1; }
  done < <(cd "$SNAP" && find . -type f | sed 's|^\./||' | sort)
  # a mutation must never ADD a source file; if one appears, say so
  local extra
  extra=$(comm -13 <(cd "$SNAP" && find . -type f | sed 's|^\./||' | sort) <(sources))
  [ -n "$extra" ] && { echo "  unexpected new source file(s): $extra"; bad=1; }
  return $bad
}

# ---- forced build: delete EVERY project artifact, then rebuild ----------
forced_build() {
  objects     | xargs -r rm -f 2>/dev/null || objects     | xargs rm -f 2>/dev/null
  archives    | xargs -r rm -f 2>/dev/null || archives    | xargs rm -f 2>/dev/null
  executables | xargs -r rm -f 2>/dev/null || executables | xargs rm -f 2>/dev/null
  cmake --build "$BUILD" -j8 > "$1" 2>&1
}

# ---- fingerprint: every object AND every linked binary ------------------
h()  { sha256 "$1" | cut -c1-16; }
ht() { textdump "$1" | sha256 /dev/stdin | cut -c1-16; }
fp() {
  { while IFS= read -r o; do echo "obj $o $(h "$o")"; done < <(objects)
    while IFS= read -r e; do echo "bin $e $(ht "$e")"; done < <(executables); } | shasum -a 256 | cut -c1-16
}
fp_counts() { echo "$(objects | wc -l | tr -d ' ') objects, $(executables | wc -l | tr -d ' ') executables"; }

restore || exit 3
forced_build "$LOG/preflight1.build" || { echo "FATAL: clean tree does not build"; exit 3; }
CLEAN=$(fp)
forced_build "$LOG/preflight2.build" || exit 3
[ "$(fp)" = "$CLEAN" ] || { echo "FATAL: build is not deterministic"; exit 3; }
ctest --test-dir "$BUILD" > "$LOG/preflight.ctest" 2>&1 || { echo "FATAL: clean suite fails"; exit 3; }
echo "preflight: $SNAP_COUNT sources snapshotted; fingerprint covers $(fp_counts); deterministic; clean suite PASS ($(grep -c ' Passed' "$LOG/preflight.ctest") passed) [$MLDSA_PLATFORM, text via $MLDSA_TEXTTOOL]"

overall=0

# ---- shared per-mutation epilogue ---------------------------------------
# Restore, force a full rebuild, re-run the whole suite, check for residue
# and print the row. Used by BOTH the normal path and the compile-killed
# path, so a mutation can never skip the restore/rebuild bookkeeping --
# that is what left stale objects behind when M8 had to be driven by hand.
finish_mutation() {
  local M="$1" prov="$2" res="$3" rp cs residue
  restore || { echo "$M: FATAL restore"; exit 4; }
  forced_build "$LOG/$M.rebuild" && [ "$(fp)" = "$CLEAN" ] && rp="restored=clean" || { rp="RESTORED-NOT-CLEAN(BAD)"; overall=1; }
  ctest --test-dir "$BUILD" > "$LOG/$M.ctest" 2>&1 && cs="clean-suite=PASS" || { cs="CLEAN-SUITE=FAIL(BAD)"; overall=1; }
  residue=$(grep -rc "MUTATION" $(sources) 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
  printf '%-4s %-19s %-26s | %s | %s | residue=%s\n' "$M" "$prov" "$res" "$rp" "$cs" "$residue"
}

while IFS='|' read -r M TESTRE WANT; do
  [ -z "${M:-}" ] && continue
  case "$M" in \#*) continue ;; esac
  restore || { echo "$M: FATAL pre-restore"; exit 3; }
  python3 "$MUTATE" "$REPO" "$M" > "$LOG/$M.apply" 2>&1 || { echo "$M: FATAL apply: $(cat "$LOG/$M.apply")"; overall=1; continue; }
  if ! forced_build "$LOG/$M.build"; then
    # A mutation that does not COMPILE is killed -- earlier and harder than
    # any test could manage (a static assert, a type error). It is credited
    # automatically, but only on evidence: the first compiler error must
    # name a file in the project's own source region, so an unrelated build
    # failure (full disk, broken toolchain, vendored dependency) can never
    # be laundered into a "kill". The preflight already proved the clean
    # tree builds, and finish_mutation proves it still does afterwards.
    err=$(grep -m1 -E "error:" "$LOG/$M.build" 2>/dev/null)
    echo "${err:-<no compiler error line found>}" > "$LOG/$M.killreason"
    if echo "$err" | grep -qE "/(src|apps|tests|bench)/[^ ]*:[0-9]+:[0-9]+: error:"; then
      finish_mutation "$M" "compile-fail" "KILLED(compile)"
    else
      echo "  $M: build failed with no project-source error: ${err:-<none>}"
      finish_mutation "$M" "compile-fail" "SURVIVED(BAD: unattributable build failure)"
      overall=1
    fi
    continue
  fi
  [ "$(fp)" != "$CLEAN" ] && prov="mutant-in-binaries" || { prov="MUTANT-NOT-IN-BINARY(BAD)"; overall=1; }
  ctest --test-dir "$BUILD" -R "$TESTRE" -V > "$LOG/$M.test" 2>&1; ex=$?
  missing=""
  if [ -n "${WANT:-}" ]; then
    IFS=';' read -ra WL <<< "$WANT"
    for w in "${WL[@]}"; do grep -F "FAIL: " "$LOG/$M.test" | grep -qF "$w" || missing="$missing [$w]"; done
  fi
  how=""
  grep -qE "SegFault|SEGFAULT" "$LOG/$M.test" && how=" via SegFault"
  grep -qE "Subprocess aborted|SIGABRT" "$LOG/$M.test" && how=" via abort"
  n=$(grep -c "FAIL: " "$LOG/$M.test")
  if [ $ex -ne 0 ] && [ -z "$missing" ]; then res="KILLED(${n} named${how})"; else res="SURVIVED(BAD:$missing)"; overall=1; fi
  finish_mutation "$M" "$prov" "$res"
done < "$SPEC"

restore; forced_build "$LOG/final.build" > /dev/null 2>&1
echo "---"
grep -rn "MUTATION" $(sources) 2>/dev/null && { echo "residue found (BAD)"; overall=1; } || echo "residue: none"
[ "$(fp)" = "$CLEAN" ] && echo "final: all sources restored; all artifacts identical to clean fingerprints" || { echo "final: MISMATCH (BAD)"; overall=1; }
exit $overall
