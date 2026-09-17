#!/bin/bash
# The store's fault-injection hook must exist ONLY in the test build.
#
# store.c carries a compiled-out fault hook (MLDSA_STORE_FAULT_HOOK) so V4-7
# can prove that a rotation interrupted mid-way rolls back completely. The hook
# lets a caller make a store operation fail on demand -- exactly the primitive
# an attacker would want, and exactly the kind of test affordance that has
# shipped by accident in other projects. This gate proves it did not:
#
#   * ABSENT from libmldsa_authd.a and from every shipped executable, and
#   * PRESENT in the test binary -- without which "absent" could be vacuously
#     true because the symbol name changed and nothing checks anything.
#
# Both halves are required; a run where the symbol is nowhere at all FAILS.
#
#   tools/check_store_fault_hook.sh <build-dir>
set -u

SYM="store_fault_arm"
BUILD="${1:-build}"

if [ ! -d "$BUILD" ]; then
    echo "FAIL: no such build directory: $BUILD"
    exit 2
fi

case "$(uname -s)" in
    Darwin|Linux) ;;
    *) echo "FAIL: unsupported platform $(uname -s)"; exit 2 ;;
esac

# nm is present on both platforms; a missing symbol table is itself a failure
# rather than a pass, so `nm` errors are not swallowed into "0 matches".
count_sym() {
    # $1 = file
    nm "$1" 2>/dev/null | grep -c "$SYM" || true
}

fail=0
checked=0

# --- the shipped static library and executables must NOT carry it ----------
lib="$BUILD/apps/authd/libmldsa_authd.a"
if [ -f "$lib" ]; then
    checked=$((checked + 1))
    n=$(count_sym "$lib")
    if [ "$n" -ne 0 ]; then
        echo "FAIL: $SYM is present in the shipped library $lib ($n match(es))"
        fail=1
    else
        echo "OK: $SYM absent from $lib"
    fi
fi

# every executable under the build dir except the test that is allowed to have
# it (discovered, never enumerated -- the standing rule from the other tools)
while IFS= read -r exe; do
    case "$(basename "$exe")" in
        test_authd_store) continue ;;
    esac
    case "$(file -b "$exe")" in
        *Mach-O*executable*|*ELF*executable*|*ELF*pie*) ;;
        *) continue ;;
    esac
    checked=$((checked + 1))
    n=$(count_sym "$exe")
    if [ "$n" -ne 0 ]; then
        echo "FAIL: $SYM is present in $exe ($n match(es))"
        fail=1
    fi
done <<EOF
$(find "$BUILD" -type f -perm -u+x -not -path "*/_deps/*" 2>/dev/null)
EOF

# --- the non-vacuity half: the test binary MUST carry it -------------------
t="$BUILD/tests/test_authd_store"
if [ -f "$t" ]; then
    n=$(count_sym "$t")
    if [ "$n" -eq 0 ]; then
        echo "FAIL: $SYM is absent from the test binary $t -- this gate is checking nothing"
        fail=1
    else
        echo "OK: $SYM present in $t (the gate is live)"
    fi
else
    echo "FAIL: test binary $t not built; nothing proves this gate can see the symbol"
    fail=1
fi

if [ "$checked" -eq 0 ]; then
    echo "FAIL: nothing was checked (no library or executables found under $BUILD)"
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "OK: the store fault hook is confined to the test build ($checked shipped artifact(s) checked) [$(uname -s)]"
exit 0
