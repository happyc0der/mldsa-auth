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

# nm is present on both platforms; a file it cannot read is a failure, not
# "0 matches". (This comment said so before the code did: the pipeline's
# status was grep's, so an unreadable artefact counted as "absent" -- V4-230,
# audit F320.) Prints the count, or ERR.
count_sym() {
    # $1 = file
    _syms=$(nm "$1" 2>/dev/null) || { echo ERR; return; }
    printf '%s\n' "$_syms" | grep -c "$SYM" || true
}

fail=0
checked=0

# --- the shipped static library and executables must NOT carry it ----------
lib="$BUILD/apps/authd/libmldsa_authd.a"
if [ ! -f "$lib" ]; then
    echo "FAIL: the shipped library $lib is not there to be checked"
    fail=1
else
    checked=$((checked + 1))
    n=$(count_sym "$lib")
    if [ "$n" = ERR ]; then
        echo "FAIL: nm cannot read the shipped library $lib"
        fail=1
    elif [ "$n" -ne 0 ]; then
        echo "FAIL: $SYM is present in the shipped library $lib ($n match(es))"
        fail=1
    else
        echo "OK: $SYM absent from $lib"
    fi
fi

# every executable under the build dir except the test that is allowed to have
# it (discovered, never enumerated -- the standing rule from the other tools)
while IFS= read -r exe; do
    # V4-339: test_authd_localapi compiles the store with the hook too (one
    # write of a request is made to fail there; it was done with a planted
    # trigger, which the daemon no longer runs). Neither is installed.
    case "$(basename "$exe")" in
        test_authd_store|test_authd_localapi) continue ;;
    esac
    case "$(file -b "$exe")" in
        *Mach-O*executable*|*ELF*executable*|*ELF*pie*) ;;
        *) continue ;;
    esac
    checked=$((checked + 1))
    n=$(count_sym "$exe")
    if [ "$n" = ERR ]; then
        echo "FAIL: nm cannot read $exe, so nothing says the hook is absent from it"
        fail=1
    elif [ "$n" -ne 0 ]; then
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
    if [ "$n" = ERR ] || [ "$n" -eq 0 ]; then
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
