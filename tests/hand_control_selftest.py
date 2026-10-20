#!/usr/bin/env python3
"""tools/hand_control.py, tested on a project of its own (V4-34).

    hand_control_selftest.py

The tool exists because a throwaway control script got a verdict wrong
(V4-33): it rebuilt a mutated object but not the static library holding
it, the archive stayed "current" under make's one-second timestamps, and
two mutants SURVIVED on unmutated binaries. So this tests the verdicts, and
it tests the trap.
- It never touches the repository's sources. A tiny CMake project (a static
  library, a probe that links it, a CTest) is generated in a temporary
  directory, and the tool runs against that.
- The trap is made deterministic, not left to timing: the library's
  archive is dated an hour ahead, so make will not re-archive it on its
  own. The test first shows that deleting only the object then leaves the
  old code linked (the trap is real here), then that the tool still links
  the mutant.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time

TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "hand_control.py"
fail = 0


def check(ok, what):
    global fail
    print(("PASS: " if ok else "FAIL: ") + what)
    if not ok:
        fail = 1


CMAKE = """cmake_minimum_required(VERSION 3.20)
project(hcprobe C)
add_library(plib STATIC plib.c)
add_executable(probe probe.c)
target_link_libraries(probe PRIVATE plib)
add_executable(probe_bin probe.c)
set_target_properties(probe_bin PROPERTIES OUTPUT_NAME probe-renamed)
target_link_libraries(probe_bin PRIVATE plib)
enable_testing()
add_test(NAME probe COMMAND probe)
add_test(NAME probe_renamed COMMAND probe_bin)
"""
PLIB = """/* the probe library */
int answer(void) { return 42; }
int unused(void) { return 7; }
"""
PROBE = """#include <stdio.h>
int answer(void);
int main(void)
{
    if (answer() != 42) { printf("FAIL: the answer is 42\\n"); return 1; }
    printf("PASS: the answer is 42\\n");
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="mldsa-hc-") as tmp:
    d = pathlib.Path(tmp)
    (d / "CMakeLists.txt").write_text(CMAKE)
    (d / "plib.c").write_text(PLIB)
    (d / "probe.c").write_text(PROBE)
    b = d / "b"
    cfg = subprocess.run(["cmake", "-S", str(d), "-B", str(b)], capture_output=True, text=True)
    check(cfg.returncode == 0, "the probe project configures")
    built = subprocess.run(["cmake", "--build", str(b)], capture_output=True, text=True)
    check(built.returncode == 0, "the probe project builds")

    def hc(old, new, expect="the answer is 42", verdict="KILLED"):
        r = subprocess.run([sys.executable, str(TOOL), "--repo", str(d), "--build", str(b), "--target", "probe",
                            "--ctest", "^probe$", "--expect", expect, "--mutation", "plib.c",
                            "--old", old, "--new", new, "--expect-verdict", verdict],
                           capture_output=True, text=True)
        print("  " + r.stdout.strip().replace("\n", "\n  "))
        return r.returncode, r.stdout

    rc, out = hc("return 42;", "return 43;")
    check(rc == 0 and ": KILLED |" in out, "a mutation the probe sees is KILLED, by name")
    rc, out = hc("return 42;", "return 43;", expect="a message the probe never prints", verdict="KILLED(other)")
    check(rc == 0 and ": KILLED(other) |" in out,
          "the same mutation, expected under a name the probe never prints, is KILLED(other) -- not a named kill")
    rc, out = hc("return 7;", "return 8;", verdict="SURVIVED")
    check(rc == 0 and ": SURVIVED |" in out, "a mutation the probe cannot see SURVIVES")
    rc, out = hc("/* the probe library */", "/* the probe library, reworded */", verdict="VOID")
    check(rc == 0 and ": VOID" in out, "a mutation that leaves the binary unchanged is VOID, not SURVIVED")
    rc, out = hc("return 42;", "return 42 +;", verdict="KILLED(compile)")
    check(rc == 0 and ": KILLED(compile)" in out, "a mutation that does not compile is KILLED(compile), which is not a kill")

    # The trap, made real. With the archive dated ahead, the old way -- delete
    # the object, rebuild -- links the old code: the probe still passes.
    lib = b / "libplib.a"
    future = time.time() + 3600
    os.utime(lib, (future, future))
    (d / "plib.c").write_text(PLIB.replace("return 42;", "return 45;"))
    for root, _dirs, files in os.walk(b):
        if "plib.c.o" in files:
            os.remove(os.path.join(root, "plib.c.o"))
    subprocess.run(["cmake", "--build", str(b), "--target", "probe"], capture_output=True, text=True)
    stale = subprocess.run(["ctest", "--test-dir", str(b), "-R", "^probe$"], capture_output=True, text=True)
    (d / "plib.c").write_text(PLIB)
    check(stale.returncode == 0,
          "the trap is real here: with the archive dated ahead, deleting only the object leaves the old code linked")
    os.utime(lib, (future, future))
    rc, out = hc("return 42;", "return 44;")
    check(rc == 0 and ": KILLED |" in out,
          "with the archive dated ahead, the tool still links the mutant (it deletes the archive), and it is KILLED")

    # A target whose OUTPUT_NAME differs (mldsa_authd_bin builds mldsa-authd):
    # with --binary the tool finds what it built, and the verdict is real.
    r = subprocess.run([sys.executable, str(TOOL), "--repo", str(d), "--build", str(b), "--target", "probe_bin",
                        "--binary", "probe-renamed", "--ctest", "^probe_renamed$", "--expect", "the answer is 42",
                        "--mutation", "plib.c", "--old", "return 42;", "--new", "return 46;"],
                       capture_output=True, text=True)
    print("  " + r.stdout.strip().replace("\n", "\n  "))
    check(r.returncode == 0 and ": KILLED |" in r.stdout,
          "a target whose OUTPUT_NAME differs, named with --binary, is built, hashed and KILLED")

    after = subprocess.run(["ctest", "--test-dir", str(b), "-R", "^probe$"], capture_output=True, text=True)
    check((d / "plib.c").read_text() == PLIB and after.returncode == 0,
          "the probe project is left as it was found: the source restored, the probe passing")

print("hand_control_selftest: " + ("FAILED" if fail else "all checks passed"))
sys.exit(fail)
