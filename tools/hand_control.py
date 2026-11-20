#!/usr/bin/env python3
"""One hand control: break the code, show a named check fails, restore (V4-34).

    hand_control.py --build B --target T [--binary NAME] --ctest REGEX --expect TEXT \\
        (--mutation FILE --old TEXT --new TEXT | --campaign vNN --id ID) \\
        [--repo R] [--label NAME]

--binary names the file the target builds, when its OUTPUT_NAME differs
(mldsa_authd_bin builds mldsa-authd); it defaults to the target's name.

Hand controls are how a check the nightly campaign tree cannot run is shown
to be able to fail: the browser and wasm tests, the tools (V4-13c, V4-26,
V4-27, V4-31, V4-32, V4-33). Each step used to write its own throwaway
script, and V4-33's had a silent flaw. It deleted the mutated object but
not the static library the object goes into. macOS's make 3.81 compares
timestamps to the second, so an object rebuilt within the second of the
last archive leaves the archive "current", and the test links the OLD code.
Two mutants "SURVIVED" on unmutated binaries. This is that rule, kept where
it cannot be lost:

  1. Build the target CLEAN, with the artifacts below deleted first, and
     record the sha256 of the target's CODE (its text section, as
     check_build_current.sh fingerprints it: a whole-file hash moves with a
     link's UUID even when not one instruction changed).
  2. Apply the mutation: an anchor that must occur exactly once, or a
     campaign's own mutate_vNN.py with its ID.
  3. Delete, build, and fingerprint again. A mutant whose code equals the
     clean code is VOID, never SURVIVED: the code under test did not change.
  4. Run `ctest -R REGEX -V`. KILLED needs a nonzero exit AND TEXT on a
     `FAIL: ` line, or in a node:test assertion message. A nonzero exit
     without TEXT is KILLED(other); a pass is SURVIVED. A failed build is
     KILLED(compile), which is not a kill (F79).
  5. Restore every touched source byte-exactly (checked by sha256), then
     rebuild, so the tree is left as it was found.

The artifacts deleted before each build are every object compiled from a
touched source, the static library each of those objects belongs to, and the
target's executable. Nothing else is touched, so a tree the tool ran in
stays current for every other target.

--interpreted (V4-64) is for a source nothing compiles -- the reference
site, the browser pages, a test script -- whose file IS the code under test.
There is no build: the fingerprint is the file's sha256 (a mutant that leaves
it unchanged is VOID), the test runs from the mutated file, and the restore is
checked by sha256 as always. V4-58 and V4-62 ran their site controls with a
throwaway script; this is that script's rule, kept here.

One line per control on stdout, in run_mutations_v2.sh's shape. Exit 0 only
when the verdict is exactly the expected one (KILLED unless
--expect-verdict says otherwise, which is for testing this tool) and the
sources are restored and rebuilt.
"""
import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def _text_tool():
    if sys.platform == "darwin":
        return ["otool", "-X", "-t"]
    for t in ("objdump", "llvm-objdump"):
        if subprocess.run(["sh", "-c", f"command -v {t}"], capture_output=True).returncode == 0:
            return [t, "-d", "--section=.text"]
    return None


TEXT_TOOL = _text_tool()


def code_fingerprint(exe):
    """The CODE, not the file: a link can differ from the last in its UUID or
    an embedded build time while its text is byte-identical (measured on
    mldsa-authd, V4-36: three links, three file hashes, one text hash). The
    same choice as check_build_current.sh. Whole file only without a tool."""
    if TEXT_TOOL is not None:
        r = subprocess.run(TEXT_TOOL + [exe], capture_output=True)
        if r.returncode == 0 and r.stdout:
            return hashlib.sha256(r.stdout).hexdigest()
    return sha(exe)


def _target_dir(path):
    """The <target>.dir a CMake object lives under. A source in a subdirectory
    of its target's directory is compiled one level deeper
    (<target>.dir/protocol/handshake.c.o), so every ancestor is asked (F370)."""
    for anc in pathlib.Path(path).parents:
        if anc.name.endswith(".dir"):
            return anc
    return None


def _with_library(obj):
    tdir = _target_dir(obj)
    target = tdir.name[:-len(".dir")]
    # <bindir>/CMakeFiles/<target>.dir -> <bindir>/lib<target>.a
    lib = tdir.parent.parent / ("lib" + target + ".a")
    return (obj, str(lib) if lib.exists() else None)


def objects_of(build, src):
    """Every object compiled from `src`, as CMake names it (<file>.o somewhere
    under a <target>.dir), with the static library that object belongs to. For
    a header: every object whose compiler dependency file names it (F371)."""
    header = src.endswith(".h")
    name = os.path.basename(src) + ".o"
    needle = re.compile(r"(?:^|[/\s])" + re.escape(src) + r"(?:\s|\\|$)", re.M)
    found = []
    for root, _dirs, files in os.walk(build):
        if "_deps" in pathlib.Path(root).parts or _target_dir(os.path.join(root, "x")) is None:
            continue
        if header:
            for f in files:
                if not f.endswith(".o.d"):
                    continue
                if needle.search(pathlib.Path(root, f).read_text(errors="replace")):
                    found.append(_with_library(os.path.join(root, f[:-2])))
        elif name in files:
            found.append(_with_library(os.path.join(root, name)))
    return found


def target_binary(build, target):
    for root, _dirs, files in os.walk(build):
        if "_deps" in pathlib.Path(root).parts or "CMakeFiles" in pathlib.Path(root).parts:
            continue
        if target in files:
            p = os.path.join(root, target)
            if os.access(p, os.X_OK):
                return p
    return None


def build(args, sources):
    victims = []
    for s in sources:
        for obj, lib in objects_of(args.build, s):
            victims.append(obj)
            if lib:
                victims.append(lib)
    exe = target_binary(args.build, args.binary or args.target)
    if exe:
        victims.append(exe)
    for v in victims:
        if os.path.exists(v):
            os.remove(v)
    r = subprocess.run(["cmake", "--build", args.build, "--target", args.target, "-j6"],
                       capture_output=True, text=True)
    exe = target_binary(args.build, args.binary or args.target)
    if r.returncode != 0 or not exe:
        return r.returncode, None
    # The executable's code AND the objects compiled from the touched files
    # (F376): a mutation that changes only data -- a label string, a table --
    # leaves the text section byte-identical and was reported VOID. An object
    # holds its data too, and is reproducible (the campaign runner's
    # determinism check stands on that). One this target does not rebuild is
    # absent in every build alike.
    h = hashlib.sha256(code_fingerprint(exe).encode())
    for s in sources:
        for obj, _lib in sorted(objects_of(args.build, s)):
            h.update(obj.encode() + b"=" + (sha(obj) if os.path.exists(obj) else "absent").encode() + b"\n")
    return 0, h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--build", required=True)
    ap.add_argument("--target", help="the executable target the ctest runs (or that it spawns)")
    ap.add_argument("--interpreted", action="store_true",
                    help="the mutated file is run as it is (JavaScript, Python, shell): no build, its sha256 is the fingerprint")
    ap.add_argument("--binary", default=None, help="the file that target builds, if its OUTPUT_NAME differs")
    ap.add_argument("--ctest", required=True, help="ctest -R regex")
    ap.add_argument("--expect", required=True, help="text a FAIL: line (or node:test assertion) must contain")
    ap.add_argument("--mutation", help="file to mutate, relative to --repo")
    ap.add_argument("--old")
    ap.add_argument("--new")
    ap.add_argument("--campaign", help="vNN: apply tools/mutations/mutate_vNN.py --id ID")
    ap.add_argument("--id")
    ap.add_argument("--label", default=None)
    ap.add_argument("--expect-verdict", default="KILLED", help="for testing this tool")
    ap.add_argument("--no-baseline", action="store_true",
                    help="skip the run of the test on the clean tree (only when it was just run)")
    args = ap.parse_args()
    if args.interpreted and args.campaign:
        sys.exit("--interpreted takes --mutation/--old/--new: campaigns mutate compiled code")
    if not args.interpreted and not args.target:
        sys.exit("--target is required unless --interpreted")
    repo = pathlib.Path(args.repo).resolve()
    args.build = str((repo / args.build) if not os.path.isabs(args.build) else pathlib.Path(args.build))
    label = args.label or (f"{args.campaign} {args.id}" if args.campaign else f"{args.mutation}")

    if args.campaign:
        script = repo / "tools" / "mutations" / f"mutate_{args.campaign}.py"
        text = script.read_text()
        # The touched files are the campaign's: every path literal it names.
        # Headers too: a campaign that mutates one was neither backed up nor restored (F371).
        sources = sorted({m for m in re.findall(r'"((?:apps|src|tests|web|bench|examples)/[^"]+\.[ch])"', text)})
        if not sources:
            sys.exit(f"{script.name} names no C source or header -- nothing to back up, nothing tested")
    else:
        if args.old is None or args.new is None:
            sys.exit("--mutation needs --old and --new")
        sources = [args.mutation]
    backups = {s: (repo / s).read_bytes() for s in sources}
    before = {s: sha(repo / s) for s in sources}

    if args.interpreted:
        rc0, clean = 0, before[sources[0]]
    else:
        rc0, clean = build(args, sources)
    if clean is None:
        print(f"{label}: CLEAN BUILD FAILED (exit {rc0}) -- nothing tested")
        sys.exit(2)

    # F675 (V4-342): the test must PASS on the clean code first. Without this
    # a check that fails by itself -- a flaky one, or one this very step
    # broke -- is a nonzero exit and a FAIL line with the expected text, and
    # was reported as the mutant's death.
    if not args.no_baseline:
        try:
            r0 = subprocess.run(["ctest", "--test-dir", args.build, "-R", args.ctest],
                                capture_output=True, text=True, timeout=3600)
            base_ok = (r0.returncode == 0)
        except subprocess.TimeoutExpired:
            base_ok = False
        if not base_ok:
            print(f"{label}: THE CLEAN TREE DOES NOT PASS {args.ctest} -- nothing tested")
            sys.exit(2)

    verdict, fails, mutant = "?", [], None
    try:
        if args.campaign:
            r = subprocess.run([sys.executable, str(script), str(repo), args.id], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"{label}: MUTATION NOT APPLIED: {r.stdout.strip()} {r.stderr.strip()}")
                sys.exit(2)
        else:
            p = repo / args.mutation
            t = p.read_text()
            n = t.count(args.old)
            if n != 1:
                print(f"{label}: ANCHOR MATCHES {n} TIMES, NOT ONCE -- nothing tested")
                sys.exit(2)
            p.write_text(t.replace(args.old, args.new, 1))
        if args.interpreted:
            rc1, mutant = 0, sha(repo / args.mutation)
        else:
            rc1, mutant = build(args, sources)
        if mutant is None:
            verdict = "KILLED(compile) -- not a kill"
        elif mutant == clean:
            verdict = "VOID (the mutant's code is the clean code)"
        else:
            # A test that never ends is not a named kill, and the tree is
            # still restored and rebuilt below (F675: the exception used to
            # leave the mutant's binary beside the restored source).
            try:
                r = subprocess.run(["ctest", "--test-dir", args.build, "-R", args.ctest, "-V"],
                                   capture_output=True, text=True, timeout=3600)
            except subprocess.TimeoutExpired:
                r = None
            if r is None:
                verdict = "KILLED(other) -- the test did not end in an hour"
            else:
                out = r.stdout
                fails = [l.split("FAIL: ", 1)[1] for l in out.splitlines() if "FAIL: " in l]
                named = any(args.expect in f for f in fails) or \
                    any(args.expect in l and ("AssertionError" in l or "not ok" in l) for l in out.splitlines())
                verdict = "KILLED" if (r.returncode != 0 and named) else ("KILLED(other)" if r.returncode != 0 else "SURVIVED")
    finally:
        for s, b in backups.items():
            (repo / s).write_bytes(b)
    restored = all(sha(repo / s) == before[s] for s in sources)
    if args.interpreted:
        back = "n/a"
    else:
        rc2, back = build(args, sources)
    kind = "(file)" if args.interpreted else "(code+objects)"
    # "ok" is the clean code again, not merely a binary that linked (F370).
    rebuilt = "n/a (interpreted)" if args.interpreted else (
        "ok" if back == clean else ("FAILED" if back is None else "NOT THE CLEAN CODE"))
    print(f"{label}: {verdict} | clean={clean[:12]} mutant={(mutant or 'none')[:12]} {kind} "
          f"| restored={'byte-exact' if restored else 'MISMATCH'} | rebuilt={rebuilt}")
    for f in fails:
        print(f"    FAIL: {f[:200]}")
    ok = verdict.split()[0] == args.expect_verdict and restored and (args.interpreted or back == clean)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
