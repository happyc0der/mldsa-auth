#!/usr/bin/env python3
"""The review packet's claim map, checked against the tree (V4-14b).

docs/review/CLAIMS.md maps every security requirement -- spec-v2 §4 (P1-P13)
and the deployment spec's §5 (D1-D14) -- to the evidence that pins it. A map
that names a test check, a mutation or a proof that no longer exists tells a
reviewer something false, and nothing else in the tree would notice. This
does, in both directions:

  - every requirement in both specs has exactly one entry, whose heading
    carries the requirement's own bold title (so a renumbered or retitled
    requirement breaks the map instead of silently mis-pointing it);
  - every entry cites at least one piece of evidence and says what it does
    NOT establish;
  - every cited piece of evidence exists:
      check `T` "text"    T is a registered CTest and "text" appears verbatim
                          in T's source file
      mutation `vNN ID`   tools/mutations/spec_vNN.txt has a line for ID
      proverif "query"    formal/run.sh expects that exact result string
      fuzz `name`         tests/fuzz/fuzz_<name>.c exists
      tool `path`         the file exists
      ci `job`            some workflow names that job

Usage: check_claim_map.py <repo>
"""
import glob
import os
import re
import sys

ok = True


def report(name, good, detail=""):
    global ok
    print("  %-5s %-44s %s" % ("ok" if good else "FAIL", name, detail))
    if not good:
        ok = False


def spec_titles(path, heading, count_stop):
    """The bold titles of a numbered requirement list under `heading`."""
    text = open(path, encoding="utf-8").read()
    i = text.find(heading)
    if i < 0:
        return None
    j = text.find(count_stop, i + len(heading))
    body = text[i:j if j > 0 else len(text)]
    titles = {}
    # A bold title can wrap onto the next line (D4 does), so the match spans
    # newlines and the whitespace is collapsed.
    for m in re.finditer(r'^(\d+)\. \*\*(.+?)\*\*', body, re.M | re.S):
        titles[int(m.group(1))] = re.sub(r'\s+', ' ', m.group(2)).rstrip('.').strip()
    return titles


def norm(s):
    """Titles compare without Markdown backticks and trailing punctuation."""
    return re.sub(r'\s+', ' ', s.replace('`', '')).strip().rstrip('.:,')


def main(repo):
    os.chdir(repo)
    print("check_claim_map: docs/review/CLAIMS.md")
    claims_path = "docs/review/CLAIMS.md"
    if not os.path.exists(claims_path):
        report("the claim map exists", False, claims_path)
        return 1
    claims = open(claims_path, encoding="utf-8").read()

    want = {}
    p = spec_titles("docs/ml-dsa-auth-protocol-spec-v2.md", "## 4. Security Requirements", "\n## 5.")
    d = spec_titles("docs/mldsa-authd-spec.md", "## 5. Security requirements", "\n## 6.")
    report("spec-v2 §4 requirements found", bool(p), "%d" % len(p or {}))
    report("deployment §5 requirements found", bool(d), "%d" % len(d or {}))
    if not p or not d:
        return 1
    for n, t in p.items():
        want["P%d" % n] = t
    for n, t in d.items():
        want["D%d" % n] = t

    # Split the map into entries by their "### Xn — title" headings.
    entries = {}
    heads = list(re.finditer(r'^### ([PD]\d+) — (.+)$', claims, re.M))
    for k, m in enumerate(heads):
        end = heads[k + 1].start() if k + 1 < len(heads) else len(claims)
        if m.group(1) in entries:
            report("each requirement has ONE entry", False, "%s twice" % m.group(1))
        entries[m.group(1)] = (m.group(2).strip(), claims[m.end():end])

    missing = sorted(set(want) - set(entries), key=lambda x: (x[0], int(x[1:])))
    extra = sorted(set(entries) - set(want))
    report("every requirement has an entry", not missing, " ".join(missing) or "%d entries" % len(entries))
    report("no entry for a requirement that does not exist", not extra, " ".join(extra))

    bad_titles = [k for k in entries if k in want and norm(entries[k][0]) != norm(want[k])]
    report("each heading carries its requirement's title", not bad_titles,
           "; ".join("%s: map says '%s', spec says '%s'" % (k, entries[k][0], want[k]) for k in bad_titles))

    # What exists, for the evidence checks.
    cmake = open("tests/CMakeLists.txt", encoding="utf-8").read()
    ctests = set(re.findall(r'add_test\(\s*NAME\s+([A-Za-z0-9_]+)', cmake))
    run_sh = open("formal/run.sh", encoding="utf-8").read()
    workflows = "".join(open(w, encoding="utf-8").read() for w in glob.glob(".github/workflows/*.yml"))

    def test_source(name):
        for ext in (".c", ".sh", ".mjs"):
            for base in ("tests/%s%s" % (name, ext), "tests/fuzz/%s%s" % (name, ext)):
                if os.path.exists(base):
                    return base
        return None

    counts = {"check": 0, "mutation": 0, "proverif": 0, "fuzz": 0, "tool": 0, "ci": 0}
    bad = []
    thin = []
    for key, (title, body) in sorted(entries.items()):
        n_evidence = 0
        for line in body.splitlines():
            m = re.match(r'^- (check|mutation|proverif|fuzz|tool|ci)\b(.*)$', line)
            if not m:
                continue
            kind, rest = m.group(1), m.group(2)
            counts[kind] += 1
            n_evidence += 1
            if kind == "check":
                mm = re.match(r'\s*`([A-Za-z0-9_]+)`\s+"(.+)"', rest)
                if not mm:
                    bad.append("%s: unparseable check line" % key); continue
                t, text = mm.group(1), mm.group(2)
                src = test_source(t)
                if t not in ctests:
                    bad.append("%s: `%s` is not a registered CTest" % (key, t))
                elif src is None or text not in open(src, encoding="utf-8").read():
                    bad.append("%s: \"%s\" is not in %s" % (key, text, src or t))
            elif kind == "mutation":
                mm = re.match(r'\s*`(v\d+[a-z]?)\s+([A-Z]+\d+b?)`', rest)
                if not mm:
                    bad.append("%s: unparseable mutation line" % key); continue
                spec = "tools/mutations/spec_%s.txt" % mm.group(1)
                if not os.path.exists(spec) or not re.search(r'^%s\|' % re.escape(mm.group(2)),
                                                             open(spec).read(), re.M):
                    bad.append("%s: mutation %s %s is not in %s" % (key, mm.group(1), mm.group(2), spec))
            elif kind == "proverif":
                mm = re.match(r'\s*"(.+)"', rest)
                if not mm or mm.group(1) not in run_sh:
                    bad.append("%s: proverif query not expected by formal/run.sh" % key)
            elif kind == "fuzz":
                mm = re.match(r'\s*`([a-z0-9_]+)`', rest)
                if not mm or not os.path.exists("tests/fuzz/fuzz_%s.c" % mm.group(1)):
                    bad.append("%s: no fuzz target %s" % (key, mm.group(1) if mm else rest.strip()))
            elif kind == "tool":
                mm = re.match(r'\s*`([^`]+)`', rest)
                if not mm or not os.path.exists(mm.group(1)):
                    bad.append("%s: no such tool %s" % (key, mm.group(1) if mm else rest.strip()))
            elif kind == "ci":
                mm = re.match(r'\s*`([^`]+)`', rest)
                if not mm or mm.group(1) not in workflows:
                    bad.append("%s: no workflow names job %s" % (key, mm.group(1) if mm else rest.strip()))
        if n_evidence == 0 or "**Not established:**" not in body:
            thin.append(key)

    report("every entry cites evidence and a limit", not thin, " ".join(thin))
    report("every cited piece of evidence exists", not bad, "%d citation(s)" % sum(counts.values()))
    for b in bad:
        print("          " + b)
    print("  ---   " + ", ".join("%d %s" % (v, k) for k, v in counts.items()))
    if ok:
        print("OK: every requirement is mapped, and everything the map cites exists")
        return 0
    print("FAIL: the claim map and the tree disagree")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check_claim_map.py <repo>")
    sys.exit(main(sys.argv[1]))
