#!/usr/bin/env python3
"""Anchor dry-run for tools/mutations/: every mutation's anchor string must
still match EXACTLY ONCE in its target file.

  check_mutation_anchors.py <repo>

WHY THIS EXISTS. A step rots OTHER steps' anchors. V4-9a rotted v47's S6/S8 and
v48a's D4 and it was the nightly that noticed, after the merge; V4-9c rotted
v47's S1 and the bring-up branch caught it first. A campaign whose anchor no
longer matches does not fail quietly -- run_mutations_v2.sh aborts loudly -- but
it aborts an hour into a nightly rather than in the second before an edit. This
runs in that second.

It reads the tables STATICALLY: the mutate scripts apply their edit on import,
so importing one to inspect it would modify the tree. Nothing here is written.

Coverage is asserted against spec_v*.txt, so a table shape this script fails to
understand is REPORTED, never silently skipped -- the first draft quietly
covered 104 of 123 mutations and called it "ALL ANCHORS OK".

Four table shapes exist in this repo and all four are handled:
  A  M = { "ID": (path, [(old,new), ...]) }            v29,v46..v49c
  B  M = { "ID": [(path, old, new), ...] }             v23
  C  M = { "ID": (path, old, new) }                    v27,v28
  D  M["ID"] = lambda: edit(path, old, new)            v24,v25,v26
Coverage is asserted against spec_v*.txt, so a shape this script fails to
understand is reported, never silently skipped."""
import ast, sys, pathlib, re
repo = pathlib.Path(sys.argv[1])
PATHRE = re.compile(r'^[\w./-]+\.(c|h|sh|py|cmake|txt|yml|mjs)$')

def ev(node, env):
    if isinstance(node, ast.Name):
        if node.id not in env: raise KeyError(node.id)
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [ev(e, env) for e in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return ev(node.left, env) + ev(node.right, env)
    return ast.literal_eval(node)

def from_calls(node, env):
    """Shape D: any edit(path, old, new) call reachable from this value."""
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "edit" and len(sub.args) >= 2:
            try:
                p, o = ev(sub.args[0], env), ev(sub.args[1], env)
            except Exception:
                continue
            if isinstance(p, str) and isinstance(o, str) and PATHRE.match(p):
                out.append((p, o))
    return out

def from_literal(v):
    if isinstance(v, list) and len(v) == 3 and all(isinstance(x, str) for x in v) and PATHRE.match(v[0]):
        return [(v[0], v[1])]
    if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and PATHRE.match(v[0]) \
       and isinstance(v[1], list):
        return [(v[0], pair[0]) for pair in v[1]]
    if isinstance(v, list):
        out = []
        for item in v: out += from_literal(item)
        return out
    raise ValueError("unrecognised literal shape")

bad = checked = 0
specs = sorted((repo/"tools/mutations").glob("spec_v*.txt"))
for spec in specs:
    ver = spec.name[len("spec_"):-len(".txt")]
    lines = [l for l in spec.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    want = [l.split("|")[0].strip() for l in lines]
    # Every kill must name its check (audit finding F90) -- the runner
    # refuses such a spec too, but only when a campaign runs; this is CI's.
    for l in lines:
        f = l.split("|")
        if len(f) != 3 or not f[2].strip():
            print(f"UNNAMED {ver} {f[0]}: no expected check (ID|ctest-regex|expectations)"); bad += 1
    sc = repo/"tools/mutations"/f"mutate_{ver}.py"
    tree = ast.parse(sc.read_text()); env = {}; entries = []
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            t = n.targets[0]
            if isinstance(t, ast.Name):
                try: env[t.id] = ev(n.value, env)
                except Exception: pass
                if t.id == "M" and isinstance(n.value, ast.Dict):
                    entries += [(ast.literal_eval(k), v) for k, v in zip(n.value.keys, n.value.values)]
            elif isinstance(t, ast.Subscript) and getattr(t.value, "id", None) == "M":
                entries.append((ast.literal_eval(t.slice), n.value))
    seen = set()
    for mid, v in entries:
        # M["ID"] = some_function  -> walk that function's body
        target = funcs[v.id] if (isinstance(v, ast.Name) and v.id in funcs) else v
        try:
            items = from_literal(ev(target, env))
        except Exception:
            items = from_calls(target, env)
        if not items:
            print(f"ROTTED? {ver} {mid}: NO ANCHOR EXTRACTED -- inspect by hand"); bad += 1; continue
        seen.add(mid)
        for path, old in items:
            f = repo/path
            checked += 1
            if not f.exists():
                print(f"ROTTED {ver} {mid}: target file is gone: {path}"); bad += 1; continue
            c = f.read_text().count(old)
            if c != 1:
                print(f"ROTTED {ver} {mid}: anchor matches {c}x in {path}"); bad += 1
    missing = [i for i in want if i not in seen]
    if missing:
        print(f"UNCOVERED {ver}: spec IDs with no checked anchor: {missing}"); bad += 1
n_mut = sum(len([l for l in s.read_text().splitlines() if l.strip() and not l.startswith('#')]) for s in specs)
print(f"--- {checked} anchors checked; {n_mut} mutations across {len(specs)} campaigns")

# V4-34: the documents that state these counts, checked against them. Three
# had drifted unnoticed -- 305 and 40 after V4-29 and V4-30 made it 312 and
# 42, and a "thirty-nine" and a "299" older still -- because nothing compared
# them. Each pattern must be FOUND as well as agree, so rewording a sentence
# fails here instead of silently retiring its check.
n_camp = len(specs)
STATED = [
    ("README.md", r"\*\*all (\d+)\*\* must-kill mutations", n_mut),
    ("README.md", r"all (\d+) committed campaigns against fresh ASan trees", n_camp),
    ("README.md", r"fresh ASan trees \u2014 (\d+) on Linux, and v35 on macOS", n_camp - 1),
    ("tools/README.md", r"authority on the count: (\d+) must-kill mutations", n_mut),
    ("tools/README.md", r"must-kill mutations across (\d+) campaigns", n_camp),
    ("tools/README.md", r"All (\d+) committed campaigns run nightly", n_camp),
    ("tools/README.md", r"(\d+) architecture-independent ones on Linux", n_camp - 1),
    ("tools/README.md", r"The nightly verifies \*\*all (\d+)\*\*", n_mut),
]
for doc, pat, want_n in STATED:
    text = (repo/doc).read_text()
    m = re.search(pat, text)
    if m is None:
        print(f"COUNT {doc}: the sentence /{pat}/ is gone -- update this check with the document"); bad += 1
    elif int(m.group(1)) != want_n:
        print(f"COUNT {doc}: says {m.group(1)} where the campaigns say {want_n} (/{pat}/)"); bad += 1
if bad == 0:
    print(f"counts: the {len(STATED)} stated counts in README.md and tools/README.md agree ({n_mut} mutations, {n_camp} campaigns)")
print("ALL ANCHORS OK" if bad == 0 else f"{bad} PROBLEM(S)")
sys.exit(1 if bad else 0)
