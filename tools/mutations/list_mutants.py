#!/usr/bin/env python3
"""list_mutants.py <repo> [file-substring ...]
Every committed mutation as: campaign id ctest-regex file[,file...]
Uses the same AST reading as tools/audit/check_mutation_anchors.py, so it sees
EVERY campaign format (the old ones execute sys.argv at import and cannot be
imported). With file substrings, only mutations touching a matching file."""
import ast, sys, pathlib, re
repo = pathlib.Path(sys.argv[1]); want = sys.argv[2:]
PATHRE = re.compile(r'^[\w./-]+\.(c|h|sh|py|cmake|txt|yml|mjs)$')
def ev(node, env):
    if isinstance(node, ast.Name):
        if node.id not in env: raise KeyError(node.id)
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List)): return [ev(e, env) for e in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add): return ev(node.left, env) + ev(node.right, env)
    return ast.literal_eval(node)
def from_calls(node, env):
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "edit" and len(sub.args) >= 2:
            try: p, o = ev(sub.args[0], env), ev(sub.args[1], env)
            except Exception: continue
            if isinstance(p, str) and isinstance(o, str) and PATHRE.match(p): out.append((p, o))
    return out
def from_literal(v):
    if isinstance(v, list) and len(v) == 3 and all(isinstance(x, str) for x in v) and PATHRE.match(v[0]): return [(v[0], v[1])]
    if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and PATHRE.match(v[0]) and isinstance(v[1], list):
        return [(v[0], pair[0]) for pair in v[1]]
    if isinstance(v, list):
        out = []
        for item in v: out += from_literal(item)
        return out
    raise ValueError
n = 0
for spec in sorted((repo/"tools/mutations").glob("spec_v*.txt")):
    ver = spec.name[5:-4]
    rx = {l.split("|")[0].strip(): l.split("|")[1].strip() for l in spec.read_text().splitlines() if l.strip() and not l.startswith("#")}
    tree = ast.parse((repo/"tools/mutations"/f"mutate_{ver}.py").read_text()); env = {}; entries = []
    funcs = {x.name: x for x in tree.body if isinstance(x, ast.FunctionDef)}
    for x in tree.body:
        if isinstance(x, ast.Assign) and len(x.targets) == 1:
            t = x.targets[0]
            if isinstance(t, ast.Name):
                try: env[t.id] = ev(x.value, env)
                except Exception: pass
                if t.id == "M" and isinstance(x.value, ast.Dict):
                    entries += [(ast.literal_eval(k), v) for k, v in zip(x.value.keys, x.value.values)]
            elif isinstance(t, ast.Subscript) and getattr(t.value, "id", None) == "M":
                entries.append((ast.literal_eval(t.slice), x.value))
    for mid, v in entries:
        if mid not in rx: continue
        target = funcs[v.id] if (isinstance(v, ast.Name) and v.id in funcs) else v
        try: items = from_literal(ev(target, env))
        except Exception: items = from_calls(target, env)
        files = sorted({p for p, _ in items})
        if want and not any(w in f for w in want for f in files): continue
        print(ver, mid, rx[mid], ",".join(files)); n += 1
print(f"# {n} mutations", file=sys.stderr)
