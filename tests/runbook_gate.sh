#!/bin/sh
#
# V4-177 (F251): the runbook gate sees a command block it would not rehearse.
#
#   runbook_gate.sh <repo>
#
# tools/rehearse_runbook.py takes a block as commands only when its opening
# line is exactly ```bash. A block opened any other way was dropped from the
# rehearsal and `--check-substitutions` still passed: measured before the
# fix, 20 of the runbook's 35 blocks could be re-fenced one at a time with
# the gate staying green. Here EVERY block is re-fenced, one at a time and
# five ways each, and the gate must refuse every copy.
set -u
REPO="${1:?usage: runbook_gate.sh <repo>}"
command -v python3 >/dev/null 2>&1 || { echo "FAIL: RUNBOOK-GATE: python3 not found"; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/runbook-gate.XXXXXX") || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM
python3 - "$REPO" "$TMP" <<'PY'
import subprocess, sys
repo, tmp = sys.argv[1], sys.argv[2]
tool = repo + "/tools/rehearse_runbook.py"
fail = 0
def say(ok, what):
    global fail
    print("%s: RUNBOOK-GATE: %s" % ("PASS" if ok else "FAIL", what))
    fail |= (not ok)
def gate(text):
    open(tmp + "/RB.md", "w").write(text)
    r = subprocess.run([sys.executable, tool, tmp + "/RB.md", "--check-substitutions"],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr
md = open(repo + "/deploy/RUNBOOK.md").read()
rc, out = gate(md)
say(rc == 0 and "PASS: REHEARSAL" in out, "the runbook as committed passes (the canary)")
lines = md.split("\n")
opens = [i for i, l in enumerate(lines) if l.strip() == "```bash"]
say(len(opens) >= 30, "the runbook has command blocks to re-fence (%d)" % len(opens))
for tag in ["```sh", "```shell", "``` bash", "```Bash", "```console"]:
    missed = []
    for i in opens:
        m = lines[:]
        m[i] = m[i].replace("```bash", tag)
        rc, out = gate("\n".join(m))
        if rc == 0 or "is not rehearsed" not in out:
            missed.append(i + 1)
    say(not missed, "a block opened %r instead of ```bash is refused, for each of %d blocks%s (F251)"
        % (tag, len(opens), "" if not missed else " -- NOT refused at lines %s" % missed[:8]))
# ~~~ needs its closing line changed too, or the block is merely unclosed.
missed = []
for i in opens:
    m = lines[:]
    j = next(k for k in range(i + 1, len(m)) if m[k].strip() == "```")
    m[i] = m[i].replace("```bash", "~~~bash"); m[j] = m[j].replace("```", "~~~")
    rc, out = gate("\n".join(m))
    if rc == 0 or "is not rehearsed" not in out:
        missed.append(i + 1)
say(not missed, "a block fenced ~~~bash is refused, for each of %d blocks (F251)" % len(opens))
# The one block that is not commands is allowed by name, and only by name.
plain = "```\nlog_identities = hashed\n"
say(md.count(plain) == 1, "the runbook's one configuration block is where NOT_COMMANDS says (the control)")
rc, out = gate(md.replace(plain, "```\nlog_identities = hashed_\n"))
say(rc != 0 and "is not rehearsed" in out and "NOT_COMMANDS names a block" in out,
    "that block with its named line changed is refused, and the stale name is reported")
rc, out = gate(md.replace("## 16. ", "```\nsudo systemctl stop mldsa-authd\n```\n\n## 16. ", 1))
say(rc != 0 and "is not rehearsed" in out, "a second, unnamed plain block in a step is refused")
rc, out = gate(md + "\n```bash\necho unclosed\n")
say(rc != 0 and "never closed" in out, "a block that is opened and never closed is refused")
sys.exit(fail)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "PASS: runbook_gate" || echo "FAIL: runbook_gate"
exit "$rc"
