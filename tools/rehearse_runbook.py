#!/usr/bin/env python3
"""Rehearse deploy/RUNBOOK.md on a disposable Linux host (V4-99).

The runbook says "each step says what it should print, so you can tell a
success from a silence" -- but until V4-99 nobody had run it top to bottom on
a host with systemd, a service user, a packaged Caddy and a site user. This
tool does, from the runbook's OWN TEXT: it extracts every ```bash block under
each numbered step and runs it as written. It never carries a second copy of
the commands, so a runbook edit is rehearsed the next time this runs.

Where a step cannot be run literally (an interactive editor, a placeholder
like <handle>, a laptop on the far end of an SSH tunnel), a SUBSTITUTION is
declared below with its reason. Each must match the step's text EXACTLY ONCE,
or the rehearsal fails: a runbook that drifted out from under a substitution
is reported, never silently skipped. Lines this tool adds of its own are
HARNESS lines, printed as such, and never stand in for a runbook command.

Each step's documented output ("must end OK: ...", "prints {"port":9080}") is
checked as an EXPECT.

It must run on a throwaway machine: it creates system users, installs into
/usr/local, writes /etc and starts services. It refuses to run unless
REHEARSAL_HOST_IS_DISPOSABLE=1 is set (the workflow sets it).

  python3 tools/rehearse_runbook.py deploy/RUNBOOK.md [--keep-going]
  python3 tools/rehearse_runbook.py deploy/RUNBOOK.md --check-substitutions

Exit 0 only if every step ran and every EXPECT held. --check-substitutions
runs NOTHING: it checks only that every substitution still matches its step's
text exactly once and that every numbered step with commands is either
rehearsed or skipped with a reason, so CI can gate a runbook edit cheaply on
any machine.
"""
import os
import re
import subprocess
import sys

SRC = "/opt/build/mldsa-auth"
STATE = "/tmp/rehearsal.env"

# step -> list of (old, new, reason). old must occur exactly once.
SUBST = {
    1: [("sh deploy/fetch-deps.sh /opt/mldsa-deps        # networked machine, once\n"
         "# carry /opt/mldsa-deps across, then, AS THE USER WHO WILL BUILD:\n"
         "chown -R \"$(id -un)\" /opt/mldsa-deps\n"
         "cmake -S . -B build-release -DMLDSA_DEPS_CACHE=/opt/mldsa-deps ...",
         "# (offline alternative not taken: this host is networked)",
         "the offline path is an alternative to the block above, not a "
         "second step; CI's `unit + offline build` job rehearses it")],
    7: [("sudo -e /etc/mldsa-authd/authd.conf      # set site_uids and proxy_uids",
         "sudo sed -i -e \"s/^site_uids = .*/site_uids = $(id -u www-data)/\" "
         "-e \"s/^proxy_uids = .*/proxy_uids = $(id -u caddy)/\" /etc/mldsa-authd/authd.conf",
         "an interactive editor; the edit the comment asks for, made with sed")],
    10: [("sudo -e /etc/caddy/Caddyfile          # set your real hostname",
          "sudo sed -i 's/^authd.example.com {/localhost {/' /etc/caddy/Caddyfile",
          "an interactive editor; `localhost` gets Caddy's internal CA, no ACME")],
    11: [("authd_client keygen --dir ~/.mldsa --passphrase-prompt",
          "HANDLE=$(authd_client keygen --dir ~/.mldsa --passphrase-file ~/op.pass | tail -n 1)\n"
          "echo \"HANDLE=$HANDLE\" >> " + STATE + "\n"
          "cp ~/.mldsa/$HANDLE.pub ./$HANDLE.pub",
          "the prompt cannot be typed at; the runbook names --passphrase-file as "
          "the scripted equivalent, held to the same policy"),
         ("--user you --handle <handle> --pub <handle>.pub --label \"laptop\"",
          "--user you --handle $HANDLE --pub $HANDLE.pub --label \"laptop\"",
          "the placeholder, filled with what keygen printed"),
         ("ssh -L 8443:127.0.0.1:8443 your-vps\n", "",
          "the laptop and the server are one host here; the tunnel's far end is "
          "the same 127.0.0.1:8443"),
         ("authd_client login --handle <handle> --key ~/.mldsa/<handle>.ek \\\n"
          "    --passphrase-prompt",
          "authd_client login --handle $HANDLE --key ~/.mldsa/$HANDLE.ek \\\n"
          "    --passphrase-file ~/op.pass",
          "the placeholder, and the scripted passphrase as above")],
    15: [("--server-id authd --id alice@example.org'",
          "--server-id authd --id '\"$HANDLE\"'' | tee /tmp/idh.out",
          "the device enrolled in step 11, whose login is in the journal "
          "(event=login-code-issued names the handle), not the example's alice"),
         ("journalctl -u mldsa-authd | grep -F 'idh=3f09c2d18a7be641'",
          "journalctl -u mldsa-authd | grep -F \"$(grep -o 'idh=[0-9a-f]*' /tmp/idh.out)\" | tail -n 3",
          "the pseudonym the first command printed, not the example's")],
    12: [("BACKUP=/var/lib/mldsa-authd/backups/YYYY-MM-DD.sqlite3    # the one to restore",
          "BACKUP=$(sudo sh -c 'ls /var/lib/mldsa-authd/backups/*.sqlite3' | tail -n 1)",
          "the placeholder, filled with the backup this step just took: the "
          "newest file there, not today's date, which is another day's when "
          "the rehearsal crosses midnight (F221)")],
    13: [("emcmake cmake", ". \"$EMSDK_ENV\" && emcmake cmake",
          "emsdk's environment, which an operator's shell would already have")],
    14: [("sudo -u www-data node /opt/mldsa-site/examples/site-node/server.mjs \\",
          "sudo -u www-data nohup node /opt/mldsa-site/examples/site-node/server.mjs \\",
          "the site runs under a process manager, not in this shell"),
         ("--invite-file /etc/mldsa-site/invite --port 9080 --secure --trust-proxy",
          "--invite-file /etc/mldsa-site/invite --port 9080 --secure --trust-proxy "
          "> /tmp/site.out 2> /tmp/site.err &\n"
          "for i in $(seq 1 50); do grep -q port /tmp/site.out 2>/dev/null && break; "
          "sleep 0.2; done; cat /tmp/site.out; cat /tmp/site.err >&2",
          "backgrounded, and its first line awaited")],
}

# Part III: the placeholder and the prompt, as in step 11.
SUBST.update({
    19: [("authd_client rotate --handle <handle> --key ~/.mldsa/<handle>.ek \\\n"
          "    --passphrase-prompt --server-id authd --server-pub ./server.pub --port 8443",
          "authd_client rotate --handle $HANDLE --key ~/.mldsa/$HANDLE.ek \\\n"
          "    --passphrase-file ~/op.pass --server-id authd --server-pub ./server.pub --port 8443",
          "the placeholder and the scripted passphrase, as in step 11"),
         ("authd_client login --handle <handle> --key ~/.mldsa/<handle>.ek \\\n"
          "    --passphrase-prompt --server-id authd --server-pub ./server.pub --port 8443",
          "authd_client login --handle $HANDLE --key ~/.mldsa/$HANDLE.ek \\\n"
          "    --passphrase-file ~/op.pass --server-id authd --server-pub ./server.pub --port 8443",
          "the placeholder and the scripted passphrase, as in step 11")],
    24: [("BACKUP=$OFFHOST/YYYY-MM-DD.sqlite3                # the store backup to restore",
          "BACKUP=$(sudo sh -c \"ls -t $OFFHOST/*.sqlite3\" | head -n 1)",
          "the placeholder, filled with the newest backup in the copy")],
    22: [("git pull --ff-only",
          "# (git pull: this host already holds the source under test)",
          "the runner's copy is the commit under test, with nowhere to pull from")],
})

# steps whose blocks are not for this host
SKIP = {
    17: "connects to authd.example.com, a host that is not this one",
    18: "a phone, and the timing tool on the build host",
}

# Lines the HARNESS runs before a step: the things the runbook says the
# operator already has ("0. What you need", "copy it to your operators").
PRE = {
    # step 19's claim is that the OLD key stops working: keep a copy of it.
    19: ["cp ~/.mldsa/$HANDLE.ek /tmp/old.ek"],
    1: ["test -d " + SRC],
    # step 23's claim is that the pseudonym does not change: step 15 left the
    # device's in /tmp/idh.out, under the old passphrase.
    23: ["cp /tmp/idh.out /tmp/idh.before",
         "sudo od -An -tu1 -j8 -N1 /var/lib/mldsa-authd/server.ek | tr -d ' ' | sed 's/^/ek-version-before=/'"],
    # Step 24 restores onto a host that has lost everything. This host has
    # not, so the harness plays what came before: the operator's latest
    # backup, the runbook's OWN copy-off block (step 12) run again as the
    # runbook says to after step 23, and then the loss itself.
    24: ["sudo authd_admin backup --socket /run/mldsa-authd/admin.sock "
         "--path /var/lib/mldsa-authd/backups/before-loss.sqlite3",
         "@runbook:12:mldsa-authd-offhost/",
         "sudo systemctl stop mldsa-authd; "
         "sudo sh -c 'rm -f /var/lib/mldsa-authd/server.ek /var/lib/mldsa-authd/server.pub "
         "/var/lib/mldsa-authd/store.sqlite3*'; "
         "echo \"left-after-loss=$(sudo ls /var/lib/mldsa-authd/ | grep -cE '^(server\\.(ek|pub)|store\\.sqlite3.*)$' || true)\""],
    11: ["sudo cp /var/lib/mldsa-authd/server.pub ./server.pub",
         "openssl rand -base64 33 | tr -d '\\n' > ~/op.pass; chmod 600 ~/op.pass"],
}

# The device's login, as step 11 makes it; and the same with the copy of the
# key step 19 retired.
LOGIN = "authd_client login --handle $HANDLE --key ~/.mldsa/$HANDLE.ek --passphrase-file ~/op.pass --server-id authd --server-pub ./server.pub --port 8443"
LOGIN_OLD = LOGIN.replace("--key ~/.mldsa/$HANDLE.ek", "--key /tmp/old.ek")

# Checks the HARNESS runs after a step, for what the step says should hold.
POST = {
    19: [LOGIN_OLD + " > /tmp/old.out 2>&1 && echo old-key-ACCEPTED || echo old-key-refused; tail -n 2 /tmp/old.out"],
    20: [LOGIN + " > /tmp/dis.out 2>&1 && echo disabled-user-ACCEPTED || echo disabled-user-refused; tail -n 2 /tmp/dis.out"],
    21: [LOGIN],
    22: [LOGIN],
    # V4-153: the restored daemon serves the device enrolled in step 11 with
    # the pin it has had since then, and the restored chain verifies.
    24: [LOGIN, "@runbook:12:audit-verify"],
    # V4-108 (F190): after the passphrase change the daemon is running on the
    # swapped key and credential; a device logs in, the runbook's OWN
    # audit-verify block (which names the standard paths, so it now reads the
    # new pair) verifies the whole chain, and the runbook's own pseudonym
    # block prints the pseudonym it printed in step 15.
    23: [LOGIN,
         "@runbook:12:audit-verify",
         "@runbook:15:pseudonym",
         "echo \"pseudonym-same=$(cmp -s /tmp/idh.before /tmp/idh.out && grep -cE '^idh=[0-9a-f]{16}$' /tmp/idh.out)\"",
         "sudo od -An -tu1 -j8 -N1 /var/lib/mldsa-authd/server.ek | tr -d ' ' | sed 's/^/ek-version-after=/'",
         # grep -c exits 1 on a count of zero, which under pipefail failed the
         # step on its first real run (V4-108 bring-up); so the counts go
         # through echo. A zero means nothing unless the listing worked, so
         # the two files that must be there are counted from the same listing.
         "sudo ls /var/lib/mldsa-authd/ /etc/mldsa-authd/ > /tmp/ls23.txt; "
         "echo \"listed=$(grep -cE '^(server\\.ek|passphrase\\.cred)$' /tmp/ls23.txt)\"; "
         "echo \"leftovers=$(grep -cE '\\.(old|new)$' /tmp/ls23.txt)\""],
    # Step 18's journal check, made here: with log_identities = hashed and
    # log_client_ip = prefix, no line may carry a plain id= or a full address.
    # A count of zero full addresses means nothing if no line carries an
    # address at all, and the operator's loopback login carries none by
    # design. So first a connection through Caddy's PROXY v2 path -- a
    # WebSocket upgrade to /authd/v1, which the daemon accepts and logs with
    # the preamble's client address -- and then at least one /24 is required.
    16: ["curl -sk --http1.1 --max-time 3 -o /dev/null -w 'upgrade %{http_code}\\n' "
         "-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' "
         "-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://localhost' "
         "https://localhost/authd/v1 || true; sleep 1",
         "sudo journalctl -u mldsa-authd --no-pager > /tmp/j16.txt; "
         "echo \"plain-ids=$(grep -cE '[[:space:]]id=' /tmp/j16.txt)\"; "
         # IPv4 AND IPv6: `localhost` is ::1 first, so Caddy's preamble
         # carries an IPv6 address (V4-99: an IPv4-only pattern saw none).
         "echo \"full-src=$(grep -cE 'src=[0-9A-Fa-f:.]+([[:space:]]|$)' /tmp/j16.txt)\"; "
         "echo \"prefix-src=$(grep -cE 'src=[0-9A-Fa-f:.]+/(24|48)([[:space:]]|$)' /tmp/j16.txt)\"; "
         "grep -F 'event=client-address' /tmp/j16.txt | tail -n 2",
         # V4-100: a person in a browser, through Caddy, the site and the
         # daemon as deployed (tools/rehearsal_browser.mjs).
         "sudo cat /etc/mldsa-site/invite > /tmp/invite",
         "node tools/rehearsal_browser.mjs https://localhost /tmp/invite browser-user \"$CHROME\"",
         # Step 18's check, on that login: the journal names it by pseudonym
         # and prefix only.
         "sleep 1; sudo journalctl -u mldsa-authd --no-pager | grep -E 'event=(login-code-issued|client-address)' | tail -n 4",
         # V4-100: the restore drill, after a CRASH -- the case a restore is
         # for. step 12 took the backup before the browser user existed. The
         # daemon is killed (and stopped inside RestartSec, so systemd does
         # not restart it and checkpoint the WAL), the store is restored as
         # the runbook says, and the browser user must be GONE.
         # (after the browser's own recovery, which spends from the same bucket)
         # V4-105: the recovery route's per-client limit, through the REAL
         # proxy, against a client that forges X-Forwarded-For: six attempts,
         # each claiming a different address, and the sixth is 429 (burst 5).
         # What this proves is the DEPLOYMENT's property -- forging the header
         # does not escape the limit here -- and not the site's rightmost-entry
         # rule (F159): a control keyed on the LEFTMOST entry passed too
         # (CI 42839894252), because Caddy replaces a client's X-Forwarded-For
         # rather than appending to it, so the forged value never arrives. The
         # rightmost rule is for proxies that append; its unit tests are V4-79's.
         "for i in 1 2 3 4 5 6; do curl -sk -c /tmp/cj -b /tmp/cj -o /dev/null -w \"recover $i %{http_code}\\n\" "
         "-X POST -H 'Origin: https://localhost' -H 'Content-Type: application/json' "
         "-H \"X-Forwarded-For: 198.51.100.$i\" "
         "--data '{\"user\":\"nobody\",\"code\":\"AAAA-AAAA-AAAA-AAAA\"}' https://localhost/api/recover; done",
         "sudo authd_admin list-users --socket /run/mldsa-authd/admin.sock | tee /tmp/users.before",
         "sudo systemctl kill -s KILL mldsa-authd; sudo systemctl stop mldsa-authd; "
         "sudo ls -l /var/lib/mldsa-authd/ | sed 's/^/  /'",
         # The runbook's OWN restore and audit-verify blocks (step 12), not a
         # copy of them: @runbook:STEP:MARKER is that step's block holding
         # MARKER, with the step's substitutions applied.
         "@runbook:12:sudo systemctl stop mldsa-authd",
         "sleep 1; systemctl is-active mldsa-authd",
         "@runbook:12:audit-verify",
         "sudo authd_admin list-users --socket /run/mldsa-authd/admin.sock | tee /tmp/users.after",
         # list-users prints ids in hex
         "U=$(printf browser-user | od -An -tx1 | tr -d ' \\n'); "
         "echo \"browser-user-before=$(grep -c \"user=$U \" /tmp/users.before) after-restore=$(grep -c \"user=$U \" /tmp/users.after)\""],
    9: ["sleep 1; journalctl -u mldsa-authd --no-pager -n 30 | tee /tmp/j9.txt"],
    14: [
        # The pages are served through Caddy, and the site reaches site.sock:
        # a session is opened, then a bogus code is EXCHANGEd and the DAEMON
        # refuses it (403 login-failed). A site that cannot reach the socket
        # answers otherwise.
        "curl -sk -o /dev/null -w 'login.html %{http_code}\\n' https://localhost/login.html",
        "curl -sk -c /tmp/cj -b /tmp/cj -o /dev/null -w 'session %{http_code}\\n' https://localhost/api/session",
        "curl -sk -c /tmp/cj -b /tmp/cj -X POST -H 'Origin: https://localhost' "
        "-H 'Content-Type: application/json' "
        "--data '{\"code\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}' "
        "-w ' login %{http_code}\\n' https://localhost/api/login",
        # V4-96 made every login failure the same 403, so the site's answer
        # cannot say whether the DAEMON refused the code or the site never
        # reached it. The daemon's own journal can: it logs every local
        # request with the command and the peer's uid.
        "sleep 0.5; sudo journalctl -u mldsa-authd --no-pager | grep -F 'event=local-request' | tail -n 3",
    ],
}

EXPECT = {
    2: [r"OK: every discovered executable carries the full hardening set \[Linux\]"],
    5: [r"server\.pub"],
    9: [r"proxy_protocol=v2", r"event=started", r"event=listening-",
        r"event=memlock-limit"],
    11: [r"(?m)^[A-Za-z0-9_-]{43}$"],
    # The audit unit's lines come from authd_admin[pid], not from the unit's
    # name; `journalctl -u mldsa-authd-audit` is what scopes them to it.
    12: [r"(?i)head",
         r"authd_admin\[\d+\]: \S*authd_admin audit-verify: head=[0-9a-f]{64}",
         r"authd_admin\[\d+\]: \S*authd_admin audit-verify: the audit chain verifies \(\d+ entries\)",
         r"Finished mldsa-authd-audit\.service"],
    13: [r"100% tests passed(, 0 tests failed)? out of 3"],
    14: [r'\{"port":9080\}', r"login\.html 200", r"session 200",
         r'"login-failed"\} login 403', r"event=local-request.*EXCHANGE"],
    15: [r"(?m)^idh=[0-9a-f]{16}$", r"event=login-code-issued.*idh="],
    19: [r"(?m)^[A-Za-z0-9_-]{43}$", r"(?m)^old-key-refused$"],
    20: [r"(?m)^disabled-user-refused$"],
    21: [r"(?m)^[A-Za-z0-9_-]{43}$"],
    22: [r"OK: every discovered executable carries the full hardening set \[Linux\]",
         r"event=started", r"(?m)^[A-Za-z0-9_-]{43}$"],
    23: [r"wrote /var/lib/mldsa-authd/server\.ek\.new \(MLDSAEK1 version 2, mode 0600\)",
         r"(?m)^ek-version-before=2$", r"(?m)^ek-version-after=2$",
         r"event=started", r"(?m)^[A-Za-z0-9_-]{43}$",
         # twice: the runbook's own check of the new pair before the swap,
         # and step 12's block after it
         r"(?s)the audit chain verifies \(\d+ entries\).*the audit chain verifies \(\d+ entries\)",
         r"(?m)^pseudonym-same=1$", r"(?m)^listed=2$", r"(?m)^leftovers=0$"],
    24: [r"(?m)^left-after-loss=0$", r"(?m)^active$", r"(?m)^[A-Za-z0-9_-]{43}$",
         r"the audit chain verifies \(\d+ entries\)"],
    16: [r"(?m)^plain-ids=0$", r"(?m)^full-src=0$", r"(?m)^prefix-src=[1-9]",
         r"PASS: BROWSER: a person enrolled and logged in through the deployed stack",
         r"PASS: BROWSER: recovery: a fresh browser recovered with a code, enrolled a new device and logged in",
         # the bucket may start below 5 (the browser's recovery spends from
         # it), so only the sixth is certain: refused, whatever it claims.
         r"(?m)^recover 6 429$",
         r"event=login-code-issued slot=\d+ idh=[0-9a-f]{16}",
         r"event=client-address slot=\d+ src=[0-9A-Fa-f:.]+/(24|48) detail=admitted",
         r"(?m)^browser-user-before=1 after-restore=0$"],
}
# patterns that must NOT appear in a step's output
FORBID = {
    # systemd-analyze verify on the audit units: any diagnostic that names
    # them (the host's OTHER units may warn; those are not this file's).
    12: [r"mldsa-authd-audit\.(service|timer):\d+"],
    8: [r"(?i)warning|unknown|invalid"],
    # The daemon's line is "<level> event=<name> ...": the level comes FIRST
    # and has no key. Until V4-111 this pattern looked for "level=warn", which
    # no line the daemon writes contains, so it could not fail (F201).
    # store-created: step 5's init made the store, so a daemon that says it
    # created one was pointed at the wrong path (F199).
    9: [r"\bwarn event=memlock-limit\b", r"event=store-created",
        r"created a new, empty store"],
}
# What each FORBID pattern is FOR, as the journal would show it. A pattern
# that matches none of its step's lines here forbids nothing, and
# --check-substitutions says so (F201). The formats are the daemon's:
# authd_log.c writes "<level> event=<name>[ key=value]...".
FORBID_SAMPLE = {
    8: ["/etc/systemd/system/mldsa-authd.service:12: Unknown key name 'Foo' in section 'Service', ignoring."],
    9: ["Nov 11 10:00:00 host mldsa-authd[812]: warn event=memlock-limit need=10485760",
        "Nov 11 10:00:00 host mldsa-authd[812]: warn event=store-created",
        "Nov 11 10:00:00 host mldsa-authd[812]: mldsa-authd: /var/lib/mldsa-authd/store.sqlite: created a new, empty store (no store was there)"],
    12: ["/etc/systemd/system/mldsa-authd-audit.service:7: Unknown key name 'Foo' in section 'Service', ignoring."],
}
# ...and what each must NOT catch: the same events on a healthy host.
FORBID_CLEAN = {
    9: ["Nov 11 10:00:00 host mldsa-authd[812]: info event=memlock-limit need=10485760",
        "Nov 11 10:00:00 host mldsa-authd[812]: info event=started"],
}
# commands whose nonzero exit is the documented result, not a failure
ALLOW_NONZERO = {16: ["grep"], 23: ["grep"], 24: ["grep"]}


def steps(md):
    """{n: (title, [bash block text, ...])} for '## n. title' headings."""
    out, cur = {}, None
    lines = md.split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^## (\d+)\. (.*)$", lines[i])
        if m:
            cur = int(m.group(1))
            out[cur] = (m.group(2), [])
        elif re.match(r"^## |^# ", lines[i]):
            cur = None
        elif cur is not None and lines[i].strip() == "```bash":
            ind = len(lines[i]) - len(lines[i].lstrip())
            j, blk = i + 1, []
            while lines[j].strip() != "```":
                blk.append(lines[j][ind:])
                j += 1
            out[cur][1].append("\n".join(blk))
            i = j
        i += 1
    return out


def runbook_block(st, ref):
    """@runbook:STEP:MARKER -> that step's one block holding MARKER, with the
    step's substitutions applied. Exactly one block must hold it."""
    _, step, marker = ref.split(":", 2)
    step = int(step)
    hits = [b for b in st[step][1] if marker in b]
    if len(hits) != 1:
        raise SystemExit("%s: %d blocks of step %d hold the marker" % (ref, len(hits), step))
    text = hits[0]
    for old, new, _why in SUBST.get(step, []):
        text = text.replace(old, new)
    return text


def post_line(st, c):
    if c.startswith("@runbook:"):
        text = runbook_block(st, c)
        return "echo 'HARNESS: again, the runbook block %s:'\n%s\n" % (c[9:].replace("'", ""), text)
    return "echo 'HARNESS: %s'\n%s\n" % (c.replace("'", "")[:90], c)


def check_substitutions(st):
    bad = []
    for n, subs in sorted(SUBST.items()):
        if n not in st:
            bad.append("step %d has substitutions but no longer exists" % n)
            continue
        text = "\n".join(st[n][1]) + "\n"
        for old, _new, _why in subs:
            c = text.count(old)
            if c != 1:
                bad.append("step %d: substitution matches %d times: %r" % (n, c, old[:70]))
    for n in sorted(set(SKIP) | set(PRE) | set(POST) | set(EXPECT)):
        if n not in st:
            bad.append("step %d is configured here but not in the runbook" % n)
    for n, cmds in list(POST.items()) + list(PRE.items()):
        for c in cmds:
            if c.startswith("@runbook:"):
                try:
                    runbook_block(st, c)
                except SystemExit as e:
                    bad.append(str(e))
    for n, pats in sorted(FORBID.items()):
        for rx in pats:
            if not any(re.search(rx, l) for l in FORBID_SAMPLE.get(n, [])):
                bad.append("step %d: FORBID /%s/ matches none of its sample lines, so it forbids nothing" % (n, rx))
            for l in FORBID_CLEAN.get(n, []):
                if re.search(rx, l):
                    bad.append("step %d: FORBID /%s/ matches a healthy line: %r" % (n, rx, l))
    for b in bad:
        print("STALE: " + b)
    rehearsed = [n for n in sorted(st) if st[n][1] and n not in SKIP]
    print("%s: REHEARSAL: %d substitutions checked; steps rehearsed %s, skipped %s"
          % ("FAIL" if bad else "PASS", sum(len(v) for v in SUBST.values()),
             rehearsed, sorted(SKIP)))
    return 1 if bad else 0


def main():
    if "--check-substitutions" in sys.argv:
        return check_substitutions(steps(open(sys.argv[1]).read()))
    if os.environ.get("REHEARSAL_HOST_IS_DISPOSABLE") != "1":
        sys.exit("refusing: this creates users and services; set "
                 "REHEARSAL_HOST_IS_DISPOSABLE=1 on a throwaway host only")
    keep = "--keep-going" in sys.argv
    md = open(sys.argv[1]).read()
    st = steps(md)
    open(STATE, "w").close()
    results, ok_all = [], True
    for n in sorted(st):
        title, blocks = st[n]
        if n in SKIP:
            results.append((n, title, "SKIP", SKIP[n]))
            continue
        if not blocks:
            continue
        text = "\n".join(blocks) + "\n"
        problems = []
        for old, new, why in SUBST.get(n, []):
            c = text.count(old)
            if c != 1:
                problems.append("substitution stale (%d matches): %r" % (c, old[:60]))
                continue
            text = text.replace(old, new)
            print("[step %d] SUBST (%s)" % (n, why))
        if problems:
            ok_all = False
            results.append((n, title, "FAIL", "; ".join(problems)))
            print("\n".join(problems))
            if not keep:
                break
            continue
        allow = ALLOW_NONZERO.get(n, [])
        trap = ("trap 'rc=$?; case \"$BASH_COMMAND\" in %s) ;; *) "
                "echo \"REHEARSAL-CMD-FAILED rc=$rc: $BASH_COMMAND\" >&2; exit 1;; esac' ERR\n"
                % ("|".join("*%s*" % a for a in allow) or "__never__"))
        pre = "".join(post_line(st, c) for c in PRE.get(n, []))
        post = "".join(post_line(st, c) for c in POST.get(n, []))
        script = ("set -o pipefail\ncd %s\n. %s\n%s%s%s\n%s\nexit 0\n"
                  % (SRC, STATE, trap, pre, text, post))
        print("\n===== step %d. %s =====" % (n, title))
        print(text)
        print("----- output -----", flush=True)
        p = subprocess.run(["bash", "-c", script], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        out = p.stdout
        print(out, flush=True)
        why = []
        if p.returncode != 0:
            why.append("exit %d" % p.returncode)
        for rx in EXPECT.get(n, []):
            if not re.search(rx, out):
                why.append("EXPECT missing: /%s/" % rx)
        for rx in FORBID.get(n, []):
            if re.search(rx, out):
                why.append("FORBID present: /%s/" % rx)
        status = "FAIL" if why else "PASS"
        results.append((n, title, status, "; ".join(why)))
        print("[step %d] %s %s" % (n, status, "; ".join(why)), flush=True)
        if why:
            ok_all = False
            if not keep:
                break
    print("\n===== rehearsal summary =====")
    for n, title, s, why in results:
        print("%-4s step %2d  %-45s %s" % (s, n, title[:45], why))
    print("PASS: REHEARSAL: every step ran as written" if ok_all
          else "FAIL: REHEARSAL: see the steps above")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
