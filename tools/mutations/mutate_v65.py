#!/usr/bin/env python3
"""V4-22b mutations: whose uid the listener compares (CLAIMS D11).

Usage: mutate_v65.py <repo> <ID>

Two-letter IDs: RU = V4-22b's Real User. The mutation changes a value and keeps
every use (F79), and its spec line names the check that must catch it (F90).

    RU1   listener_accept_ex's allowlist scan compares getuid() -- the
          daemon's OWN uid -- instead of the peer's. Every test before
          V4-22b runs the client as the daemon's own user, so "the peer's uid"
          and "my uid" were the same number: the uid+1 leg still refuses (its
          lists name neither) and still serves the proxy socket (whose list
          names the daemon's uid), test_authd_ws's getuid()+1 peer is still
          refused, and V4-22a's whole suite passed with it in place. Only a
          genuinely different user can see it: authd_e2e's real-user leg,
          whose canary -- nobody, named in site_uids -- is refused instead of
          served.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LS = "apps/authd/listener.c"

M = {
 "RU1": (LS, [("            if (allow[i] == p.uid) { ok = 1; break; }",
               "            if (allow[i] == (uid_t)getuid()) { ok = 1; break; } /* MUTATION RU1 */")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID}")
