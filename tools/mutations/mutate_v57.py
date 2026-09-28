#!/usr/bin/env python3
"""V4-14c mutations: the three medium findings the review packet surfaced.

Usage: mutate_v57.py <repo> <ID>

Two-letter IDs: HC = V4-14c's fixes. Every mutation changes a value and keeps
every use (F79; the runner now refuses any other compile kill).

  F92 -- an omitted uid allowlist (apps/authd/authd_config.c)
    HC1  a site socket without site_uids is accepted again
    HC2  proxy_protocol = v2 without proxy_uids is accepted again
  F93 -- revoke=all inside the recovery's one transaction (store.c, localapi.c)
    HC3  each revocation commits on its own again (the pre-F93 shape)
    HC4  the search for the next device to revoke skips the first one found
    HC5  RECOVERY-USE never asks the store to revoke, whatever the request says
  F94 has no mutation: the runner snapshots only C sources, and the fix is a
  CMake flag. Its control was run by hand -- a planted signed overflow passed
  under the old flags and aborts under the new ones.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
CF = "apps/authd/authd_config.c"
ST = "apps/authd/store/store.c"
LA = "apps/authd/localapi.c"

M = {
 "HC1": (CF, [("    if (cfg.site_socket[0] != '\\0' && cfg.n_site_uids == 0u) {",
               "    if (cfg.site_socket[0] != '\\0' && cfg.n_site_uids == 99u) { /* MUTATION HC1 */")]),
 "HC2": (CF, [("    if (cfg.proxy_protocol_v2 && cfg.n_proxy_uids == 0u) {",
               "    if (cfg.proxy_protocol_v2 && cfg.n_proxy_uids == 99u) { /* MUTATION HC2 */")]),
 "HC3": (ST, [("        revoked++;\n        /* Between two revocations:",
               "        revoked++;\n        (void)tx_commit(s); (void)tx_begin(s); /* MUTATION HC3: one transaction per revocation */\n        /* Between two revocations:")]),
 "HC4": (ST, [("                \"SELECT handle FROM devices WHERE user_id=?1 AND status='active' LIMIT 1;\",",
               "                \"SELECT handle FROM devices WHERE user_id=?1 AND status='active' LIMIT 1 OFFSET 1;\", /* MUTATION HC4 */")]),
 "HC5": (LA, [("                                                        revoke_all, &revoked);",
               "                                                        revoke_all & 0, &revoked); /* MUTATION HC5 */")]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
