#!/usr/bin/env python3
"""V4-306 mutations: the host's page (F403), a uid in both lists (F420), and
who a listener turned away (F450).

Usage: mutate_v165.py <repo> <ID>

    PG1   The page is half the host's (sysconf / 2): the need is understated.
    SU1   A shared uid is found but reported as none.
    SU2   --check-config no longer warns of a shared uid.
    SU3   Only the first proxy uid is compared, so a shared uid later in
          proxy_uids is missed.
    PR1   A refused peer's credentials are not copied out, so the line says
          uid=unavailable.
    PR2   The admin and site listeners are named the wrong way round.

Not here: a page fixed at 4096 (sysconf ignored). On a 4 KiB host, which is
where this campaign runs in CI, that mutant is EQUIVALENT -- no test can tell
it from the fix. It is killed on a 16 KiB host (this Mac, by hand, V4-306) by
"memlock: the page is the host's sysconf(_SC_PAGESIZE) (F403)". The proxy's
`detail=proxy` is checked only by authd_e2e's real-second-user leg, which needs
root or setpriv; it is left out for the same reason.
"""
import sys, pathlib
ML = "apps/authd/memlock.c"
CF = "apps/authd/authd_config.c"
AM = "apps/authd/authd_main.c"
LS = "apps/authd/listener.c"
EV = "apps/authd/evloop.c"

M = {
    "PG1": [(ML, "    return (page > 0) ? (uint64_t)page : (uint64_t)MEMLOCK_PAGE_BYTES;\n",
             "    return (page > 0) ? (uint64_t)page / 2u : (uint64_t)MEMLOCK_PAGE_BYTES; /* MUTATION PG1 */\n")],
    "SU1": [(CF, "                    *uid_out = cfg->site_uids[i];\n                }\n                return 1;\n",
             "                    *uid_out = cfg->site_uids[i];\n                }\n                return 0; /* MUTATION SU1 */\n")],
    "SU2": [("apps/authd/authd_cli.c", "    if (authd_config_shared_uid(cfg, &shared)) {\n",
             "    if (authd_config_shared_uid(cfg, &shared) && 0) { /* MUTATION SU2 */\n")],
    "SU3": [(CF, "        for (size_t j = 0; j < cfg->n_proxy_uids; j++) {\n",
             "        for (size_t j = 0; j < cfg->n_proxy_uids && j < 1u; j++) { /* MUTATION SU3 */\n")],
    "PR1": [(LS, "            if (peer_out != NULL) { *peer_out = p; }\n            (void)close(c);\n            return LISTENER_ERR_PEER;\n",
             "            (void)close(c); /* MUTATION PR1 */\n            return LISTENER_ERR_PEER;\n")],
    "PR2": [(EV, "                                : ev->listen_is_admin[li] ? \"admin\" : \"site\";\n",
             "                                : ev->listen_is_admin[li] ? \"site\" : \"admin\"; /* MUTATION PR2 */\n")],
}

def main():
    repo, mid = pathlib.Path(sys.argv[1]), sys.argv[2]
    if mid not in M:
        sys.exit("unknown mutation id: " + mid)
    texts = {}
    for path, old, new in M[mid]:
        t = texts.get(path, (repo / path).read_text())
        n = t.count(old)
        if n != 1:
            sys.exit(f"{mid}: expected exactly 1 occurrence in {path}, found {n}")
        texts[path] = t.replace(old, new, 1)
    for path, t in texts.items():
        (repo / path).write_text(t)
    print(f"{mid}: applied")


if __name__ == "__main__":
    main()
