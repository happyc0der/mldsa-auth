#!/usr/bin/env python3
"""V4-321 mutations: what the seventy-second review found in the C code
(F569, F570) and a test gap it named (Req 11's table).

Usage: mutate_v175.py <repo> <ID>

    RD1   The burst's sum is rounded up a term at a time.
    TH1   A timeout says nothing of the request having been sent.
    SA1   DISABLE-USER is in the site socket's table.

The browser client (F572) is JavaScript, which no campaign compiles; its
control was run with hand_control.py --interpreted and is listed in
docs/decisions.md under V4-321.
"""
import sys, pathlib
RL = "apps/authd/ratelimit.c"
AC = "apps/authd/authd_cli.c"
LA = "apps/authd/localapi.c"

M = {
    "RD1": [(RL, "        sum_milli += (gl * hold_ms + k - 1u) / k;\n",
             "        sum_milli += ((gl * hold_ms + 1000u * k - 1u) / (1000u * k)) * 1000u; /* MUTATION RD1 */\n")],
    "TH1": [(AC, "        } else if (st == LOCALCLI_ERR_TIMEOUT) {\n",
             "        } else if (st == LOCALCLI_ERR_TIMEOUT && 0) { /* MUTATION TH1 */\n")],
    "SA1": [(LA, "    { \"RECOVERY-USE\",    h_recovery_use },\n};\n\nstatic const entry_t ADMIN_TABLE[] = {\n",
             "    { \"RECOVERY-USE\",    h_recovery_use },\n    { \"DISABLE-USER\",    h_disable_user }, /* MUTATION SA1 */\n};\n\nstatic const entry_t ADMIN_TABLE[] = {\n")],
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
