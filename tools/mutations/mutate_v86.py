#!/usr/bin/env python3
"""V4-61 mutations: the daemon's start-up diagnostics agree (F126).

Usage: mutate_v86.py <repo> <ID>

Two-letter IDs: DG = DiaGnostics. A file the configuration names that cannot
be used as configured exits 3 (spec §13, erratum 51), whichever file it is;
one refusal has one name; a damaged store value is store-corrupt, and only
the audit chain is audit-chain-corrupt. Every spec line names the check that
must catch it (F90).

    DG1   a refused passphrase file exits 1.
    DG2   a refused server key exits 1 (the behaviour before V4-61).
    DG3   the passphrase reader's old name for the permissions refusal.
    DG4   a damaged store value named audit-chain-corrupt again.
    DG5   a store_id of the wrong length reported as the audit chain's status.
"""
import sys, pathlib
MN = "apps/authd/authd_main.c"
SE = "apps/authd/authd_secret.c"
ST = "apps/authd/store/store.c"

M = {
    "DG1": [(MN, "            return (ps == AUTHD_SECRET_ERR_CRYPTO) ? 1 : 3;\n",
                 "            return (ps == AUTHD_SECRET_ERR_CRYPTO) ? 1 : 1; /* MUTATION DG1 */\n")],
    "DG2": [(MN, "            return (ks == KEYFILE_ERR_CRYPTO) ? 1 : 3;\n",
                 "            return (ks == KEYFILE_ERR_CRYPTO) ? 1 : 1; /* MUTATION DG2 */\n")],
    "DG3": [(SE, "    case AUTHD_SECRET_ERR_PERMISSIONS:  return \"unsafe-permissions\";",
                 "    case AUTHD_SECRET_ERR_PERMISSIONS:  return \"permissions (mode must be 0600)\"; /* MUTATION DG3 */")],
    "DG4": [(ST, "    case STORE_ERR_DAMAGED:   return \"store-corrupt\";\n",
                 "    case STORE_ERR_DAMAGED:   return \"audit-chain-corrupt\"; /* MUTATION DG4 */\n")],
    "DG5": [(ST, "    } else if (n != sizeof s->store_id) {\n        r = STORE_ERR_DAMAGED;\n",
                 "    } else if (n != sizeof s->store_id) {\n        r = STORE_ERR_CORRUPT; /* MUTATION DG5 */\n")],
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
