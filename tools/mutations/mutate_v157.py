#!/usr/bin/env python3
"""V4-276 mutations: messages an operator acts on (F443 to F446).

Usage: mutate_v157.py <repo> <ID>

Two-letter IDs: KM = Key Mismatch, EA = EAcces, SC = Socket Connect, AV =
Audit-Verify. Every spec line names the check that must catch it (F90).

    KM1   Another identity's key is reported as a damaged image, as before.
    EA1   A file this user cannot reach is reported as missing, as before.
    SC1   A failed connect to the admin socket says why no more.
    AV1   audit-verify failing at entry 1 no longer points at the key.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CF = "apps/authd/authd_config.c"
CL = "apps/authd/authd_cli.c"

M = {
    "KM1": [(KF, "            : (ims == DEMO_KEYS_ERR_ID_MISMATCH) ? KEYFILE_ERR_ID_MISMATCH : KEYFILE_ERR_IMAGE;\n",
             "            : KEYFILE_ERR_IMAGE; /* MUTATION KM1 */\n")],
    "EA1": [(CF, "    return (e == EACCES) ? \"cannot be reached as this user (permission denied: run it as the service user)\"\n                         : missing;\n",
             "    (void)e; return missing; /* MUTATION EA1 */\n")],
    "SC1": [(CL, "        if (st == LOCALCLI_ERR_CONNECT) {\n            struct stat ss;\n",
             "        if (0 && st == LOCALCLI_ERR_CONNECT) { /* MUTATION SC1 */\n            struct stat ss;\n")],
    "AV1": [(CL, "        if (entries == 0) {\n            fprintf(stderr, \"%s audit-verify: no entry verified",
             "        if (0) { /* MUTATION AV1 */\n            fprintf(stderr, \"%s audit-verify: no entry verified")],
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
