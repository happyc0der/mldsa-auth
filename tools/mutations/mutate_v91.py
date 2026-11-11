#!/usr/bin/env python3
"""V4-112 mutations: an offline command's unusable server key is a
configuration error, 3 (F196, spec 13 erratum 82).

Usage: mutate_v91.py <repo> <ID>

Two-letter IDs: KF = Key Failed. key_failed() prints the status and returns
3 unless the failure was internal; audit-verify, pseudonym and rewrap use it
for the key they are given. Every spec line names the check that must catch
it (F90).

    KF1   key_failed's rule inverted: 1 for an unusable key (what F196
          reported), 3 for an internal failure.
    KF2   audit-verify reports its key with failed(): 1.
    KF3   pseudonym does.
    KF4   rewrap does.
"""
import sys, pathlib
CLI = "apps/authd/authd_cli.c"

M = {
    "KF1": [(CLI, "    return (ks == KEYFILE_ERR_CRYPTO) ? EX_FAIL : EX_CONFIG;\n",
                  "    return (ks != KEYFILE_ERR_CRYPTO) ? EX_FAIL : EX_CONFIG; /* MUTATION KF1 */\n")],
    "KF2": [(CLI, "        return key_failed(prog, \"audit-verify\", ek, ks);\n",
                  "        return failed(prog, \"audit-verify\", ek, keyfile_status_name(ks)); /* MUTATION KF2 */\n")],
    "KF3": [(CLI, "        return key_failed(prog, \"pseudonym\", ek, ks);\n",
                  "        return failed(prog, \"pseudonym\", ek, keyfile_status_name(ks)); /* MUTATION KF3 */\n")],
    "KF4": [(CLI, "        rc = key_failed(prog, \"rewrap\", in, ko);\n",
                  "        rc = failed(prog, \"rewrap\", in, keyfile_status_name(ko)); /* MUTATION KF4 */\n")],
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
