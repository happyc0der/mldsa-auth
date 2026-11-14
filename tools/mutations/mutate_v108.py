#!/usr/bin/env python3
"""V4-154 mutations: audit-verify's verdict, count and head come from one
walk of the chain, and a failure names the entry that failed (F230).

Usage: mutate_v108.py <repo> <ID>

Two-letter IDs: VR = Verify Report. Every spec line names the check that must
catch it (F90).

    VR1   The walk reports one entry more than it verified.
    VR2   The walk does not report the MAC it ended on.
    VR3   The command names the entry BEFORE the one that failed: the old
          message's meaning under the new words.
    VR4   A chain that does not verify is reported as a store failure, with
          no entry named.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
CL = "apps/authd/authd_cli.c"

M = {
    "VR1": [(ST,
             "    if (verified_out != NULL) { *verified_out = expect_seq - 1; }\n",
             "    if (verified_out != NULL) { *verified_out = expect_seq; } /* MUTATION VR1 */\n")],
    "VR2": [(ST,
             "    if (head_out != NULL) { memcpy(head_out, running, STORE_AUDIT_MAC_BYTES); }\n",
             "    if (head_out != NULL && 0) { memcpy(head_out, running, STORE_AUDIT_MAC_BYTES); } /* MUTATION VR2 */\n")],
    "VR3": [(CL,
             "                prog, (long long)(entries + 1), (long long)entries, db, store_status_name(vv));\n",
             "                prog, (long long)entries, (long long)entries, db, store_status_name(vv)); /* MUTATION VR3 */\n")],
    "VR4": [(CL,
             "        if (vv != STORE_ERR_CORRUPT) {\n",
             "        if (vv != STORE_ERR_CORRUPT || 1) { /* MUTATION VR4 */\n")],
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
