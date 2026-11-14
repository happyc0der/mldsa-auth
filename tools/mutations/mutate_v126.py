#!/usr/bin/env python3
"""V4-198 mutations: ROTATE's signatures are checked before its store (F276,
spec erratum 102).

Usage: mutate_v126.py <repo> <ID>

Two-letter IDs: RO = Rotation Order. Every spec line names the check that
must catch it (F90).

    RO1   sig_new is not verified before the store is asked: a ROTATE naming
          an in-use key reaches the store's "in use" refusal without proof
          of that key.
"""
import sys, pathlib

M = {
    "RO1": [("apps/authd/authd_conn.c",
             "    if (mldsa_verify(digest, sizeof digest, m.sig_new, m.sig_new_len, m.pk_new) != 0) {\n",
             "    if (0 && mldsa_verify(digest, sizeof digest, m.sig_new, m.sig_new_len, m.pk_new) != 0) { /* MUTATION RO1 */\n")],
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
