#!/usr/bin/env python3
"""V4-244 mutations: a store of an unknown version is refused before it is changed (F347).

Usage: mutate_v145.py <repo> <ID>

Two-letter IDs: SV = Store Version. Every spec line names the check that must
catch it (F90).

    SV1   The version is read only after the journal mode and the schema
          have gone into the file.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "SV1": [(ST, "                if (pvlen != 8u || have == 0u || have > (uint64_t)STORE_SCHEMA_VERSION) {\n",
                 "                if ((pvlen != 8u || have == 0u || have > (uint64_t)STORE_SCHEMA_VERSION) && 0) { /* MUTATION SV1 */\n")],
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
