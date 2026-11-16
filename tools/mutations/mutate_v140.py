#!/usr/bin/env python3
"""V4-236 mutations: the local-API fuzz target reaches the success paths (F332).

Usage: mutate_v137.py <repo> <ID>

Two-letter IDs: SP = Success Path. Every spec line names the check that must
catch it (F90).

    SP1   EXCHANGE's success reply is split over two lines.
    SP2   VERIFY's success reply does not begin with OK.
    SP3   LOGOUT deletes the token and then answers ERR.

Each needs a credential that exists. Before V4-236 no fuzz input could name
one, and these three replies were never produced by the fuzz target.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "SP1": [(LA,
             "    resp_add(&r, \"OK token=\");\n",
             "    resp_add(&r, \"OK\\ntoken=\"); /* MUTATION SP1 */\n")],
    "SP2": [(LA,
             "    resp_add(&r, \"OK user=\");\n",
             "    resp_add(&r, \"user=\"); /* MUTATION SP2 */\n")],
    "SP3": [(LA,
             "    resp_add(&r, \"OK deleted=%zu\\n\", n);\n",
             "    if (n > 0u) { return send_err(slot, \"internal\"); } /* MUTATION SP3 */\n"
             "    resp_add(&r, \"OK deleted=%zu\\n\", n);\n")],
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
