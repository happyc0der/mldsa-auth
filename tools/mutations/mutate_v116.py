#!/usr/bin/env python3
"""V4-170 mutations: a token carries the handshake id of the login code it
was exchanged for (F244).

Usage: mutate_v116.py <repo> <ID>

Two-letter IDs: HS = HandShake id. Every spec line names the check that must
catch it (F90).

    HS1   EXCHANGE passes no handshake id to the token. F244 itself.
    HS2   The consume reports a length of zero.
    HS3   The consume hands back zeroes in place of the code's id.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
LA = "apps/authd/localapi.c"

M = {
    "HS1": [(LA,
             "                     (hsid_len > 0u) ? hsid : NULL, hsid_len,\n",
             "                     NULL, 0u, /* MUTATION HS1 */\n")],
    "HS2": [(ST,
             "            *hsid_len_out = hsid_len;\n",
             "            *hsid_len_out = 0; /* MUTATION HS2 */\n")],
    "HS3": [(ST,
             "            memcpy(hsid_out, hsid, hsid_len);\n",
             "            memset(hsid_out, 0, hsid_len); /* MUTATION HS3 */\n")],
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
