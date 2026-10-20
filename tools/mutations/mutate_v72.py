#!/usr/bin/env python3
"""V4-30 mutations: the enrollment ticket at rest (CLAIMS D4).

Usage: mutate_v72.py <repo> <ID>

Two-letter IDs: TK = Ticket. Until V4-30 no mutation leaked the ticket, so its
store and backup scans had only the code's and token's proof of liveness, and
they ran only when the ticket was ISSUED -- nothing looked at the store after
ENROLL spent it. Every spec line names the check that must catch it (F90).

    TK1   ENROLL via=recovery without a label stores the raw ticket as the
          new device's label, before wiping it. Enrollment works; it passed
          V4-29's whole scan set, and only the after-spend scans see it.
    TK2   RECOVERY-USE stores the raw ticket where its SHA-256 belongs. The
          at-issue scan's first mutation kill; the ticket can then never be
          spent, which a functional check sees as well.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "TK1": [(LA, """        crypto_hash_sha256(thash, ticket, sizeof ticket);
        sodium_memzero(ticket, sizeof ticket);
""",
                 """        crypto_hash_sha256(thash, ticket, sizeof ticket);
        if (label_len == 0u) { memcpy(label, ticket, sizeof ticket); label_len = sizeof ticket; } /* MUTATION TK1 */
        sodium_memzero(ticket, sizeof ticket);
""")],
    "TK2": [(LA, """                                                        thash, app->now_unix, expires,
""",
                 """                                                        ticket, app->now_unix, expires, /* MUTATION TK2 */
""")],
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
