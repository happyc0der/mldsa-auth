#!/usr/bin/env python3
"""V4-169 mutations: a ticket enrollment that enrolls nothing is answered
and logged as idempotent, and does not spend the ticket (F243).

Usage: mutate_v115.py <repo> <ID>

Two-letter IDs: RI = Recovery Idempotent. Every spec line names the check
that must catch it (F90).

    RI1   The store does not report the idempotent case. F243 itself.
    RI2   The handler logs it as a recovery all the same.
    RI3   The reply omits idempotent=1.
    RI4   The ticket is spent on an enrollment that enrolled nothing.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
LA = "apps/authd/localapi.c"

M = {
    "RI1": [(ST,
             "         * TOLD (F243): it used to hear a plain OK and report a recovery. */\n        tx_rollback(s);\n        if (idempotent_out != NULL) { *idempotent_out = 1; }\n",
             "         * TOLD (F243): it used to hear a plain OK and report a recovery. */\n        tx_rollback(s);\n        if (idempotent_out != NULL) { *idempotent_out = 0; } /* MUTATION RI1 */\n")],
    "RI2": [(LA,
             "        if (ticket_idem) {\n",
             "        if (ticket_idem && 0) { /* MUTATION RI2 */\n")],
    "RI3": [(LA,
             "        resp_add(&rr, ticket_idem ? \" idempotent=1\\n\" : \"\\n\");\n",
             "        resp_add(&rr, \"\\n\"); /* MUTATION RI3 */\n")],
    "RI4": [(ST,
             "         * TOLD (F243): it used to hear a plain OK and report a recovery. */\n        tx_rollback(s);\n        if (idempotent_out != NULL) { *idempotent_out = 1; }\n",
             "         * TOLD (F243): it used to hear a plain OK and report a recovery. */\n        (void)tx_commit(s); /* MUTATION RI4 */\n        if (idempotent_out != NULL) { *idempotent_out = 1; }\n")],
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
