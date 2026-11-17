#!/usr/bin/env python3
"""V4-272 mutations: a local-API `internal` answer is logged at ERROR (F432);
a recovery refusal whose Argon2id cannot be computed answers `internal`
(F433).

Usage: mutate_v155.py <repo> <ID>

Two-letter IDs: LI = Local Internal, KF = Kdf Failure. Every spec line names
the check that must catch it (F90).

    LI1   An `internal` answer writes no ERROR line, as before.
    KF1   The uniform-cost computation reports success whatever happened.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"
RC = "apps/authd/recovery.c"

M = {
    "LI1": [(LA, "    if (strcmp(code, \"internal\") == 0) {\n        authd_log_local(AUTHD_LOG_ERROR, \"local-internal\",",
             "    if (0 && strcmp(code, \"internal\") == 0) { /* MUTATION LI1 */\n        authd_log_local(AUTHD_LOG_ERROR, \"local-internal\",")],
    "KF1": [(RC, "    return (r == 0) ? 0 : -1;\n",
             "    (void)r; return 0; /* MUTATION KF1 */\n")],
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
