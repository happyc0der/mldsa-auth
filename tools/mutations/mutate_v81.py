#!/usr/bin/env python3
"""V4-51 mutations: the daemon refuses to start on a file it cannot trust.

Usage: mutate_v81.py <repo> <ID>

Two-letter IDs: SU = Start-Up. authd_main.c refuses to start when the
passphrase file, the server key or the store cannot be used; V4-44's coverage
found those refusals had run only through --check-config or not at all. Every
spec line names the check that must catch it (F90).

    SU1   a refused passphrase file is ignored: start-up goes on to the key
          with no passphrase, and the message no longer names the file.
    SU2   a refused server key is ignored: the daemon goes on without it.
    SU3   a store that cannot be opened is ignored.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"

M = {
    "SU1": [(MAIN, "        if (ps != AUTHD_SECRET_OK) {\n            fprintf(stderr, \"mldsa-authd: passphrase file %s: %s\\n\",\n",
                   "        if (ps != AUTHD_SECRET_OK && 0) { /* MUTATION SU1: refusal ignored */\n            fprintf(stderr, \"mldsa-authd: passphrase file %s: %s\\n\",\n")],
    "SU2": [(MAIN, "        if (ks != KEYFILE_OK) {\n            fprintf(stderr, \"mldsa-authd: %s: %s\\n\", cfg.key_path, keyfile_status_name(ks));\n",
                   "        if (ks != KEYFILE_OK && 0) { /* MUTATION SU2: refusal ignored */\n            fprintf(stderr, \"mldsa-authd: %s: %s\\n\", cfg.key_path, keyfile_status_name(ks));\n")],
    "SU3": [(MAIN, "        if (ss != STORE_OK) {\n            fprintf(stderr, \"mldsa-authd: %s: %s\\n\", cfg.store_path, store_status_name(ss));\n",
                   "        if (ss != STORE_OK && 0) { /* MUTATION SU3: refusal ignored */\n            fprintf(stderr, \"mldsa-authd: %s: %s\\n\", cfg.store_path, store_status_name(ss));\n")],
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
