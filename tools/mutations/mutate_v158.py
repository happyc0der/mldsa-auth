#!/usr/bin/env python3
"""V4-282 mutations: the CLI client, read whole again (F465 to F469).

Usage: mutate_v158.py <repo> <ID>

Two-letter IDs: CR = Carriage Return, PO = Promote Order, SR = Stale
Rotate. The spec line names the check that must catch it (F90).

    CR1   A new passphrase from a file may end in a carriage return again.
    PO1   The interrupted rotation is promoted before its .pub is replaced.
    SR1   A rotation refused after ClientAuth keeps its staged key again.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "CR1": [(CL, "        if (r == EX_OK && fresh && *out_len > 0u && (*out)[*out_len - 1u] == '\\r') {\n",
             "        if (r == EX_OK && fresh && *out_len > 0u && (*out)[*out_len - 1u] == '\\r' && prog == NULL) { /* MUTATION CR1 */\n")],
    "PO1": [(CL, """        client_republish_pub(prog, sub, a, next_path, next_kp.public_key);
        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {
            (void)failed(prog, sub, a->key_path, "cannot-complete-rename");
            break;
        }
""", """        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) { /* MUTATION PO1 */
            (void)failed(prog, sub, a->key_path, "cannot-complete-rename");
            break;
        }
        client_republish_pub(prog, sub, a, next_path, next_kp.public_key);
""")],
    "SR1": [(CL, "        if (unlink(next_path) == 0) {\n",
             "        if (!g_open_judged && unlink(next_path) == 0) { /* MUTATION SR1 */\n")],
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
