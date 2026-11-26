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
    "PO1": [(CL, '        if (client_republish_pub(prog, sub, a, next_path, next_kp.public_key) != 0) {\n            /* F583: the .pub still names the old key, so the rename is not\n             * made: .ek.next stays, and the next run comes back here and\n             * tries both again. This login goes ahead with the live key. */\n            fprintf(stderr, "%s %s: the interrupted rotation is NOT completed: %s is kept, and the next "\n                            "run will try again. It holds the live key\\n", prog, sub, next_path);\n            g_resolve_kept_next = 1;\n            memcpy(kp_out, &next_kp, sizeof next_kp);\n            memset(&next_kp, 0, sizeof next_kp);\n            rc = EX_OK;\n            break;\n        }\n        {\n            const keyfile_status_t ps = keyfile_promote_expect(next_path, a->key_path, next_digest);\n            if (ps == KEYFILE_ERR_CHANGED) {\n                /* F817: replaced while the daemon was asked. The key the\n                 * daemon took is the one that was there; this is not it. */\n                (void)failed(prog, sub, next_path, keyfile_status_name(ps));\n                fprintf(stderr, "%s %s: %s changed while the daemon was asked about it: it is not the key "\n                                "the daemon accepted. Nothing was renamed; find what replaced it\\n",\n                        prog, sub, next_path);\n                break;\n            }\n            if (ps != KEYFILE_OK) {\n                (void)failed(prog, sub, a->key_path, "cannot-complete-rename");\n                break;\n            }\n        }\n',
             '        { /* MUTATION PO1 */\n            const keyfile_status_t ps = keyfile_promote_expect(next_path, a->key_path, next_digest);\n            if (ps == KEYFILE_ERR_CHANGED) {\n                /* F817: replaced while the daemon was asked. The key the\n                 * daemon took is the one that was there; this is not it. */\n                (void)failed(prog, sub, next_path, keyfile_status_name(ps));\n                fprintf(stderr, "%s %s: %s changed while the daemon was asked about it: it is not the key "\n                                "the daemon accepted. Nothing was renamed; find what replaced it\\n",\n                        prog, sub, next_path);\n                break;\n            }\n            if (ps != KEYFILE_OK) {\n                (void)failed(prog, sub, a->key_path, "cannot-complete-rename");\n                break;\n            }\n        }\n        if (client_republish_pub(prog, sub, a, next_path, next_kp.public_key) != 0) {\n            /* F583: the .pub still names the old key, so the rename is not\n             * made: .ek.next stays, and the next run comes back here and\n             * tries both again. This login goes ahead with the live key. */\n            fprintf(stderr, "%s %s: the interrupted rotation is NOT completed: %s is kept, and the next "\n                            "run will try again. It holds the live key\\n", prog, sub, next_path);\n            g_resolve_kept_next = 1;\n            memcpy(kp_out, &next_kp, sizeof next_kp);\n            memset(&next_kp, 0, sizeof next_kp);\n            rc = EX_OK;\n            break;\n        }\n')],
    "SR1": [(CL, "        } else if (unlink(next_path) != 0) {\n            rotate_say_kept(prog, next_path);   /* F645 */\n",
             "        } else if (g_open_judged || unlink(next_path) != 0) { /* MUTATION SR1 */\n            rotate_say_kept(prog, next_path);   /* F645 */\n")],
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
