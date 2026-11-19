#!/usr/bin/env python3
"""V4-323 mutations: a .pub that cannot be replaced (F583).

Usage: mutate_v176.py <repo> <ID>

    PR1   A recovering login promotes the key though the .pub was not replaced.
    PR2   rotate promotes the key though the .pub was not replaced.
    PR3   A recovering login whose .pub was not replaced fails.

The browser's enrollment (F584) and the site's handler (F588) are
JavaScript, which no campaign compiles; their controls were run with
hand_control.py --interpreted and are listed in docs/decisions.md under
V4-323.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "PR1": [(CL, "            memcpy(kp_out, &next_kp, sizeof next_kp);\n            memset(&next_kp, 0, sizeof next_kp);\n            rc = EX_OK;\n            break;\n        }\n        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {\n",
             "        } /* MUTATION PR1: the promotion goes ahead */\n        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {\n")],
    "PR2": [(CL, "                            \"completes the rotation\\n\", prog, pub_path, next_path);\n            goto out;\n",
             "                            \"completes the rotation\\n\", prog, pub_path, next_path);\n            /* MUTATION PR2 */\n")],
    "PR3": [(CL, "            memcpy(kp_out, &next_kp, sizeof next_kp);\n            memset(&next_kp, 0, sizeof next_kp);\n            rc = EX_OK;\n            break;\n        }\n        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {\n",
             "            break; /* MUTATION PR3: and the login fails */\n        }\n        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {\n")],
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
