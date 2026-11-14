#!/usr/bin/env python3
"""V4-157 mutations: keygen-server looks at both targets before it makes a
key (F232), and a failed init names every file it left (F233).

Usage: mutate_v110.py <repo> <ID>

Two-letter IDs: KS = Keygen-Server, IL = Init Leftovers. Every spec line
names the check that must catch it (F90).

    KS1   The up-front refusal is skipped. F232 itself.
    KS2   Only --key is looked at, not --pub.
    IL1   A store that cannot be made is reported without what was left.
    IL2   The list of what was left omits server.pub. F233 itself.
"""
import sys, pathlib
CL = "apps/authd/authd_cli.c"

M = {
    "KS1": [(CL,
             "        if (clash != NULL) {\n"
             "            fprintf(stderr, \"%s keygen-server: refusing: %s already exists; nothing was written\\n\",\n",
             "        if (clash != NULL && 0) { /* MUTATION KS1 */\n"
             "            fprintf(stderr, \"%s keygen-server: refusing: %s already exists; nothing was written\\n\",\n")],
    "KS2": [(CL,
             "        const char *clash = path_exists(key) ? key : path_exists(pub) ? pub : NULL;\n",
             "        const char *clash = path_exists(key) ? key : NULL; /* MUTATION KS2 */\n")],
    "IL1": [(CL,
             "        fprintf(stderr, \"%s init: failed: %s: %s\\n\", prog, db, store_status_name(ss));\n"
             "        init_leftovers(prog, pass_path, ek, pub, db);\n",
             "        fprintf(stderr, \"%s init: failed: %s: %s\\n\", prog, db, store_status_name(ss));\n"
             "        /* MUTATION IL1 */\n")],
    "IL2": [(CL,
             "    const char *paths[4] = { pass_path, ek, pub, db };\n",
             "    const char *paths[4] = { pass_path, ek, ek, db }; (void)pub; /* MUTATION IL2 */\n")],
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
