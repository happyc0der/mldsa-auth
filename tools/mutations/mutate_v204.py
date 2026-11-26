#!/usr/bin/env python3
"""V4-370 mutations: what the hundred-and-ninth review found (F817).

Usage: mutate_v204.py <repo> <ID>

    SE1   promote_expect renames a .ek.next whose bytes are not the ones
          that were opened.
    SE2   a .ek.next that is a hard link to .ek is "promoted" by a rename
          that does nothing, and stays.
    SE3   rotate promotes .ek.next by name, whatever is there by the ACK.
    SE4   a login completing a rotation promotes .ek.next by name.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CL = "apps/authd/client_cli.c"

M = {
    "SE1": [(KF, "        if (memcmp(got, expect, sizeof got) != 0) {\n",
             "        if (0 && memcmp(got, expect, sizeof got) != 0) { /* MUTATION SE1 */\n")],
    "SE2": [(KF, "    if (lstat(to, &tst) == 0 && tst.st_dev == st.st_dev && tst.st_ino == st.st_ino) {\n",
             "    if (0 && lstat(to, &tst) == 0 && tst.st_dev == st.st_dev && tst.st_ino == st.st_ino) { /* MUTATION SE2 */\n")],
    # V4-371: the promote is client_promote_opened; with no digest it is by name, as before.
    "SE3": [(CL, "        const keyfile_status_t ps = client_promote_opened(prog, \"rotate\", next_path, a.key_path, next_digest,\n",
             "        const keyfile_status_t ps = client_promote_opened(prog, \"rotate\", next_path, a.key_path, NULL, /* MUTATION SE3 */\n")],
    "SE4": [(CL, "            const keyfile_status_t ps = client_promote_opened(prog, sub, next_path, a->key_path, next_digest,\n",
             "            const keyfile_status_t ps = client_promote_opened(prog, sub, next_path, a->key_path, NULL, /* MUTATION SE4 */\n")],
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
