#!/usr/bin/env python3
"""V4-59 mutations: the store's backup file, from its first byte (F24's residue).

Usage: mutate_v84.py <repo> <ID>

Two-letter IDs: BK = BacKup. store_backup now creates the destination itself,
0600 and exclusive, before VACUUM INTO writes into it, and removes it if the
backup fails. Every spec line names the check that must catch it (F90).

    BK1   the destination created 0644: the copy is readable while it is made.
    BK2   no destination created first: VACUUM INTO makes it under the umask
          (the behaviour before V4-59).
    BK4   O_EXCL dropped: an existing backup is opened, the copy into it
          fails, and the failure path then deletes the existing backup.
    BK5   a failed backup's file is left behind.

(BK3, O_NOFOLLOW dropped, is not a mutation: O_CREAT|O_EXCL already refuses a
symlink at the path, so that mutant would be equivalent.)
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
OPEN = "    const int fd = open(dest_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);\n"

M = {
    "BK1": [(ST, OPEN,
                 "    const int fd = open(dest_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644); /* MUTATION BK1 */\n")],
    "BK2": [(ST, OPEN + "    if (fd < 0) { return STORE_ERR_IO; }    /* the path exists, or cannot be created */\n    (void)close(fd);\n",
                 "    const int fd = 0; /* MUTATION BK2: VACUUM INTO creates the file */\n    if (fd < 0) { return STORE_ERR_IO; }    /* the path exists, or cannot be created */\n    (void)fd;\n")],
    "BK4": [(ST, OPEN,
                 "    const int fd = open(dest_path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600); /* MUTATION BK4: no O_EXCL */\n")],
    "BK5": [(ST, "    if (r != STORE_OK) {\n        (void)unlink(dest_path);\n    }\n    return r;\n",
                 "    if (r != STORE_OK && 0) { /* MUTATION BK5: a failed backup's file is kept */\n        (void)unlink(dest_path);\n    }\n    return r;\n")],
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
