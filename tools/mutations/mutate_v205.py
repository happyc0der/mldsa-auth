#!/usr/bin/env python3
"""V4-371 mutations: what the hundred-and-tenth review found (F821, F823, F825).

Usage: mutate_v205.py <repo> <ID>

    SF1   a .ek.next that is gone by the promote is an I/O error again.
    SF2   a .ek.next that others can read by the promote is "permissions".
    SF3   a changed .ek.next ends the promote: the accepted key is not
          written to .ek (V4-370's lock-out).
    SF4   keyfile_replace_sealed links instead of renaming, so it cannot
          replace.
    SF5   the two-names test follows a symbolic link.
    SF6   rotate keeps no copy of the bytes it opened.
    SF7   keyfile_open_kept hands back bytes that are not the file's.
    SF8   keyfile_replace_sealed writes whatever it is given.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CL = "apps/authd/client_cli.c"

M = {
    "SF1": [(KF, "    if (fd < 0) {\n        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_IO;\n",
             "    if (fd < 0) {\n        return KEYFILE_ERR_IO; /* MUTATION SF1 */\n")],
    "SF2": [(KF, "        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_PERMISSIONS;\n",
             "        return KEYFILE_ERR_PERMISSIONS; /* MUTATION SF2 */\n")],
    "SF3": [(CL, "    if (ps != KEYFILE_ERR_CHANGED) {\n        return ps;\n    }\n",
             "    if (1 /* MUTATION SF3 */) {\n        return ps;\n    }\n")],
    "SF4": [(KF, "    return publish_how(to, buf, len, 1);\n",
             "    return publish_how(to, buf, len, 0); /* MUTATION SF4 */\n")],
    "SF5": [(KF, "    if (lstat(to, &tst) == 0 && tst.st_dev == st.st_dev && tst.st_ino == st.st_ino) {\n",
             "    if (stat(to, &tst) == 0 && tst.st_dev == st.st_dev && tst.st_ino == st.st_ino) { /* MUTATION SF5 */\n")],
    "SF6": [(CL, "                                                          next_sealed, next_sealed_len);\n        if (ps == KEYFILE_ERR_CHANGED) {\n",
             "                                                          NULL, 0u); /* MUTATION SF6 */\n        if (ps == KEYFILE_ERR_CHANGED) {\n")],
    "SF7": [(KF, "            memcpy(copy, fbuf, total);\n",
             "            memset(copy, 0, total); /* MUTATION SF7 */\n")],
    "SF8": [(KF, "    if (hs != KEYFILE_OK) {\n        return hs;\n    }\n    return publish_how(to, buf, len, 1);\n",
             "    if (0 && hs != KEYFILE_OK) { /* MUTATION SF8 */\n        return hs;\n    }\n    return publish_how(to, buf, len, 1);\n")],
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
