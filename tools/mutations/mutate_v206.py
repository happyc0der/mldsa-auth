#!/usr/bin/env python3
"""V4-372 mutations: what the hundred-and-eleventh review found (F830, F832 to F834).

Usage: mutate_v206.py <repo> <ID>

    SG1   a .ek.next that could not be opened is "changed" whatever the
          reason (V4-371).
    SG2   keyfile_staged_is never says the same bytes are exposed.
    SG3   keyfile_staged_is does not compare the bytes.
    SG4   keyfile_displace moves over a file already moved aside.
    SG5   a rotate that gets no reply keeps .ek.next without looking at it
          (V4-371's lock-out).
    SG6   a .ek.next that only became readable is treated as a stranger's.
    SG7   after the accepted key is written to .ek, what was swapped in is
          left at .ek.next.
    SG8   a .ek.next that became a directory is an I/O error.
    SG9   with no digest, a missing candidate is "changed".
    SG10  keyfile_open_kept hands back sealed bytes without their digest.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CL = "apps/authd/client_cli.c"

M = {
    "SG1": [(KF, "    return S_ISREG(lst.st_mode) ? KEYFILE_ERR_IO : KEYFILE_ERR_CHANGED;\n",
             "    return KEYFILE_ERR_CHANGED; /* MUTATION SG1 */\n")],
    "SG2": [(KF, "        *exposed = 1;   /* the same bytes, no longer this user's alone */\n",
             "        *exposed = 0; /* MUTATION SG2 */\n")],
    "SG3": [(KF, "    } else if (memcmp(got, expect, sizeof got) != 0) {\n        r = KEYFILE_ERR_CHANGED;\n    } else if (st.st_uid",
             "    } else if (0 && memcmp(got, expect, sizeof got) != 0) { /* MUTATION SG3 */\n        r = KEYFILE_ERR_CHANGED;\n    } else if (st.st_uid")],
    "SG4": [(KF, "    if (lstat(aside, &lst) == 0 || errno != ENOENT) {\n        return KEYFILE_ERR_EXISTS;\n",
             "    if (0 && (lstat(aside, &lst) == 0 || errno != ENOENT)) { /* MUTATION SG4 */\n        return KEYFILE_ERR_EXISTS;\n")],
    "SG5": [(CL, "        client_restage_opened(prog, \"rotate\", next_path, a.key_path, next_digest, next_sealed, next_sealed_len);   /* F830 no-reply */\n",
             "        /* MUTATION SG5 */\n")],
    "SG6": [(CL, "    if (keyfile_staged_is(next_path, digest, &exposed) == KEYFILE_OK) {\n        /* The same bytes: what changed",
             "    if (0 && keyfile_staged_is(next_path, digest, &exposed) == KEYFILE_OK) { /* MUTATION SG6 */\n        /* The same bytes: what changed")],
    "SG7": [(CL, "    const keyfile_status_t ds = keyfile_displace(next_path, aside, sizeof aside);\n    fprintf(stderr, \"%s %s: %s changed while",
             "    const keyfile_status_t ds = KEYFILE_ERR_IO; aside[0] = '\\0'; /* MUTATION SG7 */\n    fprintf(stderr, \"%s %s: %s changed while")],
    "SG8": [(KF, "    if (!S_ISREG(st.st_mode)) {\n        (void)close(fd);\n        return expect != NULL ? KEYFILE_ERR_CHANGED : KEYFILE_ERR_IO;\n",
             "    if (!S_ISREG(st.st_mode)) {\n        (void)close(fd);\n        return KEYFILE_ERR_IO; /* MUTATION SG8 */\n")],
    "SG9": [(KF, "        return expect != NULL ? unopened_is(from) : KEYFILE_ERR_IO;   /* F832 */\n",
             "        return unopened_is(from); /* MUTATION SG9 */\n")],
    "SG10": [(KF, "    if ((sealed_out == NULL) != (sealed_len == NULL) || (sealed_out != NULL && digest_out == NULL)) {\n",
              "    if ((sealed_out == NULL) != (sealed_len == NULL)) { /* MUTATION SG10 */\n")],
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
