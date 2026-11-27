#!/usr/bin/env python3
"""V4-373 mutations: what the hundred-and-twelfth review found (F838 to F842).

Usage: mutate_v207.py <repo> <ID>

    SH1   only the first name is tried for what is moved aside (V4-372).
    SH2   with every name taken, moving aside reports success.
    SH3   keyfile_staged_is follows a symbolic link.
    SH4   keyfile_restage_sealed renames over what has the name.
    SH5   keyfile_restage_sealed writes bytes that are not an envelope.
    SH6   the accepted key is written to .ek only when .ek.next was seen to
          change (V4-372's lock-out).
    SH7   a kept .ek.next that cannot be read is left as it is (V4-372).
    SH8   a kept .ek.next that became readable is not written again.
    SH9   a re-offering rotate that opens no session keeps .ek.next unseen.
    SH10  after the accepted key is written, an unreadable .ek.next is
          taken for a copy of it and removed.
    SH11  keyfile_staged_is calls a directory an I/O error.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CL = "apps/authd/client_cli.c"

M = {
    "SH1": [(KF, '    for (int n = 0; n < KEYFILE_ASIDE_NAMES; n++) {\n',
             '    for (int n = 0; n < 1; n++) { /* MUTATION SH1 */\n')],
    "SH2": [(KF, "    aside[0] = '\\0';\n    return KEYFILE_ERR_EXISTS;\n}\n",
             "    aside[0] = '\\0';\n    return KEYFILE_OK; /* MUTATION SH2 */\n}\n")],
    "SH3": [(KF, '    if (path == NULL || expect == NULL || exposed == NULL) {\n        return KEYFILE_ERR_ARG;\n    }\n    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n',
             '    if (path == NULL || expect == NULL || exposed == NULL) {\n        return KEYFILE_ERR_ARG;\n    }\n    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK); /* MUTATION SH3 */\n')],
    "SH4": [(KF, '    r = move_aside(path, 1, aside, aside_cap);\n',
             '    r = KEYFILE_OK; /* MUTATION SH4 */\n')],
    "SH5": [(KF, '    if (hs != KEYFILE_OK) {\n        return hs;\n    }\n    char fresh[4096];\n',
             '    if (0 && hs != KEYFILE_OK) { /* MUTATION SH5 */\n        return hs;\n    }\n    char fresh[4096];\n')],
    "SH6": [(CL, '    if (ps == KEYFILE_OK) {\n        return ps;\n    }\n    /* V4-373 (F838)',
             '    if (ps != KEYFILE_ERR_CHANGED) { /* MUTATION SH6 */\n        return ps;\n    }\n    /* V4-373 (F838)')],
    "SH7": [(CL, "    char aside[PATH_MAX];\n    aside[0] = '\\0';\n    const keyfile_status_t rs = sealed == NULL ? KEYFILE_ERR_ARG\n",
             "    char aside[PATH_MAX];\n    aside[0] = '\\0';\n    if (is != KEYFILE_ERR_CHANGED) { return 0; } /* MUTATION SH7 */\n    const keyfile_status_t rs = sealed == NULL ? KEYFILE_ERR_ARG\n")],
    "SH8": [(CL, '        const int ok = sealed != NULL && keyfile_replace_sealed(next_path, sealed, sealed_len) == KEYFILE_OK;\n',
             '        const int ok = sealed != NULL; /* MUTATION SH8 */\n')],
    "SH9": [(CL, '            /* V4-373 (F841): and it is compared like every other kept one. */\n            (void)client_restage_opened(prog, "rotate", next_path, a.key_path, next_digest, next_sealed, next_sealed_len);\n',
             '            /* MUTATION SH9 */\n')],
    "SH10": [(CL, '    if (is == KEYFILE_OK) {\n        /* The same bytes: what changed',
             '    if (is != KEYFILE_ERR_CHANGED) { /* MUTATION SH10 */\n        /* The same bytes: what changed')],
    "SH11": [(KF, '    } else if (!S_ISREG(st.st_mode) || st.st_size < 0 || (size_t)st.st_size > keyfile_max_total()) {\n        r = KEYFILE_ERR_CHANGED;\n    } else if (digest_fd(fd, got) != 0) {\n',
             '    } else if (!S_ISREG(st.st_mode) || st.st_size < 0 || (size_t)st.st_size > keyfile_max_total()) {\n        r = KEYFILE_ERR_IO; /* MUTATION SH11 */\n    } else if (digest_fd(fd, got) != 0) {\n')],
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
