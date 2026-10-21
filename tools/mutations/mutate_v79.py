#!/usr/bin/env python3
"""V4-48 mutations: the passphrase file's custody (authd_secret_read).

Usage: mutate_v79.py <repo> <ID>

Two-letter IDs: PF = Passphrase File. authd_secret_read is how the daemon and
both CLIs read a passphrase; V4-40/44's coverage found that only its mode
refusal had ever run. Every spec line names the check that must catch it (F90).

    PF1   a symlink is followed (O_NOFOLLOW dropped).
    PF2   a non-regular file is read (the S_ISREG check dropped): a directory
          then fails later, as short-read, not as not-a-regular-file.
    PF3   group and other bits are ignored.
    PF4   off by one: a file one byte over AUTHD_PASSPHRASE_MAX is read.
    PF5   every trailing newline is stripped, not one.
    PF6   the owner is ignored. Killed by authd_e2e's privileged Linux leg
          only, as v75's KC5 is; it survives on macOS.
    PF7   a file holding only a newline is accepted as an empty passphrase.
"""
import sys, pathlib
S = "apps/authd/authd_secret.c"

M = {
    "PF1": [(S, "    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);\n",
                "    const int fd = open(path, O_RDONLY | O_CLOEXEC); /* MUTATION PF1: symlinks followed */\n")],
    "PF2": [(S, "    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_NOT_REGULAR;\n",
                "    if (fstat(fd, &st) != 0) { /* MUTATION PF2: any file type */\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_NOT_REGULAR;\n")],
    "PF3": [(S, "    if ((st.st_mode & 077) != 0) {\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_PERMISSIONS;\n",
                "    if ((st.st_mode & 077) != 0 && 0) { /* MUTATION PF3: mode ignored */\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_PERMISSIONS;\n")],
    "PF4": [(S, "    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX) {\n",
                "    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX + 1u) { /* MUTATION PF4: off by one */\n")],
    "PF5": [(S, "    if (got > 0u && buf[got - 1u] == (uint8_t)'\\n') {\n",
                "    while (got > 0u && buf[got - 1u] == (uint8_t)'\\n') { /* MUTATION PF5: every newline */\n")],
    "PF6": [(S, "    if (st.st_uid != geteuid()) {\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_OWNER;\n",
                "    if (st.st_uid != geteuid() && 0) { /* MUTATION PF6: owner ignored */\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_OWNER;\n")],
    "PF7": [(S, "    if (got == 0u) {\n        secure_mem_free(buf, want);\n        return AUTHD_SECRET_ERR_SIZE;\n",
                "    if (got == 0u && 0) { /* MUTATION PF7: an empty passphrase accepted */\n        secure_mem_free(buf, want);\n        return AUTHD_SECRET_ERR_SIZE;\n")],
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
