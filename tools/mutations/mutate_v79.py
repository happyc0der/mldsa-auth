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
    PF6   the owner is ignored. Until V4-99 only authd_e2e's privileged Linux
          leg could kill it; the custody decision is now a pure function, so
          test_authd_cli kills it on every platform.
    PF7   a file holding only a newline is accepted as an empty passphrase.

V4-99 (erratum 74), systemd's root:root credential, accepted only directly
inside $CREDENTIALS_DIRECTORY:
    PF8   the exception is gone: the deployment path cannot start again.
    PF9   the directory prefix is not bounded by '/'.
    PF10  a subdirectory of the credentials directory counts as inside it.
    PF11  "other" bits are allowed on a credential.
    PF12  any group, not only root's, earns the exception.
    PF13  a relative $CREDENTIALS_DIRECTORY is trusted.
    PF14  group write is allowed on a credential.
"""
import sys, pathlib
S = "apps/authd/authd_secret.c"

M = {
    "PF1": [(S, "    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);\n",
                "    const int fd = open(path, O_RDONLY | O_CLOEXEC); /* MUTATION PF1: symlinks followed */\n")],
    "PF2": [(S, "    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_NOT_REGULAR;\n",
                "    if (fstat(fd, &st) != 0) { /* MUTATION PF2: any file type */\n        (void)close(fd);\n        return AUTHD_SECRET_ERR_NOT_REGULAR;\n")],
    "PF3": [(S, "    if ((mode & 077) != 0) {\n        return AUTHD_SECRET_ERR_PERMISSIONS;\n",
                "    if ((mode & 077) != 0 && 0) { /* MUTATION PF3: mode ignored */\n        return AUTHD_SECRET_ERR_PERMISSIONS;\n")],
    "PF4": [(S, "    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX) {\n",
                "    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX + 1u) { /* MUTATION PF4: off by one */\n")],
    "PF5": [(S, "    if (got > 0u && buf[got - 1u] == (uint8_t)'\\n') {\n",
                "    while (got > 0u && buf[got - 1u] == (uint8_t)'\\n') { /* MUTATION PF5: every newline */\n")],
    "PF6": [(S, "    if (uid != euid) {\n        return AUTHD_SECRET_ERR_OWNER;\n",
                "    if (uid != euid && 0) { /* MUTATION PF6: owner ignored */\n        return AUTHD_SECRET_ERR_OWNER;\n")],
    "PF7": [(S, "    if (got == 0u) {\n        secure_mem_free(buf, want);\n        return AUTHD_SECRET_ERR_SIZE;\n",
                "    if (got == 0u && 0) { /* MUTATION PF7: an empty passphrase accepted */\n        secure_mem_free(buf, want);\n        return AUTHD_SECRET_ERR_SIZE;\n")],
    # V4-99 (erratum 74): the systemd-credential exception.
    "PF8": [(S, "    if (uid == (uid_t)0 && gid == (gid_t)0 && in_creds_dir(path, creds_dir)) {\n",
                "    if (0 && uid == (uid_t)0 && gid == (gid_t)0 && in_creds_dir(path, creds_dir)) { /* MUTATION PF8: no credential exception */\n")],
    "PF9": [(S, "    if (strncmp(path, creds_dir, n) != 0 || path[n] != '/') {\n",
                "    if (strncmp(path, creds_dir, n) != 0) { /* MUTATION PF9: prefix not bounded by '/' */\n")],
    "PF10": [(S, "    return base[0] != '\\0' && strchr(base, '/') == NULL;\n",
                 "    return base[0] != '\\0'; /* MUTATION PF10: a subdirectory is inside */\n")],
    "PF11": [(S, "        if ((mode & 027) != 0) {\n",
                 "        if ((mode & 020) != 0) { /* MUTATION PF11: other bits allowed on a credential */\n")],
    "PF12": [(S, "    if (uid == (uid_t)0 && gid == (gid_t)0 && in_creds_dir(path, creds_dir)) {\n",
                 "    if (uid == (uid_t)0 && (gid == (gid_t)0 || 1) && in_creds_dir(path, creds_dir)) { /* MUTATION PF12: any group */\n")],
    "PF13": [(S, "    if (path == NULL || creds_dir == NULL || creds_dir[0] != '/') {\n",
                 "    if (path == NULL || creds_dir == NULL) { /* MUTATION PF13: a relative directory trusted */\n")],
    "PF14": [(S, "        if ((mode & 027) != 0) {\n",
                 "        if ((mode & 007) != 0) { /* MUTATION PF14: group write allowed on a credential */\n")],
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
