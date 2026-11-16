#!/usr/bin/env python3
"""V4-239 mutations: --check-config looks at the secret files as the start does; a path directly under / (F336, F337).

Usage: mutate_v142.py <repo> <ID>

Two-letter IDs: CP = Check Paths. Every spec line names the check that must
catch it (F90).

    CP1   The directory of "/x" is "/x" again, not "/".
    CP2   --check-config does not look at the passphrase file.
    CP3   --check-config does not look at the key file.
    CP4   The passphrase probe follows a symlink.
    CP5   The key probe refuses only the "other" bits.
"""
import sys, pathlib
CF = "apps/authd/authd_config.c"
MN = "apps/authd/authd_main.c"
SE = "apps/authd/authd_secret.c"
KF = "apps/authd/keyfile.c"

M = {
    "CP1": [(CF,
             "    if (last_slash == path) {\n        path[1] = '\\0';\n",
             "    if (last_slash == path) {\n        path[0] = '/'; /* MUTATION CP1 */\n")],
    "CP2": [(MN,
             "        const authd_secret_status_t probe_pass = authd_secret_probe(cfg.key_passphrase_file);\n",
             "        const authd_secret_status_t probe_pass = AUTHD_SECRET_OK; /* MUTATION CP2 */\n")],
    "CP3": [(MN,
             "        const keyfile_status_t probe_key = keyfile_probe(cfg.key_path);\n",
             "        const keyfile_status_t probe_key = KEYFILE_OK; /* MUTATION CP3 */\n")],
    "CP4": [(SE,
             "    const int probe_fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n",
             "    const int probe_fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK); /* MUTATION CP4 */\n")],
    "CP5": [(KF,
             "    } else if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {   /* its owner's alone */\n",
             "    } else if (st.st_uid != geteuid() || (st.st_mode & 007) != 0) { /* MUTATION CP5 */\n")],
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
