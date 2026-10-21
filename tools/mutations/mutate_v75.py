#!/usr/bin/env python3
"""V4-42 mutations: key-file custody (audit F122, spec 12).

Usage: mutate_v75.py <repo> <ID>

Two-letter IDs: KC = Key-file Custody. keyfile_open refuses a key file that is
not this euid's or has any group or other bit set, and keyfile_promote refuses
to rename such a file into place. V4-40's coverage run found neither refusal
had ever run, so deleting either half passed every check. Every spec line names
the check that must catch it (F90).

    KC1   keyfile_open ignores the mode: a 0644 key file opens.
    KC2   keyfile_open ignores the GROUP bits only (077 becomes 007).
    KC3   keyfile_open ignores the OTHER bits only (077 becomes 070).
    KC4   keyfile_promote ignores the mode: rotation renames a group-readable
          candidate over the live key.
    KC5   keyfile_open ignores the owner: a key file another user owns opens.
          Only a privileged leg can make such a file readable to the client,
          so this is killed by authd_e2e on Linux with root or passwordless
          sudo (CI, the nightly), and survives on macOS, where that leg is
          skipped -- as v58's GA13 and GA14 do.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"

M = {
    "KC1": [(KF, "    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n",
                 "    if (st.st_uid != geteuid() || 0 /* MUTATION KC1: mode ignored */) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n")],
    "KC2": [(KF, "    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n",
                 "    if (st.st_uid != geteuid() || (st.st_mode & 007) != 0 /* MUTATION KC2: group bits ignored */) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n")],
    "KC3": [(KF, "    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n",
                 "    if (st.st_uid != geteuid() || (st.st_mode & 070) != 0 /* MUTATION KC3: other bits ignored */) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n")],
    "KC4": [(KF, "    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {\n        (void)close(fd);\n        return KEYFILE_ERR_PERMISSIONS;\n",
                 "    if (st.st_uid != geteuid() || 0 /* MUTATION KC4: promote ignores the mode */) {\n        (void)close(fd);\n        return KEYFILE_ERR_PERMISSIONS;\n")],
    "KC5": [(KF, "    if (st.st_uid != geteuid() || (st.st_mode & 077) != 0) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n",
                 "    if (/* MUTATION KC5: owner ignored */ (st.st_mode & 077) != 0) {\n        r = KEYFILE_ERR_PERMISSIONS; goto done;\n")],
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
