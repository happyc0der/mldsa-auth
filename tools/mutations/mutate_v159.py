#!/usr/bin/env python3
"""V4-284 mutations: the daemon's store, read whole again (F470 to F472).

Usage: mutate_v159.py <repo> <ID>

Two-letter IDs: RA = Revoke All, DR = Disable Reason, SW = SWapped name.
The spec line names the check that must catch it (F90).

    RA1   revoke=all stops after 1024 devices and commits, as before.
    DR1   An enable erases the last disable's time again.
    SW1   The backup does not check that its name is still its file.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "RA1": [(ST, "    while (revoke_all) {\n",
             "    for (size_t g = 0; revoke_all && g < 1024u; g++) { /* MUTATION RA1 */\n")],
    "DR1": [(ST, "\"disabled_at=CASE WHEN ?2='disabled' THEN ?3 ELSE disabled_at END, \"\n",
             "\"disabled_at=CASE WHEN ?2='disabled' THEN ?3 ELSE NULL END, \" /* MUTATION DR1 */\n")],
    "SW1": [(ST, "    if (r == STORE_OK && !ours) {\n",
             "    if (r == STORE_OK && !ours && 0) { /* MUTATION SW1 */\n")],
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
