#!/usr/bin/env python3
"""V4-200 mutations: evidence the claim map cited and did not have (F278).

Usage: mutate_v127.py <repo> <ID>

Two-letter IDs: LB = LaBel. Every spec line names the check that must catch
it (F90). (F277 is pinned by v49c W7, which the new store check now kills;
F279 by v49c W12, which authd_e2e now kills too: both shown by hand.)

    LB1   The rotate-new label is a different string. Both sides share the
          macro, so every round trip still works.
"""
import sys, pathlib

M = {
    "LB1": [("apps/authd/authmsg.h",
             "#define AUTHMSG_LABEL_ROTATE_NEW \"mldsa-authd/v1/rotate-new\"\n",
             "#define AUTHMSG_LABEL_ROTATE_NEW \"mldsa-authd/v1/rotate-nxw\" /* MUTATION LB1 */\n")],
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
