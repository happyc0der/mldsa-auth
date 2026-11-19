#!/usr/bin/env python3
"""V4-329 mutations: the clock after a BACKUP (F612).

Usage: mutate_v179.py <repo> <ID>

    BC1   h_backup does not ask for the clock to be read again.
    BC2   it asks only when the backup was written.

The browser's flow (F611, F618) is JavaScript, which no campaign compiles;
its controls were run with hand_control.py --interpreted and are listed in
docs/decisions.md under V4-329. F613 and F614 changed the probe that kills
campaign v103's CK4 and CK5, which were killed again by hand.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "BC1": [(LA, "        app->clock_refresh(app);          /* F612: the copy took as long as it took */\n",
             "        /* MUTATION BC1 */\n")],
    "BC2": [(LA, "    if (app->clock_refresh != NULL) {\n        app->clock_refresh(app);          /* F612",
             "    if (app->clock_refresh != NULL && bs == STORE_OK) { /* MUTATION BC2 */\n        app->clock_refresh(app);          /* F612")],
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
