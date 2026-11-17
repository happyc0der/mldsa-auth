#!/usr/bin/env python3
"""V4-256 mutations: the configuration's size limit, which the fuzz harness
could not reach while its own bound was 4096 (F372).

Usage: mutate_v149.py <repo> <ID>

Two-letter ID: CB = Config Bound. Every spec line names the check that must
catch it (F90). Both are caught by the two seeds F372 added, one of exactly
AUTHD_CONFIG_MAX_BYTES and one a byte over.

    CB1   A configuration of exactly the maximum size is refused as too large.
    CB2   A configuration one byte over the maximum is parsed.
"""
import sys, pathlib
CFG = "apps/authd/authd_config.c"

M = {
    "CB1": [(CFG, "    if (len > AUTHD_CONFIG_MAX_BYTES) {\n        return AUTHD_CFG_ERR_TOO_LARGE;\n",
             "    if (len >= AUTHD_CONFIG_MAX_BYTES) { /* MUTATION CB1 */\n        return AUTHD_CFG_ERR_TOO_LARGE;\n")],
    "CB2": [(CFG, "    if (len > AUTHD_CONFIG_MAX_BYTES) {\n        return AUTHD_CFG_ERR_TOO_LARGE;\n",
             "    if (len > AUTHD_CONFIG_MAX_BYTES + 1u) { /* MUTATION CB2 */\n        return AUTHD_CFG_ERR_TOO_LARGE;\n")],
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
