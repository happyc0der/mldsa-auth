#!/usr/bin/env python3
"""V4-45 mutations: a damaged store is refused at open (audit F122 item 4).

Usage: mutate_v77.py <repo> <ID>

Two-letter IDs: SD = Store Damage. store_open refuses a store whose
schema_version is malformed or from a later schema, or whose store_id or
decoy_pk has the wrong length; V4-40's coverage run found none of those
refusals had ever run. Every spec line names the check that must catch it (F90).

    SD1   a schema_version of the wrong length is read anyway.
    SD2   a store from a later schema is opened.
    SD3   off by one: the next schema version is accepted.
    SD4   a store_id of the wrong length is accepted.
    SD5   a decoy_pk of the wrong length is accepted.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    # (SD1, the length check on schema_version removed, is gone since V4-213:
    # the value is read into a zeroed buffer and decoded unsigned, so a short
    # one is a multiple of 256 -- zero, which F291 refuses, or far above this
    # build's version. The check stays in the code for what it says; no input
    # can tell a build without it.)
    # (Re-anchored in V4-213: F291 made the comparison unsigned and added
    # v == 0. The mutants are the same.)
    "SD2": [(ST, "        if (v == 0u || v > (uint64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; }\n",
                 "        if (v == 0u || (v > (uint64_t)STORE_SCHEMA_VERSION && 0)) { r = STORE_ERR_SCHEMA; goto fail_tx; } /* MUTATION SD2: later schemas open */\n")],
    "SD3": [(ST, "        if (v == 0u || v > (uint64_t)STORE_SCHEMA_VERSION) { r = STORE_ERR_SCHEMA; goto fail_tx; }\n",
                 "        if (v == 0u || v > (uint64_t)STORE_SCHEMA_VERSION + 1u) { r = STORE_ERR_SCHEMA; goto fail_tx; } /* MUTATION SD3: off by one */\n")],
    "SD4": [(ST, "    } else if (n != sizeof s->store_id) {\n",
                 "    } else if (n != sizeof s->store_id && 0) { /* MUTATION SD4: any store_id length */\n")],
    "SD5": [(ST, "    } else if (n != sizeof s->decoy_pk) {\n",
                 "    } else if (n != sizeof s->decoy_pk && 0) { /* MUTATION SD5: any decoy_pk length */\n")],
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
