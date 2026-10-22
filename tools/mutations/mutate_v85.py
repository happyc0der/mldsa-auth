#!/usr/bin/env python3
"""V4-60 mutations: REVOKE-TOKENS user= handle= is scoped to the user (F123).

Usage: mutate_v85.py <repo> <ID>

Two-letter IDs: RT = Revoke Tokens. store_delete_tokens_for_handle deletes
only the named user's tokens on the handle. Every spec line names the check
that must catch it (F90).

    RT1   the user condition neutralised: any user named with a handle revokes
          the handle's tokens (the behaviour before V4-60).
    RT2   the handle bound where the user belongs: the handle's own user can
          no longer revoke its tokens.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
DEL = "    if (sqlite3_prepare_v2(s->db, \"DELETE FROM tokens WHERE handle=?1 AND user_id=?2;\", -1, &st, NULL) != SQLITE_OK) {\n"

M = {
    "RT1": [(ST, "\"DELETE FROM tokens WHERE handle=?1 AND user_id=?2;\"",
                 "\"DELETE FROM tokens WHERE handle=?1 AND ?2 IS NOT NULL;\" /* MUTATION RT1 */")],
    # The bind line alone occurs five times in store.c; the block from this
    # function's DELETE through its second bind occurs once.
    "RT2": [(ST, DEL + "        return STORE_ERR_DB;\n    }\n    store_status_t r = STORE_OK;\n"
                 "    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||\n"
                 "        sqlite3_bind_blob(st, 2, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||\n",
                 DEL + "        return STORE_ERR_DB;\n    }\n    store_status_t r = STORE_OK;\n"
                 "    if (sqlite3_bind_blob(st, 1, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK ||\n"
                 "        sqlite3_bind_blob(st, 2, handle, (int)handle_len, SQLITE_TRANSIENT) != SQLITE_OK || /* MUTATION RT2 */\n")],
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
