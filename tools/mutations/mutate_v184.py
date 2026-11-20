#!/usr/bin/env python3
"""V4-339 mutations: the store's shape, and nothing in the file is run (F653 to F655).

Usage: mutate_v184.py <repo> <ID>

    SH1   the shape is not checked at open.
    SH2   the columns are not compared, only the objects and their count.
    SH3   triggers the file holds are run.
    SH5   a tool that only reads does not check the shape.
    SH6   an audit row's detail may be stored as NULL.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "SH1": [(ST, "    if ((r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; }\n",
             "    if (0 && (r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; } /* MUTATION SH1 */\n")],
    "SH2": [(ST, "        \"FROM sqlite_master m, pragma_table_xinfo(m.name) x WHERE m.type = 'table' ORDER BY m.name, x.cid;\",\n",
             "        \"FROM sqlite_master m, pragma_table_xinfo(m.name) x WHERE m.type = 'tablex' ORDER BY m.name, x.cid;\", /* MUTATION SH2 */\n")],
    "SH3": [(ST, "    if (sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, &on) != SQLITE_OK || on != 0 ||\n        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, &on) != SQLITE_OK || on != 0 ||\n",
             "    if ( /* MUTATION SH3 */\n        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, &on) != SQLITE_OK || on != 0 ||\n")],
    "SH5": [(ST, "    if ((r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; }\n",
             "    if (!existing && (r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; } /* MUTATION SH5 */\n")],
    "SH6": [(ST, "    return audit_text_ok(st, 2, 0) && audit_text_ok(st, 5, 0);   /* F655: the writer never stored a NULL */\n",
             "    return audit_text_ok(st, 2, 0) && audit_text_ok(st, 5, 1); /* MUTATION SH6 */\n")],
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
