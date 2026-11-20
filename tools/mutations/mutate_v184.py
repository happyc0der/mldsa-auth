#!/usr/bin/env python3
"""V4-339 mutations: the store's shape, and nothing in the file is run (F653 to F655).

Usage: mutate_v184.py <repo> <ID>

    SH1   the shape is not checked inside the open's transaction, which is the only check a tool's open has.
    SH3   triggers the file holds are run.
    SH6   an audit row's detail may be stored as NULL.
    SH7   an object's definition is not compared (V4-341).
    SH8   SQLite's own tables are part of the shape.
    SH9   the daemon writes to a file before it looks at it.
    SH10  a refusal does not say where it stopped.
    SH11  one space more in the schema's text (every released store refused).
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "SH1": [(ST, "    if ((r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; }\n",
             "    if (0 && (r = schema_is_ours(s->db)) != STORE_OK) { goto fail_tx; } /* MUTATION SH1 */\n")],
    "SH3": [(ST, "    if (sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, &on) != SQLITE_OK || on != 0 ||\n        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, &on) != SQLITE_OK || on != 0 ||\n",
             "    if ( /* MUTATION SH3 */\n        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, &on) != SQLITE_OK || on != 0 ||\n")],
    "SH7": [(ST, "        \"SELECT type, name, tbl_name, ifnull(sql, '') FROM sqlite_master \"\n",
             "        \"SELECT type, name, tbl_name, '' FROM sqlite_master \" /* MUTATION SH7 */\n")],
    "SH8": [(ST, "        \"WHERE NOT (type = 'table' AND tbl_name = name AND (\"\n",
             "        \"WHERE NOT (type = 'tablex' AND tbl_name = name AND (\" /* MUTATION SH8 */\n")],
    "SH9": [(ST, "        if (objects > 0 && (r = schema_is_ours(s->db)) != STORE_OK) { goto fail; }\n",
             "        if (0 && objects > 0 && (r = schema_is_ours(s->db)) != STORE_OK) { goto fail; } /* MUTATION SH9 */\n")],
    "SH10": [(ST, "            if (r != STORE_OK) { shape_note_set(fa, b); }\n",
              "            if (0 && r != STORE_OK) { shape_note_set(fa, b); } /* MUTATION SH10 */\n")],
    "SH11": [("apps/authd/store/schema.sql.h", "    \"CREATE TABLE IF NOT EXISTS meta(\"\n",
              "    \"CREATE TABLE IF NOT EXISTS meta( \" /* MUTATION SH11 */\n")],
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
