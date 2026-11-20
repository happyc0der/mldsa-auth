#!/usr/bin/env python3
"""V4-338 mutations: an audit row is stored as it was written (F643).

Usage: mutate_v183.py <repo> <ID>

    AS1   a text column may have bytes after a NUL.
    AS2   a text column may be stored as bytes.
    AS3   the time may be stored as anything that converts to a number.
    AS4   the user id may be stored as text.
    AS5   the MACs may be stored as text.
    AS6   the check of the last row at start does not look at how it is stored.
    AS7   the reader that shows rows does not.
    AS8   the handle may be stored as text (V4-339).
    AS9   the previous MAC may be.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"

M = {
    "AS1": [(ST, "    return p != NULL && n >= 0 && strlen((const char *)p) == (size_t)n;\n",
             "    return p != NULL && n >= 0; /* MUTATION AS1 */\n")],
    "AS2": [(ST, "    if (t != SQLITE_TEXT) {\n        return 0;\n    }\n",
             "    if (t != SQLITE_TEXT && t != SQLITE_BLOB) { /* MUTATION AS2 */\n        return 0;\n    }\n")],
    "AS3": [(ST, "    if (sqlite3_column_type(st, 0) != SQLITE_INTEGER || sqlite3_column_type(st, 1) != SQLITE_INTEGER) {\n",
             "    if (sqlite3_column_type(st, 0) != SQLITE_INTEGER) { /* MUTATION AS3 */\n")],
    "AS4": [(ST, "    if (!audit_blob_ok(st, 3, 1) || !audit_blob_ok(st, 4, 1)) {\n",
             "    if (!audit_blob_ok(st, 4, 1)) { /* MUTATION AS4 */\n")],
    "AS5": [(ST, "    if (with_macs && (!audit_blob_ok(st, 6, 0) || !audit_blob_ok(st, 7, 0))) {\n",
             "    if (with_macs && !audit_blob_ok(st, 6, 0)) { /* MUTATION AS5 */\n")],
    "AS8": [(ST, "    if (!audit_blob_ok(st, 3, 1) || !audit_blob_ok(st, 4, 1)) {\n",
             "    if (!audit_blob_ok(st, 3, 1)) { /* MUTATION AS8 */\n")],
    "AS9": [(ST, "    if (with_macs && (!audit_blob_ok(st, 6, 0) || !audit_blob_ok(st, 7, 0))) {\n",
             "    if (with_macs && !audit_blob_ok(st, 7, 0)) { /* MUTATION AS9 */\n")],
    "AS6": [(ST, "    if (rc == SQLITE_ROW && !audit_row_shape_ok(st, 1)) {\n        r = STORE_ERR_CORRUPT;                                               /* F643 */\n",
             "    if (rc == SQLITE_ROW && !audit_row_shape_ok(st, 1) && rc != SQLITE_ROW) { /* MUTATION AS6 */\n        r = STORE_ERR_CORRUPT;                                               /* F643 */\n")],
    "AS7": [(ST, "            if (!audit_row_shape_ok(st, 0)) { r = STORE_ERR_CORRUPT; break; }\n",
             "            /* MUTATION AS7 */\n")],
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
