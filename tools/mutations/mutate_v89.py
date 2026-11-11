#!/usr/bin/env python3
"""V4-109 mutations: the offline commands and the live store (F192, F193), a
repeated disable (F194, spec 10.3 erratum 80) and init's refusals (F195).

Usage: mutate_v89.py <repo> <ID>

Two-letter IDs: OE = Open Existing. store_open_existing opens a store without
creating one and waits for another connection's lock; the daemon's handle
waits briefly; a second disable or enable of a user changes nothing; init
finds an old server.pub before writing anything and says whether it created
the directory. Every spec line names the check that must catch it (F90).

    OE1   store_open_existing is store_open: a mistyped path becomes a store.
    OE2   the open flags always carry SQLITE_OPEN_CREATE.
    OE3   a file with no meta table is not refused before the schema runs (it
          is still refused, for having no store id, but no longer left empty).
    OE4   a database with no store id is given one.
    OE5   the offline open waits only as long as the daemon does.
    OE6   the daemon's handle does not wait at all (what F192 reported).
    OE7   the daemon's handle waits as long as an offline tool.
    OE8   audit-verify opens with store_open.
    OE9   pseudonym opens with store_open.
    OE10  the status UPDATE matches a user already in that state (what F194
          reported: the first disable's time and reason are overwritten).
    OE11  a user already in that state is answered NOT_FOUND.
    OE12  a user that does not exist is answered OK.
    OE13  init does not look for server.pub up front.
    OE14  init always says it created the directory.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
CLI = "apps/authd/authd_cli.c"

M = {
    "OE1": [(ST, "    return open_impl(path, kek, 1, out);\n",
                 "    return open_impl(path, kek, 0 /* MUTATION OE1 */, out);\n")],
    "OE2": [(ST, "                        existing ? SQLITE_OPEN_READWRITE : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),\n",
                 "                        (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE), /* MUTATION OE2 */\n")],
    "OE3": [(ST, "        if (!has) { r = STORE_ERR_DAMAGED; goto fail; }\n",
                 "        if (0 && !has) { r = STORE_ERR_DAMAGED; goto fail; } /* MUTATION OE3 */\n")],
    "OE4": [(ST, "    if (!found && existing) {\n",
                 "    if (0 && !found && existing) { /* MUTATION OE4 */\n")],
    "OE5": [(ST, "    if (sqlite3_busy_timeout(s->db, existing ? STORE_BUSY_MS_OFFLINE : STORE_BUSY_MS_DAEMON) != SQLITE_OK) {\n",
                 "    if (sqlite3_busy_timeout(s->db, STORE_BUSY_MS_DAEMON) != SQLITE_OK) { /* MUTATION OE5 */\n")],
    "OE6": [(ST, "#define STORE_BUSY_MS_DAEMON  250\n",
                 "#define STORE_BUSY_MS_DAEMON  0 /* MUTATION OE6 */\n")],
    "OE7": [(ST, "    if (sqlite3_busy_timeout(s->db, existing ? STORE_BUSY_MS_OFFLINE : STORE_BUSY_MS_DAEMON) != SQLITE_OK) {\n",
                 "    if (sqlite3_busy_timeout(s->db, STORE_BUSY_MS_OFFLINE) != SQLITE_OK) { /* MUTATION OE7 */\n")],
    "OE8": [(CLI, "    const store_status_t so = store_open_existing(db, kek, &store);\n"
                  "    secure_mem_free(kek, STORE_KEK_BYTES);\n"
                  "    if (so != STORE_OK) {\n"
                  "        return failed(prog, \"audit-verify\", db, store_status_name(so));\n",
                  "    const store_status_t so = store_open(db, kek, &store); /* MUTATION OE8 */\n"
                  "    secure_mem_free(kek, STORE_KEK_BYTES);\n"
                  "    if (so != STORE_OK) {\n"
                  "        return failed(prog, \"audit-verify\", db, store_status_name(so));\n")],
    "OE9": [(CLI, "    const store_status_t so = store_open_existing(db, kek, &store);\n"
                  "    secure_mem_free(kek, STORE_KEK_BYTES);\n"
                  "    if (so != STORE_OK) {\n"
                  "        return failed(prog, \"pseudonym\", db, store_status_name(so));\n",
                  "    const store_status_t so = store_open(db, kek, &store); /* MUTATION OE9 */\n"
                  "    secure_mem_free(kek, STORE_KEK_BYTES);\n"
                  "    if (so != STORE_OK) {\n"
                  "        return failed(prog, \"pseudonym\", db, store_status_name(so));\n")],
    "OE10": [(ST, "            \"WHERE user_id=?1 AND status<>?2;\",\n",
                  "            \"WHERE user_id=?1;\", /* MUTATION OE10 */\n")],
    "OE11": [(ST, "            r = (rc == SQLITE_DONE) ? STORE_ERR_NOT_FOUND : (rc == SQLITE_ROW ? STORE_OK : STORE_ERR_DB);\n",
                  "            r = (rc == SQLITE_DONE) ? STORE_ERR_NOT_FOUND : (rc == SQLITE_ROW ? STORE_ERR_NOT_FOUND : STORE_ERR_DB); /* MUTATION OE11 */\n")],
    "OE12": [(ST, "            r = (rc == SQLITE_DONE) ? STORE_ERR_NOT_FOUND : (rc == SQLITE_ROW ? STORE_OK : STORE_ERR_DB);\n",
                  "            r = (rc == SQLITE_DONE) ? STORE_OK : (rc == SQLITE_ROW ? STORE_OK : STORE_ERR_DB); /* MUTATION OE12 */\n")],
    "OE13": [(CLI, "                      : path_exists(pub) ? pub\n",
                   "                      /* MUTATION OE13: server.pub is not looked for */\n")],
    "OE14": [(CLI, "        made_dir = 0;\n",
                   "        made_dir = 1; /* MUTATION OE14 */\n")],
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
