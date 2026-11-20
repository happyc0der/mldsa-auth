#!/usr/bin/env python3
"""V4-342 mutations: a signal during start-up (F657).

Usage: mutate_v185.py <repo> <ID>

    SE1   SIGTERM is handled only once the listeners are bound, as before V4-342.
    SE2   a stop is not looked for before `started`: the daemon starts, then drains
          (since V4-344 that is one look, the last; V4-342 had a second after the
          store was made, which nothing could tell from it).
    SE3   a daemon stopped before it started exits 1.
    SE4   SIGHUP is handled only once the listeners are bound.
    RS1   any table whose name begins sqlite_ is SQLite's own (as in V4-341).
    RS2   sqlite_stat1 is exempt whatever its definition.
    (RS3 to RS5, the three checks inside the open's transaction, went in
    V4-344 with those checks: v186's RA4 removes the one check there is now.)
    RS6   a tool's open does not ask the version before the shape.
    RS7   a meta table that cannot be read is a database error, not the shape's.
    RS8   a refused file is checkpointed on close.
    RS9   the note never says "lacks".
    RS10  the note is not cleared when an open begins.
"""
import sys, pathlib
A = "apps/authd/authd_main.c"
ST = "apps/authd/store/store.c"

M = {
    "SE1": [(A, "        (void)sigaction(SIGTERM, &sa, NULL);\n        (void)sigaction(SIGINT, &sa, NULL);\n        (void)sigaction(SIGHUP, &sa, NULL);\n        signal(SIGPIPE, SIG_IGN);   /* a peer that vanishes mid-write is routine */\n",
             "        (void)sigaction(SIGHUP, &sa, NULL); /* MUTATION SE1 */\n        signal(SIGPIPE, SIG_IGN);\n"),
            (A, "    /* How much of this daemon's memory can actually be locked (spec 16,\n",
             "    { struct sigaction sl; memset(&sl, 0, sizeof sl); sl.sa_handler = on_signal; (void)sigaction(SIGTERM, &sl, NULL); (void)sigaction(SIGINT, &sl, NULL); } /* MUTATION SE1 */\n    /* How much of this daemon's memory can actually be locked (spec 16,\n")],
    "SE2": [(A, "     * told that look from this one, so it went (F683). */\n    if (g_stop) {\n",
             "     * told that look from this one, so it went (F683). */\n    if (0 && g_stop) { /* MUTATION SE2 */\n")],
    "SE3": [(A, "    early_rc = 0;\nlistener_failed:\n",
             "    early_rc = 1; /* MUTATION SE3 */\nlistener_failed:\n")],
    "SE4": [(A, "        (void)sigaction(SIGINT, &sa, NULL);\n        (void)sigaction(SIGHUP, &sa, NULL);\n        signal(SIGPIPE, SIG_IGN);   /* a peer that vanishes mid-write is routine */\n",
             "        (void)sigaction(SIGINT, &sa, NULL); /* MUTATION SE4 */\n        signal(SIGPIPE, SIG_IGN);\n"),
            (A, "    /* How much of this daemon's memory can actually be locked (spec 16,\n",
             "    { struct sigaction sl; memset(&sl, 0, sizeof sl); sl.sa_handler = on_signal; (void)sigaction(SIGHUP, &sl, NULL); } /* MUTATION SE4 */\n    /* How much of this daemon's memory can actually be locked (spec 16,\n")],
    "RS1": [(ST, "        \"(name = 'sqlite_sequence' AND sql = 'CREATE TABLE sqlite_sequence(name,seq)'))) \"\n",
             "        \"(name LIKE 'sqlite_%'))) \" /* MUTATION RS1 */\n")],
    "RS2": [(ST, "        \"(name = 'sqlite_stat1' AND sql = 'CREATE TABLE sqlite_stat1(tbl,idx,stat)') OR \"\n",
             "        \"(name = 'sqlite_stat1') OR \" /* MUTATION RS2 */\n")],
    "RS6": [(ST, "        if ((r = has_meta_table(s->db, &has_meta)) != STORE_OK) { goto fail; }\n        if (has_meta) {\n",
             "        if ((r = has_meta_table(s->db, &has_meta)) != STORE_OK) { goto fail; }\n        if (has_meta && !existing) { /* MUTATION RS6 */\n")],
    "RS7": [(ST, "                if (r == STORE_ERR_DB && schema_is_ours(s->db) == STORE_ERR_DAMAGED) { r = STORE_ERR_DAMAGED; }\n",
             "                if (0 && r == STORE_ERR_DB && schema_is_ours(s->db) == STORE_ERR_DAMAGED) { r = STORE_ERR_DAMAGED; } /* MUTATION RS7 */\n")],
    "RS8": [(ST, "        (void)sqlite3_db_config(s->db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, (int *)NULL);\n",
             "        (void)sqlite3_db_config(s->db, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 0, (int *)NULL); /* MUTATION RS8 */\n")],
    "RS9": [(ST, "        const int cmp = f_end ? 1 : (o_end ? -1 : strcmp(f, o));\n",
             "        const int cmp = f_end ? 1 : (o_end ? -1 : -1); /* MUTATION RS9 */\n")],
    "RS10": [(ST, "    g_shape_note[0] = '\\0';     /* F677: never an earlier open's */\n",
              "    /* MUTATION RS10 */\n")],
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
