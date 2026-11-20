#!/usr/bin/env python3
"""V4-251 mutations: a failed start takes the store it created with it (F361);
--check-config looks at the store (F362) and at socket paths that are one
file under two spellings (F363).

Usage: mutate_v147.py <repo> <ID>

Two-letter IDs: FS = Failed Start, ST = STore check, SK = SocKet aliases.
Every spec line names the check that must catch it (F90).

    FS1   The store a failed start created is left behind.
    FS2   A failed start removes the store whether it created it or not.
    FS3   The store is removed without a word.
    ST1   A store_path that is not a regular file is not refused as one.
    ST2   The first bytes of the store are not looked at.
    ST3   An empty file is refused as "not a store".
    ST4   The daemon's --check-config does not ask about the store.
    ST5   authd_admin --check-config does not ask about the store.
    SK1   Two spellings of one directory are two directories.
    SK2   Any two sockets in one directory collide.
    SK3   site_socket and admin_socket are not compared.
    SK4   listen_unix and admin_socket are not compared.
    SK5   Directories are compared by device alone.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"
CFG = "apps/authd/authd_config.c"
CLI = "apps/authd/authd_cli.c"

M = {
    "FS1": [(MAIN, "    if (store_created) {\n        remove_created_store(cfg.store_path);\n",
             "    if (0) { /* MUTATION FS1 */\n        remove_created_store(cfg.store_path);\n")],
    "FS2": [(MAIN, "    if (store_created) {\n        remove_created_store(cfg.store_path);\n",
             "    if (1) { /* MUTATION FS2 */\n        remove_created_store(cfg.store_path);\n")],
    "FS3": [(MAIN, "    authd_log_say(\"mldsa-authd: %s: this start created the store and did not get as far as serving it, \"\n",
             "    if (0) authd_log_say(\"mldsa-authd: %s: this start created the store and did not get as far as serving it, \" /* MUTATION FS3 */\n")],
    "ST1": [(CFG, "    if (!S_ISREG(st.st_mode)) {\n        detail_set(detail, cap, K_STORE, path, \"is not a regular file\");\n",
             "    if (0) { /* MUTATION ST1 */\n        detail_set(detail, cap, K_STORE, path, \"is not a regular file\");\n")],
    "ST2": [(CFG, "    if (n != 0 && (n != (ssize_t)sizeof head || memcmp(head, magic, sizeof magic) != 0)) {\n",
             "    if (n != 0 && (n != (ssize_t)sizeof head || memcmp(head, magic, sizeof magic) != 0) && 0) { /* MUTATION ST2 */\n")],
    "ST3": [(CFG, "    if (n != 0 && (n != (ssize_t)sizeof head || memcmp(head, magic, sizeof magic) != 0)) {\n",
             "    if ((n != (ssize_t)sizeof head || memcmp(head, magic, sizeof magic) != 0)) { /* MUTATION ST3 */\n")],
    "ST4": [(MAIN, "            if (authd_config_check_store(&cfg, detail, sizeof detail) != AUTHD_CFG_OK) {\n",
             "            if (0 && authd_config_check_store(&cfg, detail, sizeof detail) != AUTHD_CFG_OK) { /* MUTATION ST4 */\n")],
    "ST5": [(CLI, "    if (authd_config_check_store(&cfg, detail, sizeof detail) != AUTHD_CFG_OK) {\n",
             "    if (0 && authd_config_check_store(&cfg, detail, sizeof detail) != AUTHD_CFG_OK) { /* MUTATION ST5 */\n")],
    "SK1": [(CFG, "    return stat(da, &ta) == 0 && stat(db, &tb) == 0 && ta.st_dev == tb.st_dev && ta.st_ino == tb.st_ino;\n",
             "    return strcmp(da, db) == 0 && stat(da, &ta) == 0 && stat(db, &tb) == 0; /* MUTATION SK1 */\n")],
    "SK2": [(CFG, "    if (strcmp(na, nb) != 0) {\n        return 0;\n    }\n    if (sa != NULL) { dir_of(da, sa); }",
             "    if (strcmp(na, nb) != 0 && 0) { /* MUTATION SK2 */\n        return 0;\n    }\n    if (sa != NULL) { dir_of(da, sa); }")],
    "SK3": [(CFG, "    if (same_socket(cfg->site_socket, cfg->admin_socket)) {\n",
             "    if (0 && same_socket(cfg->site_socket, cfg->admin_socket)) { /* MUTATION SK3 */\n")],
    "SK4": [(CFG, "    if (same_socket(cfg->listen_unix, cfg->admin_socket)) {\n",
             "    if (0 && same_socket(cfg->listen_unix, cfg->admin_socket)) { /* MUTATION SK4 */\n")],
    "SK5": [(CFG, "    return stat(da, &ta) == 0 && stat(db, &tb) == 0 && ta.st_dev == tb.st_dev && ta.st_ino == tb.st_ino;\n",
             "    return stat(da, &ta) == 0 && stat(db, &tb) == 0 && ta.st_dev == tb.st_dev; /* MUTATION SK5 */\n")],
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
