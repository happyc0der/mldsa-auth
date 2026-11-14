#!/usr/bin/env python3
"""V4-111 mutations: a daemon that creates its store says so (F199), and a
store is created 0600 whatever the umask is (F200).

Usage: mutate_v90.py <repo> <ID>

Two-letter IDs: SC = Store Created. store_open remembers whether this call
gave the store its id; the daemon prints a line on standard error and logs
store-created at WARN when it did. Every spec line names the check that must
catch it (F90).

    SC1   the open that makes a store does not remember it.
    SC2   every open says it made the store.
    SC3   the file is not created before SQLite opens it, so it takes the
          umask's mode (what F200 reported).
    SC4   the creating open has no O_EXCL: an existing store is chmod-ed.
    SC5   the daemon prints nothing on standard error (half of F199).
    SC6   the daemon does not log the event (the other half).
    SC7   the event is logged at INFO.
    SC8   the daemon says it created the store on every start.
"""
import sys, pathlib
ST = "apps/authd/store/store.c"
MAIN = "apps/authd/authd_main.c"

M = {
    "SC1": [(ST, "        s->created = 1;\n",
                 "        s->created = 0; /* MUTATION SC1 */\n")],
    "SC2": [(ST, "    return (s != NULL) ? s->created : 0;\n",
                 "    return (s != NULL) ? 1 : 0; /* MUTATION SC2 */\n")],
    # Since V4-172 (F246) the condition also leaves SQLite's ":memory:" alone.
    "SC3": [(ST, "    if (!existing && strcmp(path, \":memory:\") != 0) {\n"
                 "        /* A store this call creates is 0600 whatever the caller's umask is\n",
                 "    if (0 && !existing) { /* MUTATION SC3 */\n"
                 "        /* A store this call creates is 0600 whatever the caller's umask is\n")],
    "SC4": [(ST, "        const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);\n"
                 "        if (fd >= 0) {\n"
                 "            (void)fchmod(fd, 0600);\n",
                 "        const int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600); /* MUTATION SC4 */\n"
                 "        if (fd >= 0) {\n"
                 "            (void)fchmod(fd, 0600);\n")],
    "SC5": [(MAIN, "    if (store_created) {\n"
                   "        fprintf(stderr, \"mldsa-authd: %s: created a new, empty store (no store was there)\\n\", cfg.store_path);\n",
                   "    if (0 && store_created) { /* MUTATION SC5 */\n"
                   "        fprintf(stderr, \"mldsa-authd: %s: created a new, empty store (no store was there)\\n\", cfg.store_path);\n")],
    "SC6": [(MAIN, "    if (store_created) {\n"
                   "        authd_log_event(AUTHD_LOG_WARN, \"store-created\");\n",
                   "    if (0 && store_created) { /* MUTATION SC6 */\n"
                   "        authd_log_event(AUTHD_LOG_WARN, \"store-created\");\n")],
    "SC7": [(MAIN, "        authd_log_event(AUTHD_LOG_WARN, \"store-created\");\n",
                   "        authd_log_event(AUTHD_LOG_INFO, \"store-created\"); /* MUTATION SC7 */\n")],
    "SC8": [(MAIN, "    const int store_created = store_was_created(store);\n",
                   "    const int store_created = 1; (void)store_was_created(store); /* MUTATION SC8 */\n")],
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
