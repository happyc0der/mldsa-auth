#!/usr/bin/env python3
"""V4-347 mutations: what the ninetieth review found (F700 to F709).

Usage: mutate_v188.py <repo> <ID>

    RC1   a stopping daemon's log line is given no time limit.
    RC2   --check-config passes a store_path that is a symbolic link.
    RC3   a NOTIFY_SOCKET the daemon cannot use is said to be usable.
"""
import sys, pathlib
LG = "apps/authd/authd_log.c"
CF = "apps/authd/authd_config.c"
SD = "apps/authd/sdnotify.c"

M = {
    "RC1": [(LG, "        g_timed = 1;\n        line_timer(LOG_STOPPING_LINE_USEC);\n",
             "        g_timed = 1; /* MUTATION RC1 */\n")],
    "RC2": [(CF, "    if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {\n        detail_set(detail, cap, K_STORE, path, \"is a symbolic link; name the file itself\");\n",
             "    if (0 && lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) { /* MUTATION RC2 */\n        detail_set(detail, cap, K_STORE, path, \"is a symbolic link; name the file itself\");\n")],
    "RC3": [(SD, "    return (p[0] == '/' || p[0] == '@') && strlen(p) < sizeof ((struct sockaddr_un *)0)->sun_path;\n",
             "    return 1; /* MUTATION RC3 */\n")],
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
