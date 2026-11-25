#!/usr/bin/env python3
"""V4-366 mutations: what the hundred-and-fifth review found (F794, F796).

Usage: mutate_v202.py <repo> <ID>

    SC1   a ROTATE is judged however long after its login code it arrives.
    SC2   a ROTATE exactly the window after its login code is refused.
    SC3   the daemon does not set the window, so a held ROTATE commits
          while the daemon is busy (F794 as it was).
    SC4   the login code's time is not recorded, so every ROTATE is late.
    SC5   a copy of the live key that cannot be removed does not stop the
          run, which goes on as if it had been removed.
"""
import sys, pathlib
AC = "apps/authd/authd_conn.c"
AM = "apps/authd/authd_main.c"
CL = "apps/authd/client_cli.c"

M = {
    "SC1": [(AC, "    if (app->rotate_window_ms != 0u) {\n",
             "    if (0 && app->rotate_window_ms != 0u) { /* MUTATION SC1 */\n")],
    "SC2": [(AC, "        if (age > (uint64_t)app->rotate_window_ms) {\n",
             "        if (age >= (uint64_t)app->rotate_window_ms) { /* MUTATION SC2 */\n")],
    "SC3": [(AM, "    app.rotate_window_ms = cfg.idle_timeout_ms;\n",
             "    /* MUTATION SC3 */\n")],
    "SC4": [(AC, "    c->code_at_ms = rotate_clock(app);\n    c->stage = CONN_STAGE_SERVING;\n",
             "    /* MUTATION SC4 */\n    c->stage = CONN_STAGE_SERVING;\n")],
    "SC5": [(CL, "                if (unlink(next_path) != 0 && errno != ENOENT) {\n                    authd_secret_free(pass, pass_len);\n",
             "                if (unlink(next_path) != 0 && errno != ENOENT && 0) { /* MUTATION SC5 */\n                    authd_secret_free(pass, pass_len);\n")],
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
