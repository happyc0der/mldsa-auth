#!/usr/bin/env python3
"""V4-233 mutations: the local-API fuzz target reaches the admin handlers (F325).

Usage: mutate_v137.py <repo> <ID>

Two-letter IDs: FA = Fuzz Admin. Every spec line names the check that must
catch it (F90).

    FA1   DISABLE-USER disables the user and then answers ERR.
    FA2   LIST-USERS sends its items without the count line or END.

Both are admin-only handlers. Before V4-233 the fuzz target chose the socket
by the parity of the command's first letter, and neither was ever entered.
"""
import sys, pathlib
LA = "apps/authd/localapi.c"

M = {
    "FA1": [(LA,
             "    if (disable) {\n        const size_t closed = authd_app_close_user(app, user, user_len);\n",
             "    if (disable) { return send_err(slot, \"internal\"); } /* MUTATION FA1 */\n"
             "    if (disable) {\n        const size_t closed = authd_app_close_user(app, user, user_len);\n")],
    "FA2": [(LA,
             "    if (store_list_users(app->store, on_user, &c) != STORE_OK) {\n        return send_err(slot, \"internal\");\n    }\n    return finish_list(slot, &body, &c);\n",
             "    if (store_list_users(app->store, on_user, &c) != STORE_OK) {\n        return send_err(slot, \"internal\");\n    }\n    return send_resp(slot, &body); /* MUTATION FA2 */\n")],
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
