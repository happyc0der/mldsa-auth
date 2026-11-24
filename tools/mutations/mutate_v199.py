#!/usr/bin/env python3
"""V4-362 mutations: what the hundred-and-first review found (F777, F780, F781).

Usage: mutate_v199.py <repo> <ID>

    RZ1   a loopback port that is taken is a failure of bind like any other.
    RZ2   a start that found its loopback port taken does not note it, and
          removes the store it created.
    RZ3   the same for the proxy's Unix socket.
    RZ4   the same for the site socket.
    RZ5   the same for the admin socket.
    RZ7   (V4-363) every failure to bind a Unix path is in-use.
    RZ6   every preamble that is not a client's address counts as refused,
          so one that names no client, with a bad request behind it, is a
          protocol failure.
"""
import sys, pathlib
MA = "apps/authd/authd_main.c"
LI = "apps/authd/listener.c"
CI = "apps/authd/conn_io.c"

M = {
    "RZ1": [(LI, "        return in_use ? LISTENER_ERR_IN_USE : LISTENER_ERR_BIND;\n",
             "        return in_use ? LISTENER_ERR_BIND : LISTENER_ERR_BIND; /* MUTATION RZ1 */\n")],
    "RZ2": [(MA, "            authd_log_say(\"mldsa-authd: loopback listener: %s\\n\", listener_status_name(ls));\n            socket_in_use = (ls == LISTENER_ERR_IN_USE);",
             "            authd_log_say(\"mldsa-authd: loopback listener: %s\\n\", listener_status_name(ls));\n            socket_in_use = 0; /* MUTATION RZ2 */ (void)(ls == LISTENER_ERR_IN_USE);")],
    "RZ3": [(MA, "            authd_log_say(\"mldsa-authd: unix listener %s: %s\\n\", unix_path, listener_status_name(ls));\n            socket_in_use = (ls == LISTENER_ERR_IN_USE);",
             "            authd_log_say(\"mldsa-authd: unix listener %s: %s\\n\", unix_path, listener_status_name(ls));\n            socket_in_use = 0; /* MUTATION RZ3 */ (void)(ls == LISTENER_ERR_IN_USE);")],
    "RZ4": [(MA, "            authd_log_say(\"mldsa-authd: site socket %s: %s\\n\", site_path, listener_status_name(ls));\n            socket_in_use = (ls == LISTENER_ERR_IN_USE);",
             "            authd_log_say(\"mldsa-authd: site socket %s: %s\\n\", site_path, listener_status_name(ls));\n            socket_in_use = 0; /* MUTATION RZ4 */ (void)(ls == LISTENER_ERR_IN_USE);")],
    "RZ5": [(MA, "            authd_log_say(\"mldsa-authd: admin socket %s: %s\\n\", admin_path, listener_status_name(ls));\n            socket_in_use = (ls == LISTENER_ERR_IN_USE);",
             "            authd_log_say(\"mldsa-authd: admin socket %s: %s\\n\", admin_path, listener_status_name(ls));\n            socket_in_use = 0; /* MUTATION RZ5 */ (void)(ls == LISTENER_ERR_IN_USE);")],
    "RZ7": [(LI, "        return (berr == EADDRINUSE) ? LISTENER_ERR_IN_USE : LISTENER_ERR_BIND;\n",
             "        return (berr == EADDRINUSE || 1) ? LISTENER_ERR_IN_USE : LISTENER_ERR_BIND; /* MUTATION RZ7 */\n")],
    "RZ6": [(CI, "c->proxy.done && c->proxy.result == PROXY_V2_ERR) ? 1 : 0;",
             "c->proxy.done && c->proxy.result != PROXY_V2_OK) ? 1 : 0; /* MUTATION RZ6 */")],
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
