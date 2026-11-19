#!/usr/bin/env python3
"""V4-309 mutations: the notification socket is kept (F437); one local slot is
the administrator's (F421).

Usage: mutate_v167.py <repo> <ID>

    NS1   The notification socket is closed after each datagram again.
    RS1   A site connection may take the last free local slot.
    RS2   The administrative listener is held to the site's rule too.
"""
import sys, pathlib
SD = "apps/authd/sdnotify.c"
EV = "apps/authd/evloop.c"

M = {
    "NS1": [(SD, "    const ssize_t w = sendto(g_notify_fd, msg, ml, 0, (const struct sockaddr *)&a, alen);\n",
             "    const ssize_t w = sendto(g_notify_fd, msg, ml, 0, (const struct sockaddr *)&a, alen);\n    authd_sd_notify_close(); /* MUTATION NS1 */\n")],
    "RS1": [(EV, "    return (free_slots >= 2u) ? s : NULL;\n",
             "    return (free_slots >= 1u) ? s : NULL; /* MUTATION RS1 */\n")],
    "RS2": [(EV, "    if (s == NULL || kind != SLOT_KIND_LOCAL || ev->listen_is_admin[li] || ev->n_local_slots < 2u) {\n",
             "    if (s == NULL || kind != SLOT_KIND_LOCAL || ev->n_local_slots < 2u) { /* MUTATION RS2 */\n")],
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
