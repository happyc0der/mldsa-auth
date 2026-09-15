#!/usr/bin/env python3
"""V3-3 mutations S1-S2 (T12's redesigned EINTR storm). Usage: mutate_v33.py <repo> <ID>"""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
NET = "apps/net_io.c"

M = {
    # S1: every EINTR is still retried, but none is ever counted -- the exact
    # shape of a regression that would make T12's assertion vacuous.
    "S1": (NET, [
        ("            if (st != NULL) {\n"
         "                st->eintr_retries++;\n"
         "            }\n",
         "            if (st != NULL) {\n"
         "                (void)st; /* MUTATION S1: the retry is no longer counted */\n"
         "            }\n"),
        ("                out->stats.eintr_retries++;\n"
         "                continue;",
         "                (void)out; /* MUTATION S1 */\n"
         "                continue;"),
        ("            out->stats.eintr_retries++; /* the connect continues asynchronously */",
         "            (void)out; /* MUTATION S1 */"),
        ("            c->stats.eintr_retries++;\n"
         "            continue;\n"
         "        }\n"
         "        if (errno == EAGAIN || errno == EWOULDBLOCK) {\n"
         "            continue;\n"
         "        }\n"
         "        *got = off;",
         "            /* MUTATION S1 */\n"
         "            continue;\n"
         "        }\n"
         "        if (errno == EAGAIN || errno == EWOULDBLOCK) {\n"
         "            continue;\n"
         "        }\n"
         "        *got = off;"),
        ("            c->stats.eintr_retries++;\n"
         "            continue;\n"
         "        }\n"
         "        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {",
         "            /* MUTATION S1 */\n"
         "            continue;\n"
         "        }\n"
         "        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {"),
    ]),

    # S2: EINTR is no longer retried at all in the poll wait. If the storm did
    # not really interrupt blocking calls, this would change nothing.
    "S2b": (NET, [
        ("        if (errno == EINTR) {\n"
         "            if (st != NULL) {\n"
         "                st->eintr_retries++;\n"
         "            }\n"
         "            continue;\n"
         "        }\n"
         "        return NET_ERR_IO;",
         "        if (errno == EINTR) {\n"
         "            (void)st; /* MUTATION S2b: keeps the parameter used */\n"
         "            return NET_ERR_IO; /* an interrupted poll is now fatal */\n"
         "        }\n"
         "        return NET_ERR_IO;"),
    ]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}:\n{old}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
