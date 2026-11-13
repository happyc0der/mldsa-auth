#!/usr/bin/env python3
"""V4-144 mutations: the event loop asks the clock when poll() returns, so a
connection accepted late in a long poll gets its whole handshake time (F224).

Usage: mutate_v103.py <repo> <ID>

Two-letter IDs: CK = ClocK. Every spec line names the check that must catch
it (F90).

    CK1   The loop never asks its clock. The defect itself.
    CK2   The loop asks and drops the answer.
    CK3   evloop_set_clock() reports success and registers nothing.
    CK4   The daemon's clock answers without reading the time: the loop is
          handed the instant it already had.
    CK5   The loop asks BEFORE poll() instead of after: the wrong fix, which
          every fixed-clock unit check passes.
"""
import sys, pathlib
EV = "apps/authd/evloop.c"
MA = "apps/authd/authd_main.c"

ASK = ("    if (ev->clock != NULL) {\n"
       "        now_ms = ev->clock(ev->clock_ctx);\n"
       "    }\n"
       "\n"
       "    int activity = 0;\n")
TOTAL = "    const size_t total = npfd + nspfd;\n"

M = {
    "CK1": [(EV, ASK,
             "    if (ev->clock != NULL && 0) { /* MUTATION CK1 */\n"
             "        now_ms = ev->clock(ev->clock_ctx);\n"
             "    }\n"
             "\n"
             "    int activity = 0;\n")],
    "CK2": [(EV, ASK,
             "    if (ev->clock != NULL) {\n"
             "        (void)ev->clock(ev->clock_ctx); /* MUTATION CK2 */\n"
             "    }\n"
             "\n"
             "    int activity = 0;\n")],
    "CK3": [(EV,
             "    ev->clock = clock;\n",
             "    (void)clock; /* MUTATION CK3 */\n")],
    "CK4": [(MA,
             "    app->now_ms = now_ms();\n"
             "    app->now_unix = (int64_t)time(NULL);\n"
             "    return app->now_ms;\n",
             "    /* MUTATION CK4 */\n"
             "    return app->now_ms;\n")],
    "CK5": [(EV, ASK,
             "    /* MUTATION CK5 */\n"
             "\n"
             "    int activity = 0;\n"),
            (EV, TOTAL,
             "    if (ev->clock != NULL) { /* MUTATION CK5 */\n"
             "        now_ms = ev->clock(ev->clock_ctx);\n"
             "    }\n" + TOTAL)],
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
