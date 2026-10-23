#!/usr/bin/env python3
"""V4-67 mutations: the pin's time floor (F135, spec 7.3 erratum 53).

Usage: mutate_v87.py <repo> <ID>

Two-letter IDs: FL = FLoor. authd_conn_resolve_pin does not return until
AUTHD_PIN_FLOOR_NS after the lookup began, whichever key it pinned, and
on_client_hello resolves every pin through it. Every spec line names the check
that must catch it (F90).

    FL1   the floor set to 0.
    FL2   the wait removed: the floor is measured and never waited out.
    FL3   the floor's clock started after the lookup, so the lookup's own
          time is outside the floor (the gap F135 measured comes back).
    FL4   the decoy path returns before the floor.
    FL5   on_client_hello resolves the pin without the floor (the code before
          V4-67).
    FL6   the decoy path leaves the caller's user length as it was.
"""
import sys, pathlib
CH = "apps/authd/authd_conn.h"
CC = "apps/authd/authd_conn.c"
LOOKUP = ("    if (store_lookup_active(app->store, handle, handle_len, pk, user_id, user_id_cap, user_id_len, NULL) == STORE_OK) {\n"
          "        pin = 0;\n"
          "    } else if (store_get_decoy_pk(app->store, pk) == STORE_OK) {\n"
          "        *user_id_len = 0;\n"
          "        pin = 1;\n"
          "    } else {\n"
          "        return -1;\n"
          "    }\n")
T0 = "    const int timed = (now(&t0) == 0);\n"

M = {
    "FL1": [(CH, "#define AUTHD_PIN_FLOOR_NS 50000u\n",
                 "#define AUTHD_PIN_FLOOR_NS 0u /* MUTATION FL1 */\n")],
    "FL2": [(CC, "        while (t - t0 < AUTHD_PIN_FLOOR_NS && now(&t) == 0) {\n"
                 "            /* wait */\n"
                 "        }\n",
                 "        /* MUTATION FL2: no wait */\n")],
    "FL3": [(CC, T0 + "    int pin;\n" + LOOKUP,
                 "    int pin;\n" + LOOKUP +
                 "    const int timed = (now(&t0) == 0); /* MUTATION FL3: the clock starts after the lookup */\n")],
    "FL4": [(CC, "        *user_id_len = 0;\n        pin = 1;\n",
                 "        *user_id_len = 0;\n        return 1; /* MUTATION FL4: the decoy skips the floor */\n")],
    "FL5": [(CC, "    const int pin = authd_conn_resolve_pin(app, ch.id, ch.id_len, pk,\n"
                 "                                           c->user_id, sizeof c->user_id, &c->user_id_len);\n",
                 "    const int pin = (store_lookup_active(app->store, ch.id, ch.id_len, pk, c->user_id, sizeof c->user_id,\n"
                 "                                         &c->user_id_len, NULL) == STORE_OK) ? 0\n"
                 "                  : (store_get_decoy_pk(app->store, pk) == STORE_OK ? 1 : -1); /* MUTATION FL5 */\n")],
    "FL6": [(CC, "        *user_id_len = 0;\n        pin = 1;\n",
                 "        pin = 1; /* MUTATION FL6: the user length is left as it was */\n")],
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
