#!/usr/bin/env python3
"""V4-260 mutations: a store that fails during ROTATE is not a refusal (F389);
one `state` in the upgrade URL, the first (F390).

Usage: mutate_v150.py <repo> <ID>

Two-letter IDs: RS = Rotate Store, US = Upgrade State. Every spec line names
the check that must catch it (F90).

    RS1   Only a database error is a failure, as before: a damaged store refuses.
    RS2   The failure is journalled at INFO.
    RS3   "That key is already enrolled" is treated as the store failing.
    US1   A second `state` is not refused.
    US2   An empty `state=` is skipped and a later one bound, as before.
"""
import sys, pathlib
CN = "apps/authd/authd_conn.c"
WS = "apps/authd/ws.c"
D = "            const int declined = (rs == STORE_ERR_NOT_FOUND || rs == STORE_ERR_STATE || rs == STORE_ERR_CONFLICT);\n"

M = {
    "RS1": [(CN, D, "            const int declined = (rs != STORE_ERR_DB); /* MUTATION RS1 */\n")],
    "RS2": [(CN, "                authd_log_slot_detail(AUTHD_LOG_ERROR, \"rotate-store-failed\", slot->index, store_status_name(rs));\n",
             "                authd_log_slot_detail(AUTHD_LOG_INFO, \"rotate-store-failed\", slot->index, store_status_name(rs)); /* MUTATION RS2 */\n")],
    "RS3": [(CN, D, "            const int declined = (rs == STORE_ERR_NOT_FOUND || rs == STORE_ERR_STATE); /* MUTATION RS3 */\n")],
    "US1": [(WS, "            if (taken) {\n                return WS_ERR_PROTOCOL;     /* a second `state` */\n",
             "            if (0 && taken) { /* MUTATION US1 */\n                return WS_ERR_PROTOCOL;     /* a second `state` */\n")],
    "US2": [(WS, "        if (e - s >= 6u && memcmp(target + s, \"state=\", 6) == 0) {\n",
             "        if (e - s > 6u && memcmp(target + s, \"state=\", 6) == 0) { /* MUTATION US2 */\n")],
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
