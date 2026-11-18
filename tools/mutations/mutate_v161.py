#!/usr/bin/env python3
"""V4-287 mutations: one URL, one request (F478, F479).

Usage: mutate_v161.py <repo> <ID>

Two-letter IDs: QS = Query String, OR = One Request. The spec line names
the check that must catch it (F90).

    QS1   A percent-encoded name, a `+` or a fragment is read literally again.
    QS2   A bare `state` is not a `state`.
    OR1   A bare-LF line ends a header again.
    OR2   A repeated header is read as its last again.
"""
import sys, pathlib
WS = "apps/authd/ws.c"

M = {
    "QS1": [(WS, "        if (target[k] == '%' || target[k] == '+' || target[k] == '#') { return WS_ERR_PROTOCOL; }\n",
             "        if (0) { return WS_ERR_PROTOCOL; } /* MUTATION QS1 */\n")],
    "QS2": [(WS, "        const int bare = (e - s == 5u && memcmp(target + s, \"state\", 5) == 0);\n",
             "        const int bare = 0; /* MUTATION QS2 */\n")],
    "OR1": [(WS, "        if (hl == 0u || req[off + hl - 1u] != '\\r') { return WS_ERR_PROTOCOL; }   /* F479: CRLF only */\n        hl--;\n",
             "        if (hl > 0u && req[off + hl - 1u] == '\\r') { hl--; } /* MUTATION OR1 */\n")],
    "OR2": [(WS, "    if (n_upgrade != 1 || n_connection != 1 || n_version != 1 || n_key != 1) {\n",
             "    if (0 && (n_upgrade != 1 || n_connection != 1 || n_version != 1 || n_key != 1)) { /* MUTATION OR2 */\n")],
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
