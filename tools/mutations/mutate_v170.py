#!/usr/bin/env python3
"""V4-314 mutations: what the sixty-eighth review found in the C tools
(F543, F545, F547).

Usage: mutate_v170.py <repo> <ID>

    KX1   Two key files that would not open exit 1, "the daemon was asked".
    KX2   rotate with a key directory it cannot lock exits 1.
    CW1   authd_admin --check-config gives none of the warnings.
    KG1   keygen-server names a leftover key only when --pub is absent.

The site's client (F540, F542) is JavaScript, which no campaign compiles;
its controls were run with hand_control.py --interpreted and are listed in
docs/decisions.md under V4-314.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"
AC = "apps/authd/authd_cli.c"

M = {
    "KX1": [(CL, "            rc = (client_key_exit(ks_ek) == EX_FAIL || client_key_exit(ks_next) == EX_FAIL) ? EX_FAIL : EX_CONFIG;\n",
             "            rc = EX_FAIL; /* MUTATION KX1 */\n")],
    "KX2": [(CL, "        (void)failed(prog, \"rotate\", a.key_path, \"cannot-lock-key-directory\");   /* F543 */\n        return EX_CONFIG;\n",
             "        (void)failed(prog, \"rotate\", a.key_path, \"cannot-lock-key-directory\");   /* F543 */\n        return EX_FAIL; /* MUTATION KX2 */\n")],
    "CW1": [(AC, "    (void)authd_cli_config_warnings(&cfg, prog);   /* F545 */\n",
             "    /* MUTATION CW1 */\n")],
    "KG1": [(AC, "    } else if (path_exists(key)) {\n",
             "    } else if (path_exists(key) && !path_exists(pub)) { /* MUTATION KG1 */\n")],
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
