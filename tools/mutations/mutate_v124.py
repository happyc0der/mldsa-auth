#!/usr/bin/env python3
"""V4-194 mutations: a login code that could not be written is a failure (F272).

Usage: mutate_v124.py <repo> <ID>

Two-letter IDs: CW = Code Written. Every spec line names the check that must
catch it (F90).

    CW1   The write's result is not looked at: exit 0 with no code.
"""
import sys, pathlib

M = {
    "CW1": [("apps/authd/client_cli.c",
             "    const int wrote = printf(\"%s\\n\", b64) > 0 && fflush(stdout) == 0;\n",
             "    (void)printf(\"%s\\n\", b64); const int wrote = 1; /* MUTATION CW1 */\n")],
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
