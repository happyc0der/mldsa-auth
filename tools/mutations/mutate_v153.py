#!/usr/bin/env python3
"""V4-265 mutations: a FIFO where a public key or a plaintext secret key is
expected is refused, not waited on (F407).

Usage: mutate_v153.py <repo> <ID>

Two-letter ID: FK = Fifo Key. Every spec line names the check that must catch
it (F90). Each mutant blocks in open(); the test's child is given three
seconds and the check then fails by name.

    FK1   The public-key reader opens without O_NONBLOCK, as before.
    FK2   The plaintext secret-key reader opens without O_NONBLOCK, as before.
"""
import sys, pathlib
DK = "apps/demo_keys.c"

M = {
    "FK1": [(DK, "    const int fd = open(pub_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);   /* F407: as above */\n",
             "    const int fd = open(pub_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FK1 */\n")],
    "FK2": [(DK, "    const int fd = open(sk_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);\n",
             "    const int fd = open(sk_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); /* MUTATION FK2 */\n")],
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
