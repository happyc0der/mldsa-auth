#!/usr/bin/env python3
"""V4-149 mutations: a recovery that promotes .ek.next republishes the
device's .pub, so it does not go on naming the superseded key (F227).

Usage: mutate_v105.py <repo> <ID>

Two-letter IDs: PB = PuBlic file. Every spec line names the check that must
catch it (F90).

    PB1   The promotion does not republish the .pub. The defect itself.
    PB2   The .pub is rewritten from the key in .ek, the superseded one.
    PB3   The new .pub is written beside the key and never renamed into
          place.
    PB4   The .pub path keeps the ".ek" suffix, so rotate and the recovery
          both publish to a file nobody reads. Caught first by the older
          check on an acknowledged rotation.
"""
import sys, pathlib
CL = "apps/authd/client_cli.c"

M = {
    "PB1": [(CL,
             "        client_republish_pub(prog, sub, a, next_path, next_kp.public_key);\n",
             "        if (0) { client_republish_pub(prog, sub, a, next_path, next_kp.public_key); } /* MUTATION PB1 */\n")],
    "PB2": [(CL,
             "        client_republish_pub(prog, sub, a, next_path, next_kp.public_key);\n",
             "        client_republish_pub(prog, sub, a, next_path, ek_kp.public_key); /* MUTATION PB2 */\n")],
    "PB3": [(CL,
             "    if (demo_keys_write_public(pub_tmp, a->hid, a->hid_len, pk) != DEMO_KEYS_OK ||\n"
             "        rename(pub_tmp, pub_path) != 0) {\n",
             "    if (demo_keys_write_public(pub_tmp, a->hid, a->hid_len, pk) != DEMO_KEYS_OK ||\n"
             "        0) { /* MUTATION PB3 */\n")],
    "PB4": [(CL,
             "    const int n = snprintf(out, cap, \"%.*s.pub\", (int)(has_ek ? kl - 3u : kl), key_path);\n",
             "    const int n = snprintf(out, cap, \"%.*s.pub\", (int)(has_ek ? kl : kl), key_path); /* MUTATION PB4 */\n")],
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
