#!/usr/bin/env python3
"""V4-296 mutations: fuzz oracles that see what they are about (F500 to F505).

Usage: mutate_v162.py <repo> <ID>

Each mutant is one the fifty-ninth review built and the fuzz target then
passed; each must now fail the target's replay, by name. Two-letter IDs:
FC = Fuzz Config, FA = Fuzz Ack, FP = Fuzz Proxy.

    FC1   max_local_slots accepted past its maximum.
    FC2   site_socket and admin_socket allowed on one path.
    FA1   ROTATE_ACK's fp_new read one byte early.
    FP1   the PROXY preamble's DESTINATION handed on as the client.
"""
import sys, pathlib
CF = "apps/authd/authd_config.c"
AM = "apps/authd/authmsg.c"
PX = "apps/authd/proxy_v2.c"

M = {
    "FC1": [(CF, "            r = parse_u32(v, vn, AUTHD_LOCAL_SLOTS_MIN, AUTHD_LOCAL_SLOTS_MAX, &cfg.max_local_slots);\n",
             "            r = parse_u32(v, vn, AUTHD_LOCAL_SLOTS_MIN, 1000u, &cfg.max_local_slots); /* MUTATION FC1 */\n")],
    "FC2": [(CF, "    if (cfg.site_socket[0] != '\\0' && strcmp(cfg.site_socket, cfg.admin_socket) == 0) {\n",
             "    if (0 && cfg.site_socket[0] != '\\0' && strcmp(cfg.site_socket, cfg.admin_socket) == 0) { /* MUTATION FC2 */\n")],
    "FA1": [(AM, "    memcpy(out->fp_new, in + 3u + hl, AUTHMSG_FP_BYTES);\n",
             "    memcpy(out->fp_new, in + 2u + hl, AUTHMSG_FP_BYTES); /* MUTATION FA1 */\n")],
    "FP1": [(PX, "        memcpy(p->addr.addr, p->buf + PROXY_V2_HDR_LEN, 4);\n",
             "        memcpy(p->addr.addr, p->buf + PROXY_V2_HDR_LEN + 4u, 4); /* MUTATION FP1 */\n")],
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
