#!/usr/bin/env python3
"""V4-24b mutations: the secure-memory inventory (CLAIMS P2/D2).

Usage: mutate_v69.py <repo> <ID>

Two-letter IDs: SM = V4-24b's Secure Memory. Every mutation changes a value
and keeps every use (F79), and every spec line names the check that must
catch it (F90). Both passed V4-24a's whole suite: a secret moved to the
ordinary heap works, and nothing looked at where it lived.

    SM1   the store's audit-MAC key, s->key_audit, is allocated with calloc
          and released with free: unguarded, swappable, and left in freed
          heap rather than zeroed.
    SM2   the client's plaintext MLDSASK2 image at enrollment -- the one
          moment a device's secret key exists unsealed -- is allocated with
          malloc and released with free, so the plaintext key stays in
          freed heap. <stdlib.h> is included for it.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"
CC = "apps/authd/client_core.c"

M = {
 "SM1": (ST, [("    s->key_audit = secure_mem_alloc(STORE_AUDIT_MAC_BYTES);",
               "    s->key_audit = calloc(1, STORE_AUDIT_MAC_BYTES); /* MUTATION SM1 */"),
              ("        secure_mem_free(s->key_audit, STORE_AUDIT_MAC_BYTES);",
               "        free(s->key_audit); /* MUTATION SM1 */")]),
 "SM2": (CC, [("#include <string.h>\n",
               "#include <string.h>\n#include <stdlib.h> /* MUTATION SM2 */\n"),
              ("    uint8_t *img = secure_mem_alloc(img_len);",
               "    uint8_t *img = malloc(img_len); /* MUTATION SM2 */"),
              ("        secure_mem_free(img, img_len);",
               "        free(img); /* MUTATION SM2 */")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID}")
