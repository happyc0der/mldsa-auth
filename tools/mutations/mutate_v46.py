#!/usr/bin/env python3
"""V4-6 mutations for the MLDSAEK1 envelope (apps/authd/keyfile.c).
Each must make test_authd_keyfile fail on the named check.
Usage: mutate_v46.py <repo> <ID>

E1 (prove the header-AAD is load-bearing) is deliberately absent: every header
field is independently range-checked or feeds the KDF/AEAD, so a single-byte
flip is caught with or without the AAD -- the AAD is defense-in-depth. Bounds
are exercised with OPSLIMIT, whose over-ceiling value is a few iterations, so a
mutation kills cleanly instead of triggering a multi-gigabyte Argon2 alloc."""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
KF = "apps/authd/keyfile.c"
M = {
 "E2": (KF, [("    if (!params_ok(opslimit, memlimit)) {\n        return KEYFILE_ERR_PARAMS;\n    }",
             "    if (0) {\n        return KEYFILE_ERR_PARAMS;\n    } /* MUTATION E2: seal bound off */")]),
 "E3": (KF, [("                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {\n            r = KEYFILE_ERR_DECRYPT; goto freebufs;\n        }",
             "                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {\n            /* MUTATION E3: decrypt failure ignored */\n        }")]),
 "E4": (KF, [("open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)",
             "open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600) /* MUTATION E4 */")]),
 "E5": (KF, [("        r = (demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp) == DEMO_KEYS_OK)\n                ? KEYFILE_OK : KEYFILE_ERR_IMAGE;",
             "        (void)demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp);\n        r = KEYFILE_OK; /* MUTATION E5 */")]),
 "E6": (KF, [("O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)",
             "O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644) /* MUTATION E6 */")]),
 "E7": (KF, [("    if (!params_ok(ops, mem)) {\n        return KEYFILE_ERR_PARAMS;\n    }",
             "    if (0) {\n        return KEYFILE_ERR_PARAMS;\n    } /* MUTATION E7: open bound off */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
