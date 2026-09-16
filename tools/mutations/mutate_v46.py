#!/usr/bin/env python3
"""V4-6 mutations E1-E6: the MLDSAEK1 envelope (apps/authd/keyfile.c).
Each must make test_authd_keyfile fail on a named check.
Usage: mutate_v46.py <repo> <ID>"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
KF = "apps/authd/keyfile.c"
M = {
 # E1: the header is not bound as associated data -> tampering with the KDF
 # params (or any header byte) is no longer detected.
 "E1": (KF, [("out, KEYFILE_HEADER_LEN, NULL, out + OFF_NONCE, key)",
             "NULL, 0, NULL, out + OFF_NONCE, key) /* MUTATION E1: header not AAD */")]),
 # E2: parameter bounds not enforced on open -> a hostile memlimit is honoured.
 "E2": (KF, [("    if (!params_ok(ops, mem)) { r = KEYFILE_ERR_PARAMS; goto freebufs; }",
             "    if (0) { r = KEYFILE_ERR_PARAMS; goto freebufs; } /* MUTATION E2 */")]),
 # E3: the AEAD verification result is ignored -> a wrong passphrase or a
 # tampered ciphertext is accepted.
 "E3": (KF, [("                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {\n            r = KEYFILE_ERR_DECRYPT; goto freebufs;\n        }",
             "                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {\n            /* MUTATION E3: decrypt failure ignored */\n        }")]),
 # E4: seal writes in place / clobbers (O_TRUNC instead of O_EXCL).
 "E4": (KF, [("open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)",
             "open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600) /* MUTATION E4 */")]),
 # E5: the decrypted image is not validated -> a wrong id (or corrupt image)
 # is accepted as the identity.
 "E5": (KF, [("        r = (demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp) == DEMO_KEYS_OK)\n                ? KEYFILE_OK : KEYFILE_ERR_IMAGE;",
             "        (void)demo_keys_load_identity_from_image(img, (size_t)mlen, expect_id, id_len, kp);\n        r = KEYFILE_OK; /* MUTATION E5 */")]),
 # E6: the sealed file is world-readable (0644 instead of 0600).
 "E6": (KF, [("O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)",
             "O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644) /* MUTATION E6 */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
