#!/usr/bin/env python3
"""V4-15c mutations: the artifact-side gaps.

Usage: mutate_v60.py <repo> <ID>

Two-letter IDs: GC = V4-15c's gap checks. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90). The two gates of V4-15c -- no_hand_rolled_primitives and build_flags --
were shown red by hand: their subjects (a planted constant, a CMake flag) are
outside what the runner snapshots.

  D1 -- the envelope composes libsodium unmodified (apps/authd/keyfile.c).
        Each is made in seal AND open, so every round trip through keyfile.c
        still works; only a reader that does not share keyfile.c can see it.
    GC1   the associated data shortened to bytes [0, 63)
    GC2   the KDF uses half the memlimit the header states
  D10 -- keys at rest (keyfile.c)
    GC3   the envelope stops encrypting: seal copies the image in, open copies
          it back out -- sealed files now hold the secret key in the clear
  D13 -- the journal (apps/authd/authd_conn.c)
    GC4   the rotation's fp_new line prints the session send key
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
KF = "apps/authd/keyfile.c"
CN = "apps/authd/authd_conn.c"

M = {
 "GC1": (KF, [("                                                       out, KEYFILE_HEADER_LEN, NULL, out + OFF_NONCE, key) != 0 ||",
               "                                                       out, KEYFILE_HEADER_LEN - 4u, NULL, out + OFF_NONCE, key) != 0 || /* MUTATION GC1 */"),
              ("                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {",
               "                                                       buf, KEYFILE_HEADER_LEN - 4u, buf + OFF_NONCE, key) != 0) { /* MUTATION GC1 */")]),
 "GC2": (KF, [("(unsigned long long)ops, (size_t)mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {",
               "(unsigned long long)ops, (size_t)(mem / 2u), crypto_pwhash_ALG_ARGON2ID13) != 0) { /* MUTATION GC2 */")]),
 "GC3": (KF, [("        if (crypto_aead_xchacha20poly1305_ietf_encrypt(out + KEYFILE_HEADER_LEN, &clen, sk2_image, image_len,\n"
               "                                                       out, KEYFILE_HEADER_LEN, NULL, out + OFF_NONCE, key) != 0 ||",
               "        if ((memcpy(out + KEYFILE_HEADER_LEN, sk2_image, image_len), /* MUTATION GC3: no encryption */\n"
               "             memset(out + KEYFILE_HEADER_LEN + image_len, 0, crypto_aead_xchacha20poly1305_ietf_ABYTES),\n"
               "             clen = image_len + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0) != 0 ||"),
              ("        if (crypto_aead_xchacha20poly1305_ietf_decrypt(img, &mlen, NULL, buf + KEYFILE_HEADER_LEN, ct_len,\n"
               "                                                       buf, KEYFILE_HEADER_LEN, buf + OFF_NONCE, key) != 0) {",
               "        if ((memcpy(img, buf + KEYFILE_HEADER_LEN, ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES), /* MUTATION GC3 */\n"
               "             mlen = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES, 0) != 0) {")]),
 "GC4": (CN, [('    authd_log_fp(AUTHD_LOG_INFO, "rotate-fp-new", fp);',
               '    authd_log_fp(AUTHD_LOG_INFO, "rotate-fp-new", c->sess.keys); /* MUTATION GC4 */')]),
}

path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s)
print(f"applied {MID} to {path}")
