#!/usr/bin/env python3
"""V4-108 mutations: the store root key in the server key file (F190, spec 12
erratum 79).

Usage: mutate_v88.py <repo> <ID>

Two-letter IDs: RK = Root Key. A version-2 MLDSAEK1 file seals a 32-byte store
root key after the image; keyfile_open returns it (a version-1 file's KEK
stands in), rewrap reseals the same one, and init, keygen-server and
migrate-key write version 2. Every spec line names the check that must catch
it (F90).

    RK1   rewrap seals a fresh random root instead of the one it opened (the
          defect F190 reported, one layer down: the chain stops verifying).
    RK2   keyfile_open returns the KEK for a version-2 file too.
    RK3   the header's lower bound forgets the root: a version-2 file with no
          room for an image parses.
    RK4   the header's upper bound forgets the root: the largest version-2
          file is refused.
    RK5   the header's upper bound adds the root for every version: a
          version-1 file may be 32 bytes longer than any image.
    RK6   init and keygen-server write version 1.
    RK7   the root is not taken off the plaintext before the image is loaded.
    RK8   keyfile_seal_root ignores the root it is given.
    RK9   migrate-key writes version 1.
    RK10  any version at or above 1 is accepted.
    RK11  rewrap writes version 1 (the root is dropped at the next change).
    RK12  keyfile_open returns the image's first 32 bytes as the root key.
    RK13  keyfile_seal_root copies only 31 bytes of the root it is given.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CLI = "apps/authd/authd_cli.c"

M = {
    "RK1": [(CLI, "        const keyfile_status_t ks = keyfile_seal_root(out, img, img_len, root, (const char *)pb, lb,\n",
                  "        const keyfile_status_t ks = keyfile_seal_root(out, img, img_len, NULL /* MUTATION RK1 */, (const char *)pb, lb,\n")],
    "RK2": [(KF, "            memcpy(kek_out, (hdr.root_len != 0u) ? img + mlen : key, KEYFILE_ROOT_BYTES);\n",
                 "            memcpy(kek_out, key, KEYFILE_ROOT_BYTES); /* MUTATION RK2: always the KEK */\n")],
    "RK3": [(KF, "        ct_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES + root_len) {\n",
                 "        ct_len <= crypto_aead_xchacha20poly1305_ietf_ABYTES) { /* MUTATION RK3 */\n")],
    "RK4": [(KF, "    const size_t max_ct = demo_keys_sk2_image_len(64) + root_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;\n",
                 "    const size_t max_ct = demo_keys_sk2_image_len(64) + crypto_aead_xchacha20poly1305_ietf_ABYTES; /* MUTATION RK4 */\n")],
    "RK5": [(KF, "    const size_t max_ct = demo_keys_sk2_image_len(64) + root_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;\n",
                 "    const size_t max_ct = demo_keys_sk2_image_len(64) + KEYFILE_ROOT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES; /* MUTATION RK5 */\n")],
    "RK6": [(CLI, "    const keyfile_status_t ks = keyfile_seal_root(ek_path, img, img_len, NULL, pass, pass_len, ops, mem);\n",
                  "    const keyfile_status_t ks = keyfile_seal(ek_path, img, img_len, pass, pass_len, ops, mem); /* MUTATION RK6 */\n")],
    "RK7": [(KF, "            mlen -= hdr.root_len;   /* version 2: the image is what precedes the root key */\n",
                 "            /* MUTATION RK7: the root stays on the image */\n")],
    "RK8": [(KF, "        if (root != NULL) {\n            memcpy(pt + image_len, root, KEYFILE_ROOT_BYTES);\n",
                 "        if (root != NULL && image_len == 0u) { /* MUTATION RK8: the given root is ignored */\n            memcpy(pt + image_len, root, KEYFILE_ROOT_BYTES);\n")],
    "RK9": [(CLI, "        const keyfile_status_t ks = keyfile_seal_root(out, img, img_len, NULL, (const char *)pass, pass_len,\n"
                  "                                                      KDF_OPS_SERVER, KDF_MEM_256MIB);\n",
                  "        const keyfile_status_t ks = keyfile_seal(out, img, img_len, (const char *)pass, pass_len, /* MUTATION RK9 */\n"
                  "                                                 KDF_OPS_SERVER, KDF_MEM_256MIB);\n")],
    "RK10": [(KF, "        (buf[OFF_VERSION] != KEYFILE_VERSION && buf[OFF_VERSION] != KEYFILE_VERSION_ROOT) ||\n",
                  "        (buf[OFF_VERSION] < KEYFILE_VERSION) || /* MUTATION RK10 */\n")],
    "RK11": [(CLI, "        const keyfile_status_t ks = keyfile_seal_root(out, img, img_len, root, (const char *)pb, lb,\n"
                   "                                                      KDF_OPS_SERVER, KDF_MEM_256MIB);\n",
                   "        const keyfile_status_t ks = keyfile_seal(out, img, img_len, (const char *)pb, lb, /* MUTATION RK11 */\n"
                   "                                                 KDF_OPS_SERVER, KDF_MEM_256MIB);\n")],
    "RK12": [(KF, "            memcpy(kek_out, (hdr.root_len != 0u) ? img + mlen : key, KEYFILE_ROOT_BYTES);\n",
                  "            memcpy(kek_out, (hdr.root_len != 0u) ? img : key, KEYFILE_ROOT_BYTES); /* MUTATION RK12 */\n")],
    "RK13": [(KF, "        if (root != NULL) {\n            memcpy(pt + image_len, root, KEYFILE_ROOT_BYTES);\n",
                  "        if (root != NULL) {\n            memcpy(pt + image_len, root, KEYFILE_ROOT_BYTES - 1u); /* MUTATION RK13 */\n")],
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
