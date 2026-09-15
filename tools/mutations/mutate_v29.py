#!/usr/bin/env python3
"""V2-9 mutations Y1-Y9. Usage: mutate_v29.py <repo> <ID>"""
import sys, pathlib

REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
KEYS = "apps/demo_keys.c"; APP = "apps/demo_app.c"; FUZZ = "tests/fuzz/fuzz_keys.c"

M = {
    # Y1: migration skips the self-test entirely.
    "Y1": (KEYS, [(
        "        if (mldsa_verify(SELFTEST_MSG, sizeof(SELFTEST_MSG) - 1u, sig, sig_len, kp.public_key) != 0) {\n"
        "            r = DEMO_KEYS_ERR_KEY_MISMATCH;\n"
        "            goto done;\n"
        "        }",
        "        if (0) { /* MUTATION Y1: the self-test's verdict is ignored */\n"
        "            r = DEMO_KEYS_ERR_KEY_MISMATCH;\n"
        "            goto done;\n"
        "        }")]),

    # Y2: the migrated digest is computed over a body that omits the id.
    "Y2": (KEYS, [(
        "    integrity_digest(img + SK2_BODY_LEN(idl), (uint8_t)idl, id, kp.public_key, kp.secret_key);",
        "    integrity_digest(img + SK2_BODY_LEN(idl), (uint8_t)idl, id + 1, kp.public_key,\n"
        "                     kp.secret_key); /* MUTATION Y2 */")]),

    # Y3: an already-current MLDSASK2 file is treated as legacy.
    "Y3": (KEYS, [(
        "    if (memcmp(hdr, DEMO_KEY_MAGIC_SECRET, DEMO_KEY_MAGIC_LEN) == 0) {\n"
        "        r = DEMO_KEYS_ERR_NOT_LEGACY;\n"
        "        goto done;\n"
        "    }",
        "    if (0) { /* MUTATION Y3: MLDSASK2 input no longer reported */\n"
        "        r = DEMO_KEYS_ERR_NOT_LEGACY;\n"
        "        goto done;\n"
        "    }")]),

    # Y4: migration trusts the file's own id.
    "Y4": (KEYS, [(
        "    if (idl != id_len || memcmp(id, expect_id, idl) != 0) {\n"
        "        r = DEMO_KEYS_ERR_ID_MISMATCH;\n"
        "        goto done;\n"
        "    }\n"
        "    /* 7. The ONLY integrity signal",
        "    if (0) { /* MUTATION Y4: the caller's --id is not checked */\n"
        "        r = DEMO_KEYS_ERR_ID_MISMATCH;\n"
        "        goto done;\n"
        "    }\n"
        "    /* 7. The ONLY integrity signal")]),

    # Y5: the output is truncated into place instead of published atomically.
    "Y5": (KEYS, [(
        "    if (lstat(out_path, &st) == 0) {\n"
        "        r = DEMO_KEYS_ERR_EXISTS;\n"
        "        goto done;\n"
        "    }",
        "    if (0) { /* MUTATION Y5a: no early refusal */\n"
        "        r = DEMO_KEYS_ERR_EXISTS;\n"
        "        goto done;\n"
        "    }"),
       ("    if (write_new_file(tmp_path, img, img_len, 0600, &tmp_made) != 0) {\n"
        "        r = DEMO_KEYS_ERR_IO;\n"
        "        goto done;\n"
        "    }\n"
        "    if (link(tmp_path, out_path) != 0) {\n"
        "        r = (errno == EEXIST) ? DEMO_KEYS_ERR_EXISTS : DEMO_KEYS_ERR_IO;\n"
        "        goto done;\n"
        "    }",
        "    { /* MUTATION Y5b: O_TRUNC in place of O_EXCL + link() */\n"
        "        const int ofd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);\n"
        "        if (ofd < 0 || write_all_fd(ofd, img, img_len) != 0) {\n"
        "            if (ofd >= 0) {\n"
        "                (void)close(ofd);\n"
        "            }\n"
        "            r = DEMO_KEYS_ERR_IO;\n"
        "            goto done;\n"
        "        }\n"
        "        (void)close(ofd);\n"
        "    }")]),

    # Y6: the exact-size check is dropped.
    "Y6": (KEYS, [(
        "    if (idl < 1u || idl > 64u || (size_t)st.st_size != LEGACY_FILE_LEN(idl)) {\n"
        "        goto done;\n"
        "    }\n"
        "    /* 5. Read;",
        "    if (idl < 1u || idl > 64u) { /* MUTATION Y6: exact size unchecked */\n"
        "        goto done;\n"
        "    }\n"
        "    /* 5. Read;")]),

    # Y7: the CLI prints no warning.
    "Y7": (APP, [(
        '    fprintf(stderr,\n'
        '            "WARNING: the source is a legacy MLDSASK1 file, which carries no integrity digest. Its integrity "',
        '    if (0) fprintf(stderr, /* MUTATION Y7 */\n'
        '            "WARNING: the source is a legacy MLDSASK1 file, which carries no integrity digest. Its integrity "')]),

    # Y8: a failed link() leaves the 0600 temp file behind.
    "Y8": (KEYS, [(
        "    if (tmp_made) {\n"
        "        (void)unlink(tmp_path); /* success or failure: never leave a 0600 secret behind */\n"
        "    }",
        "    if (0) { /* MUTATION Y8: the temp file is not cleaned up */\n"
        "        (void)unlink(tmp_path);\n"
        "    }")]),

    # Y9: test-side -- the fuzz model predicts OK for a short legacy file.
    "Y9": (FUZZ, [(
        "    const size_t idl = b[8];\n"
        "    if (idl < 1u || idl > 64u || L != SK_BODY_LEN(idl)) {\n"
        "        return M_FORMAT;\n"
        "    }\n"
        "    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {\n"
        "        return M_ID_MISMATCH;\n"
        "    }\n"
        "    return M_VALID;\n"
        "}",
        "    const size_t idl = b[8];\n"
        "    if (idl < 1u || idl > 64u || L + 1u < SK_BODY_LEN(idl)) { /* MUTATION Y9 */\n"
        "        return M_FORMAT;\n"
        "    }\n"
        "    if (idl != elen || memcmp(b + HDR, eid, idl) != 0) {\n"
        "        return M_ID_MISMATCH;\n"
        "    }\n"
        "    return M_VALID;\n"
        "}")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
rel, edits = M[MID]
p = REPO / rel
s = p.read_text()
for old, new in edits:
    n = s.count(old)
    if n != 1:
        sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, rel, n))
    s = s.replace(old, new, 1)
p.write_text(s)
print("%s applied to %s (%d edit(s))" % (MID, rel, len(edits)))
