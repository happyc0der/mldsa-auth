#!/usr/bin/env python3
"""V4-9b mutations for the two CLIs, the shared line client and the three
daemon defects this step fixes.
Usage: mutate_v49b.py <repo> <ID>

Most of these are invisible to every functional check in the tree, which is the
reason each has its own assertion:

  S1  changes no BEHAVIOUR at all -- the e2e runs as one uid, so a 0660 admin
      socket still serves every command. Only a mode assertion can see it.
  K1  leaves the .ek and .pub correct, so enrollment and login still work; it
      merely also writes the plaintext secret key Req 10 forbids.
  K2  seals at the wrong Argon2id cost. The key opens, the daemon starts, and
      nothing anywhere else notices.
  L1  is the one that would have SURVIVED a path-based check: no admin
      subcommand issues REVOKE-TOKENS, so the hang it causes is unreachable
      through the CLI. It is killed by a table-level test that measures every
      command's real reply shape instead.
  P2  is caught EARLIER than its name suggests, and that is the system working:
      init writes the passphrase file, then reads it back through the same
      custody-checking reader the daemon uses, so a 0644 file is refused before
      anything is sealed. The e2e's mode assertion never gets to run. The spec
      therefore names init's own refusal, not the mode check.

  R1  is memory-hygiene class: the real damage is the decrypted ML-DSA server
      key left unwiped in secure memory when a listener fails. LSan would see
      it -- but LSan does not run under macOS ASan, so the check cannot rest on
      it. What the epilogue ALSO does is close and unlink every socket it
      already created, so the e2e starts a daemon whose admin socket path is a
      regular file and requires the site socket to be gone afterwards. That is
      observable on both platforms and is true exactly when the epilogue ran.

Not mutated, and the reason stated rather than assumed: "the daemon logs the
login code" is still UNREPRESENTABLE -- authd_log.h has no arbitrary-buffer
sink. Its inverse is now representable, because authd_cli.c uses fprintf
freely, and the e2e scans every CLI stream for the passphrase bytes."""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LS = "apps/authd/listener.c"
MN = "apps/authd/authd_main.c"
CLI = "apps/authd/authd_cli.c"
LC = "apps/authd/localcli.c"
ST = "apps/authd/store/store.c"
M = {
 # every Unix socket is 0660 again, so admin.sock is group-reachable (spec 8)
 "S1": (LS, [("    if (chmod(path, mode) != 0) {",
              "    if (chmod(path, 0660) != 0) { /* MUTATION S1: admin.sock group-reachable */")]),
 # a configuration failure exits 1 again instead of 3 (spec 13)
 "C1": (MN, [("        /* Spec 13: 3 = configuration error, distinct from 1 = operation\n         * failed. An operator's start-up script can tell \"your config is\n         * wrong\" from \"the key would not open\" without parsing prose. */\n        return 3;",
              "        return 1; /* MUTATION C1: config error indistinguishable from failure */")]),
 # authd_admin --check-config grows its own parser instead of the shared one
 "C2": (CLI, [("    const authd_config_status_t cs = authd_config_load(path, &cfg, &err_line);",
               "    authd_config_status_t cs = AUTHD_CFG_ERR_SYNTAX; /* MUTATION C2: second parser */\n    { FILE *pf = fopen(path, \"r\"); if (pf != NULL) { (void)fclose(pf); cs = AUTHD_CFG_ERR_VALUE; } }")]),
 # the keygen paths ALSO leave a plaintext MLDSASK2 copy on disk (Req 10)
 "K1": (CLI, [("    const keyfile_status_t ks = keyfile_seal(ek_path, img, img_len, pass, pass_len, ops, mem);",
               "    const keyfile_status_t ks = keyfile_seal(ek_path, img, img_len, pass, pass_len, ops, mem);\n"
               "    { char bak[PATH_MAX]; /* MUTATION K1: a plaintext copy beside the sealed key */\n"
               "      if (snprintf(bak, sizeof bak, \"%s.sk\", ek_path) > 0) {\n"
               "          FILE *mf = fopen(bak, \"wb\");\n"
               "          if (mf != NULL) { (void)fwrite(img, 1u, img_len, mf); (void)fclose(mf); } } }")]),
 # the server key is sealed at the operator's Argon2id cost (spec 12)
 "K2": (CLI, [("#define KDF_OPS_SERVER    4u",
               "#define KDF_OPS_SERVER    3u /* MUTATION K2: server sealed at the operator cost */")]),
 # init seals under its in-memory bytes instead of the bytes it wrote
 "P1": (CLI, [("    uint8_t *pass = NULL;\n    size_t pass_len = 0;\n    int rc = read_pass(prog, \"init\", pass_path, &pass, &pass_len);\n    if (rc != EX_OK) {\n        return rc;\n    }\n\n    rc = seal_new_identity(prog, \"init\", ek, pub, id, id_len, (const char *)pass, pass_len,",
               "    uint8_t *pass = NULL;\n    size_t pass_len = 0;\n    int rc = read_pass(prog, \"init\", pass_path, &pass, &pass_len);\n    if (rc != EX_OK) {\n        return rc;\n    }\n    if (pass_len > 1u) { pass[pass_len - 1u] ^= 0x01u; } /* MUTATION P1: not the bytes on disk */\n\n    rc = seal_new_identity(prog, \"init\", ek, pub, id, id_len, (const char *)pass, pass_len,")]),
 # init writes the passphrase file world-readable
 "P2": (CLI, [("    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);",
               "    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644); /* MUTATION P2 */")]),
 # the list table gains a command whose reply is a SINGLE line
 "L1": (LC, [('    return strcmp(cmd, "LIST-USERS") == 0 ||',
              '    return strcmp(cmd, "REVOKE-TOKENS") == 0 || /* MUTATION L1: not a list */\n           strcmp(cmd, "LIST-USERS") == 0 ||')]),
 # a list is truncated at its header line
 "L2": (LC, [("    if (strncmp(buf, \"ERR \", 4) == 0 || !is_list) {\n        return 1;\n    }",
              "    if (1) {\n        return 1; /* MUTATION L2: a list stops at its first line */\n    }")]),
 # enroll-operator believes the .pub's embedded id rather than --handle
 "E1": (CLI, [("    const demo_keys_status_t ps = demo_keys_load_public(pubpath, hid, hid_len, pk);",
               "    uint8_t pk_id[64]; size_t pk_id_len = 0; (void)pk_id; (void)pk_id_len;\n    demo_keys_status_t ps = DEMO_KEYS_OK;\n    { FILE *pf = fopen(pubpath, \"rb\"); /* MUTATION E1: trusts the file's own label */\n      if (pf == NULL) { ps = DEMO_KEYS_ERR_IO; }\n      else { uint8_t hdr[9]; (void)fread(hdr, 1u, 9u, pf);\n             uint8_t fid[64]; (void)fread(fid, 1u, hdr[8], pf);\n             (void)fread(pk, 1u, MLDSA_PUBLIC_KEY_BYTES, pf); (void)fclose(pf); } }")]),
 # init no longer refuses an existing store
 "I1": (CLI, [("    const char *clash = path_exists(ek) ? ek : (path_exists(db) ? db : (path_exists(pass_path) ? pass_path : NULL));",
               "    const char *clash = NULL; /* MUTATION I1: init over an existing store */")]),
 # a listener failure leaks the decrypted server key and every allocation
 "R1": (MN, [("        const listener_status_t ls = listener_open_unix(admin_path, 16, LISTENER_MODE_PRIVATE, &admin_fd);\n        if (ls != LISTENER_OK) {\n            fprintf(stderr, \"mldsa-authd: admin socket %s: %s\\n\", admin_path, listener_status_name(ls));\n            goto listener_failed;\n        }",
              "        const listener_status_t ls = listener_open_unix(admin_path, 16, LISTENER_MODE_PRIVATE, &admin_fd);\n        if (ls != LISTENER_OK) {\n            fprintf(stderr, \"mldsa-authd: admin socket %s: %s\\n\", admin_path, listener_status_name(ls));\n            free(slots); return 1; /* MUTATION R1: epilogue skipped, server key unwiped */\n        }")]),
 # a store backup is written with the daemon's umask instead of the store's mode
 "B1": (ST, [("    if (r == STORE_OK && chmod(dest_path, 0600) != 0) {\n        r = STORE_ERR_IO;\n    }",
              "    /* MUTATION B1: the backup keeps the umask's mode */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
