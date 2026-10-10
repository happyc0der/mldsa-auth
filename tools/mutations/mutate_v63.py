#!/usr/bin/env python3
"""V4-21 mutations: a fingerprint is a type (audit finding F41).

Usage: mutate_v63.py <repo> <ID>

Two-letter IDs: FT = V4-21's Fingerprint Type. Every mutation changes a value
and keeps every use (F79), and every spec line names the check that must catch
it (F90).

    FT1   authd_log_fp's parameter widened to `const void *`, header and
          definition, the body casting back: the "make it generic" regression.
          Every caller still compiles and every byte logged is the same, so no
          test binary can tell -- only log_fp_type, which finds a bare 32-byte
          buffer accepted again.
    FT2   authd_fp_of_pk hashes one byte short of the public key: every
          fingerprint changes, consistently, so the daemon's own round trips
          agree with themselves; test_authd_log's independent SHA-256 does not.

The three mutations that log a secret through this sink (v49c W12, v49d G12,
v60 GC4) were re-authored in the same step to cast to authd_fp_t -- the one
shape left -- and are killed by the log scans, as before.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
LH = "apps/authd/authd_log.h"
LC = "apps/authd/authd_log.c"

M = {
 "FT1": [(LH, "void authd_log_fp(authd_log_level_t lvl, const char *event, const authd_fp_t *fp);",
              "void authd_log_fp(authd_log_level_t lvl, const char *event, const void *fp); /* MUTATION FT1 */"),
         (LC, "void authd_log_fp(authd_log_level_t lvl, const char *event, const authd_fp_t *fp)\n{",
              "void authd_log_fp(authd_log_level_t lvl, const char *event, const void *fp_) /* MUTATION FT1 */\n{\n"
              "    const authd_fp_t *fp = fp_;")],
 "FT2": [(LC, "    crypto_hash_sha256(out->b, pk, AUTHD_FP_PK_BYTES);",
              "    crypto_hash_sha256(out->b, pk, AUTHD_FP_PK_BYTES - 1u); /* MUTATION FT2 */")],
}

for path, old, new in M[MID]:
    f = REPO / path
    s = f.read_text()
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    f.write_text(s.replace(old, new, 1))
print(f"applied {MID}")
