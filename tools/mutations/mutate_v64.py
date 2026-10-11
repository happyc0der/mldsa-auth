#!/usr/bin/env python3
"""V4-22a mutations: the claim map's test-level gaps (CLAIMS D9, D8, D4, P13).

Usage: mutate_v64.py <repo> <ID>

Two-letter IDs: TG = V4-22a's Test Gaps. Every mutation changes a value and
keeps every use (F79), and every spec line names the check that must catch it
(F90). Each was shown surviving the suite as it stood before V4-22a, except
TG2, whose shape v49d G14 already kills in-process.

    TG1   store_lookup_active's key clause excludes only superseded keys:
          rotation still works, a revoked device is still stopped by its
          device clause, and a revoked key under an active device resolves.
          Only test_authd_store's keyfilter block makes that state (D9).
    TG2   revoke=all's in-transaction device search matches nothing -- v49d
          G14's shape, named here against authd_e2e: the stolen-device
          recovery through the shipped daemon and the site's own library,
          which until V4-22a nothing end to end exercised (D9).
    TG3   sig_old accepted if it verifies under pk_old OR pk_new: the honest
          rotation and the old-key-wrong-digest vector both still pass; only
          a sig_old by the INCOMING key over the right digest is let in (D8).
    TG4   the token's base64 parked in the token row's handshake_id column
          (where v58 GA4 parks its raw half): the raw and lower-case-hex scans
          miss it; the base64 windows added in V4-22a do not, in the store
          and in its backup (D4).
    TG5   the padding check stops after the first 64 padding bytes -- capped
          where pad_len is computed, so the inventoried sodium_is_zero call
          is untouched. The 64-byte inner of P4(b), (c) and (g) has 52, so
          only P4(h)'s larger buckets reach past it (P13).
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ST = "apps/authd/store/store.c"
CN = "apps/authd/authd_conn.c"
TK = "apps/authd/tokens.c"
SE = "src/protocol/session.c"

M = {
 "TG1": (ST, [("            \" WHERE dk.handle = ?1 AND dk.status='active'\"",
               "            \" WHERE dk.handle = ?1 AND dk.status<>'superseded'\" /* MUTATION TG1 */")]),
 "TG2": (ST, [("""                "SELECT handle FROM devices WHERE user_id=?1 AND status='active' LIMIT 1;",""",
               """                "SELECT handle FROM devices WHERE user_id=?1 AND status='none' LIMIT 1;", /* MUTATION TG2 */""")]),
 "TG3": (CN, [("    if (mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, pk_old) != 0) {",
               "    if (mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, pk_old) != 0 && /* MUTATION TG3 */\n"
               "        mldsa_verify(digest, sizeof digest, m.sig_old, m.sig_old_len, m.pk_new) != 0) {")]),
 "TG4": (TK, [("    const store_status_t r = store_add_token(s, token_hash,",
               "    char tg4[TOKEN_BYTES * 2u]; /* MUTATION TG4 */\n"
               "    (void)sodium_bin2base64(tg4, sizeof tg4, token_out, TOKEN_BYTES, sodium_base64_VARIANT_ORIGINAL);\n"
               "    const store_status_t r = store_add_token(s, token_hash,"),
              ("                                             hsid, hsid_len,",
               "                                             hsid != NULL ? hsid : (const uint8_t *)tg4, hsid != NULL ? hsid_len : strlen(tg4),")]),
 "TG5": (SE, [("    const size_t pad_len = body - SESSION_CONTENT_LEN_BYTES - content_len;",
               "    const size_t pad_len = (body - SESSION_CONTENT_LEN_BYTES - content_len) > 64u ? 64u : (body - SESSION_CONTENT_LEN_BYTES - content_len); /* MUTATION TG5 */")]),
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
