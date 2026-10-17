#!/usr/bin/env python3
"""V4-24c mutations: rotation's keys on disk (CLAIMS D10), recovery codes in
the store (CLAIMS D4, audit F117) and the rotation's temp file (audit F118).

Usage: mutate_v70.py <repo> <ID>

Two-letter IDs: RK = V4-24c's Rotation and Recovery. Every spec line names the
check that must catch it (F90). RK1-RK5 passed V4-24b's whole suite: a raw
secret key carries no MLDSASK magic, so authd_e2e.sh's header scan -- the only
thing that ever looked at rotation's files -- passes it, and until V4-24c no C
test ran the CLI's rotate or the login that completes one. RK6 is F118's fix
reverted at the one site a test can reach.

    RK1   rotate keeps the OLD key's raw secret as <key>.prev once both
          ROTATE signatures are made, "in case the rotation fails".
    RK2   rotate writes the NEW key's raw secret beside .ek.next once it has
          reopened it from the sealed file.
    RK3   the login that completes an interrupted rotation (PROMOTE_NEXT)
          keeps the superseded key's raw secret as <key>.superseded.
    RK4   a rotation whose session cannot open keeps the new key's raw secret
          "for a retry" -- the path a device holding a superseded key takes.
    RK5   every recovery code from the third on is stored as itself instead
          of its Argon2id hash. Such a code can never be spent (its row holds
          no hash), but nothing spends a third code, and the first two -- the
          only ones any test or the e2e uses -- work as before. Until F117's
          fix only the first code was looked for in the store.
    RK6   a rotation whose session cannot open leaves its .newpub temp file
          again (F118's fix removed at that site).
"""
import sys, pathlib
CLI = "apps/authd/client_cli.c"
LA = "apps/authd/localapi.c"

M = {
    "RK1": [(CLI, """    const cc_status_t bs = cc_rotate_build(cs.cc, &new_kp, 0u, tx, sizeof tx, &n);
""",
                  """    const cc_status_t bs = cc_rotate_build(cs.cc, &new_kp, 0u, tx, sizeof tx, &n);
    { char pv[PATH_MAX + 8]; FILE *pf; /* MUTATION RK1: the old key, raw, "in case" */
      const int pvn = snprintf(pv, sizeof pv, "%s.prev", a.key_path);
      if (pvn > 0 && (size_t)pvn < sizeof pv && old_kp.secret_key != NULL && (pf = fopen(pv, "wb")) != NULL) {
          (void)!fwrite(old_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, pf); (void)fclose(pf); } }
""")],
    "RK2": [(CLI, """    /* CC_KEEP_FOR_ROTATE: the old key signs ROTATE after the session exists,
""",
                  """    { char rw[PATH_MAX + 8]; FILE *rf; /* MUTATION RK2: the new key, raw, beside .ek.next */
      const int rwn = snprintf(rw, sizeof rw, "%s.raw", next_path);
      if (rwn > 0 && (size_t)rwn < sizeof rw && new_kp.secret_key != NULL && (rf = fopen(rw, "wb")) != NULL) {
          (void)!fwrite(new_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, rf); (void)fclose(rf); } }
    /* CC_KEEP_FOR_ROTATE: the old key signs ROTATE after the session exists,
""")],
    "RK3": [(CLI, """        /* The server committed and the rename was interrupted. Finish it. */
""",
                  """        /* The server committed and the rename was interrupted. Finish it. */
        { char sv[PATH_MAX + 16]; FILE *sf; /* MUTATION RK3: the superseded key, raw */
          const int svn = snprintf(sv, sizeof sv, "%s.superseded", a->key_path);
          if (svn > 0 && (size_t)svn < sizeof sv && ek_kp.secret_key != NULL && (sf = fopen(sv, "wb")) != NULL) {
              (void)!fwrite(ek_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, sf); (void)fclose(sf); } }
""")],
    "RK4": [(CLI, """                                CC_KEEP_FOR_ROTATE, &cs);
    if (rc != EX_OK) {
""",
                  """                                CC_KEEP_FOR_ROTATE, &cs);
    if (rc != EX_OK) {
        { char rt[PATH_MAX + 8]; FILE *tf; /* MUTATION RK4: the new key, raw, "for a retry" */
          const int rtn = snprintf(rt, sizeof rt, "%s.retry", next_path);
          if (rtn > 0 && (size_t)rtn < sizeof rt && new_kp.secret_key != NULL && (tf = fopen(rt, "wb")) != NULL) {
              (void)!fwrite(new_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, tf); (void)fclose(tf); } }
""")],
    "RK5": [(LA, """        hp[made] = hashes[made];
""",
                 """        hp[made] = (made >= 2u) ? codes[made] : hashes[made];   /* MUTATION RK5 */
""")],
    "RK6": [(CLI, """        (void)unlink(pub_tmp);   /* F118 */
""",
                  """        /* MUTATION RK6: F118's unlink removed on the session-failure return */
""")],
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
