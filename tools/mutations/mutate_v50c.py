#!/usr/bin/env python3
"""V4-10c mutations: `authd_admin audit-verify`.

Usage: mutate_v50c.py <repo> <ID>

Letter O (F and Z remain free).

A small campaign, because the step is a documentation step with one command in
it -- but the command is the operator's only means of checking the audit chain
(spec 9.2, audit finding F29), so every way it could LOOK like it works while
verifying nothing is worth a mutation. All four die in `authd_e2e`, which is
the only place a real chain with real entries exists.

Two things about this command make its mutations unusual.

FIRST, an EMPTY chain verifies trivially. `store_audit_verify()` walks the
audit table and returns OK when there is nothing to walk, so a command that
printed "the audit chain verifies" and nothing else would pass every plausible
test against a store that had recorded nothing at all. That is why the entry
count is printed and why O3 exists: the count is the only thing separating
"verified" from "found nothing to verify".

SECOND, a wrong passphrase and a corrupt chain are different failures with the
same visible shape -- both end in a non-zero exit. The chain is keyed from the
envelope KEK, so failing to open the key means the verification never ran; an
operator told "corrupt" would go looking for an intruder instead of for their
passphrase file. O4 restores that confusion.

NOT MUTATED, and the reason stated rather than implied:

  * "the KEK is not wiped after store_open takes its derived key". The leak is
    real and LeakSanitizer would catch it -- on LINUX. LSan does not run under
    macOS ASan, so the mutation would SURVIVE on the machine this campaign is
    usually run on and be killed only in the nightly. A mutation whose verdict
    depends on which platform ran it is worse than no mutation: it teaches
    that a survivor is normal. The wipe is asserted by inspection and by the
    same `secure_mem_free` pattern `init` uses three functions above.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
CLI = "apps/authd/authd_cli.c"

M = {
 # O1 -- the verdict is computed and then thrown away. The command still
 # prints a head MAC, still exits 0, and looks exactly like a working one.
 "O1": (CLI, [("""    if (vv != STORE_OK) {""",
               """    if (0) { /* MUTATION O1: the verdict is ignored */""")]),

 # O2 -- the chain is never walked at all. Everything downstream still works
 # because an unverified chain and a verified one differ in nothing observable
 # except this call.
 "O2": (CLI, [("    const store_status_t vv = store_audit_verify(store);",
               "    const store_status_t vv = STORE_OK; /* MUTATION O2: never verified */")]),

 # O3 -- the tail query asks for zero rows, so the count is always zero and
 # "verifies (0 entries)" is printed for a chain with three. Only a check that
 # reads the COUNT sees it, and without one an empty store would pass this
 # command every time.
 #
 # Phrased as an off-by-one in the QUERY rather than as `ctx = 0` in the
 # callback, because the latter leaves `seq` unused and dies on
 # -Werror=unused-parameter: KILLED(compile) proves the compiler works and
 # nothing whatever about the check under test.
 "O3": (CLI, [("    (void)store_audit_tail(store, 1u, audit_last_seq, &entries);",
               "    (void)store_audit_tail(store, 0u, audit_last_seq, &entries); /* MUTATION O3 */")]),

 # O4 -- a key that will not open is reported as a corrupt chain: the
 # verification never ran, and the operator is sent looking for an intruder.
 "O4": (CLI, [("""    if (ks != KEYFILE_OK) {
        secure_mem_free(kek, STORE_KEK_BYTES);
        return failed(prog, "audit-verify", ek, keyfile_status_name(ks));
    }""",
               """    if (ks != KEYFILE_OK) {
        secure_mem_free(kek, STORE_KEK_BYTES);
        return failed(prog, "audit-verify", ek, "audit-chain-corrupt"); /* MUTATION O4 */
    }""")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)
path, edits = M[MID]
f = REPO / path
s = f.read_text()
for old, new in edits:
    n = s.count(old)
    if n != 1:
        sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, path, n))
    s = s.replace(old, new, 1)
f.write_text(s)
print("%s applied to %s" % (MID, path))
