#!/usr/bin/env python3
"""V4-9d mutations for recovery codes, lockout and enrollment tickets.
Usage: mutate_v49d.py <repo> <ID>

Letter G: F, H, J, O and Z remain free. IDs only have to be unique within a
spec file, but a campaign log that says "R1" twice is a log nobody can grep.

Three things about recovery make its mutations unusual.

FIRST, a round trip cannot catch a wrong ALPHABET. The encoder that issues a
code and the normaliser that accepts it share one table, so a wrong alphabet
moves both together and the code still verifies against its own hash. G3 is
killed only by the hand-computed literal vectors in test_authd_localapi; a
"recovery works end to end" test kills it never.

SECOND, a lockout enforced too LATE is indistinguishable from one enforced in
time, by error code. Both answer `locked`. What separates them is the cost: a
lockout checked after the verify loop still spends ~0.8 s of a single-threaded
daemon's time on an attacker's guess, which is the whole thing §10.3's lockout
exists to prevent. That is why authd_app_t carries recovery_kdf_calls and why
G4 is killed by a counter rather than by a status.

THIRD, superseding looks like housekeeping and is actually the bound. Without
it the RECOVERY-USE verify loop grows by `count` on every issue, so the
measured worst case (0.82 s for 16 codes, V4-9d) stops being a bound at all.
G9 is killed by the previous generation still working AND by the KDF counter.

NOT MUTATED, and the reason stated rather than left implied:

  * "the ticket hash is compared with memcmp instead of sodium_memcmp". The
    ticket is looked up by an indexed BLOB equality in SQLite, so there is no
    constant-time comparison to remove; the timing surface is the index, and
    saying so is more honest than campaigning a mutation that cannot exist.

  * "authd_main.c assigns the wrong KDF parameters". The parameters are FIELDS
    on authd_app_t so tests and fuzzing can lower them, which means no test can
    observe what the daemon writes into them. It is pinned by
    tools/audit/check_spec_constants.sh, which has its own negative control,
    rather than by a mutation that would have to pass either way.

  * "the recovery CODE is logged". Still unrepresentable: authd_log.h offers no
    arbitrary-buffer sink. But its 32-byte sibling is NOT -- see G12.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
B32 = "apps/authd/base32.c"
REC = "apps/authd/recovery.c"
LA  = "apps/authd/localapi.c"
ST  = "apps/authd/store/store.c"

M = {
 # G1 -- the typed code is hashed as typed, so only a perfectly transcribed
 # code works. Every happy-path test still passes; the mistyped one does not.
 "G1": (REC, [("    match_ctx_t ctx = { canonical, 0, 0, 0u };",
               "    match_ctx_t ctx = { typed, 0, 0, 0u }; /* MUTATION G1: hashed before normalisation */")]),

 # G2 -- the confusables are dropped, so O/I/l are rejected rather than folded.
 "G2": (B32, [('    if (c == \'O\') { return 0; }          /* the letter read as the digit */\n'
               '    if (c == \'I\' || c == \'L\') { return 1; }',
               '    /* MUTATION G2: confusables not folded */')]),

 # G3 -- RFC 4648's alphabet instead of Crockford's. Encode and decode still
 # agree with each other, so only a literal vector can see it.
 "G3": (B32, [('static const char ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";',
               'static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; /* MUTATION G3 */')]),

 # G4 -- the lockout is enforced AFTER the verify loop. Same error code, same
 # refusal; the difference is a second of a single-threaded daemon per guess.
 "G4": (LA, [("""    if (locked) {
        authd_log_slot_detail(AUTHD_LOG_WARN, "recovery-use", slot->index, "locked");
        return send_err(slot, "locked");
    }

    int64_t code_id = 0;
    size_t tried = 0;
    const int m = recovery_find_match(app->store, user, user_len,
                                      (const char *)code->val, code->val_len, &code_id, &tried);
    app->recovery_kdf_calls += (uint64_t)tried;""",
              """    int64_t code_id = 0;
    size_t tried = 0;
    const int m = recovery_find_match(app->store, user, user_len,
                                      (const char *)code->val, code->val_len, &code_id, &tried);
    app->recovery_kdf_calls += (uint64_t)tried;
    if (locked) {   /* MUTATION G4: lockout enforced after the KDF, not before */
        authd_log_slot_detail(AUTHD_LOG_WARN, "recovery-use", slot->index, "locked");
        return send_err(slot, "locked");
    }""")]),

 # G5 -- failures are never counted, so the lockout can never trigger.
 "G5": (ST, [("""    if (sqlite3_bind_blob(st, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE) {
        r = STORE_ERR_DB;
    } else if (sqlite3_changes(s->db) == 0) {
        r = STORE_ERR_NOT_FOUND;
    }
    sqlite3_finalize(st);
    if (r != STORE_OK) { tx_rollback(s); return r; }

    int count = 0;""",
             """    if (sqlite3_bind_blob(st, 1, user_id, (int)user_id_len, SQLITE_TRANSIENT) != SQLITE_OK) {
        r = STORE_ERR_DB;
    }
    sqlite3_finalize(st);   /* MUTATION G5: the increment is never stepped */
    if (r != STORE_OK) { tx_rollback(s); return r; }

    int count = 0;""")]),

 # G6 -- a success does not clear the accumulated failures, so a user who
 # fumbles four times stays one mistake from an hour's lockout for ever.
 "G6": (ST, [('            "UPDATE users SET recovery_fail_count=0, recovery_locked_until=0 WHERE user_id=?1;",',
              '            "UPDATE users SET recovery_locked_until=0 WHERE user_id=?1;", /* MUTATION G6 */')]),

 # G7 -- the ticket is inserted outside the transaction, so a crash between
 # "code spent" and "ticket issued" costs the user their way back in.
 "G7": (ST, [("""    /* The window a non-transactional implementation would leave half-open: the
     * code is spent but no ticket exists, so the user has burned their one way
     * back in and received nothing. Armed only in the test build. */
    if (STORE_FAULT_POINT()) {
        tx_rollback(s);
        return STORE_ERR_DB;
    }""",
             """    if (STORE_FAULT_POINT()) {
        (void)tx_commit(s);   /* MUTATION G7: the spend is committed without the ticket */
        return STORE_ERR_DB;
    }""")]),

 # G8 -- the consume forgets whose code it is, so any user can spend another's.
 "G8": (ST, [('            " WHERE code_id=?1 AND used_at IS NULL AND user_id=?3;", -1, &st, NULL) != SQLITE_OK) {',
              '            " WHERE code_id=?1 AND used_at IS NULL AND ?3 IS NOT NULL;", -1, &st, NULL) != SQLITE_OK) { /* MUTATION G8 */')]),

 # G9 -- issuing does not supersede, so every generation stays live and the
 # verify loop grows without bound.
 "G9": (ST, [('            "UPDATE recovery_codes SET used_at=?2, used_from=\'superseded\'"\n'
              '            " WHERE user_id=?1 AND used_at IS NULL;", -1, &st, NULL) != SQLITE_OK) {',
              '            "UPDATE recovery_codes SET used_at=?2, used_from=\'superseded\'"\n'
              '            " WHERE user_id=?1 AND used_at IS NULL AND 0;", -1, &st, NULL) != SQLITE_OK) { /* MUTATION G9 */')]),

 # G10 -- the ticket lives an hour instead of ten minutes.
 "G10": (LA, [("    const int64_t expires = app->now_unix + (int64_t)app->ticket_ttl_s;",
               "    const int64_t expires = app->now_unix + 3600; /* MUTATION G10: an hour, not ten minutes */")]),

 # G11 -- the ticket is never marked used, so one recovery enrolls forever.
 "G11": (ST, [('            "UPDATE enroll_tickets SET used_at=?2 WHERE ticket_hash=?1 AND used_at IS NULL;",',
               '            "UPDATE enroll_tickets SET used_at=used_at WHERE ticket_hash=?1 AND used_at IS NULL;", /* MUTATION G11 */')]),

 # G12 -- the TICKET is RECOVERY_TICKET_BYTES == 32, exactly what authd_log_fp
 # takes, so this compiles and puts a live bearer credential in the journal.
 # The never-list's one entry the logging API cannot enforce by shape (F41).
 # NOTE: the first draft logged `thash` instead and SURVIVED -- correctly, since
 # a ticket's SHA-256 cannot be redeemed and so is not the property. The
 # survivor was an authoring error, and this is the mutation that was meant.
 "G12": (LA, [('    app->recoveries_used++;',
                '    authd_log_fp(AUTHD_LOG_INFO, "recovery-ticket", ticket); /* MUTATION G12 */\n    app->recoveries_used++;')]),

 # G13 -- `via=site ticket=...` is accepted and the ticket silently ignored:
 # the defect this step fixed, restored.
 "G13": (LA, [("    if (via_site && ticket_kv != NULL) {\n        return send_err(slot, \"malformed\");\n    }",
                "    /* MUTATION G13: a ticket on via=site is accepted and ignored */")]),

 # G15 -- the user creation is committed separately, so it survives the
 # rollback of a refused enrollment (F47's defect, in the shape the fix left
 # behind). Every functional check still passes: the refusal, its code and the
 # absence of a device are unchanged. Only a user census across the request
 # sees it -- which is why the test takes one.
 "G15": (ST, [("""    if (!exists) {
        r = add_user_locked(s, user_id, user_id_len, role);
        if (r != STORE_OK) { tx_rollback(s); return r; }
    }""",
               """    if (!exists) {
        r = add_user_locked(s, user_id, user_id_len, role);
        if (r != STORE_OK) { tx_rollback(s); return r; }
        (void)tx_commit(s);                  /* MUTATION G15: user committed separately */
        if (tx_begin(s) != STORE_OK) { return STORE_ERR_DB; }
    }""")]),

 # G14 -- revoke=all issues the ticket but leaves the stolen device working.
 # Two earlier forms died at COMPILE time instead, which says nothing about
 # whether any TEST can see the defect (the v49b I1 lesson): `revoked = 0u;`
 # leaves revoke_all_devices unreferenced (-Wunused-function), and neutering
 # first_active leaves `status` unused (-Wunused-parameter). Dropping the
 # revoke CALL keeps every symbol referenced -- store_revoke_device still has
 # h_revoke_device as a caller -- so what changes is behaviour, not linkage.
 "G14": (LA, [("""        if (store_revoke_device(app->store, c.handle, c.len, "recovery",
                                (const uint8_t *)"recovery revoke=all", 19u) != STORE_OK) {
            break;
        }
        revoked++;""",
               """        break; /* MUTATION G14: the stolen device is never revoked */""")]),
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
