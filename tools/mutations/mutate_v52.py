#!/usr/bin/env python3
"""V4-12 mutations: ledger capacity, the pin callback, and poll fairness.

Usage: mutate_v52.py <repo> <ID>

Letter P (F remains free).

THE DEFECT CLASS THIS CAMPAIGN EXISTS FOR. V4-12 rewrote nine accessors in the
pending store from `s->entries[i]` to `s->slots[i]`, and every one of them
STILL COMPILES if it is missed -- `entries` is a real array at a real offset.
Worse, a missed site is invisible to every test written before this step,
because all of them use the inline path where the two expressions are the same
address. P4 is that defect, deliberately chosen because the compiler is blind
to it, and it is the mutation this campaign is really about.

TWO MUTATIONS WERE RE-AUTHORED BEFORE THEY EVER RAN, both for the same reason
that bit v50b's J1, v50c's O3 and v51's Z4:

  * P7's first draft left `lookup_fn` unset in the init path, which makes the
    parameter unused and -Werror stops the build. KILLED(compile) proves the
    compiler works and NOTHING about whether any check reads the resolver, so
    it became "the callback's lookup_ctx is dropped" -- which compiles, is a
    plausible slip, and dies on a named check. Making that land cleanly also
    meant hardening the test's own callback against a NULL context, since a
    crash is a weaker verdict than a check.
  * P10's first draft restored only the F62 constant, which leaves the
    per-pool bound unused and again fails -Werror. It now reverts the whole
    block -- constant, bound and counter -- which is the state the finding
    actually describes. Its three edits are written as a LIST rather than
    hidden in a helper, because check_mutation_anchors.py reads these tables
    statically: an anchor kept outside M is an anchor nothing verifies, which
    is the exact failure that tool exists to prevent.

SIX EXPECTATIONS WERE WRONG ON THE FIRST RUN, and every one of them was a
defect in this campaign rather than in the tree -- each mutation did break
something, just not the thing predicted. Recorded because the shapes recur:

  * P4 and P11 ABORTED under ASan instead of failing a check. P4 made
    find_slot walk `capacity` entries of the 256-entry INLINE array, which at
    2,048 runs off the end; P11's own test claimed 65 local slots while
    passing a 1-element array, so removing the bound overran it. Both were
    fixed in the TESTS, not the expectations: Pext-2b exercises the same
    distinction at capacity 200, where the wrong array is merely wrong rather
    than out of bounds, and the P11 fixture now allocates what it claims.
    Pext-2b also had to run BEFORE the 2,048 case -- placed after it, the
    abort happened first and the named check still never printed, which cost
    a second full campaign to discover. P4 does still abort later in the run;
    that is fine and even correct, because by then its named check has fired. An
    abort is a weaker verdict than a named failure, and a campaign that
    accepts one has stopped checking what it thinks it checks.
  * P2's predicted check PASSED. cap_limit_for is used by the INIT path as
    well as store_usable, so init_ext(2048) still succeeded and only the
    inserts failed -- the expectation had to move one check later.
  * P3's predicted check PASSED for a subtler reason: active_count counts only
    entries whose state is exactly ACTIVE, and an unzeroed 0xAA slot is not
    ACTIVE. It reads as neither free nor active, so the count stayed 0 and the
    failure surfaced at the next INSERT instead.
  * P5's predicted check PASSED because decoy_pins is incremented before the
    pin is ever resolved. The observable damage is further along, where the
    unknown handle stops reaching the same client-side outcome as a known one
    -- which is the property that actually matters.
  * P6 kills the process at a fixture before reaching its callback-specific
    check, so it is pinned on the earliest named failure it does produce.

NOT MUTATED, with the reason stated rather than implied (the register N7 /
v48a D7 / v48b C8 / v49c W6 / v49d / v51 established):

  * `store_usable` widened to the EXTERNAL limit for both cases.
    handshake_pending_store_init still caps the inline array at 256 and
    nothing else can set capacity > 256 with slots == entries, so no test can
    distinguish the two versions. An equivalent mutant. (P2 is the opposite
    direction and is NOT equivalent.)
  * `memcmp` for `sodium_memcmp` in authd_conn_pin_lookup. No test can observe
    the timing difference; constant_time_inventory.sh is a report, not a gate.
  * `handshake_pending_insert` writing `s->entries[i]` while find_slot reads
    `s->slots[i]`. It compiles, but at capacity 2048 it overruns the inline
    array by 144 KiB -- an ASan abort, not a named FAIL. This project treats an
    abort as the weaker verdict, and P4 already covers the entries/slots
    confusion from the read side where the failure is clean.
  * `authd_main.c`'s ledger_cap. No test runs main(), which is why V4-9d
    pinned the recovery KDF parameters with check_spec_constants.sh instead of
    a mutation. Manufacturing one that "dies" on authd_e2e.sh would be
    theatre.
  * Removing the per-pool `taken < pool_max` bound on its own. With the poll
    array sized from both maxima and both pool sizes refused at registration,
    nothing can observe it -- which is the honest statement that the array
    size is the fix and the per-pool bound is defence in depth.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
HS = "src/protocol/handshake.c"
CN = "apps/authd/authd_conn.c"
EH = "apps/authd/evloop.h"
EC = "apps/authd/evloop.c"

M = {
 # P1 -- the struct is zeroed BEFORE the external array, so s->slots is NULL by
 # the time it would be used and the caller's ledger of handshake_ids and
 # transcript digests survives untouched. sizeof(*s) cannot reach it.
 "P1": (HS, [("""    if (s->slots != NULL && s->slots != s->entries) {
        sodium_memzero(s->slots, s->capacity * sizeof(*s->slots));
    }
    sodium_memzero(s, sizeof(*s));""",
              """    sodium_memzero(s, sizeof(*s)); /* MUTATION P1: struct first, array never */
    if (s->slots != NULL && s->slots != s->entries) {
        sodium_memzero(s->slots, s->capacity * sizeof(*s->slots));
    }""")]),

 # P2 -- the inline limit is applied to every store, so an external ledger
 # above 256 is unusable and the whole point of the step is silently undone.
 "P2": (HS, [("           s->capacity <= cap_limit_for(s, s->slots) && s->ttl_ms > 0;",
              "           s->capacity <= HANDSHAKE_PENDING_MAX && s->ttl_ms > 0; /* MUTATION P2 */")]),

 # P3 -- the caller's array is not zeroed, so a reused static starts life with
 # stale bytes that read as occupied slots nothing will ever free.
 "P3": (HS, [("    memset(slots, 0, capacity * sizeof(*slots));",
              "    /* MUTATION P3: the caller's array is not zeroed */")]),

 # P4 -- find_slot searches the INLINE array while everything else uses the
 # caller's. Compiles at every one of the nine rewritten sites, and is
 # invisible to every test that predates the step.
 "P4": (HS, [("""        const handshake_pending_entry_t *e = &s->slots[i];
        const bool in_use = (e->state != PENDING_SLOT_FREE);""",
              """        const handshake_pending_entry_t *e = &s->entries[i]; /* MUTATION P4 */
        const bool in_use = (e->state != PENDING_SLOT_FREE);""")]),

 # P5 -- the pin lookup refuses decoy connections, so an unknown identity now
 # fails EARLIER and differently from a known one. That is the enumeration
 # channel the decoy flow exists to close, reopened inside the one function
 # whose comment says it must not branch on c->decoy.
 "P5": (CN, [("""    if (c == NULL || !c->pin_set || id == NULL || id_len == 0u || id_len != c->handle_len) {
        return NULL;
    }""",
              """    if (c == NULL || !c->pin_set || c->decoy || id == NULL || id_len == 0u ||
        id_len != c->handle_len) { /* MUTATION P5 */
        return NULL;
    }""")]),

 # P6 -- the resolver is asked about the LOCAL identity instead of the peer's.
 "P6": (HS, [("""    /* Unknown initiator: fail closed WITHOUT creating any pending entry. */
    ctx->peer_pk = resolve_peer_pk(ctx, msg.id, msg.id_len);""",
              """    /* Unknown initiator: fail closed WITHOUT creating any pending entry. */
    ctx->peer_pk = resolve_peer_pk(ctx, ctx->local_id, ctx->local_id_len); /* MUTATION P6 */""")]),

 # P7 -- the callback's context is dropped. Re-authored; see the docstring.
 "P7": (HS, [("        return ctx->lookup_fn(ctx->lookup_ctx, id, id_len);",
              "        return ctx->lookup_fn(NULL, id, id_len); /* MUTATION P7 */")]),

 # P8 -- the pin is returned for ANY identity, so a slot stops speaking for
 # exactly one. Unreachable through the wire, which is precisely why the
 # resolver is exported and tested directly.
 "P8": (CN, [("""    if (sodium_memcmp(id, c->handle, id_len) != 0) {
        return NULL;
    }
    return c->pin_pk;""",
              """    /* MUTATION P8: the identity is not compared */
    return c->pin_pk;""")]),

 # P9 -- the pinned key survives the connection that held it.
 "P9": (CN, [("""    sodium_memzero(c->pin_pk, sizeof c->pin_pk);
    c->pin_set = 0;
    sodium_memzero(c->handle, sizeof c->handle);""",
              """    /* MUTATION P9: the pin outlives its connection */
    sodium_memzero(c->handle, sizeof c->handle);""")]),

 # P10 -- F62 restored in full: the shared bound and the literal constant. All
 # three edits together, because any subset fails -Werror (see the docstring).
 "P10": [(EH, "#define AUTHD_SLOTS_POLL_MAX (AUTHD_SLOTS_MAX + AUTHD_LOCAL_SLOTS_MAX)   /* 4160 */",
               "#define AUTHD_SLOTS_POLL_MAX AUTHD_SLOTS_MAX /* MUTATION P10 */"),
          (EC, """        const size_t pool_max = (pool == 0) ? AUTHD_SLOTS_MAX : AUTHD_LOCAL_SLOTS_MAX;
        size_t taken = 0;
        if (arr == NULL) {
            continue;
        }
        for (size_t i = 0; i < n && taken < pool_max; i++) {""",
               """        if (arr == NULL) {
            continue;
        }
        for (size_t i = 0; i < n && nspfd < AUTHD_SLOTS_POLL_MAX; i++) { /* MUTATION P10 */"""),
          (EC, """            slot_ref[nspfd] = s;
            nspfd++;
            taken++;""",
               """            slot_ref[nspfd] = s;
            nspfd++;""")],

 # P11 -- a local pool larger than its maximum is accepted at registration, so
 # the poll array's own bound becomes reachable again.
 "P11": (EC, [("""    if (ev == NULL || local_slots == NULL || n_local_slots == 0u ||
        n_local_slots > AUTHD_LOCAL_SLOTS_MAX || on_line == NULL) {""",
               """    if (ev == NULL || local_slots == NULL || n_local_slots == 0u ||
        on_line == NULL) { /* MUTATION P11 */""")]),
}

if MID not in M:
    sys.exit("unknown mutation id: " + MID)

def apply(path, edits):
    f = REPO / path
    s = f.read_text()
    for old, new in edits:
        n = s.count(old)
        if n != 1:
            sys.exit("%s: expected exactly 1 occurrence in %s, found %d" % (MID, path, n))
        s = s.replace(old, new, 1)
    f.write_text(s)

entry = M[MID]
if isinstance(entry, tuple):                  # shape A: (path, [(old, new), ...])
    apply(entry[0], entry[1])
    where = entry[0]
else:                                         # shape B: [(path, old, new), ...]
    for path, old, new in entry:
        apply(path, [(old, new)])
    where = ", ".join(sorted({e[0] for e in entry}))
print("%s applied to %s" % (MID, where))
