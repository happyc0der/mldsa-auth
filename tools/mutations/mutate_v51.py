#!/usr/bin/env python3
"""V4-11 mutations: the daemon's RLIMIT_MEMLOCK check.

Usage: mutate_v51.py <repo> <ID>

Letter Z (F remains free).

WHAT THIS GUARDS, and why it needs guarding at all. V4-2's S1 spike ran 1,000
concurrent `sodium_malloc` allocations under a 64 KiB `RLIMIT_MEMLOCK`: all
1,000 SUCCEEDED and about 16 were actually locked. libsodium calls mlock(),
ignores its failure, and returns memory indistinguishable from locked memory.
So a daemon with a too-small limit has swappable secret keys, swappable
session keys and swappable login codes -- and NO symptom whatsoever. The only
thing standing between that and an operator is one startup line, which is
exactly the kind of code that rots unnoticed, because nothing downstream
depends on it being right.

All five die in `test_authd_evloop`, which stages a genuinely lowered limit
with `setrlimit` rather than asserting about the ambient one. That matters
twice over: a test that only read the ambient limit would answer UNLIMITED on
a developer's macOS shell and OK-or-LOW by luck in CI, so it could not pin
anything; and the staged limit is what lets both sides of the boundary be
named from literals.

TWO MUTATIONS ARE ABOUT THE FORMULA, NOT THE COMPARISON. Z3 and Z5 both leave
a check that reads correct, compares correctly and reports a plausible number
-- they simply derive the wrong requirement. Z3 is the more dangerous of the
pair: dropping the ten-blocks factor understates the need by 10x, so a host
with a 1 MiB limit and 256 slots is told everything is fine when it covers
barely a tenth of the handshakes in flight. This is the reason the test asserts
`memlock_required_bytes` against LITERALS (40960, 10485760, 167772160) rather
than against the macros the implementation uses: an expectation computed from
MEMLOCK_PAGE_BYTES and MEMLOCK_BLOCKS_PER_SLOT would move with the mutation
and could never catch one.

Z4 EXISTS BECAUSE THE REQUIREMENT IS "LOUD", NOT MERELY "LOGGED". A line at
INFO in a daemon whose journal is filtered to warnings is a line nobody sees,
which for this particular failure is the same as no line at all. That check is
only possible because the level decision is a named function; while it was a
ternary inside main() the ambient limit decided which branch ran, and no
deterministic test could reach it.

NOT MUTATED, and the reason stated rather than implied:

  * "the daemon REFUSES to start when the limit is low". That is not the
    behaviour and deliberately so (see memlock.h): Linux's usual 8 MiB default
    is already under the need at the default 256 slots, so refusing would turn
    a widespread misconfiguration into an outage and would stop every
    development run and the end-to-end test besides. A mutation asserting the
    opposite would be a mutation against the design, not against a defect.

  * "getrlimit's failure is treated as OK instead of UNKNOWN". Reachable on no
    platform this project builds on -- getrlimit(RLIMIT_MEMLOCK) does not fail
    on Linux or macOS -- so the mutation would SURVIVE everywhere and teach
    that a survivor is normal. The path is covered by inspection and by
    MEMLOCK_UNKNOWN's own naming check. A documented equivalent mutant, in the
    register N7 / v48a D7 / v48b C8 / v49c established.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
ML = "apps/authd/memlock.c"

M = {
 # Z1 -- the limit is never read. getrlimit is skipped and the answer is
 # always OK, so the check runs, logs a number and reassures the operator
 # about a limit it never looked at. Nothing else in the daemon can tell.
 "Z1": (ML, [("""    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        return MEMLOCK_UNKNOWN;
    }""",
              """    struct rlimit rl;
    rl.rlim_cur = 0; /* MUTATION Z1: the limit is never read */
    return MEMLOCK_OK;""")]),

 # Z2 -- the comparison is inverted. Caught in BOTH directions by the test:
 # the present canary (16 slots inside 1 MiB must answer OK) fails as well as
 # the LOW case, so this cannot be mistaken for a check that answers LOW
 # unconditionally.
 "Z2": (ML, [("    return (limit >= need) ? MEMLOCK_OK : MEMLOCK_LOW;",
              "    return (limit <= need) ? MEMLOCK_OK : MEMLOCK_LOW; /* MUTATION Z2 */")]),

 # Z3 -- the ten-blocks-per-slot factor is dropped, understating the need by
 # 10x. The most dangerous of the five: everything still reads correctly and
 # the reported number is plausible, so only an expectation written as a
 # LITERAL sees it.
 "Z3": (ML, [("""    return (uint64_t)MEMLOCK_PAGE_BYTES * (uint64_t)MEMLOCK_BLOCKS_PER_SLOT *
           (uint64_t)max_slots;""",
              """    return (uint64_t)MEMLOCK_PAGE_BYTES *
           (uint64_t)max_slots; /* MUTATION Z3: the ten blocks are dropped */""")]),

 # Z4 -- the WRONG status is the loud one: UNKNOWN warns and LOW does not. The
 # line still appears for every status and still carries the right number; the
 # one case with no other symptom is the one filtered out of a journal set to
 # warnings, and an operator is instead warned about a platform that has
 # nothing to misconfigure.
 #
 # AUTHORED THIS WAY ON PURPOSE. The obvious phrasing -- `return
 # AUTHD_LOG_INFO;` -- does not compile: `st` goes unused and -Werror stops it
 # at `unused parameter 'st' [-Wunused-parameter]`. That scores KILLED(compile),
 # which proves the compiler works and NOTHING about whether any test reads the
 # level. v50b's J1 and v50c's O3 were both caught doing exactly this and both
 # had to be re-authored; so was the first draft of this mutation. Swapping
 # which status is loud keeps `st` live, so the kill has to come from a check.
 "Z4": (ML, [("    return (st == MEMLOCK_LOW) ? AUTHD_LOG_WARN : AUTHD_LOG_INFO;",
              "    return (st == MEMLOCK_UNKNOWN) ? AUTHD_LOG_WARN : AUTHD_LOG_INFO; /* MUTATION Z4 */")]),

 # Z5 -- the page size is halved, understating the need by 2x. Z3's sibling at
 # a subtler scale: a 2x error is far easier to believe than a 10x one, and
 # the boundary cases (25 slots fit in 1 MiB, 26 do not) are what catch it
 # where the coarse cases would not.
 "Z5": (ML, [("#include \"memlock.h\"",
              "#include \"memlock.h\"\n#undef MEMLOCK_PAGE_BYTES\n#define MEMLOCK_PAGE_BYTES 2048u /* MUTATION Z5 */")]),
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
