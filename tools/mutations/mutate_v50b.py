#!/usr/bin/env python3
"""V4-10b mutations: the PROXY v2 preamble, the client address, the limiter.

Usage: mutate_v50b.py <repo> <ID>

Letter J (F, O and Z remain free).

Three things shape this campaign.

FIRST, most of these defects FAIL OPEN. A limiter that never refuses, an
address check that admits a connection with no address, a preamble whose
signature is not checked -- every one of them leaves a daemon that logs in
perfectly well. authd_e2e would stay green through several of them on its own,
which is exactly why the checks they die on are negative ones: a login that
must NOT happen, a count that must NOT move, a response that must be 429.

SECOND, the limiter's boundaries are only assertable because time is an
argument. J5 is the clearest case: discarding the refill remainder leaves a
bucket that fills eventually, so anything phrased as "it refills" survives it.
Only "empty at 11999 ms and full at 12000" sees it, and only an injected clock
can say that without flaking.

THIRD, one defect here is not V4-10b's at all. J12 restores the infinite
recursion V4-10a shipped in authd_client's raw transport (audit finding F55),
which survived a whole step because every test and every e2e leg used --unix.
It is in this campaign because this is the step whose e2e finally drives both
transports, and a defect nobody can re-introduce silently is worth more than
a tidy scope.

NOT MUTATED, and the reason stated rather than implied:

  * "note_header does not guard the PROXY stage". The preamble is consumed
    strictly inside WS_STAGE_UPGRADE and never reaches `in`, so the existing
    condition already covers it and an added `|| proxy_pending` would be an
    EQUIVALENT MUTANT -- nothing could distinguish the two versions. The
    argument is written into conn_io.c next to the guard, and the split test
    that WOULD have caught it is written anyway. (The register of documented
    equivalent mutants: N7, v48a D7, v48b C8, v49c W6, v49d's KDF parameters.)

  * "the limiter is attached when no listener supplies an address". A daemon
    with proxy_protocol = none has app.rl == NULL by construction in
    authd_main.c, and no test can observe what main() assigns -- the same
    reason V4-9d pinned the recovery KDF parameters with
    check_spec_constants.sh instead of a mutation.

  * "the address is logged". src= is emitted by authd_log_slot_addr and the
    never-list is a property of the API's shape, not of this call site; a
    mutation that removed the log line would prove only that a log line
    exists.
"""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
PX = "apps/authd/proxy_v2.c"
RL = "apps/authd/ratelimit.c"
CN = "apps/authd/authd_conn.c"
EV = "apps/authd/evloop.c"
CI = "apps/authd/conn_io.c"
CL = "apps/authd/authd_cli.c"

M = {
 # J1 -- only the FIRST signature byte is compared, so eleven of the twelve
 # fixed bytes stop meaning anything. Deleting the check outright would be
 # KILLED(compile) on -Wunused-const-variable, which proves the compiler works
 # and nothing about the test; this is the defect a careless edit actually
 # leaves behind, and it compiles.
 "J1": (PX, [("        if (memcmp(p->buf, PROXY_V2_SIG, PROXY_V2_SIG_LEN) != 0) {",
              "        if (memcmp(p->buf, PROXY_V2_SIG, 1u) != 0) { /* MUTATION J1 */")]),

 # J2 -- the declared body length has no ceiling, so a 16-bit field decides how
 # long a connection may occupy a slot having said nothing.
 "J2": (PX, [("        if (ver != 0x2u || (cmd != 0x0u && cmd != 0x1u) || blen > PROXY_V2_LEN_MAX) {",
              "        if (ver != 0x2u || (cmd != 0x0u && cmd != 0x1u)) { /* MUTATION J2: no ceiling */")]),

 # J3 -- Req 12 fails OPEN: a preamble that established no client address is
 # served anyway. Every functional check still passes.
 "J3": (CN, [("    if (addr->family == 0u) {\n        app->refused_no_address++;",
              "    if (0) { /* MUTATION J3: no address is served anyway */\n        app->refused_no_address++;")]),

 # J4 -- the uid allowlist is dropped on every protocol listener, so anyone who
 # can reach the socket may state a client address (Req 11).
 "J4": (EV, [("    ev->listen_proxy[i] = (is_ws && proxy_v2) ? 1 : 0;\n    ev->listen_n_allow[i] = n_allow;",
              "    ev->listen_proxy[i] = (is_ws && proxy_v2) ? 1 : 0;\n    ev->listen_n_allow[i] = 0u; /* MUTATION J4: allowlist dropped */")]),

 # J5 -- the refill discards its remainder by advancing last_ms to now. The
 # bucket still fills, just never at the moment it should, so only a boundary
 # with a LOWER bound sees it.
 "J5": (RL, [("    *last_ms += (add * per_ms_den) / per_ms_num;",
              "    *last_ms = now_ms; /* MUTATION J5: the remainder is discarded */")]),

 # J6 -- the whole-daemon bucket is never consulted, so many addresses (or one
 # lying proxy) have no ceiling at all.
 "J6": (RL, [("    refill_global(r, now_ms);\n    if (r->global_tokens_milli < 1000u) {\n        r->denied_global++;\n        return RATELIMIT_DENY_GLOBAL;\n    }",
              "    refill_global(r, now_ms); /* MUTATION J6: the global ceiling is not applied */")]),

 # J7 -- a closed connection is never given back, so max_conns_per_addr counts
 # down to zero over a daemon's lifetime and then refuses everyone.
 "J7": (CN, [("        if (slot->addr_admitted && app != NULL && app->rl != NULL) {\n            ratelimit_release(app->rl, conn_io_client_addr(&slot->io));\n            slot->addr_admitted = 0;\n        }",
              "        /* MUTATION J7: the connection count is never released */")]),

 # J8 -- the limiter's verdict is logged and then ignored, which is the shape a
 # "monitor first, enforce later" change would take and the one most likely to
 # be left in by accident.
 "J8": (CN, [("        (void)conn_io_ws_refuse(&slot->io, (v == RATELIMIT_DENY_TABLE) ? 503u : 429u);\n        return EV_ACTION_CLOSE;",
              "        return EV_ACTION_CONTINUE; /* MUTATION J8: refusal is advisory */")]),

 # J9 -- admission stops being atomic: the connection is counted before the
 # token check, so a refused connection leaves a phantom behind it.
 "J9": (RL, [("    if (e->conns >= r->max_conns) {\n        r->denied_conns++;\n        return RATELIMIT_DENY_CONNS;\n    }",
              "    if (e->conns >= r->max_conns) {\n        e->conns++; /* MUTATION J9: a refusal counts a connection */\n        r->denied_conns++;\n        return RATELIMIT_DENY_CONNS;\n    }")]),

 # J10 -- IPv6 is keyed on all 128 bits, so a single /64 holder rotates through
 # 2^64 addresses and meets the limiter exactly never.
 "J10": (PX, [("    if (a->family == 6u) {\n        memcpy(out, a->addr, 8);        /* the /64 -- see the header */\n        return 8u;\n    }",
               "    if (a->family == 6u) {\n        memcpy(out, a->addr, 16);      /* MUTATION J10: the full address */\n        return 16u;\n    }")]),

 # J11 -- the 101 built moments earlier is left queued when the connection is
 # refused for having no address, so the refusal says 101-then-EOF whenever the
 # preamble and the request arrive in one read -- and a bare EOF when they do
 # not. F52's divergence, in a new place.
 "J11": (CN, [("        conn_io_ws_silence(&slot->io);\n        return EV_ACTION_CLOSE;",
               "        return EV_ACTION_CLOSE; /* MUTATION J11: whatever was queued still goes out */")]),

 # J12 -- audit finding F55, restored: authd_client's raw transport recurses
 # into itself instead of calling frame_send. Only a login over --port sees it.
 "J12": (CL, [("        return frame_send(&cs->conn, buf, payload_len, cs->deadline);",
               "        return cs_send(cs, buf, payload_len); /* MUTATION J12: F55 restored */")]),

 # J13 -- the listener's proxy_protocol setting never reaches the connection,
 # so a daemon configured for PROXY v2 quietly does not speak it.
 "J13": (EV, [("        conn_io_set_proxy(&s->io, ev->listen_proxy[li]);",
               "        /* MUTATION J13: the listener's PROXY setting is dropped */")]),
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
