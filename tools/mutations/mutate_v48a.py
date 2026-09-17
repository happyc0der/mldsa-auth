#!/usr/bin/env python3
"""V4-8a mutations for the daemon's transport skeleton.
Each must make test_authd_evloop fail on the named check.
Usage: mutate_v48a.py <repo> <ID>

D1 is the one that matters most: it disables deadline enforcement entirely. It
is killed by the check that the connection is gone AT its deadline -- and the
paired lower-bound check (still open one millisecond BEFORE) is what stops the
opposite defect, a loop that closes everything immediately, from passing."""
import sys, pathlib
REPO = pathlib.Path(sys.argv[1]); MID = sys.argv[2]
EV = "apps/authd/evloop.c"
IO = "apps/authd/conn_io.c"
CF = "apps/authd/authd_config.c"
M = {
 # deadlines are never enforced
 "D1": (EV, [("        if (now_ms >= s->deadline_ms) {",
              "        if (0) { /* MUTATION D1: deadline never enforced */")]),
 # the frame-length cap is gone: an oversized declared length is accepted
 "D2": (IO, [("    if (len == 0u || len > (uint32_t)AUTHD_FRAME_MAX) {",
              "    if (len == 0u) { /* MUTATION D2: frame cap removed */")]),
 # a frame is handed over before its payload has fully arrived
 "D3": (IO, [("    if (c->in_len < AUTHD_FRAME_HEADER + c->frame_len) {\n        return 0;                       /* payload still arriving */\n    }",
              "    if (0) {\n        return 0;\n    } /* MUTATION D3: incomplete frame released */")]),
 # a released slot keeps the previous connection's bytes
 "D4": (EV, [("    const int local = (s->kind == SLOT_KIND_LOCAL);\n    conn_io_reset(&s->io);\n    if (local) {\n        conn_io_set_mode(&s->io, CONN_IO_MODE_LINE);   /* the mode is the pool's, not the connection's */\n    }",
              "    const int local = (s->kind == SLOT_KIND_LOCAL);\n    if (local) {\n        conn_io_set_mode(&s->io, CONN_IO_MODE_LINE);\n    } /* MUTATION D4: slot not wiped on release */")]),
 # a partial write is recorded as a complete one, so the tail is never sent
 "D5": (IO, [("    c->out_sent += (n > pending) ? pending : n;",
              "    (void)pending; c->out_sent = c->out_len; /* MUTATION D5: partial send treated as complete */")]),
 # numeric bounds are not enforced
 "D6": (CF, [("    if (acc < (uint64_t)lo || acc > (uint64_t)hi) {\n        return AUTHD_CFG_ERR_RANGE;\n    }",
              "    if (0) {\n        return AUTHD_CFG_ERR_RANGE;\n    } /* MUTATION D6: numeric bounds off */")]),
 # a repeated key silently overwrites the earlier one
 "D8": (CF, [("        if ((seen & (1u << bit)) != 0u) {\n            if (err_line != NULL) { *err_line = line_no; }\n            return AUTHD_CFG_ERR_DUPLICATE_KEY;\n        }",
              "        if (0) {\n            return AUTHD_CFG_ERR_DUPLICATE_KEY;\n        } /* MUTATION D8: duplicates allowed */")]),
}
path, edits = M[MID]
f = REPO / path; s = f.read_text()
for old, new in edits:
    if s.count(old) != 1:
        sys.exit(f"anchor for {MID} matched {s.count(old)} times in {path}")
    s = s.replace(old, new, 1)
f.write_text(s); print(f"applied {MID} to {path}")
