#!/usr/bin/env python3
"""V4-10c: the specification's VOCABULARIES, checked against the daemon both ways.

    check_spec_vocabularies.py <repo>

check_spec_constants.sh does this for numbers. Numbers were never the problem:
§6 and §12's byte tables have been right since V4-3 because a script re-derived
them. What drifted was the prose that enumerates *names* --

  * §8 listed `bad-handle` as an error code for eight steps. Nothing has ever
    emitted it; a malformed handle answers `malformed`.
  * §8 defined no code at all for a refused or unknown command, while the
    daemon answered `not-permitted` from the day the local API existed, and
    none for RECOVERY-ISSUE's failures.
  * §15 promised the fields `ev`, `conn`, `stage`, `status`, `ms`, `rx`, `tx`.
    The daemon has never emitted one of them.

Each of those was found by a person reading the document, one step at a time,
which is the slowest possible detector. This is the fast one, and it fails in
BOTH directions: a name the daemon can emit that the spec does not define is a
failure, and so is a name the spec defines that nothing emits. The second half
is the one that matters -- an undefined name is a documentation gap, but a
DEFINED name nothing emits is a promise to a reader that the software does not
keep, and it is invisible to every test.

This is exact rather than heuristic because every call site passes a string
literal: 17 send_err() calls, 53 event names (one of them a ternary of two
literals, which is why the second argument is parsed as an expression rather
than matched as a token), and a fixed set of format strings in authd_log.c.
A non-literal at any of those call sites is itself reported as a failure --
the check would otherwise silently start covering less than it claims.
"""
import re
import sys
import glob
import os

ok = True


def report(name, good, detail=""):
    global ok
    if good:
        print("  ok    %-38s %s" % (name, detail))
    else:
        print("  FAIL  %-38s %s" % (name, detail))
        ok = False


def compare(what, emitted, defined):
    """Both directions, each reported separately: they are different defects."""
    missing = sorted(emitted - defined)     # the daemon can say it; the spec does not
    unused = sorted(defined - emitted)      # the spec promises it; nothing says it
    report("%s: defined in the spec" % what, not missing,
           "%d name(s)" % len(defined) if not missing
           else "emitted but UNDEFINED: " + " ".join(missing))
    report("%s: emitted by the daemon" % what, not unused,
           "%d name(s)" % len(emitted) if not unused
           else "defined but NEVER EMITTED: " + " ".join(unused))


def section(text, heading, stop="\n## "):
    """The body of one top-level section, so a name defined in a neighbouring
    section cannot satisfy a check about this one."""
    i = text.index(heading)
    j = text.find(stop, i + len(heading))
    return text[i:] if j < 0 else text[i:j]


def main(repo):
    os.chdir(repo)
    spec_path = "docs/mldsa-authd-spec.md"
    if not os.path.exists(spec_path):
        print("FAIL: %s not found" % spec_path)
        return 2
    spec = open(spec_path).read()
    print("check_spec_vocabularies: %s" % spec_path)

    # ---- 1. error codes: send_err() vs §8 -------------------------------
    api = open("apps/authd/localapi.c").read()
    # `send_err(slot, ...)` -- anchored on the parameter name so the function's
    # own DEFINITION (`const char *code`) is not mistaken for a call site.
    calls = re.findall(r'send_err\s*\(\s*slot\s*,\s*([^)]+)\)', api)
    nonliteral = [c.strip() for c in calls if not re.fullmatch(r'"[a-z][a-z0-9-]*"', c.strip())]
    report("error codes: every call site is a literal", not nonliteral,
           "%d call site(s)" % len(calls) if not nonliteral
           else "non-literal: " + " ".join(nonliteral))
    emitted = {c.strip().strip('"') for c in calls if re.fullmatch(r'"[a-z][a-z0-9-]*"', c.strip())}
    # `internal` is also emitted from a static buffer on the resp-overflow path.
    emitted |= set(re.findall(r'"ERR code=([a-z][a-z0-9-]*)\\n"', api))

    sec8 = section(spec, "## 8. Local socket protocol")
    defined = set()
    for run in re.findall(r'ERR code=([a-z0-9|\\`-]+)', sec8):
        for name in run.replace("\\|", "|").strip("`").split("|"):
            name = name.strip("`").strip()
            if re.fullmatch(r'[a-z][a-z0-9-]*', name):
                defined.add(name)
    compare("error codes", emitted, defined)

    # ---- 2. log events: authd_log_*(<level>, <event>, ...) vs §15 --------
    #
    # Every authd_log_* call is found FIRST, and its arguments split at top
    # level afterwards -- deliberately, because the original version anchored
    # on a literal `AUTHD_LOG_[A-Z]+,` immediately after the paren and a call
    # whose LEVEL is computed therefore matched nothing and was skipped in
    # silence. V4-11 added exactly such a call (`ms == MEMLOCK_LOW ?
    # AUTHD_LOG_WARN : AUTHD_LOG_INFO`) and the gate reported "53 names, all
    # match" while looking straight past it (audit finding F71).
    #
    # So the rule is inverted: find the call, then require that its first two
    # arguments are extractable. A call this parser cannot read is reported,
    # never ignored -- that is the difference between a check that covers what
    # it claims and one that merely says so.
    def split_args(src, i):
        """Arguments of a call whose opening paren is at src[i]."""
        args, depth, cur = [], 0, ""
        i += 1
        while i < len(src):
            c = src[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                if depth == 0:
                    args.append(cur)
                    return args, i
                depth -= 1
            elif c == ',' and depth == 0:
                args.append(cur)
                cur = ""
                i += 1
                continue
            cur += c
            i += 1
        return args, i

    # WHICH functions take an event is derived from authd_log.h's prototypes --
    # every one whose second parameter is `const char *event` -- rather than
    # listed here. A new logging function is then covered the day it is
    # declared, and `authd_log_init` (which takes a stream and a level, and no
    # event) is excluded without naming it.
    hdr = open("apps/authd/authd_log.h").read()
    evfns = set(re.findall(
        r'\b(authd_log_[a-z_]+)\s*\([^;]*?authd_log_level_t\s+\w+\s*,\s*const char \*event',
        hdr, re.S))
    report("log events: the event-taking functions are discoverable", evfns,
           "%d function(s): %s" % (len(evfns), " ".join(sorted(evfns))))

    events = set()
    bad_event_sites = []
    # authd_log.c holds the DEFINITIONS; call sites are everywhere else.
    for path in sorted(p for p in glob.glob("apps/authd/*.c")
                       if not p.endswith("authd_log.c")):
        src = open(path).read()
        for m in re.finditer(r'\b(' + "|".join(sorted(evfns)) + r')\s*\(', src):
            args, _ = split_args(src, m.end() - 1)
            where = "%s:%d" % (path, src.count("\n", 0, m.start()) + 1)
            # What is gated here is the EVENT NAME, which is argument 2. The
            # level is argument 1 and is deliberately not inspected: it may be
            # a literal, a ternary, or -- as `memlock_log_level(ms)` is -- a
            # named function, which is the shape a level decision takes once it
            # is a requirement somebody has to test. An earlier version of this
            # check required `AUTHD_LOG_` to appear in argument 1, and V4-11's
            # first such helper made a perfectly readable call site report as
            # unreadable. Requiring only that the call HAS two arguments keeps
            # the property that matters: a site whose event is not a literal is
            # still reported below, because a computed event name is the one
            # thing that could evade the vocabulary entirely.
            if len(args) < 2:
                bad_event_sites.append(where + " (fewer than two arguments)")
                continue
            found = re.findall(r'"([a-z][a-z0-9-]*)"', args[1])
            if not found:
                bad_event_sites.append(where + " (event is not a literal)")
                continue
            events.update(found)
    report("log events: every call site is readable", not bad_event_sites,
           "%d name(s)" % len(events) if not bad_event_sites
           else "unreadable: " + " ".join(bad_event_sites))

    sec15 = section(spec, "## 15. Logging")
    # The two lists are located by §15's own headings rather than by guessing
    # from their contents. Content-sniffing was the first attempt and it made a
    # renamed FIELD look like an event catalogue, so a one-word error produced
    # thirty lines of noise; anchoring on the prose means a restructured §15
    # fails with "the heading is missing" instead.
    #
    # They are also collected separately rather than by subtraction, because
    # the two vocabularies legitimately overlap: `accepted` is both an event
    # name and a counted quantity, and subtracting one from the other would
    # silently delete it from the catalogue.
    def blocks_after(marker):
        i = sec15.find(marker)
        if i < 0:
            return None
        j = sec15.find("**", i + len(marker))
        return re.findall(r'```\n(.*?)```', sec15[i:] if j < 0 else sec15[i:j], re.S)

    field_blocks = blocks_after("**Fields.**")
    cat_blocks = blocks_after("**Event catalogue.**")
    report("log vocabularies: §15 still has both lists",
           field_blocks and cat_blocks,
           "%d field block, %d catalogue block(s)" % (len(field_blocks or []), len(cat_blocks or []))
           if field_blocks and cat_blocks else "a §15 heading is missing or moved")
    if not (field_blocks and cat_blocks):
        return 1
    names_of = lambda bs: {w for b in bs for w in b.split()
                           if re.fullmatch(r'[a-z][a-z0-9_-]*', w)}
    fields = names_of(field_blocks)
    catalogue = names_of(cat_blocks)
    compare("log events", events, catalogue)

    # ---- 3. log fields: authd_log.c's formats + authd_log_num keys -------
    logc = open("apps/authd/authd_log.c").read()
    emitted_fields = set(re.findall(r'\b([a-z][a-z0-9_]*)=%', logc))
    emitted_fields.discard("s")          # the `%s=%llu` placeholder, not a name
    num_keys = set()
    for path in sorted(glob.glob("apps/authd/*.c")):
        src = open(path).read()
        for m in re.finditer(r'\bauthd_log_num\s*\(', src):
            args, _ = split_args(src, m.end() - 1)
            if len(args) >= 3:
                num_keys.update(re.findall(r'"([a-z][a-z0-9_]*)"', args[2]))
    report("log fields: the numeric key is a literal", num_keys,
           "%d counted quantity(ies)" % len(num_keys))
    compare("log fields", emitted_fields | num_keys, fields)

    print("  ---")
    if ok:
        print("OK: the specification's error codes, log events and log fields "
              "match the daemon exactly")
        return 0
    print("FAIL: the specification and the daemon disagree about a name")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check_spec_vocabularies.py <repo>")
    sys.exit(main(sys.argv[1]))
