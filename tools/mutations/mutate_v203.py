#!/usr/bin/env python3
"""V4-367 mutations: what the hundred-and-sixth review found (F797, F798).

Usage: mutate_v203.py <repo> <ID>

    SD1   a daemon that sets no rotate clock judges a ROTATE on the loop's
          pushed now_ms, which a pass a slow handler made long holds still.
    SD2   the age is judged after both signatures, not before them as
          section 6.3 orders it.
"""
import sys, pathlib
AC = "apps/authd/authd_conn.c"

LATE = """    if (app->rotate_window_ms != 0u) {
        /* Unsigned: a clock that reads before the code's time wraps to an
         * age far past any window, and is refused with the rest. */
        const uint64_t age = rotate_clock(app) - c->code_at_ms;
        if (age > (uint64_t)app->rotate_window_ms) {
            return fail_with_error(slot, c, AUTHMSG_ERR_REJECTED, "rotate-late");
        }
    }
"""
STORE = "    /* store_rotate_key re-reads device and user status INSIDE its transaction\n"

M = {
    "SD1": [(AC, "app->rotate_clock_ms() : rotate_clock_real();",
             "app->rotate_clock_ms() : (rotate_clock_real(), app->now_ms); /* MUTATION SD1 */")],
    "SD2": [(AC, LATE, "    /* MUTATION SD2: the age check moved below */\n"),
            (AC, STORE, LATE + STORE)],
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
