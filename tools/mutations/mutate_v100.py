#!/usr/bin/env python3
"""V4-126 mutations: the daemon pings systemd's watchdog from its event
loop, so a daemon that hangs is killed and restarted (F209).

Usage: mutate_v100.py <repo> <ID>

Two-letter IDs: WD = WatchDog. Every spec line names the check that must
catch it (F90).

    WD1   the loop never pings: a daemon under WatchdogSec= is killed as
          hung every 30 s.
    WD2   no WATCHDOG_USEC is read as a watchdog of the longest period.
    WD3   WATCHDOG_PID is not compared: a watchdog meant for another
          process is taken as this one's.
    WD4   the loop does not wake for a period shorter than its own idle
          wait: a short watchdog is pinged a second apart whatever it asks.
    WD5   the period is the whole timeout, not a quarter: every ping
          arrives as the watchdog expires.
    WD6   the loop pings whether or not a watchdog is set.
    WD7   an overflowing WATCHDOG_USEC wraps instead of being refused.
"""
import sys, pathlib
MAIN = "apps/authd/authd_main.c"
SDN = "apps/authd/sdnotify.c"

M = {
    "WD1": [(MAIN, "        if (wd_ms != 0u && app.now_ms - wd_last_ms >= (uint64_t)wd_ms) {\n",
                   "        if (wd_ms != 0u && app.now_ms - wd_last_ms >= (uint64_t)wd_ms + 3600000u) { /* MUTATION WD1 */\n")],
    "WD2": [(SDN, "    if (parse_u64_strict(getenv(\"WATCHDOG_USEC\"), &usec) != 0 || usec == 0u) {\n        return 0u;\n",
                  "    if (parse_u64_strict(getenv(\"WATCHDOG_USEC\"), &usec) != 0 || usec == 0u) {\n        return AUTHD_SD_WATCHDOG_MAX_MS; /* MUTATION WD2 */\n")],
    "WD3": [(SDN, "        if (parse_u64_strict(pid, &want) != 0 || want != (uint64_t)getpid()) {\n",
                  "        if (parse_u64_strict(pid, &want) != 0) { /* MUTATION WD3 */\n")],
    "WD4": [(MAIN, "    const int idle_wait_ms = (wd_ms != 0u && wd_ms < 1000u) ? (int)wd_ms : 1000;\n",
                   "    const int idle_wait_ms = (wd_ms != 0u && wd_ms < 1000u) ? 1000 : 1000; /* MUTATION WD4 */\n")],
    "WD5": [(SDN, "    uint64_t ms = usec / 4000u;\n",
                  "    uint64_t ms = usec / 1000u; /* MUTATION WD5 */\n")],
    "WD6": [(MAIN, "        if (wd_ms != 0u && app.now_ms - wd_last_ms >= (uint64_t)wd_ms) {\n",
                   "        if (app.now_ms - wd_last_ms >= (uint64_t)wd_ms) { /* MUTATION WD6 */\n")],
    "WD7": [(SDN, "        if (v > (UINT64_MAX - d) / 10u) {\n",
                  "        if (0 && v > (UINT64_MAX - d) / 10u) { /* MUTATION WD7 */\n")],
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
