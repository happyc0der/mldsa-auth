#!/usr/bin/env python3
"""V4-374 mutations: what the hundred-and-thirteenth review found (F847 to F851).

Usage: mutate_v208.py <repo> <ID>

    SI1   keyfile_restage_sealed moves what has the name aside before it
          has written the staged bytes (V4-372's order).
    SI2   a file left under the restage's own name is unlinked (V4-373).
    SI3   a restage that fails leaves its written copy behind.
    SI4   rotate, .ek.next changed and .ek unwritable: the accepted key is
          not put back at .ek.next.
    SI5   the same at the login that completes a rotation.
    SI6   after putting it back, rotate still says .ek.next "is not the key
          the daemon accepted" (V4-373).
    SI7   rotate, .pub unwritable: .ek.next is kept unseen and said to hold
          the new key.
    SI8   client_restage_opened answers "held" whatever happened.
    SI9   an unsent rotate unlinks whatever is at .ek.next (V4-373).
    SI10  the restage says "was no longer the key" of a file it could not
          read, and "could not be read back" of one that changed.
    SI11  the kept-.ek.next exits say "is KEPT" whatever the restage said.
"""
import sys, pathlib
KF = "apps/authd/keyfile.c"
CL = "apps/authd/client_cli.c"

M = {
    "SI1": [(KF, '    r = publish(fresh, buf, len);\n    if (r != KEYFILE_OK) {\n        return r == KEYFILE_ERR_EXISTS ? KEYFILE_ERR_IO : r;\n    }\n    r = move_aside(path, 1, aside, aside_cap);\n',
             '    r = move_aside(path, 1, aside, aside_cap); /* MUTATION SI1 */\n    if (r == KEYFILE_OK) { r = publish(fresh, buf, len); }\n    if (r != KEYFILE_OK) {\n        return r == KEYFILE_ERR_EXISTS ? KEYFILE_ERR_IO : r;\n    }\n')],
    "SI2": [(KF, '    keyfile_status_t r = move_aside(fresh, 0, stale, sizeof stale);\n',
             '    (void)stale; (void)unlink(fresh);\n    keyfile_status_t r = KEYFILE_OK; /* MUTATION SI2 */\n')],
    "SI3": [(KF, '    if (r != KEYFILE_OK) {\n        (void)unlink(fresh);\n        return r;\n    }\n    fsync_parent_dir(path);\n',
             '    if (r != KEYFILE_OK) {\n        return r; /* MUTATION SI3 */\n    }\n    fsync_parent_dir(path);\n')],
    "SI4": [(CL, '            const int held = client_restage_opened(prog, "rotate", next_path, a.key_path, next_digest, next_sealed, next_sealed_len);\n            (void)failed(prog, "rotate", next_path, keyfile_status_name(ps));\n            if (held) {\n',
             '            const int held = 1; /* MUTATION SI4 */\n            (void)failed(prog, "rotate", next_path, keyfile_status_name(ps));\n            if (held) {\n')],
    "SI5": [(CL, '                const int held = client_restage_opened(prog, sub, next_path, a->key_path, next_digest,\n                                                       next_sealed, next_sealed_len);\n                (void)failed(prog, sub, next_path, keyfile_status_name(ps));\n',
             '                const int held = 1; /* MUTATION SI5 */\n                (void)failed(prog, sub, next_path, keyfile_status_name(ps));\n')],
    "SI6": [(CL, '            if (held) {\n                /* V4-374 (F847): as F645 says it at the exit below. */\n',
             '            if (0 && held) { /* MUTATION SI6 */\n                /* V4-374 (F847): as F645 says it at the exit below. */\n')],
    "SI7": [(CL, '            if (!client_restage_opened(prog, "rotate", next_path, a.key_path, next_digest, next_sealed, next_sealed_len)) {\n                /* V4-374 (F848) */\n',
             '            if (0) { /* MUTATION SI7 */\n                /* V4-374 (F848) */\n')],
    "SI8": [(CL, '    return rs == KEYFILE_OK;\n}\n\nstatic int client_resolve_key_locked(',
             '    return 1; /* MUTATION SI8 */\n}\n\nstatic int client_resolve_key_locked(')],
    "SI9": [(CL, '    if (is == KEYFILE_OK) {\n        return unlink(next_path) == 0 ? 1 : (errno == ENOENT ? 2 : 0);\n',
             '    if (1) { /* MUTATION SI9 */\n        return unlink(next_path) == 0 ? 1 : (errno == ENOENT ? 2 : 0);\n')],
    "SI10": [(CL, '    } else if (rs == KEYFILE_OK && is == KEYFILE_ERR_CHANGED) {\n        fprintf(stderr, "%s %s: %s was no longer the key this run staged',
             '    } else if (rs == KEYFILE_OK && is != KEYFILE_ERR_CHANGED) { /* MUTATION SI10 */\n        fprintf(stderr, "%s %s: %s was no longer the key this run staged')],
    "SI11": [(CL, '    return held ? "is KEPT so the next run can resolve it"\n',
             '    return (1 || held) ? "is KEPT so the next run can resolve it" /* MUTATION SI11 */\n')],
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
