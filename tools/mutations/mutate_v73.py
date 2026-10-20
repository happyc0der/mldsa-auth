#!/usr/bin/env python3
"""V4-35 mutations: a rotation whose reply is refused or lost (CLAIMS D10).

Usage: mutate_v73.py <repo> <ID>

Two-letter IDs: RL = Rotation reply Lost or refused. After ROTATE is sent,
cmd_client_rotate keeps .ek.next, sealed, on a refusal and on no reply at all,
"so the next run can resolve it" -- and until V4-35 no test scanned the disk
after either. Each mutation keeps the NEW key's raw secret beside .ek.next "for
a retry" on one of those paths. The CLI frees the new key before it sends
ROTATE, so each is two sites: that free moved into the path that keeps it.
Every spec line names the check that must catch it (F90).

    RL1   the refused path keeps the new key's raw secret as <.ek.next>.retry
    RL2   the no-reply path does the same
"""
import sys, pathlib
CLI = "apps/authd/client_cli.c"

M = {
    "RL1": [(CLI, '    mldsa_keypair_free(&old_kp);   /* both signatures are made */\n    mldsa_keypair_free(&new_kp);\n',
             '    mldsa_keypair_free(&old_kp);   /* both signatures are made */\n'),
            (CLI, '            fprintf(stderr, "%s rotate: %s is KEPT so the next run can resolve it\\n",\n                    prog, next_path);\n            goto out;\n',
             '            fprintf(stderr, "%s rotate: %s is KEPT so the next run can resolve it\\n",\n                    prog, next_path);\n            { char rt[PATH_MAX + 8]; FILE *tf; /* MUTATION RL1: the new key, raw, "for a retry" */\n          const int rtn = snprintf(rt, sizeof rt, "%s.retry", next_path);\n          if (rtn > 0 && (size_t)rtn < sizeof rt && new_kp.secret_key != NULL && (tf = fopen(rt, "wb")) != NULL) {\n              (void)!fwrite(new_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, tf); (void)fclose(tf); }\n          mldsa_keypair_free(&new_kp); }\n            goto out;\n')],
    "RL2": [(CLI, '    mldsa_keypair_free(&old_kp);   /* both signatures are made */\n    mldsa_keypair_free(&new_kp);\n',
             '    mldsa_keypair_free(&old_kp);   /* both signatures are made */\n'),
            (CLI, '        fprintf(stderr, "%s rotate: no reply; %s is KEPT so the next run can resolve it\\n",\n                prog, next_path);\n        goto out;\n',
             '        fprintf(stderr, "%s rotate: no reply; %s is KEPT so the next run can resolve it\\n",\n                prog, next_path);\n        { char rt[PATH_MAX + 8]; FILE *tf; /* MUTATION RL2: the new key, raw, "for a retry" */\n          const int rtn = snprintf(rt, sizeof rt, "%s.retry", next_path);\n          if (rtn > 0 && (size_t)rtn < sizeof rt && new_kp.secret_key != NULL && (tf = fopen(rt, "wb")) != NULL) {\n              (void)!fwrite(new_kp.secret_key, 1u, MLDSA_SECRET_KEY_BYTES, tf); (void)fclose(tf); }\n          mldsa_keypair_free(&new_kp); }\n        goto out;\n')],
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
