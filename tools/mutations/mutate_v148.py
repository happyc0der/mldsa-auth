#!/usr/bin/env python3
"""V4-254 mutations: listed passwords that hold digits (F368); a log line's
detail is one word (F369).

Usage: mutate_v148.py <repo> <ID>

Two-letter IDs: PW = Password With digits, LD = Log Detail. Every spec line
names the check that must catch it (F90).

    PW1   The core is never tried with the symbols alone stripped.
    PW2   The word estimate looks a substring up only with substitutions undone.
    PW3   The as-typed substring is not case-folded.
    LD1   An '=' in a detail is written as it is.
    LD2   A space in a detail is written as it is.
    LD3   A detail is cut at 65 bytes.
    LD4   The detail beside an address is written as it came.
"""
import sys, pathlib
PP = "apps/authd/passphrase.c"
LOG = "apps/authd/authd_log.c"

M = {
    "PW1": [(PP, "        if (sb - sa >= 4u && !(sa == 0 && sb == n)) {\n",
             "        if (sb - sa >= 4u && !(sa == 0 && sb == n) && 0) { /* MUTATION PW1 */\n")],
    "PW2": [(PP, "            if (!hit && memcmp(w, typed + j, len) != 0) {\n",
             "            if (0 && !hit && memcmp(w, typed + j, len) != 0) { /* MUTATION PW2 */\n")],
    "PW3": [(PP, "        typed[i] = (cp[i] < 0x80u) ? (char)fold(cp[i]) : '\\x01';\n",
             "        typed[i] = (cp[i] < 0x80u) ? (char)cp[i] : '\\x01'; /* MUTATION PW3 */\n")],
    "LD1": [(LOG, "        word[j] = (ch > 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.';\n",
             "        word[j] = (ch > 0x20u && ch <= 0x7eu) ? (char)ch : '.'; /* MUTATION LD1 */\n")],
    "LD2": [(LOG, "        word[j] = (ch > 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.';\n",
             "        word[j] = (ch >= 0x20u && ch <= 0x7eu && ch != '=') ? (char)ch : '.'; /* MUTATION LD2 */\n")],
    "LD3": [(LOG, "#define DETAIL_FIELD_MAX 64u\n",
             "#define DETAIL_FIELD_MAX 65u /* MUTATION LD3 */\n")],
    "LD4": [(LOG, "            level_name(lvl), event ? event : \"?\", slot, src, suffix, detail_word(detail, \"-\", word));\n",
             "            level_name(lvl), event ? event : \"?\", slot, src, suffix, detail ? detail : \"-\"); /* MUTATION LD4 */\n")],
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
