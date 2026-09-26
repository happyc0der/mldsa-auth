/*
 * V4-13c: the passphrase policy (apps/authd/passphrase.c).
 *
 * One named check per rule, with the passphrase chosen so that ONLY that rule
 * can decide it: a length case is otherwise strong, a common case is long
 * enough, a predictable case is in no list. The estimator's numbers are
 * asserted where the rule depends on them, so a change to a constant shows up
 * as a named failure rather than as a policy that quietly moved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "passphrase.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { printf("PASS: %s\n", msg); } \
    else { printf("FAIL: %s\n", msg); g_fail = 1; } } while (0)

static pp_verdict_t v(const char *s, pp_report_t *r) { return pp_check((const uint8_t *)s, strlen(s), r); }

/* The whole of a small text file, NUL-terminated, or NULL. */
static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    static char buf[65536];
    const size_t n = fread(buf, 1u, sizeof buf - 1u, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static int explains(pp_verdict_t vd, uint32_t cps, uint32_t bits, uint32_t rs, const char *want)
{
    const pp_report_t rep = { cps, bits, rs };
    char out[200];
    const size_t n = pp_explain(vd, &rep, out, sizeof out);
    if (strcmp(out, want) != 0 || n != strlen(want)) {
        printf("  pp_explain gave \"%s\", wanted \"%s\"\n", out, want);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    pp_report_t r;

    /* ---- the pinned list ---- */
    { int sorted = 1, lower = 1;
      for (size_t i = 0; i < pp_common_count; i++) {
          if (i > 0 && strcmp(pp_common[i - 1], pp_common[i]) >= 0) { sorted = 0; }
          for (const char *c = pp_common[i]; *c; c++) { if (*c >= 'A' && *c <= 'Z') { lower = 0; } }
      }
      CHECK(pp_common_count == 9913u && sorted && lower,
            "list: 9913 entries, strictly sorted bytewise and lower-case, as generated"); }

    /* ---- accepted ---- */
    CHECK(v("correct horse battery staple", &r) == PP_OK && r.code_points == 28u && r.est_bits >= PP_MIN_BITS,
          "ok: a four-word passphrase");
    CHECK(v("Tr0ub4dor&3xy", &r) == PP_OK, "ok: 13 characters from all four ASCII classes");
    CHECK(v("qmxvhbtrnzlw", &r) == PP_OK && r.est_bits == 56u && (r.reasons & PP_R_ONE_CLASS) != 0u,
          "ok: 12 lower-case letters with no pattern (56 bits), flagged one-class but accepted");

    /* ---- length, in code points ---- */
    CHECK(v("Tr0ub4dor&3", &r) == PP_TOO_SHORT && r.code_points == 11u,
          "too-short: 11 characters, however varied");
    CHECK(v("\xc3\x85\xc3\x84\xc3\x96\xc3\xa5\xc3\xa4\xc3\xb6\xc3\x86\xc3\x98\xc3\xa6\xc3\xb8\xc3\x9f", &r) ==
              PP_TOO_SHORT && r.code_points == 11u,
          "too-short: 11 non-ASCII characters are 22 bytes -- characters are counted, not bytes");
    CHECK(v("\xc3\x85\xc3\x84\xc3\x96\xc3\xa5\xc3\xa4\xc3\xb6\xc3\x86\xc3\x98\xc3\xa6\xc3\xb8\xc3\x9f\xc3\x89", &r) ==
              PP_OK && r.code_points == 12u,
          "ok: 12 non-ASCII characters");
    { static char big[PP_MAX_BYTES + 2u];
      memset(big, 'k', sizeof big - 1u);
      CHECK(pp_check((const uint8_t *)big, PP_MAX_BYTES + 1u, &r) == PP_TOO_LONG,
            "too-long: one byte over PP_MAX_BYTES"); }
    CHECK(pp_check(NULL, 0, &r) == PP_TOO_SHORT && pp_check(NULL, 5, &r) == PP_NOT_UTF8,
          "edges: an empty passphrase is too short; NULL with a length is refused, not read");

    /* ---- UTF-8, strictly ---- */
    { static const struct { const char *s; size_t n; const char *what; } bad[] = {
          { "abcdefghijk\xc0\x80", 13, "overlong NUL" },
          { "abcdefghijk\xed\xa0\x80", 14, "a surrogate" },
          { "abcdefghijk\xf4\x90\x80\x80", 15, "above U+10FFFF" },
          { "abcdefghijkl\xe2\x82", 14, "a truncated sequence" },
          { "abcdefghijkl\x80", 13, "a stray continuation byte" },
      };
      int all = 1;
      for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
          if (pp_check((const uint8_t *)bad[i].s, bad[i].n, &r) != PP_NOT_UTF8) { printf("  (%s accepted)\n", bad[i].what); all = 0; }
      }
      CHECK(all, "not-utf8: overlong, surrogate, above U+10FFFF, truncated, stray continuation"); }

    /* ---- the common list ---- */
    CHECK(v("qwertyqwerty", &r) == PP_COMMON, "common: a 12-character entry of the list itself");
    CHECK(v("password1234", &r) == PP_COMMON, "common: a listed word with digits appended");
    CHECK(v("!!Password1234!!", &r) == PP_COMMON, "common: case and surrounding symbols do not hide it");
    CHECK(v("1234monkey5678", &r) == PP_COMMON, "common: digits on both sides do not hide it");
    CHECK(v("monkey9ab1234", &r) != PP_COMMON, "common: a listed word INSIDE other text is not a match");

    /* ---- predictable ---- */
    CHECK(v("zzzzzzzzzzzz", &r) == PP_PREDICTABLE && (r.reasons & PP_R_REPEATS) != 0u && r.est_bits < PP_MIN_BITS,
          "predictable: one character repeated (also one repeated unit -- either rule refuses it)");
    /* Only the repeat discount can decide this one: four runs, no single
     * repeated unit, no sequence, no keyboard walk. 4 x (4.7 + 3 x 1) = 30.8
     * bits with the discount; 16 x 4.7 = 75 without it. (v55 PP7 survived the
     * case above, which a second rule also refuses.) */
    CHECK(v("ggggmmmmssssxxxx", &r) == PP_PREDICTABLE && (r.reasons & PP_R_REPEATS) != 0u &&
              (r.reasons & PP_R_REPEATED_UNIT) == 0u && r.est_bits == 30u,
          "predictable: runs of a repeated character count almost nothing (30 bits, not 75)");
    CHECK(v("mnopqrstuvwx", &r) == PP_PREDICTABLE && (r.reasons & PP_R_SEQUENCE) != 0u,
          "predictable: an alphabetic run");
    CHECK(v("98765432109876543", &r) == PP_PREDICTABLE && (r.reasons & PP_R_SEQUENCE) != 0u,
          "predictable: a descending digit run");
    CHECK(v("yuiopasdfghj", &r) == PP_PREDICTABLE && (r.reasons & PP_R_KEYBOARD) != 0u,
          "predictable: a walk along the keyboard rows");
    CHECK(v("kx7kx7kx7kx7", &r) == PP_PREDICTABLE && (r.reasons & PP_R_REPEATED_UNIT) != 0u && r.est_bits == 17u,
          "predictable: one 3-character unit repeated counts as the unit plus 2 bits (17)");
    CHECK(v("839201748392", &r) == PP_PREDICTABLE && (r.reasons & PP_R_ONE_CLASS) != 0u && r.est_bits == 39u,
          "predictable: 12 random digits are 39 bits, under the 50-bit floor");

    CHECK(strcmp(pp_verdict_name(PP_COMMON), "common") == 0 && strcmp(pp_verdict_name(PP_PREDICTABLE), "predictable") == 0,
          "names: verdicts have the names a page shows");

    /* ---- pp_explain (V4-13d): the enrollment page's words, for the CLI ---- */
    CHECK(explains(PP_OK, 16u, 74u, 0u, "acceptable (~74 bits estimated)") &&
          explains(PP_NOT_UTF8, 0u, 0u, 0u, "not valid text") &&
          explains(PP_TOO_LONG, 0u, 0u, 0u, "too long") &&
          explains(PP_TOO_SHORT, 9u, 0u, 0u, "too short (9 of 12 characters)") &&
          explains(PP_COMMON, 12u, 0u, 0u, "a common password"),
          "explain: each verdict in the page's words");
    CHECK(explains(PP_PREDICTABLE, 16u, 30u, PP_R_REPEATS | PP_R_ONE_CLASS,
                   "too predictable (~30 bits: repeated characters, only one kind of character)") &&
          explains(PP_PREDICTABLE, 12u, 17u,
                   PP_R_REPEATS | PP_R_SEQUENCE | PP_R_KEYBOARD | PP_R_REPEATED_UNIT | PP_R_ONE_CLASS,
                   "too predictable (~17 bits: repeated characters, a run like abc or 321, a keyboard walk, "
                   "one piece repeated, only one kind of character)") &&
          explains(PP_PREDICTABLE, 12u, 44u, 0u, "too predictable (~44 bits)"),
          "explain: predictable lists every reason, in the page's order, and none when there are none");
    { char tiny[8];
      memset(tiny, 'x', sizeof tiny);
      const pp_report_t z = { 9u, 0u, 0u };
      CHECK(pp_explain(PP_TOO_SHORT, &z, tiny, sizeof tiny) == 0u && tiny[0] == '\0',
            "explain: a buffer too small gives 0 and an empty string, never a cut sentence"); }
    { char out[200];
      pp_report_t rr;
      const pp_verdict_t vd = v("ggggmmmmssssxxxx", &rr);
      (void)pp_explain(vd, &rr, out, sizeof out);
      CHECK(strstr(out, "gggg") == NULL && strncmp(out, "too predictable (~30 bits: repeated characters", 46) == 0,
            "explain: a real refusal names its reasons and contains no passphrase byte"); }

    /* The SAME words as the browser: every phrase above must appear in
     * web/pages/enroll.mjs, so the two cannot drift apart unseen. */
    if (argc > 1) {
        const char *js = slurp(argv[1]);
        static const char *const phrases[] = {
            "repeated characters", "a run like abc or 321", "a keyboard walk", "one piece repeated",
            "only one kind of character", "not valid text", "too long", "a common password",
            "of 12 characters)", "too predictable (~", "acceptable (~", " bits estimated)",
        };
        int all = js != NULL;
        for (size_t i = 0; all && i < sizeof phrases / sizeof phrases[0]; i++) {
            if (strstr(js, phrases[i]) == NULL) { printf("  missing from %s: %s\n", argv[1], phrases[i]); all = 0; }
        }
        CHECK(all, "explain: every phrase is the enrollment page's own (web/pages/enroll.mjs)");
    } else {
        printf("FAIL: explain: no path to web/pages/enroll.mjs was given\n");
        g_fail = 1;
    }

    printf(g_fail ? "\nFAILED\n" : "\nAll checks passed\n");
    return g_fail;
}
