#ifndef MLDSA_AUTH_APPS_AUTHD_PASSPHRASE_H
#define MLDSA_AUTH_APPS_AUTHD_PASSPHRASE_H

/*
 * The passphrase policy (V4-13c), in ONE place: the browser calls it through
 * the wasm shim, the CLI's interactive prompt (V4-13d) will call it natively.
 *
 * What it is for, stated plainly: an XSS or a stolen disk can take a sealed
 * envelope (spec 14's honest limits), and then only Argon2id and the
 * passphrase stand between an offline guesser and the key. Argon2id sets the
 * price per guess; this refuses the passphrases that need very few guesses.
 *
 * It REFUSES the obviously weak; it does not certify strength. The estimator
 * overestimates anything a human chose, as every such estimator does -- a
 * passphrase it accepts can still be a bad one, and the enrollment page says
 * so. The rules, in order (first failure wins):
 *
 *   NOT_UTF8     not well-formed UTF-8 (a browser never sends this; a file can)
 *   TOO_LONG     more than PP_MAX_BYTES bytes
 *   TOO_SHORT    fewer than PP_MIN_CODE_POINTS characters (code points, not bytes)
 *   COMMON       the passphrase, or its core with leading/trailing digits and
 *                symbols stripped, is in a pinned list of 9,913 common
 *                passwords (passphrase_common.c), compared case-insensitively
 *   PREDICTABLE  the estimate is under PP_MIN_BITS: repeated characters,
 *                runs (abc, 321), keyboard rows (qwerty, asdf) and a string
 *                made of one repeated unit count for almost nothing
 */

#include <stddef.h>
#include <stdint.h>

#define PP_MIN_CODE_POINTS 12u
#define PP_MAX_BYTES       1024u
#define PP_MIN_BITS        50u

typedef enum {
    PP_OK = 0,
    PP_NOT_UTF8,
    PP_TOO_LONG,
    PP_TOO_SHORT,
    PP_COMMON,
    PP_PREDICTABLE
} pp_verdict_t;

/* Why the estimate is low, for the page to say so. A bit is set whenever the
 * feature is present, whatever the verdict. */
#define PP_R_REPEATS       0x01u   /* the same character twice in a row */
#define PP_R_SEQUENCE      0x02u   /* a run like abc or 987 */
#define PP_R_KEYBOARD      0x04u   /* a run along a keyboard row */
#define PP_R_REPEATED_UNIT 0x08u   /* the whole thing is one unit repeated */
#define PP_R_ONE_CLASS     0x10u   /* only lower case, or only digits, or ... */

typedef struct {
    uint32_t code_points;
    uint32_t est_bits;     /* floor of the estimate; 0 unless the length checks passed */
    uint32_t reasons;      /* PP_R_* */
} pp_report_t;

/* `report` may be NULL. Never allocates; never logs the passphrase. */
pp_verdict_t pp_check(const uint8_t *pass, size_t len, pp_report_t *report);
const char *pp_verdict_name(pp_verdict_t v);

/* The generated table (passphrase_common.c): sorted bytewise, lower-case. */
extern const size_t pp_common_count;
extern const char *const pp_common[];

#endif /* MLDSA_AUTH_APPS_AUTHD_PASSPHRASE_H */
