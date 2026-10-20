#ifndef MLDSA_AUTH_TESTS_JOURNAL_SCAN_H
#define MLDSA_AUTH_TESTS_JOURNAL_SCAN_H

/* Does a captured journal hold a secret? (CLAIMS D13.) Shared by
 * test_authd_conn (a login, a ROTATE and a BYE) and test_authd_localapi (the
 * local API's own secrets) since V4-29, so the two scans look for the same
 * encodings and cannot drift apart. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "key_windows.h"

static inline int scan_hit(const char *what, size_t w, size_t len, const char *how)
{
    printf("  (scan: the journal holds %s[%zu..%zu) in %s)\n", what, w, w + len, how);
    return 1;
}

typedef struct { size_t lo, hi; } span_t;

/* 1 if [w, w+len) lies wholly inside one of the spans. */
static inline int in_spans(size_t w, size_t len, const span_t *skip, size_t nskip)
{
    for (size_t i = 0; i < nskip; i++) {
        if (w >= skip[i].lo && w + len <= skip[i].hi) { return 1; }
    }
    return 0;
}

/* How authd_log_slot_id writes a byte into an `id=` field: itself if
 * printable ASCII, '.' otherwise (apps/authd/authd_log.c). */
static inline char journal_escaped(uint8_t b)
{
    return (b >= 0x20u && b <= 0x7eu) ? (char)b : '.';
}

#define JOURNAL_ESC_WIN 16u
#define JOURNAL_ESC_MIN_PRINTABLE 2u

/* V4-29: 1 if some `id=` field in `log` holds the ESCAPED image of a 16-byte
 * window of s. With `log_ids = full`, authd_log_slot_id prints its bytes
 * that way, truncated at 64 and marked '~' -- a form no hex or base64 search
 * can see, so a secret passed where an identifier belongs printed about a
 * third of its bytes verbatim and every scan stayed clean.
 *
 * The match is per character over a whole 16-character window: each printable
 * byte must be itself, each other byte a '.'. A window needs at least two
 * printable characters to count, so a run of dots is never evidence. Only the
 * id= fields are read, because that is the only place the logger escapes. */
static inline int log_id_field_holds(const char *log, const char *what, const uint8_t *s, size_t n, int is_sk,
                              const span_t *skip, size_t nskip)
{
    if (n < JOURNAL_ESC_WIN) { return 0; }
    char *img = (char *)malloc(n);
    if (img == NULL) { return scan_hit(what, 0u, n, "an allocation failure (counted as a hit)"); }
    for (size_t i = 0; i < n; i++) { img[i] = journal_escaped(s[i]); }
    int hit = 0;
    for (const char *p = strstr(log, " id="); p != NULL && !hit; p = strstr(p + 1, " id=")) {
        const char *f = p + 4;
        size_t fl = strcspn(f, "\n");
        if (fl > 0u && f[fl - 1u] == '~') { fl--; }
        for (size_t j = 0; j + JOURNAL_ESC_WIN <= fl && !hit; j++) {
            size_t printable = 0;
            for (size_t i = 0; i < JOURNAL_ESC_WIN; i++) { printable += (f[j + i] != '.') ? 1u : 0u; }
            if (printable < JOURNAL_ESC_MIN_PRINTABLE) { continue; }
            /* Every place this 16-character window occurs in s's image. */
            for (size_t from = 0; from + JOURNAL_ESC_WIN <= n && !hit;) {
                const char *m = (const char *)memmem(img + from, n - from, f + j, JOURNAL_ESC_WIN);
                if (m == NULL) { break; }
                const size_t w = (size_t)(m - img);
                if ((!is_sk || sk_window_is_secret(w, JOURNAL_ESC_WIN)) && !in_spans(w, JOURNAL_ESC_WIN, skip, nskip)) {
                    hit = scan_hit(what, w, JOURNAL_ESC_WIN, "an escaped id= field");
                }
                from = w + 1u;
            }
        }
    }
    free(img);
    return hit;
}

/* 1 if any 16-byte window of s[0..n) appears in `log` in lowercase or
 * uppercase hex, or any 12-byte window in base64 (standard or url-safe), or
 * -- since V4-29 -- any 16-byte window as an escaped id= field. A logger that
 * base64-encodes a buffer holding the secret at ANY offset writes the
 * encoding of some 3-aligned 12-byte chunk of it verbatim, so the base64
 * search covers every alignment. With `is_sk`, s is an ML-DSA secret key and
 * only its wholly secret windows are looked for. Windows wholly inside `skip`
 * are not looked for: the parts of a buffer that are logged on purpose (a
 * fingerprint) or are evidence of nothing (a signature's mostly-zero hint).
 * A hit names `what` and the window, so a failure explains itself. */
static inline int log_holds_window_skip(const char *log, const char *what, const uint8_t *s, size_t n, int is_sk,
                                 const span_t *skip, size_t nskip)
{
    char hex[33], b64[32];
    for (size_t w = 0; w + 12u <= n; w++) {
        if (w + 16u <= n && (!is_sk || sk_window_is_secret(w, 16u)) && !in_spans(w, 16u, skip, nskip)) {
            (void)sodium_bin2hex(hex, sizeof hex, s + w, 16u);
            if (strstr(log, hex) != NULL) { return scan_hit(what, w, 16u, "hex"); }
            for (size_t i = 0; hex[i] != '\0'; i++) {
                if (hex[i] >= 'a' && hex[i] <= 'f') { hex[i] = (char)(hex[i] - 'a' + 'A'); }
            }
            if (strstr(log, hex) != NULL) { return scan_hit(what, w, 16u, "upper-case hex"); }
        }
        if ((!is_sk || sk_window_is_secret(w, 12u)) && !in_spans(w, 12u, skip, nskip)) {
            (void)sodium_bin2base64(b64, sizeof b64, s + w, 12u, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
            if (strstr(log, b64) != NULL) { return scan_hit(what, w, 12u, "base64"); }
            (void)sodium_bin2base64(b64, sizeof b64, s + w, 12u, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
            if (strstr(log, b64) != NULL) { return scan_hit(what, w, 12u, "url-safe base64"); }
        }
    }
    return log_id_field_holds(log, what, s, n, is_sk, skip, nskip);
}

static inline int log_holds_window(const char *log, const char *what, const uint8_t *s, size_t n, int is_sk)
{
    return log_holds_window_skip(log, what, s, n, is_sk, NULL, 0u);
}

#endif
