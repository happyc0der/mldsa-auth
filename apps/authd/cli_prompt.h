#ifndef MLDSA_AUTH_APPS_AUTHD_CLI_PROMPT_H
#define MLDSA_AUTH_APPS_AUTHD_CLI_PROMPT_H
/*
 * Typing a passphrase at a terminal (V4-13d), for authd_client's
 * --passphrase-prompt.
 *
 * Spec 12 keeps a passphrase out of argv and the environment, because other
 * processes on the host can read both; until now that left a FILE as the only
 * way in, which is right for a service and wrong for a person: a file holding
 * a human's passphrase is a copy of it at rest. A terminal is the other
 * channel nothing else on the host can read.
 *
 *   - Only a terminal. The caller opens /dev/tty, so the prompt and the
 *     passphrase never touch stdin or stdout -- stdout is where login prints
 *     the code a script may be capturing. A descriptor that is not a terminal
 *     is refused: piping a passphrase in is what --passphrase-file is for.
 *   - Echo is off while the line is read and the terminal's settings are put
 *     back on every path, including a signal: SIGINT, SIGTERM, SIGHUP and
 *     SIGQUIT are caught for the duration, the terminal restored, and the
 *     signal re-raised with its previous disposition.
 *   - The bytes go straight into secure memory (mlocked, wiped on free), are
 *     never written back, and never reach a log. The line's end ("\n", or
 *     "\r\n") is not part of the passphrase -- the file reader strips one
 *     newline for the same reason.
 *   - A NEW passphrase is checked against the one policy (passphrase.h), with
 *     the browser's words for a refusal, and typed twice. Three tries.
 */
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CLI_PROMPT_OK = 0,
    CLI_PROMPT_ERR_NOT_TTY,      /* the descriptor is not a terminal */
    CLI_PROMPT_ERR_IO,           /* read/write failed, or end of input */
    CLI_PROMPT_ERR_EMPTY,        /* an empty line */
    CLI_PROMPT_ERR_TOO_LONG,     /* over AUTHD_PASSPHRASE_MAX bytes */
    CLI_PROMPT_ERR_INTERRUPTED,  /* a signal arrived; the terminal was restored */
    CLI_PROMPT_ERR_REFUSED,      /* a new passphrase failed the policy or the repeat, three times */
    CLI_PROMPT_ERR_CRYPTO        /* secure memory could not be allocated */
} cli_prompt_status_t;

const char *cli_prompt_status_name(cli_prompt_status_t st);

/* Writes `prompt` to `fd`, reads one line from it with echo off, and writes
 * the newline the terminal did not echo. On OK, *out is a secure-memory
 * buffer of *out_len (>= 1) bytes that the caller frees with
 * authd_secret_free(). On every failure *out is NULL and *out_len 0. */
cli_prompt_status_t cli_prompt_read(int fd, const char *prompt, uint8_t **out, size_t *out_len);

/* A new passphrase: asked, checked with pp_check (the refusal explained with
 * pp_explain), asked again and compared in constant time; up to three tries.
 * `who` prefixes the messages ("authd_client keygen"). Same ownership as
 * cli_prompt_read. */
cli_prompt_status_t cli_prompt_new(int fd, const char *who, uint8_t **out, size_t *out_len);

#endif /* MLDSA_AUTH_APPS_AUTHD_CLI_PROMPT_H */
