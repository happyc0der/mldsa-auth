#include "cli_prompt.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_config.h"   /* AUTHD_PASSPHRASE_MAX: the same bound as a file */
#include "authd_secret.h"
#include "passphrase.h"
#include "secure_mem.h"

#define TRIES 3

const char *cli_prompt_status_name(cli_prompt_status_t st)
{
    switch (st) {
    case CLI_PROMPT_OK:              return "ok";
    case CLI_PROMPT_ERR_NOT_TTY:     return "not-a-terminal";
    case CLI_PROMPT_ERR_IO:          return "no-input";
    case CLI_PROMPT_ERR_EMPTY:       return "empty";
    case CLI_PROMPT_ERR_TOO_LONG:    return "too-long";
    case CLI_PROMPT_ERR_INTERRUPTED: return "interrupted";
    case CLI_PROMPT_ERR_REFUSED:     return "refused";
    case CLI_PROMPT_ERR_CRYPTO:      return "allocation-failed";
    }
    return "unknown";
}

static volatile sig_atomic_t g_caught = 0;

static void say(int fd, const char *s)
{
    size_t n = strlen(s);
    while (n > 0u) {
        const ssize_t k = write(fd, s, n);
        if (k < 0) {
            /* Retried, unless it is one of OUR caught signals: a write from
             * the background of a TOSTOP terminal fails this way every time,
             * and the caller has a stop to honour. */
            if (errno == EINTR && g_caught == 0) { continue; }
            return;
        }
        s += k;
        n -= (size_t)k;
    }
}

/* The signals that would otherwise kill the process with the terminal left
 * silent. Caught for the length of one read, WITHOUT SA_RESTART, so the read
 * returns EINTR and the terminal is restored before the signal is honoured. */
/* The stop signals are caught too (F203): a process stopped at the prompt
 * hands the terminal to a shell that turns echo back on, and one that merely
 * resumed its read would have the rest of the passphrase typed in clear. */
static const int k_sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU };
#define N_SIGS (sizeof k_sigs / sizeof k_sigs[0])

static void on_signal(int sig)
{
    g_caught = sig;
}

static int is_stop(int sig)
{
    return sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

cli_prompt_status_t cli_prompt_read(int fd, const char *prompt, uint8_t **out, size_t *out_len)
{
    if (out != NULL) { *out = NULL; }
    if (out_len != NULL) { *out_len = 0u; }
    if (out == NULL || out_len == NULL || fd < 0) {
        return CLI_PROMPT_ERR_IO;
    }
    struct termios saved;
    if (!isatty(fd) || tcgetattr(fd, &saved) != 0) {
        return CLI_PROMPT_ERR_NOT_TTY;
    }
    /* One byte over the bound, to tell "exactly at the limit" from "over". */
    const size_t cap = (size_t)AUTHD_PASSPHRASE_MAX + 1u;
    uint8_t *buf = secure_mem_alloc(cap);
    if (buf == NULL) {
        return CLI_PROMPT_ERR_CRYPTO;
    }

    struct sigaction sa, old[N_SIGS];
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                       /* no SA_RESTART: read must return */
    g_caught = 0;
    for (size_t i = 0; i < N_SIGS; i++) {
        (void)sigaction(k_sigs[i], NULL, &old[i]);
        if (is_stop(k_sigs[i]) && old[i].sa_handler == SIG_IGN) {
            continue;                      /* no job control here: it stays ignored */
        }
        (void)sigaction(k_sigs[i], &sa, NULL);
    }

    struct termios quiet = saved;
    cli_prompt_status_t st = CLI_PROMPT_OK;

    size_t len = 0;
    int over = 0, ended = 0;
    int armed = 0;                         /* echo is off and the prompt is shown */
    while (st == CLI_PROMPT_OK && !ended) {
        const int sig = (int)g_caught;     /* during a read, or between two */
        if (sig != 0 && !is_stop(sig)) {
            st = CLI_PROMPT_ERR_INTERRUPTED;
            break;
        }
        if (sig != 0) {
            /* F203: the terminal back, the stop honoured under the old
             * disposition, and on the way back echo off AGAIN and the prompt
             * again: whatever was typed before the stop is discarded
             * (TCSAFLUSH), so the person starts the line over and knows it. */
            (void)tcsetattr(fd, TCSANOW, &saved);
            for (size_t i = 0; i < N_SIGS; i++) {
                if (k_sigs[i] == sig) { (void)sigaction(sig, &old[i], NULL); }
            }
            (void)raise(sig);              /* stops here; returns when continued */
            (void)sigaction(sig, &sa, NULL);
            if (is_stop((int)g_caught)) {
                g_caught = 0;              /* a SIGINT caught meanwhile is kept */
            }
            armed = 0;
            continue;
        }
        if (!armed) {
            /* The first time round as well, so a prompt started in the
             * background stops on this call (SIGTTOU) and is asked properly
             * once it is brought forward. The settings to put back are read
             * HERE, in the foreground: read from the background they are the
             * shell's own line editor's (zsh: no ICANON, no ICRNL), and a
             * prompt built on those never sees the end of the line. */
            if (tcgetattr(fd, &saved) != 0) {
                st = CLI_PROMPT_ERR_NOT_TTY;
                break;
            }
            quiet = saved;
            quiet.c_lflag &= (tcflag_t)~(ECHO | ECHOE | ECHOK | ECHONL);
            if (tcsetattr(fd, TCSAFLUSH, &quiet) != 0) {
                if (g_caught != 0) {
                    continue;              /* in the background: stop, or stop again */
                }
                st = CLI_PROMPT_ERR_NOT_TTY;
                break;
            }
            sodium_memzero(buf, cap);
            len = 0;
            over = 0;
            if (prompt != NULL) {
                say(fd, prompt);
            }
            armed = 1;
            continue;
        }
        uint8_t c = 0;
        const ssize_t k = read(fd, &c, 1u);
        if (k < 0) {
            if (errno == EINTR) {
                continue;                  /* the top of the loop decides */
            }
            st = CLI_PROMPT_ERR_IO;
        } else if (k == 0) {
            st = CLI_PROMPT_ERR_IO;        /* end of input before a line ended */
        } else if (c == (uint8_t)'\n') {
            ended = 1;
        } else if (len < cap) {
            buf[len++] = c;
        } else {
            over = 1;                      /* keep reading to the end of the line */
        }
    }

    /* The terminal back, THEN the signals: in the other order a signal landing
     * between the two would kill the process with echo still off. */
    (void)tcsetattr(fd, TCSANOW, &saved);
    say(fd, "\n");                         /* the newline echo did not print */
    for (size_t i = 0; i < N_SIGS; i++) {
        (void)sigaction(k_sigs[i], &old[i], NULL);
    }
    if (st == CLI_PROMPT_ERR_INTERRUPTED) {
        const int sig = (int)g_caught;
        secure_mem_free(buf, cap);
        (void)raise(sig);                  /* honoured under the old disposition */
        return CLI_PROMPT_ERR_INTERRUPTED; /* reached only if the signal was ignored or handled */
    }
    if (st == CLI_PROMPT_OK) {
        if (len > 0u && buf[len - 1u] == (uint8_t)'\r') {
            len--;                         /* a terminal in raw CRLF mode */
        }
        if (over || len > (size_t)AUTHD_PASSPHRASE_MAX) {
            st = CLI_PROMPT_ERR_TOO_LONG;
        } else if (len == 0u) {
            st = CLI_PROMPT_ERR_EMPTY;
        }
    }
    if (is_stop((int)g_caught)) {
        /* A stop that landed after the line ended is still a stop: honoured
         * now, with the terminal already back; nothing more is read. */
        const int sig = (int)g_caught;
        g_caught = 0;
        (void)raise(sig);
    }
    if (st != CLI_PROMPT_OK) {
        secure_mem_free(buf, cap);
        return st;
    }
    /* An exact-size copy, so the caller frees what it was given with the
     * length it was given -- the authd_secret_read contract. */
    uint8_t *exact = secure_mem_alloc(len);
    if (exact == NULL) {
        secure_mem_free(buf, cap);
        return CLI_PROMPT_ERR_CRYPTO;
    }
    memcpy(exact, buf, len);
    secure_mem_free(buf, cap);
    *out = exact;
    *out_len = len;
    return CLI_PROMPT_OK;
}

cli_prompt_status_t cli_prompt_new(int fd, const char *who, uint8_t **out, size_t *out_len)
{
    if (out != NULL) { *out = NULL; }
    if (out_len != NULL) { *out_len = 0u; }
    if (out == NULL || out_len == NULL) {
        return CLI_PROMPT_ERR_IO;
    }
    char line[256];
    for (int t = 0; t < TRIES; t++) {
        uint8_t *p1 = NULL, *p2 = NULL;
        size_t n1 = 0, n2 = 0;
        cli_prompt_status_t st = cli_prompt_read(fd, "New passphrase (at least 12 characters): ", &p1, &n1);
        if (st == CLI_PROMPT_ERR_EMPTY || st == CLI_PROMPT_ERR_TOO_LONG) {
            (void)snprintf(line, sizeof line, "%s: %s; try again\n", who ? who : "", cli_prompt_status_name(st));
            say(fd, line);
            continue;
        }
        if (st != CLI_PROMPT_OK) {
            return st;
        }
        pp_report_t rep;
        const pp_verdict_t v = pp_check(p1, n1, &rep);
        char why[160];
        (void)pp_explain(v, &rep, why, sizeof why);
        if (v != PP_OK) {
            authd_secret_free(p1, n1);
            (void)snprintf(line, sizeof line, "%s: refused by the passphrase policy: %s\n",
                           who ? who : "", why);
            say(fd, line);
            continue;
        }
        st = cli_prompt_read(fd, "Repeat it: ", &p2, &n2);
        if (st != CLI_PROMPT_OK && st != CLI_PROMPT_ERR_EMPTY && st != CLI_PROMPT_ERR_TOO_LONG) {
            authd_secret_free(p1, n1);
            return st;
        }
        const int same = (st == CLI_PROMPT_OK && n1 == n2 && sodium_memcmp(p1, p2, n1) == 0);
        authd_secret_free(p2, n2);
        if (!same) {
            authd_secret_free(p1, n1);
            (void)snprintf(line, sizeof line, "%s: the two did not match; try again\n", who ? who : "");
            say(fd, line);
            continue;
        }
        /* Said once, where the person can read it: accepted is not certified. */
        (void)snprintf(line, sizeof line, "%s: %s -- the policy refuses the obviously weak; "
                                          "it does not certify strength\n", who ? who : "", why);
        say(fd, line);
        sodium_memzero(why, sizeof why);
        *out = p1;
        *out_len = n1;
        return CLI_PROMPT_OK;
    }
    (void)snprintf(line, sizeof line, "%s: no acceptable passphrase after %d tries\n", who ? who : "", TRIES);
    say(fd, line);
    return CLI_PROMPT_ERR_REFUSED;
}
