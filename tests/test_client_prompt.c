/*
 * V4-13d: authd_client's --passphrase-prompt (apps/authd/cli_prompt.c), driven
 * through a real pseudo-terminal.
 *
 * A prompt's properties are all about the TERMINAL -- whether what is typed is
 * echoed, whether the settings come back, what happens on Ctrl-C -- so every
 * check here has a child process reading from the slave side of a pty while
 * this process types on the master side and reads back everything the
 * terminal showed. The last group runs the whole `authd_client keygen
 * --passphrase-prompt` under forkpty, so the CLI opens /dev/tty exactly as it
 * does for a person.
 *
 * The typed passphrases are test values; every transcript is checked NOT to
 * contain them, which is the property echo-off exists for.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif

#include <sodium.h>

#include "authd_secret.h"
#include "cli_prompt.h"
#include "client_cli.h"
#include "keyfile.h"
#include "mldsa_wrap.h"

static int g_fail = 0;
static int g_checks = 0;
static char g_dir[512];

static void check(int ok, const char *what)
{
    g_checks++;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_fail = 1;
    }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

#define GOOD  "tidal-harbor-quilted-lantern"   /* passes the policy */
#define GOOD2 "moss-cobalt-verandah-thimble"   /* passes too; a different one */
#define SHORT "short"                          /* too short (5 of 12 characters) */

/* ------------------------------------------------------ the master's side */

typedef struct {
    int  master;
    char out[32768];
    size_t n;
} term_t;

/* Reads whatever the terminal showed, for up to `ms`, until `needle` has
 * appeared `times` times in the whole transcript. 1 = seen. */
static int term_wait(term_t *t, const char *needle, int times, int ms)
{
    for (int waited = 0; waited <= ms; waited += 20) {
        size_t seen = 0;
        for (const char *q = t->out; (q = strstr(q, needle)) != NULL; q++) { seen++; }
        if (seen >= (size_t)times) {
            return 1;
        }
        struct pollfd pf = { t->master, POLLIN, 0 };
        if (poll(&pf, 1, 20) > 0) {
            const ssize_t k = read(t->master, t->out + t->n, sizeof t->out - 1u - t->n);
            if (k > 0) {
                t->n += (size_t)k;
                t->out[t->n] = '\0';
            } else if (k <= 0 && errno != EINTR && errno != EAGAIN) {
                return 0;                /* the child is gone: EIO on Linux */
            }
        }
    }
    return 0;
}

static void term_drain(term_t *t)
{
    (void)term_wait(t, "\x01never\x01", 1, 300);
}

static void term_type(term_t *t, const char *s)
{
    const size_t n = strlen(s);
    if (write(t->master, s, n) != (ssize_t)n) {
        printf("FAIL: could not type on the master side\n");
        g_fail = 1;
    }
}

static int echo_on(int fd)
{
    struct termios tio;
    return tcgetattr(fd, &tio) == 0 && (tio.c_lflag & ECHO) != 0;
}

/* ---------------------------------------------- the prompt, in a child */

typedef struct { int status; size_t len; uint8_t hash[32]; } result_t;

/* Forks a child that runs `fn` against the slave side and reports the status,
 * the length and the SHA-256 of what it read -- never the bytes. */
static pid_t run_child(int slave, int report_fd, int which)
{
    const pid_t pid = fork();
    if (pid != 0) {
        return pid;
    }
    result_t r;
    memset(&r, 0, sizeof r);
    uint8_t *p = NULL;
    size_t n = 0;
    r.status = (int)((which == 0) ? cli_prompt_read(slave, "Passphrase: ", &p, &n)
                                  : cli_prompt_new(slave, "test keygen", &p, &n));
    r.len = n;
    if (p != NULL) {
        crypto_hash_sha256(r.hash, p, n);
        authd_secret_free(p, n);
    }
    (void)!write(report_fd, &r, sizeof r);
    _exit(0);
}

static int child_result(int report_rd, pid_t pid, result_t *r, int *wstatus)
{
    memset(r, 0, sizeof *r);
    const ssize_t k = read(report_rd, r, sizeof *r);
    (void)waitpid(pid, wstatus, 0);
    return k == (ssize_t)sizeof *r;
}

static int is_hash_of(const result_t *r, const char *s)
{
    uint8_t h[32];
    crypto_hash_sha256(h, (const uint8_t *)s, strlen(s));
    return r->len == strlen(s) && memcmp(h, r->hash, 32) == 0;
}

static void test_read(void)
{
    int master = -1, slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        CHECK(0, "read: openpty");
        return;
    }
    term_t t;
    memset(&t, 0, sizeof t);
    t.master = master;
    CHECK(echo_on(slave), "read: the terminal echoes before the prompt (the canary)");

    int pr[2];
    CHECK(pipe(pr) == 0, "read: report pipe");
    pid_t pid = run_child(slave, pr[1], 0);
    CHECK(term_wait(&t, "Passphrase: ", 1, 5000), "read: the prompt is shown");
    term_type(&t, GOOD "\n");
    result_t r;
    int ws = 0;
    CHECK(child_result(pr[0], pid, &r, &ws), "read: the child reported");
    term_drain(&t);
    CHECK(r.status == CLI_PROMPT_OK && is_hash_of(&r, GOOD),
          "read: the line typed is what was read, without its newline");
    CHECK(strstr(t.out, GOOD) == NULL, "read: nothing typed was echoed to the terminal");
    CHECK(echo_on(slave), "read: echo is back on afterwards");

    /* CRLF, as a terminal in raw mode sends it */
    memset(&t, 0, sizeof t);
    t.master = master;
    pid = run_child(slave, pr[1], 0);
    CHECK(term_wait(&t, "Passphrase: ", 1, 5000), "read: prompt again");
    term_type(&t, GOOD "\r\n");
    CHECK(child_result(pr[0], pid, &r, &ws) && r.status == CLI_PROMPT_OK && is_hash_of(&r, GOOD),
          "read: a trailing CR is not part of the passphrase");

    /* an empty line is refused, not an empty passphrase */
    memset(&t, 0, sizeof t);
    t.master = master;
    pid = run_child(slave, pr[1], 0);
    CHECK(term_wait(&t, "Passphrase: ", 1, 5000), "read: prompt for the empty case");
    term_type(&t, "\n");
    CHECK(child_result(pr[0], pid, &r, &ws) && r.status == CLI_PROMPT_ERR_EMPTY && r.len == 0u,
          "read: an empty line is refused");

    /* Ctrl-C mid-prompt: the process dies of the signal AND the terminal is
     * restored -- a prompt that died with echo off leaves a shell that no
     * longer shows what is typed. */
    memset(&t, 0, sizeof t);
    t.master = master;
    pid = run_child(slave, pr[1], 0);
    CHECK(term_wait(&t, "Passphrase: ", 1, 5000), "read: prompt for the signal case");
    term_type(&t, "half-typ");
    usleep(100000);
    CHECK(!echo_on(slave), "read: echo is OFF while the prompt waits (the canary for the next check)");
    (void)kill(pid, SIGINT);
    (void)waitpid(pid, &ws, 0);
    CHECK(WIFSIGNALED(ws) && WTERMSIG(ws) == SIGINT,
          "read: SIGINT during the prompt still ends the process with SIGINT");
    CHECK(echo_on(slave), "read: ...and the terminal's echo was restored first");
    tcflush(slave, TCIOFLUSH);

    /* a descriptor that is not a terminal */
    { int p2[2];
      uint8_t *p = NULL;
      size_t n = 7;
      CHECK(pipe(p2) == 0 && cli_prompt_read(p2[0], "x", &p, &n) == CLI_PROMPT_ERR_NOT_TTY &&
            p == NULL && n == 0u, "read: a pipe is refused as not a terminal");
      (void)close(p2[0]); (void)close(p2[1]); }

    (void)close(pr[0]); (void)close(pr[1]);
    (void)close(slave); (void)close(master);
}

static void test_new(void)
{
    int master = -1, slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        CHECK(0, "new: openpty");
        return;
    }
    term_t t;
    int pr[2];
    CHECK(pipe(pr) == 0, "new: report pipe");
    result_t r;
    int ws = 0;

    /* a refusal in the browser's words, then a good one typed twice */
    memset(&t, 0, sizeof t);
    t.master = master;
    pid_t pid = run_child(slave, pr[1], 1);
    CHECK(term_wait(&t, "New passphrase", 1, 5000), "new: asks for a new passphrase");
    term_type(&t, SHORT "\n");
    CHECK(term_wait(&t, "refused by the passphrase policy: too short (5 of 12 characters)", 1, 5000),
          "new: a short one is refused in the enrollment page's words");
    CHECK(term_wait(&t, "New passphrase", 2, 5000), "new: and asked again");
    term_type(&t, GOOD "\n");
    CHECK(term_wait(&t, "Repeat it: ", 1, 5000), "new: an acceptable one is asked for twice");
    term_type(&t, GOOD "\n");
    CHECK(child_result(pr[0], pid, &r, &ws) && r.status == CLI_PROMPT_OK && is_hash_of(&r, GOOD),
          "new: the passphrase typed twice is returned");
    term_drain(&t);
    CHECK(strstr(t.out, "it does not certify strength") != NULL,
          "new: acceptance says the policy does not certify strength");
    CHECK(strstr(t.out, GOOD) == NULL && strstr(t.out, SHORT "\n") == NULL,
          "new: neither the refused nor the accepted passphrase appears on the terminal");

    /* three mismatches: refused, nothing returned */
    memset(&t, 0, sizeof t);
    t.master = master;
    pid = run_child(slave, pr[1], 1);
    int ok = 1;
    for (int i = 1; i <= 3; i++) {
        ok &= term_wait(&t, "New passphrase", i, 5000);
        term_type(&t, GOOD "\n");
        ok &= term_wait(&t, "Repeat it: ", i, 5000);
        term_type(&t, GOOD2 "\n");
    }
    CHECK(ok && child_result(pr[0], pid, &r, &ws) && r.status == CLI_PROMPT_ERR_REFUSED && r.len == 0u,
          "new: three mismatched repeats are refused and nothing is returned");
    term_drain(&t);
    CHECK(strstr(t.out, "did not match") != NULL && strstr(t.out, "after 3 tries") != NULL,
          "new: it says why, and when it gives up");

    (void)close(pr[0]); (void)close(pr[1]);
    (void)close(slave); (void)close(master);
}

/* ------------------------------------------- the whole CLI, under forkpty */

static int count_files(const char *dir)
{
    char cmd[700];
    (void)snprintf(cmd, sizeof cmd, "ls -A '%s' 2>/dev/null | wc -l", dir);
    FILE *p = popen(cmd, "r");
    int n = -1;
    if (p != NULL) {
        if (fscanf(p, "%d", &n) != 1) { n = -1; }
        pclose(p);
    }
    return n;
}

static void test_cli(void)
{
    char dir[600];
    (void)snprintf(dir, sizeof dir, "%s/dev", g_dir);

    int master = -1;
    const pid_t pid = forkpty(&master, NULL, NULL, NULL);
    if (pid == 0) {
        char *argv[] = { "authd_client", "keygen", "--dir", dir, "--passphrase-prompt", NULL };
        const int rc = authd_cli_client(5, argv);
        fflush(stdout);
        fflush(stderr);
        _exit(rc);
    }
    CHECK(pid > 0, "cli: forkpty");
    if (pid < 0) { return; }
    term_t t;
    memset(&t, 0, sizeof t);
    t.master = master;
    CHECK(term_wait(&t, "New passphrase", 1, 10000), "cli: keygen --passphrase-prompt asks at the terminal");
    term_type(&t, SHORT "\n");
    CHECK(term_wait(&t, "too short (5 of 12 characters)", 1, 5000), "cli: and refuses a short one there");
    CHECK(term_wait(&t, "New passphrase", 2, 5000), "cli: asks again");
    term_type(&t, GOOD "\n");
    CHECK(term_wait(&t, "Repeat it: ", 1, 5000), "cli: asks for the repeat");
    term_type(&t, GOOD "\n");
    (void)term_wait(&t, "The secret key never leaves this machine.", 1, 60000);
    int ws = 0;
    (void)waitpid(pid, &ws, 0);
    term_drain(&t);
    CHECK(WIFEXITED(ws) && WEXITSTATUS(ws) == 0, "cli: keygen exits 0");
    CHECK(strstr(t.out, GOOD) == NULL, "cli: the passphrase never appears on the terminal");

    /* the handle it printed, and the key sealed under what was typed */
    char handle[64] = {0};
    { const char *q = strstr(t.out, "\nd1");
      if (q == NULL && strncmp(t.out, "d1", 2) == 0) { q = t.out - 1; }
      if (q != NULL) { (void)sscanf(q + 1, "%63[0-9a-f]", handle); } }
    char ek[700];
    (void)snprintf(ek, sizeof ek, "%s/%s.ek", dir, handle);
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    CHECK(strlen(handle) == 34u &&
          keyfile_open(ek, (const uint8_t *)handle, strlen(handle), GOOD, strlen(GOOD), &kp, NULL) == KEYFILE_OK,
          "cli: the new key opens with the passphrase that was typed");
    mldsa_keypair_free(&kp);
    (void)close(master);
}

static int write_pass(const char *path, const char *text)
{
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { return -1; }
    const ssize_t k = write(fd, text, strlen(text));
    (void)close(fd);
    return k == (ssize_t)strlen(text) ? 0 : -1;
}

/* The same policy for a FILE, and the flags. In-process: no terminal needed. */
static void test_file_and_flags(void)
{
    char dir[600], weak[600], good[600];
    (void)snprintf(dir, sizeof dir, "%s/filedev", g_dir);
    (void)snprintf(weak, sizeof weak, "%s/weak.pass", g_dir);
    (void)snprintf(good, sizeof good, "%s/good.pass", g_dir);
    CHECK(write_pass(weak, "password1234\n") == 0 && write_pass(good, GOOD "\n") == 0,
          "flags: passphrase fixtures");

    { char *argv[] = { "authd_client", "keygen", "--dir", dir, "--passphrase-file", weak, NULL };
      CHECK(authd_cli_client(6, argv) == 1, "flags: keygen with a common passphrase in a FILE fails (1)"); }
    CHECK(count_files(dir) == 0, "flags: ...and writes no key");
    { char *argv[] = { "authd_client", "keygen", "--dir", dir, "--passphrase-file", good, NULL };
      CHECK(authd_cli_client(6, argv) == 0, "flags: keygen with an acceptable passphrase file succeeds (the canary)"); }
    CHECK(count_files(dir) == 2, "flags: ...and writes the .ek and the .pub");
    { char *argv[] = { "authd_client", "keygen", "--dir", dir, "--passphrase-file", good,
                       "--passphrase-prompt", NULL };
      CHECK(authd_cli_client(7, argv) == 2, "flags: a file AND the prompt is usage (2)"); }
    { char *argv[] = { "authd_client", "keygen", "--dir", dir, NULL };
      CHECK(authd_cli_client(4, argv) == 2, "flags: neither is usage (2)"); }
    { char *argv[] = { "authd_client", "login", "--handle", "d1aa", "--key", "k.ek",
                       "--passphrase-file", good, "--passphrase-prompt", "--server-id", "authd",
                       "--server-pub", "s.pub", "--port", "1", NULL };
      CHECK(authd_cli_client(15, argv) == 2, "flags: login with a file AND the prompt is usage (2)"); }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }
    const char *tmp = getenv("TMPDIR");
    (void)snprintf(g_dir, sizeof g_dir, "%s/prompt.XXXXXX", (tmp != NULL && tmp[0] != '\0') ? tmp : "/tmp");
    if (mkdtemp(g_dir) == NULL) {
        printf("FAIL: mkdtemp\n");
        return 1;
    }
    test_read();
    test_new();
    test_cli();
    test_file_and_flags();

    char cmd[700];
    (void)snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    (void)!system(cmd);
    printf("%d checks\n", g_checks);
    if (g_fail) {
        printf("FAILED\n");
        return 1;
    }
    printf("All checks passed\n");
    return 0;
}
