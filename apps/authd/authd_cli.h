#ifndef MLDSA_AUTHD_CLI_H
#define MLDSA_AUTHD_CLI_H

/*
 * The two command-line tools (spec mldsa-authd 13).
 *
 *   authd_admin   init, keygen-server, migrate-key, rewrap        (offline)
 *                 enroll-operator, disable-user, enable-user,
 *                 list-users, list-devices, audit-tail, backup    (via admin.sock)
 *                 --check-config
 *   authd_client  keygen, login
 *
 * The subcommands live here, as library functions returning a process exit
 * status, rather than inside the two main() files -- the demo_cli_keygen()
 * precedent. That is what lets tests/test_authd_cli.c drive every refusal path
 * directly instead of forking a binary and parsing its output.
 *
 * Exit codes (spec 13), and they are a contract, not decoration:
 *   0 success   1 operation failed   2 usage error   3 configuration error
 * Every failure prints a status name from the same enums the daemon logs, so
 * one string can be searched for across the CLIs and the journal.
 *
 * PASSPHRASES ARE FILES. There is no prompt and no environment variable and no
 * argv form, exactly as the daemon's key_passphrase_file is. argv is readable
 * by every process on the host; a file has an owner and a mode.
 *
 * The ONLINE subcommands are thin clients of admin.sock (localcli.h), so there
 * is exactly one code path in this project that mutates a live store: the
 * daemon's. An admin tool that opened the store directly would be a second
 * writer racing the first.
 */

/* Which key file is live after an interrupted rotation (spec 10.2).
 *
 * Exposed for tests: it is the subtlest decision in the client, and the only
 * way to exercise every branch without staging a crash mid-round-trip. The
 * rule is NOT the spec's wording -- see authd_cli.c for why "if it is unknown,
 * the server never committed" cannot be implemented, and why only .ek
 * authenticating licenses discarding .ek.next. */
typedef enum {
    KEY_PLAN_USE_EK = 0,    /* .ek is current; if .ek.next exists it is stale */
    KEY_PLAN_PROMOTE_NEXT,  /* .ek.next is live: finish the interrupted rename */
    KEY_PLAN_REFUSE         /* neither authenticates: say so, change nothing */
} key_plan_t;

key_plan_t client_key_plan(int ek_ok, int next_present, int next_ok);

/* argv[0] is the program name, argv[1] the subcommand. */
int authd_cli_admin(int argc, char **argv);
int authd_cli_client(int argc, char **argv);

#endif /* MLDSA_AUTHD_CLI_H */
