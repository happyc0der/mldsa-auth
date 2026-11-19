#ifndef MLDSA_AUTHD_CLI_H
#define MLDSA_AUTHD_CLI_H

/*
 * The two command-line tools (spec mldsa-authd 13).
 *
 *   authd_admin   init, keygen-server, migrate-key, rewrap        (offline)
 *                 enroll-operator, disable-user, enable-user,
 *                 list-users, list-devices, audit-tail, backup    (via admin.sock)
 *                 --check-config
 *   authd_client  keygen, login, rotate -- client_cli.c since V4-13a
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

/* Since V4-13a authd_client lives in client_cli.c (declared in client_cli.h)
 * and the .ek.next decision, key_plan_t / client_key_plan(), in client_core.h.
 * Both are included here so a caller of either tool needs one header. */
#include "client_core.h"
#include "authd_config.h"
#include "client_cli.h"

/* argv[0] is the program name, argv[1] the subcommand. */
int authd_cli_admin(int argc, char **argv);

/* How long the tool waits for the daemon's answer to `cmd` (F533): ten
 * seconds, and ten minutes for BACKUP, whose time grows with the store. And
 * what it adds to `timeout` for a command the daemon may still complete, or
 * NULL. Exposed so a test can name both without waiting for either. */
uint64_t authd_cli_timeout_ms(const char *cmd);
const char *authd_cli_timeout_hint(const char *cmd);

/* What --check-config says of a configuration that is valid and worth a
 * word (V4-314, F545): a uid in both site_uids and proxy_uids (F420), and
 * rates that can hold more addresses than the limiter's table (F338). One
 * function, because `mldsa-authd --check-config` warned and `authd_admin
 * --check-config` said only "is valid" of the same file. On stderr, so the
 * unit's ExecStartPre puts it in the journal. Returns how many it printed. */
int authd_cli_config_warnings(const authd_config_t *cfg, const char *prog);

#endif /* MLDSA_AUTHD_CLI_H */
