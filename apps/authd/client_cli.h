#ifndef MLDSA_AUTH_APPS_AUTHD_CLIENT_CLI_H
#define MLDSA_AUTH_APPS_AUTHD_CLIENT_CLI_H

/* authd_client (spec 13): keygen, login, rotate. argv[0] is the program name,
 * argv[1] the subcommand; returns a process exit status (0 ok, 1 failed,
 * 2 usage, 3 configuration). Built on client_core.c since V4-13a, and linked
 * without the daemon's store. */
int authd_cli_client(int argc, char **argv);

#endif /* MLDSA_AUTH_APPS_AUTHD_CLIENT_CLI_H */
