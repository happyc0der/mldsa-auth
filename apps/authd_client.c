/* authd_client: the device's tool (spec mldsa-authd 13).
 *
 * `keygen` creates a device handle and a sealed key; `login` performs the
 * post-quantum handshake and prints the login code the site exchanges for a
 * token. `rotate` is V4-9c.
 *
 * A thin main(): the subcommands live in authd_cli.c, for the same reason
 * demo_cli_keygen() does -- so the tests drive them without fork/exec.
 */
#include <stdio.h>

#include <sodium.h>

#include "authd_cli.h"

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "authd_client: libsodium failed to initialise\n");
        return 1;
    }
    return authd_cli_client(argc, argv);
}
