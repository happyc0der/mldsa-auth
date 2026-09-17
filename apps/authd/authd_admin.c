/* authd_admin: the administrator's tool (spec mldsa-authd 13).
 *
 * A thin main(). Every subcommand lives in authd_cli.c as a library function
 * so tests/test_authd_cli.c can drive its refusal paths directly rather than
 * forking a binary and parsing prose.
 */
#include <stdio.h>

#include <sodium.h>

#include "authd_cli.h"

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "authd_admin: libsodium failed to initialise\n");
        return 1;
    }
    return authd_cli_admin(argc, argv);
}
