/* authd_admin: the administrator's tool (spec mldsa-authd 13).
 *
 * A thin main(). Every subcommand lives in authd_cli.c as a library function
 * so tests/test_authd_cli.c can drive its refusal paths directly rather than
 * forking a binary and parsing prose.
 */
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <stdio.h>

#include <sodium.h>

#include "authd_cli.h"
#include "stdfds.h"

int main(int argc, char **argv)
{
    /* V4-201, F280: before anything is opened. A CLI whose standard output
     * was closed has nowhere to put its result -- and without this, on Linux,
     * its socket took descriptor 1 and the result was written into it. */
    /* F721 (V4-349): as authd_client since V4-347 and V4-348. This tool
     * reads passphrases and writes keys, and had neither. */
    {
        struct rlimit none = { 0, 0 };
        (void)setrlimit(RLIMIT_CORE, &none);
#ifdef __linux__
        (void)prctl(PR_SET_DUMPABLE, 0);
#endif
    }
    const int closed = stdfds_ensure_open();
    if (closed < 0) {
        return 1;
    }
    if ((closed & STDFDS_STDOUT_WAS_CLOSED) != 0) {
        fprintf(stderr, "%s: standard output is closed, so nothing this command prints could be read; "
                        "nothing was done\n", argv[0] != NULL ? argv[0] : "authd_admin");
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "authd_admin: libsodium failed to initialise\n");
        return 1;
    }
    return authd_cli_admin(argc, argv);
}
