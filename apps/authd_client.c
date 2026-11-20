/* authd_client: the device's tool (spec mldsa-authd 13).
 *
 * `keygen` creates a device handle and a sealed key; `login` performs the
 * post-quantum handshake and prints the login code the site exchanges for a
 * token. `rotate` is V4-9c.
 *
 * A thin main(): the subcommands live in authd/client_cli.c (on the shared
 * client core since V4-13a), for the same reason demo_cli_keygen() does -- so
 * the tests drive them without fork/exec. This binary links no store and no
 * sqlite3; client_links_no_sqlite checks that on every build.
 */
#include <sys/resource.h>
#include <stdio.h>

#include <sodium.h>

#include "client_cli.h"
#include "stdfds.h"

int main(int argc, char **argv)
{
    /* V4-201, F280: before anything is opened. A CLI whose standard output
     * was closed has nowhere to put its result -- and without this, on Linux,
     * its socket took descriptor 1 and the result was written into it. */
    /* F707 (V4-347): no core file. The session keys of a login are in this
     * process's memory, and a crash would have written them to disk under
     * whatever the system's core pattern is. The daemon's unit sets
     * LimitCORE=0; nothing did it for the client. */
    {
        struct rlimit none = { 0, 0 };
        (void)setrlimit(RLIMIT_CORE, &none);
    }
    const int closed = stdfds_ensure_open();
    if (closed < 0) {
        return 1;
    }
    if ((closed & STDFDS_STDOUT_WAS_CLOSED) != 0) {
        fprintf(stderr, "%s: standard output is closed, so nothing this command prints could be read; "
                        "nothing was done\n", argv[0] != NULL ? argv[0] : "authd_client");
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "authd_client: libsodium failed to initialise\n");
        return 1;
    }
    return authd_cli_client(argc, argv);
}
