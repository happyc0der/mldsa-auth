/*
 * A real daemon for the wasm client to log in to (V4-13b).
 *
 * The daemon is assembled in-process exactly as authd_main.c assembles it
 * (tests/authd_harness.h), with one difference a deployment never has: its
 * WebSocket listener is loopback TCP instead of the Unix socket Caddy reaches,
 * because Node's built-in WebSocket can only dial TCP. Everything above the
 * socket -- the upgrade, the handshake, the store, the site socket -- is the
 * daemon's own code.
 *
 * It prints one JSON line for tests/wasm_interop.mjs --
 *   {"site": <site socket path>, "ws_port": N, "server_id": "authd",
 *    "server_pub": <the server's MLDSAPK1 image, hex>}
 * -- and serves on the wall clock until the deadline (argv[1] seconds,
 * default 60), so a wedged test can never leave it behind. Enrollment and
 * EXCHANGE are the test's to do, through the site socket, as a site would.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "authd_harness.h"
#include "demo_keys.h"

int main(int argc, char **argv)
{
    const int seconds = (argc > 1) ? atoi(argv[1]) : 60;
    if (sodium_init() < 0) { return 1; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    /* mkdtemp, not a pid-keyed name: see authd_node_fixture.c for the leak
     * that rule came from. */
    char dir[256];
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] == '\0') { tmpdir = "/tmp"; }
    if (snprintf(dir, sizeof dir, "%s/authd-wasm-XXXXXX", tmpdir) < 0 || mkdtemp(dir) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }

    static h_daemon_t d;
    if (h_start_opts(&d, dir, "wasm.sqlite3", 1, 0, 1) != 0) { fprintf(stderr, "h_start_opts failed\n"); return 1; }
    /* The harness sizes the pending-handshake ledger to its 8 slots, which
     * suits the C tests. The browser tests run a handshake per login AND per
     * recovery probe, and a completed handshake holds its replay tombstone for
     * the 10 s TTL -- so 8 entries cap the fixture at 0.8 handshakes/s and the
     * daemon (correctly) refuses the rest (V4-12's capacity ceiling). A real
     * daemon sizes it to max_slots; this fixture uses the inline maximum. */
    handshake_pending_store_wipe(&d.pending);
    if (handshake_pending_store_init(&d.pending, HANDSHAKE_PENDING_MAX, 10000u, authd_app_clock, &d.app) !=
            PENDING_OK) {
        fprintf(stderr, "pending store failed\n");
        return 1;
    }
    /* Node is on the wall clock; so must the codes be (authd_node_fixture.c). */
    d.app.now_unix = (int64_t)time(NULL);

    uint8_t pub[4096];
    char pub_hex[8192];
    const size_t pl = demo_keys_public_image_len(sizeof H_SERVER_ID);
    if (demo_keys_build_public_image(pub, sizeof pub, H_SERVER_ID, sizeof H_SERVER_ID, d.server_kp.public_key) !=
            DEMO_KEYS_OK) {
        fprintf(stderr, "server public image failed\n");
        return 1;
    }
    h_hex(pub_hex, sizeof pub_hex, pub, pl);
    printf("{\"site\":\"%s\",\"ws_port\":%u,\"server_id\":\"authd\",\"server_pub\":\"%s\"}\n",
           d.site_path, (unsigned)d.ws_port, pub_hex);
    fflush(stdout);

    const time_t deadline = time(NULL) + seconds;
    while (time(NULL) < deadline) {
        d.app.now_ms += 5u;
        d.app.now_unix = (int64_t)time(NULL);
        (void)evloop_run_once(&d.ev, 5, d.app.now_ms);
    }
    h_stop(&d);
    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
      if (system(cmd) != 0) { /* best-effort */ } }
    return 0;
}
